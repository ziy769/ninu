mod common;
mod config;
mod proxy;

use crate::config::Config;
use crate::proxy::*;

use std::collections::HashMap;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde_json::json;
use uuid::Uuid;
use worker::*;
use once_cell::sync::Lazy;
use regex::Regex;

static PROXYIP_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^.+-\d+$").unwrap());
static PROXYKV_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([A-Z]{2})").unwrap());

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    let uuid = env
        .var("UUID")
        .map(|x| Uuid::parse_str(&x.to_string()).unwrap_or_default())?;
    let host = req.url()?.host().map(|x| x.to_string()).unwrap_or_default();
    let main_page_url = env.var("MAIN_PAGE_URL").map(|x|x.to_string()).unwrap_or_default(); // Added .unwrap_or_default() for safety
    let sub_page_url = env.var("SUB_PAGE_URL").map(|x|x.to_string()).unwrap_or_default(); // Added .unwrap_or_default() for safety
    let config = Config { uuid, host: host.clone(), proxy_addr: host, proxy_port: 443, main_page_url, sub_page_url };

    Router::with_data(config)
        .on_async("/", fe)
        .on_async("/sub", sub)
        .on("/link", link)
        .on_async("/:proxyip", tunnel)
        .run(req, env)
        .await
}

async fn get_response_from_url(url: String) -> Result<Response> {
    let req = Fetch::Url(Url::parse(url.as_str())?);
    let mut res = req.send().await?;
    Response::from_html(res.text().await?)
}

async fn fe(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.main_page_url).await
}

async fn sub(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.sub_page_url).await
}


async fn tunnel(req: Request, mut cx: RouteContext<Config>) -> Result<Response> {
    let mut proxyip = cx.param("proxyip").unwrap().to_string(); // Unwrap here means we expect "proxyip" to always be present
    
    if PROXYKV_PATTERN.is_match(&proxyip)  {
        let kvid_list: Vec<String> = proxyip.split(',').map(|s| s.to_string()).collect();
        if kvid_list.is_empty() {
            console_error!("Proxy KV ID list is empty for proxyip: {}", proxyip);
            return Response::error("Invalid proxy KV ID list", 400);
        }

        let kv = cx.kv("YUMI")?;
        let mut proxy_kv_str = kv.get("proxy_kv").text().await?.unwrap_or_default(); // Using unwrap_or_default() for a safe empty string
        let mut rand_buf = [0u8; 1]; // Use [0u8; 1] for fixed size array init
        
        // Use a better random number for index if possible, as rand_buf[0] may be 0 repeatedly
        // For simple testing, this is fine, but for production, consider a more robust random source
        // Cloudflare Workers provide getrandom for secure random bytes
        getrandom::getrandom(&mut rand_buf).expect("failed generating random number");
        
        if proxy_kv_str.is_empty() {
            console_log!("getting proxy kv from github...");
            let req_fetch = Fetch::Url(Url::parse("https://raw.githubusercontent.com/datayumiwandi/shiroko/refs/heads/main/Data/Alive.json")?);
            let mut res_fetch = req_fetch.send().await?;
            if res_fetch.status_code() == 200 {
                proxy_kv_str = res_fetch.text().await?.to_string();
                kv.put("proxy_kv", &proxy_kv_str)?.expiration_ttl(60 * 60 * 12).execute().await?; // 12 hours
            } else {
                console_error!("Failed to get proxy KV from GitHub: {}", res_fetch.status_code());
                return Err(Error::from(format!("Error getting proxy kv: HTTP {}", res_fetch.status_code())));
            }
        }
        
        let proxy_kv: HashMap<String, Vec<String>> = serde_json::from_str(&proxy_kv_str).map_err(|e| {
            console_error!("Failed to parse proxy KV JSON: {}", e);
            Error::RustError(format!("Failed to parse proxy KV JSON: {}", e))
        })?;
        
        // Select random KV ID
        let kv_index = (rand_buf[0] as usize) % kvid_list.len();
        proxyip = kvid_list[kv_index].clone();
        
        // Select random proxy ip
        let proxyip_values = proxy_kv.get(&proxyip).ok_or_else(|| {
            console_error!("Proxy ID '{}' not found in KV data.", proxyip);
            Error::RustError(format!("Proxy ID not found: {}", proxyip))
        })?;
        if proxyip_values.is_empty() {
             console_error!("No proxy IPs found for ID '{}'.", proxyip);
             return Response::error("No proxy IPs available for selected ID", 500);
        }
        let proxyip_index = (rand_buf[0] as usize) % proxyip_values.len();
        proxyip = proxyip_values[proxyip_index].clone().replace(':', "-"); // Use char literal for single char replace
    }

    let upgrade_header = req.headers().get("Upgrade")?.unwrap_or_default();
    if upgrade_header == "websocket".to_string() && PROXYIP_PATTERN.is_match(&proxyip) {
        if let Some((addr, port_str)) = proxyip.split_once('-') {
            if let Ok(port) = port_str.parse() {
                cx.data.proxy_addr = addr.to_string();
                cx.data.proxy_port = port;
            } else {
                // Log and return error if port parsing fails
                console_error!("Failed to parse port from '{}'", port_str);
                return Response::error("Invalid port in proxyip", 400);
            }
        } else {
            // Log and return error if proxyip format is invalid
            console_error!("Invalid proxyip format for WebSocket upgrade: {}", proxyip);
            return Response::error("Invalid proxyip format", 400);
        }
        
        let ws_pair = WebSocketPair::new()?;
        let server = ws_pair.server;
        let client = ws_pair.client;

        server.accept()?;
    
        wasm_bindgen_futures::spawn_local(async move {
            // **PENTING: Tangani hasil server.events() dengan aman**
            match server.events() {
                Ok(events) => {
                    if let Err(e) = ProxyStream::new(cx.data, &server, events).process().await {
                        // Ini akan menangkap error dari dalam ProxyStream
                        console_error!("[tunnel] ProxyStream error: {}", e);
                    }
                },
                Err(e) => {
                    // Ini akan menangkap error jika tidak bisa mendapatkan events dari WebSocket server
                    console_error!("[tunnel] Failed to get WebSocket server events: {}", e);
                    // Pertimbangkan untuk menutup server secara eksplisit di sini jika koneksi klien masih terbuka
                    // server.close(Some(1011), Some("Internal server error: Failed to get events")).unwrap_or_default();
                }
            }
        });
    
        Response::from_websocket(client)
    } else {
        // Jika bukan WebSocket upgrade atau proxyip tidak cocok, berikan respons HTML biasa
        Response::from_html("hi from wasm!")
    }
}

fn link(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    let host = cx.data.host.to_string();
    let uuid = cx.data.uuid.to_string();

    let vmess_link = {
        let config = json!({
            "ps": "Changli vmess",
            "v": "2",
            "add": host,
            "port": "80", // Note: This might be 443 if you're expecting TLS on the Vmess link itself
            "id": uuid,
            "aid": "0",
            "scy": "zero",
            "net": "ws",
            "type": "none",
            "host": host,
            "path": "/ID",
            "tls": "", // This should be "tls" if port 443 is used, or "none" if port 80
            "sni": host,
            "alpn": ""}
        );
        format!("vmess://{}", URL_SAFE.encode(config.to_string()))
    };
    // Perhatikan bahwa di sini Anda menggunakan port 443 dan security=tls, pastikan konsisten dengan konfigurasi Vmess
    let vless_link = format!("vless://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2FID&security=tls&sni={host}#Changli vless");
    let trojan_link = format!("trojan://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2FID&security=tls&sni={host}#Changli trojan");
    let ss_link = format!("ss://{}@{host}:443?plugin=v2ray-plugin%3Btls%3Bmux%3D0%3Bmode%3Dwebsocket%3Bpath%3D%2FID%3Bhost%3D{host}#Changli ss", URL_SAFE.encode(format!("none:{uuid}")));
    
    Response::from_body(ResponseBody::Body(format!("{vmess_link}\n{vless_link}\n{trojan_link}\n{ss_link}").into()))
}
