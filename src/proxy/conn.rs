use crate::config::Config;

use std::pin::Pin;
use std::task::{Context, Poll};
use bytes::{BufMut, BytesMut};
use futures_util::Stream;
use pin_project_lite::pin_project;
use pretty_bytes::converter::convert;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use worker::*; // Penting: Pastikan ini ada untuk console_log! dan console_error!

static MAX_WEBSOCKET_SIZE: usize = 64 * 1024; // 64kb
static MAX_BUFFER_SIZE: usize = 512 * 1024; // 512kb

pin_project! {
    pub struct ProxyStream<'a> {
        pub config: Config,
        pub ws: &'a WebSocket,
        pub buffer: BytesMut,
        #[pin]
        pub events: EventStream<'a>,
    }
}

impl<'a> ProxyStream<'a> {
    pub fn new(config: Config, ws: &'a WebSocket, events: EventStream<'a>) -> Self {
        let buffer = BytesMut::with_capacity(MAX_BUFFER_SIZE);
        console_log!("ProxyStream: New instance created."); // Added log
        Self {
            config,
            ws,
            buffer,
            events,
        }
    }
    
    pub async fn fill_buffer_until(&mut self, n: usize) -> std::io::Result<()> {
        use futures_util::StreamExt;

        console_log!("ProxyStream: Filling buffer until {} bytes. Current: {}", n, self.buffer.len()); // Added log

        while self.buffer.len() < n {
            match self.events.next().await {
                Some(Ok(WebsocketEvent::Message(msg))) => {
                    if let Some(data) = msg.bytes() {
                        if data.len() > MAX_WEBSOCKET_SIZE {
                            console_error!("ProxyStream: Incoming WebSocket message too large ({} bytes). Max allowed: {} bytes.", data.len(), MAX_WEBSOCKET_SIZE); // Added error log
                            return Err(std::io::Error::new(std::io::ErrorKind::Other, "websocket message too large"));
                        }
                        if self.buffer.len() + data.len() > MAX_BUFFER_SIZE {
                            console_error!("ProxyStream: Buffer full ({} bytes). Cannot add {} bytes more. Applying backpressure.", self.buffer.len(), data.len()); // Added error log
                            // In a real scenario, you might want to return Poll::Pending here if in poll_read,
                            // but in fill_buffer_until, returning an error or breaking might be better
                            return Err(std::io::Error::new(std::io::ErrorKind::Other, "websocket buffer full"));
                        }
                        self.buffer.put_slice(&data);
                        console_log!("ProxyStream: Added {} bytes to buffer. Total: {}", data.len(), self.buffer.len()); // Added log
                    } else {
                        console_log!("ProxyStream: Received empty or non-binary WebSocket message."); // Added log
                    }
                }
                Some(Ok(WebsocketEvent::Close(close_event))) => {
                    console_log!("ProxyStream: WebSocket client closed connection. Code: {:?}, Reason: {:?}", close_event.code(), close_event.reason()); // Added log
                    break;
                }
                Some(Err(e)) => {
                    console_error!("ProxyStream: Error receiving from WebSocket events: {}", e); // Added error log
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
                }
                None => {
                    console_log!("ProxyStream: WebSocket event stream ended."); // Added log
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn peek_buffer(&self, n: usize) -> &[u8] {
        let len = self.buffer.len().min(n);
        &self.buffer[..len]
    }

    pub async fn process(&mut self) -> Result<()> {
        console_log!("ProxyStream: Starting protocol detection."); // Added log
        let peek_buffer_len = 62;
        
        // Timeout for initial buffer filling to prevent indefinite hanging if no data comes
        let fill_result = tokio::time::timeout(
            std::time::Duration::from_secs(5), // 5 seconds timeout
            self.fill_buffer_until(peek_buffer_len)
        ).await;

        let filled_buffer = match fill_result {
            Ok(Ok(_)) => {
                let peeked_buffer = self.peek_buffer(peek_buffer_len);
                if peeked_buffer.len() < (peek_buffer_len / 2) {
                    console_error!("ProxyStream: Not enough buffer for protocol detection. Buffer size: {}", peeked_buffer.len()); // Added error log
                    return Err(Error::RustError("not enough buffer for protocol detection".to_string()));
                }
                peeked_buffer
            },
            Ok(Err(e)) => {
                console_error!("ProxyStream: Error filling buffer for protocol detection: {}", e); // Added error log
                return Err(Error::RustError(format!("Failed to fill buffer: {}", e)));
            },
            Err(_) => { // Timeout occurred
                console_error!("ProxyStream: Timeout occurred while waiting for initial WebSocket data."); // Added error log
                self.ws.close(Some(1008), Some("No initial data received")).unwrap_or_default(); // Close WebSocket with 1008 Policy Violation
                return Err(Error::RustError("Initial WebSocket data timeout".to_string()));
            }
        };

        // PROTOCOL DETECTION
        // Pastikan Anda sudah mengimplementasikan `process_vless`, `process_shadowsocks`,
        // `process_trojan`, dan `process_vmess` di tempat lain (misalnya di file-file terpisah seperti vless.rs, vmess.rs dll)
        // dan mereka diimpor atau dapat diakses oleh ProxyStream.
        // Jika belum, ini akan menjadi error "method not found".
        if self.is_vless(filled_buffer) {
            console_log!("vless detected!");
            self.process_vless().await // Assumes this method exists and is reachable
        } else if self.is_shadowsocks(filled_buffer) {
            console_log!("shadowsocks detected!");
            self.process_shadowsocks().await // Assumes this method exists and is reachable
        } else if self.is_trojan(filled_buffer) {
            console_log!("trojan detected!");
            self.process_trojan().await // Assumes this method exists and is reachable
        } else if self.is_vmess(filled_buffer) {
            console_log!("vmess detected!");
            self.process_vmess().await // Assumes this method exists and is reachable
        } else {
            console_error!("ProxyStream: Unknown protocol detected. First bytes: {:?}", &filled_buffer[..std::cmp::min(16, filled_buffer.len())]); // Log first bytes for debugging
            Err(Error::RustError("protocol not implemented or unrecognized".to_string()))
        }
    }

    pub fn is_vless(&self, buffer: &[u8]) -> bool {
        // Logika Vless Anda
        if buffer.is_empty() { return false; }
        buffer[0] == 0
    }

    fn is_shadowsocks(&self, buffer: &[u8]) -> bool {
        // Logika Shadowsocks Anda
        if buffer.is_empty() { return false; }
        match buffer[0] {
            1 => { // IPv4
                if buffer.len() < 7 {
                    return false;
                }
                let remote_port = u16::from_be_bytes([buffer[5], buffer[6]]);
                remote_port != 0
            }
            3 => { // Domain name
                if buffer.len() < 2 {
                    return false;
                }
                let domain_len = buffer[1] as usize;
                if buffer.len() < 2 + domain_len + 2 {
                    return false;
                }
                let remote_port = u16::from_be_bytes([
                    buffer[2 + domain_len],
                    buffer[2 + domain_len + 1],
                ]);
                remote_port != 0
            }
            4 => { // IPv6
                if buffer.len() < 19 {
                    return false;
                }
                let remote_port = u16::from_be_bytes([buffer[17], buffer[18]]);
                remote_port != 0
            }
            _ => false,
        }
    }

    fn is_trojan(&self, buffer: &[u8]) -> bool {
        // Logika Trojan Anda
        buffer.len() > 57 && buffer[56] == 13 && buffer[57] == 10
    }

    fn is_vmess(&self, buffer: &[u8]) -> bool {
        // Logika Vmess Anda - ini adalah fallback, sangat luas.
        // Jika ini selalu true, maka protokol lain tidak akan pernah terdeteksi.
        // Pertimbangkan logika yang lebih spesifik jika Vmess memiliki signature awal.
        // Misalnya: return buffer.len() > 0 && buffer[0] == <VMESS_MAGIC_BYTE>;
        buffer.len() > 0 // fallback
    }

    pub async fn handle_tcp_outbound(&mut self, addr: String, port: u16) -> Result<()> {
        console_log!("ProxyStream: Attempting TCP outbound connection to {}:{}", addr, port); // Added log

        let connect_result = tokio::time::timeout(
            std::time::Duration::from_secs(10), // 10 seconds timeout for TCP connect
            Socket::builder().connect(&addr, port)
        ).await;

        let mut remote_socket = match connect_result {
            Ok(Ok(s)) => {
                console_log!("ProxyStream: TCP connection to {}:{} established. Waiting for socket to open.", addr, port); // Added log
                let open_result = tokio::time::timeout(
                    std::time::Duration::from_secs(5), // 5 seconds timeout for socket.opened()
                    s.opened()
                ).await;

                match open_result {
                    Ok(Ok(_)) => {
                        console_log!("ProxyStream: Remote socket to {}:{} is fully opened.", addr, port); // Added log
                        s
                    },
                    Ok(Err(e)) => {
                        console_error!("ProxyStream: Error waiting for remote socket to open to {}:{}: {}", addr, port, e); // Added error log
                        self.ws.close(Some(1011), Some("Backend socket failed to open")).unwrap_or_default();
                        return Err(Error::RustError(format!("Remote socket opened error: {}", e)));
                    },
                    Err(_) => {
                        console_error!("ProxyStream: Timeout waiting for remote socket to open to {}:{}.", addr, port); // Added error log
                        self.ws.close(Some(1008), Some("Backend socket open timeout")).unwrap_or_default();
                        return Err(Error::RustError("Remote socket open timeout".to_string()));
                    }
                }
            },
            Ok(Err(e)) => {
                console_error!("ProxyStream: Failed to connect to TCP outbound {}:{}: {}", addr, port, e); // Added error log
                self.ws.close(Some(1011), Some("Failed to connect to backend")).unwrap_or_default();
                return Err(Error::RustError(format!("TCP connect error: {}", e)));
            },
            Err(_) => {
                console_error!("ProxyStream: Timeout connecting to TCP outbound {}:{}.", addr, port); // Added error log
                self.ws.close(Some(1008), Some("Backend connection timeout")).unwrap_or_default();
                return Err(Error::RustError("TCP connection timeout".to_string()));
            }
        };

        // Write any buffered data from initial WebSocket handshake
        if !self.buffer.is_empty() {
            console_log!("ProxyStream: Writing {} bytes from buffer to remote socket.", self.buffer.len()); // Added log
            if let Err(e) = remote_socket.write_all(&self.buffer.split_to(self.buffer.len())).await {
                console_error!("ProxyStream: Failed to write initial buffer to remote socket: {}", e);
                self.ws.close(Some(1011), Some("Backend write error")).unwrap_or_default();
                return Err(Error::RustError(format!("Initial write to backend failed: {}", e)));
            }
        }
        
        console_log!("ProxyStream: Starting bidirectional copy between WebSocket and TCP socket."); // Added log
        tokio::io::copy_bidirectional(self, &mut remote_socket)
            .await
            .map(|(a_to_b, b_to_a)| {
                console_log!("ProxyStream: Copied data from {}:{}, up: {} and dl: {}", &addr, &port, convert(a_to_b as f64), convert(b_to_a as f64)); // Added log
            })
            .map_err(|e| {
                console_error!("ProxyStream: Bidirectional copy error for {}:{}: {}", &addr, &port, e); // Added error log
                // Close WebSocket gracefully if copy fails
                self.ws.close(Some(1011), Some("Data transfer failed")).unwrap_or_default();
                Error::RustError(e.to_string())
            })?;
        
        console_log!("ProxyStream: Bidirectional copy finished for {}:{}.", addr, port); // Added log
        Ok(())
    }

    pub async fn handle_udp_outbound(&mut self) -> Result<()> {
        console_log!("ProxyStream: Handling UDP outbound. (Note: UDP is usually sessionless, this might not directly translate to a long-lived 'hung' state but issues here could cause protocol detection failures.)"); // Added log
        let mut buff = vec![0u8; 65535];

        let n = self.read(&mut buff).await?;
        let data = &buff[..n];
        if crate::dns::doh(data).await.is_ok() {
            console_log!("ProxyStream: Successfully processed DNS over HTTPS (DoH). Writing response."); // Added log
            self.write(&data).await?;
        } else {
            console_error!("ProxyStream: DNS over HTTPS (DoH) failed."); // Added error log
        };
        Ok(())
    }
}

// Bagian AsyncRead dan AsyncWrite tetap sama, tapi saya tambahkan sedikit logging
impl<'a> AsyncRead for ProxyStream<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        let mut this = self.project();

        loop {
            let size = std::cmp::min(this.buffer.len(), buf.remaining());
            if size > 0 {
                buf.put_slice(&this.buffer.split_to(size));
                // console_log!("ProxyStream: Poll Read - Copied {} bytes from internal buffer to ReadBuf.", size); // Too verbose, uncomment for deep debugging
                return Poll::Ready(Ok(()));
            }

            match this.events.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(WebsocketEvent::Message(msg)))) => {
                    if let Some(data) = msg.bytes() {
                        if data.len() > MAX_WEBSOCKET_SIZE {
                            console_error!("ProxyStream: Poll Read - Incoming WS message too large ({} bytes).", data.len());
                            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, "websocket buffer too long")))
                        }
                        
                        if this.buffer.len() + data.len() > MAX_BUFFER_SIZE {
                            console_error!("ProxyStream: Poll Read - Internal buffer full ({} bytes), applying backpressure. Cannot add {} bytes.", this.buffer.len(), data.len());
                            return Poll::Pending; // This will signal the Tokio runtime to poll again later
                        }
                        
                        this.buffer.put_slice(&data);
                        // console_log!("ProxyStream: Poll Read - Added {} bytes from WS to internal buffer. Total: {}", data.len(), this.buffer.len()); // Too verbose
                    } else {
                        // console_log!("ProxyStream: Poll Read - Received empty/non-binary WS message."); // Too verbose
                    }
                }
                Poll::Pending => return Poll::Pending,
                // Handle WebSocket close/error events more gracefully
                Poll::Ready(Some(Ok(WebsocketEvent::Close(close_event)))) => {
                    console_log!("ProxyStream: Poll Read - WS client closed connection. Code: {:?}, Reason: {:?}", close_event.code(), close_event.reason());
                    return Poll::Ready(Ok(())); // Signal EOF for read
                },
                Poll::Ready(Some(Err(e))) => {
                    console_error!("ProxyStream: Poll Read - Error from WS event stream: {}", e);
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, format!("WS stream error: {}", e))));
                },
                Poll::Ready(None) => {
                    console_log!("ProxyStream: Poll Read - WS event stream ended (EOF).");
                    return Poll::Ready(Ok(())); // Signal EOF for read
                },
            }
        }
    }
}

impl<'a> AsyncWrite for ProxyStream<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<tokio::io::Result<usize>> {
        // console_log!("ProxyStream: Poll Write - Sending {} bytes to WebSocket.", buf.len()); // Too verbose
        return Poll::Ready(
            self.ws
                .send_with_bytes(buf)
                .map(|_| buf.len())
                .map_err(|e| {
                    console_error!("ProxyStream: Poll Write - Failed to send bytes to WebSocket: {}", e); // Added error log
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                }),
        );
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
        console_log!("ProxyStream: Poll Shutdown - Attempting to close WebSocket."); // Added log
        match self.ws.close(Some(1000), Some("shutdown".to_string())) {
            Ok(_) => {
                console_log!("ProxyStream: Poll Shutdown - WebSocket closed successfully."); // Added log
                Poll::Ready(Ok(()))
            },
            Err(e) => {
                console_error!("ProxyStream: Poll Shutdown - Failed to close WebSocket: {}", e); // Added error log
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                )))
            },
        }
    }
}

// Anda perlu memastikan implementasi metode-metode ini ada di tempat lain,
// misalnya di file terpisah (vless.rs, shadowsocks.rs, trojan.rs, vmess.rs)
// dan mereka diimpor atau dapat diakses oleh ProxyStream.
// Jika tidak, Anda akan mendapatkan error "method not found" saat kompilasi.
// Contoh stub (jangan gunakan ini jika Anda sudah punya implementasi):
// impl<'a> ProxyStream<'a> {
//    async fn process_vless(&mut self) -> Result<()> {
//        console_log!("PROCESS VLESS (STUB)");
//        self.handle_tcp_outbound(self.config.proxy_addr.clone(), self.config.proxy_port).await
//    }
//    async fn process_shadowsocks(&mut self) -> Result<()> {
//        console_log!("PROCESS SHADOWSOCKS (STUB)");
//        self.handle_tcp_outbound(self.config.proxy_addr.clone(), self.config.proxy_port).await
//    }
//    async fn process_trojan(&mut self) -> Result<()> {
//        console_log!("PROCESS TROJAN (STUB)");
//        self.handle_tcp_outbound(self.config.proxy_addr.clone(), self.config.proxy_port).await
//    }
//    async fn process_vmess(&mut self) -> Result<()> {
//        console_log!("PROCESS VMESS (STUB)");
//        self.handle_tcp_outbound(self.config.proxy_addr.clone(), self.config.proxy_port).await
//    }
// }
