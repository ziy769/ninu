# Siren

**A Serverless V2Ray Tunnel Optimized for Indonesia**

We are cloning a public repository by using its URL [FoolVPN-ID Siren](https://github.com/FoolVPN-ID/Siren)
Siren is a lightweight and serverless V2Ray tunnel built on [Cloudflare Workers](https://workers.cloudflare.com/), supporting modern proxy protocols.  
It offers fast, secure, and scalable deployment without the need for a traditional VPS.

---

## 🔧 Features

- ✅ **Multi-Protocol Support**

  - VMess
  - Trojan
  - VLESS
  - Shadowsocks

- ✅ **Domain over HTTPS (DoH)**  
  Encrypts DNS queries for improved privacy and security.

---

## 🌐 Endpoints

| Endpoint | Description                       |
| -------- | --------------------------------- |
| `/`      | Main landing page                 |
| `/link`  | Generate shareable proxy links    |
| `/sub`   | Subscription endpoint for clients |

---

## 🚀 Deployment Guide

Siren can be deployed seamlessly using GitHub Actions with Cloudflare Workers.

### ⚙️ CI/CD via GitHub Actions

1. **Create a KV Namespace**

   - Go to Cloudflare Dashboard → Workers → KV.
   - Create a new namespace named `SIREN`.

2. **Configure `wrangler.toml`**

   - Add the KV namespace to your config file:
     ```toml
     [[kv_namespaces]]
     binding = "SIREN"
     id = "YOUR_KV_NAMESPACE_ID"
     ```

3. **Generate API Token**

   - [Create an API Token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) with:
     - Permissions: Workers & KV Storage

4. **Set GitHub Repository Secret**

   - Navigate to: GitHub → Your Repo → Settings → Secrets and variables → Actions
   - Add a new secret:
     - Name: `CLOUDFLARE_API_TOKEN`
     - Value: Your API token

5. **Enable GitHub Actions**

   - Open the **Actions** tab on GitHub.
   - Enable workflows if prompted.

6. **Trigger Deployment**

   - Push any commit or manually trigger the deployment workflow.

7. **Access Your Siren Instance**
   - Visit: `https://<YOUR-WORKERS-SUBDOMAIN>.workers.dev`
