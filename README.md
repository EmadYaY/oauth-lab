# 🔐 OAuth 2.0 Security Lab

> A fully interactive, self-hosted lab for learning and testing OAuth 2.0 / OIDC flows, attack vectors, and security hardening, all in a single Node.js file.

![OAuth Thumbnail](./OAuth%202.0%20security%20essentials%20in%20focus.png)

---

## 📖 Background & Research

This lab was built alongside a complete technical research paper covering the full history and architecture of OAuth — from the password anti-pattern era through OAuth 1.0, 2.0, OpenID Connect, PKCE, and OAuth 2.1.

| Document | Description |
|---|---|
| 📄 **[OAuth_Complete_Research.pdf](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6454142)** | Full research paper — History · Architecture · CVEs · Security Hardening · RFCs. Covers OAuth 1.0, 2.0, OIDC, PKCE, Device Flow, DPoP, and advanced patterns like the Phantom Token Flow and API Gateway patterns. |
| 🧪 **[OAuth_Lab_Test_Cases.pdf](./OAuth_Lab_Test_Cases.pdf)** | Step-by-step test case reference for the lab — 14 test cases with expected outputs, pass criteria, and checkboxes for every flow and vulnerability. |

## 🎥 OAuth 2.0 Security

[▶️ Watch the video on YouTube](https://www.youtube.com/playlist?list=PLfNdRslbnf0Y2bD_opftFS69WDMgrQ6hT)

---

## 🏗️ Architecture

Three services run from a **single file** (`lab.js`). The host IP is detected automatically — no hardcoded `localhost`.

```
┌─────────────────────────────────────────────────┐
│                   Browser                       │
│         http://<YOUR-IP>:3000                   │
└───────────────────┬─────────────────────────────┘
                    │  All fetches via /proxy/*
                    ▼
┌─────────────────────────────────────────────────┐
│         Client App  :3000                       │
│   • Lab UI (dark theme)                         │
│   • Proxy routes (no cross-port browser fetches)│
│   • Session management                          │
│   • PKCE + state generation                     │
└──────────┬──────────────────────┬───────────────┘
           │ server-to-server     │ server-to-server
           ▼                      ▼
┌──────────────────┐   ┌───────────────────────────┐
│  Auth Server     │   │  Resource API  :3002      │
│  :3001           │   │                           │
│  • /oauth/       │   │  • /api/status  (public)  │
│    authorize     │   │  • /api/profile (any tok) │
│  • /oauth/token  │   │  • /api/posts   (read:*)  │
│  • /oauth/device │   │  • /api/admin   (admin)   │
│  • /oauth/       │   │  • /api/debug-token       │
│    introspect    │   │  • JWT validation         │
│  • /oauth/revoke │   │  • Scope enforcement      │
│  • /.well-known/ │   └───────────────────────────┘
│    openid-config │
└──────────────────┘
```

---

## 🚀 Quick Start

**Requirements:** Node.js ≥ 18

```bash
# 1. Clone or download
git clone https://github.com/EmadYaY/oauth-lab.git
cd oauth-lab

# 2. Install the only dependency
npm install express

# 3. Run
node lab.js
```

You'll see:
```
🌐 Detected host: 192.168.x.x
🔐 Auth Server  → http://192.168.x.x:3001
🛡️  Resource API → http://192.168.x.x:3002
🌐 Client App   → http://192.168.x.x:3000

✅ All servers up. Open: http://192.168.x.x:3000
```

Open the URL in your browser. All three badges in the header should turn **green** within a few seconds.

> **Custom IP / hostname?**
> ```bash
> HOST=0.0.0.0 node lab.js   # listen on all interfaces
> HOST=myserver.local node lab.js
> ```

---

## 🧭 Lab Panels

### Core Flows

| Panel | What it tests |
|---|---|
| 🔑 **Auth Code + PKCE** | Full Authorization Code flow with PKCE (S256) and state CSRF token, the gold standard flow required by OAuth 2.1 |
| 🤖 **Client Credentials** | Machine-to-machine token issuance with no user redirect, for microservices and backend APIs |
| 📺 **Device Flow** | RFC 8628, input-constrained devices (Smart TVs, CLI tools, IoT). Requires two browser tabs to simulate |
| ♻️ **Refresh Tokens** | Side-by-side comparison of secure rotation vs vulnerable no-rotation, plus token revocation (RFC 7009) |

### Vulnerability Lab

| Panel | Vulnerability | CVE Class |
|---|---|---|
| 💥 **CSRF Attack** | Missing `state` parameter allows attacker to inject their auth code into victim's session | CWE-352 |
| 🔓 **Implicit Flow** | Access token in URL fragment, leaks via browser history, Referer headers, JavaScript | Deprecated in OAuth 2.1 |
| ↗️ **Open Redirect** | Loose `redirect_uri` validation, 4 bypass payloads tested (suffix append, path traversal, param injection, URL encoding) | CWE-601 |
| 🎣 **Consent Phishing** | APT29/Midnight Blizzard technique — malicious OAuth app on the REAL consent page URL bypasses all phishing detectors | Nation-state TTPs |

### Tools

| Panel | Purpose |
|---|---|
| 🔍 **Token Inspector** | Client-side JWT decode (header + payload) + server-side introspection. Shows the difference between "I can read this" and "this is valid" |
| ⚡ **API Tester** | Test all Resource Server endpoints with any token. Observe 401 (no token), 403 (wrong scope), 200 (success) |
| 📋 **OIDC Discovery** | Fetch the `/.well-known/openid-configuration` document, all endpoints, grant types, and supported scopes |

---

## 🧪 Test Accounts & Clients

### Users

| Username | Password | Roles |
|---|---|---|
| `alice` | `password123` | user |
| `bob` | `password123` | user, admin |

### OAuth Clients

| Client ID | Secret | Type | Scopes |
|---|---|---|---|
| `demo-client` | `demo-secret` | public | openid, profile, email, read:posts, write:posts, admin |
| `service-client` | `service-secret` | confidential | api:read, api:write |
| `malicious-app` | *(none)* | public (phishing demo) | all of the above |

---

## 🔬 Flows Implemented

```
OAuth 2.0 Grant Types:
  ✅ Authorization Code + PKCE (RFC 7636)
  ✅ Client Credentials
  ✅ Refresh Token (with and without rotation)
  ✅ Device Authorization Grant (RFC 8628)
  ❌ Implicit Grant (intentionally not runnable — removed in OAuth 2.1)
  ❌ Resource Owner Password Credentials (deprecated)

OIDC Extensions:
  ✅ ID Token (signed JWT with nonce)
  ✅ UserInfo endpoint
  ✅ /.well-known/openid-configuration discovery

Token Operations:
  ✅ Introspection (RFC 7662)
  ✅ Revocation (RFC 7009)
  ✅ JWT decode (header + payload + signature verification)

Security Features:
  ✅ PKCE S256 (required in secure mode)
  ✅ state parameter CSRF protection
  ✅ Exact redirect_uri matching
  ✅ Issuer (iss) validation
  ✅ Audience (aud) validation
  ✅ Scope enforcement per endpoint
  ✅ Refresh token rotation
  ✅ Token revocation list
```

---

## 📡 API Endpoints

### Authorization Server `:3001`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/oauth/authorize` | Authorization endpoint — shows consent page |
| `POST` | `/oauth/consent` | Process user consent and issue auth code |
| `POST` | `/oauth/token` | Token endpoint, all grant types |
| `POST` | `/oauth/device` | Device authorization request |
| `GET` | `/device` | Device approval UI |
| `POST` | `/device/approve` | Approve/deny device code |
| `POST` | `/oauth/introspect` | Token introspection (RFC 7662) |
| `POST` | `/oauth/revoke` | Token revocation (RFC 7009) |
| `GET` | `/oauth/userinfo` | UserInfo endpoint (OIDC) |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery document |

### Resource API `:3002`

| Method | Endpoint | Required Scope | Description |
|---|---|---|---|
| `GET` | `/api/status` | *(none)* | Public health check |
| `GET` | `/api/profile` | any valid token | Authenticated user info |
| `GET` | `/api/posts` | `read:posts` | User's posts |
| `POST` | `/api/posts` | `write:posts` | Create a post |
| `GET` | `/api/admin` | `admin` | Admin-only data (all posts, uptime) |
| `GET` | `/api/debug-token` | any | Decode token without validation |

### Client App `:3000` — Proxy Routes

All browser interactions go through these proxy routes, no cross-port fetches from the browser:

| Method | Endpoint | Proxies to |
|---|---|---|
| `GET` | `/proxy/health/auth` | Auth Server health |
| `GET` | `/proxy/health/api` | API Server health |
| `GET` | `/proxy/oauth/start` | Generates PKCE + state, returns redirect URL |
| `GET` | `/callback` | Exchanges auth code for tokens |
| `POST` | `/proxy/client-credentials` | M2M token request |
| `POST` | `/proxy/device-start` | Start device flow |
| `POST` | `/proxy/device-poll` | Poll device token |
| `POST` | `/proxy/refresh` | Refresh token (with/without rotation) |
| `POST` | `/proxy/introspect` | Introspect a token |
| `POST` | `/proxy/revoke` | Revoke a token |
| `GET` | `/proxy/discovery` | OIDC discovery |
| `POST` | `/proxy/api` | Forward request to Resource API |
| `POST` | `/proxy/test-redirect` | Test redirect_uri bypass attempt |

---

## 📚 Key Concepts Demonstrated

### Why PKCE?

Without PKCE, an attacker who intercepts the authorization code (e.g., via a malicious app on the same device) can exchange it for tokens. PKCE binds the code to the original requester:

```
Client generates:
  code_verifier  = high-entropy random string (43–128 chars)
  code_challenge = BASE64URL(SHA256(code_verifier))

Authorization request includes:  &code_challenge=<hash>&code_challenge_method=S256
Token request includes:           &code_verifier=<original>

Auth server verifies: SHA256(code_verifier) == code_challenge
→ Only the original client can exchange the code.
```

### Why state?

Without `state`, an attacker can force a victim to complete an OAuth flow using the attacker's authorization code, linking the victim's session to the attacker's account (CSRF).

```
Secure:   state = RANDOM_TOKEN|SESSION_ID  →  verified on callback
Insecure: state = (absent)                 →  any code accepted
```

### Why exact redirect_uri matching?

If the auth server uses prefix or regex matching instead of exact comparison:
```
Registered:  http://app.com/callback
Attack:      http://app.com/callback.attacker.com  ← passes prefix check
             http://app.com/callback/../steal       ← passes prefix check
→ Auth code delivered to attacker's server
```

---

## 📄 Related Documents

The following documents are included in this repository:

### 📄 OAuth_Complete_Research.pdf
A 28-page technical research paper covering:
- Authentication vs Authorization — core concepts and why the distinction matters
- OAuth 1.0 history, HMAC-SHA1 signatures, and the Session Fixation vulnerability
- OAuth 2.0 complete redesign — all grant types explained with code examples
- OpenID Connect — the id_token, UserInfo endpoint, and standard claims
- OAuth 2.1 — what changed and why (PKCE everywhere, Implicit removed)
- CVE analysis — CRIME, Covert Redirect, Mix-Up Attack, Consent Phishing
- Advanced architecture — Phantom Token Flow, API Gateway patterns, by-value vs by-reference tokens, fine-grained authorization
- Full RFC reference table (RFC 6749 through RFC 9700)

### 🧪 OAuth_Lab_Test_Cases.docx
A structured test case document with 14 test cases including:
- Step-by-step instructions for every lab panel
- Exact expected outputs for each step
- Pass/fail criteria
- Checkbox columns for manual test execution tracking

---

## 🛡️ Security Notes

This lab is for **educational purposes only**. It intentionally implements both secure and insecure patterns so you can observe the difference.

- **Do not expose port 3001 or 3002 publicly** — the auth server has no rate limiting
- JWT signing uses HS256 with a shared secret — production systems should use RS256 with asymmetric keys
- All data is in-memory — restarting the server clears all sessions and tokens
- The "malicious-app" client is harmless in this lab context — it only redirects to a local page

---

## 📖 References

| RFC | Title |
|---|---|
| RFC 6749 | The OAuth 2.0 Authorization Framework |
| RFC 6750 | Bearer Token Usage |
| RFC 7009 | Token Revocation |
| RFC 7519 | JSON Web Token (JWT) |
| RFC 7636 | PKCE — Proof Key for Code Exchange |
| RFC 7662 | Token Introspection |
| RFC 8628 | Device Authorization Grant |
| RFC 9700 | OAuth 2.0 Security Best Current Practice (2025) |
| OpenID Connect Core 1.0 | Identity layer on top of OAuth 2.0 |
| OAuth 2.1 (draft) | Consolidated OAuth with security hardening |

---

## 📁 Repository Structure

```
oauth-lab/
├── lab.js                      # Single-file lab — all 3 servers
├── OAuth_Complete_Research.pdf # Full OAuth technical research paper
├── OAuth_Lab_Test_Cases.docx   # Step-by-step test cases with expected outputs
├── package.json
└── README.md
```

---

<div align="center">
  <sub>Built for learning OAuth 2.0 security — from RFC to attack to defense.</sub>
</div>
