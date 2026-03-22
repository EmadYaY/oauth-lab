/**
 * OAuth 2.0 Client Application + Lab UI — Port 3000
 * ALL browser fetches go through proxy routes on this server.
 * No cross-port fetches from browser.
 * https://github.com/EmadYaY
 */
const express = require('express');
const crypto  = require('crypto');
const http    = require('http');
const app     = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const AUTH   = 'http://localhost:3001';
const API    = 'http://localhost:3002';
const ME     = 'http://localhost:3000';
const CID    = 'demo-client';
const CSECRET= 'demo-secret';
const CB     = `${ME}/callback`;

const sessions = new Map();

// ── Internal HTTP helper (server-side only) ───────────────────────────────────
function req(url, opts) {
  opts = opts || {};
  return new Promise((resolve, reject) => {
    const u   = new URL(url);
    const lib = u.protocol === 'https:' ? require('https') : http;
    const body = opts.body || null;
    const headers = Object.assign({}, opts.headers || {});
    if (body) headers['Content-Length'] = Buffer.byteLength(body);

    const r = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol==='https:'?443:80),
      path: u.pathname + (u.search||''), method: opts.method || 'GET', headers
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve({
        status: res.statusCode,
        json:   () => { try { return JSON.parse(d); } catch { return { error:'parse_error', raw:d }; } },
        text:   () => d
      }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// SERVER-SIDE PROXY ROUTES  (browser never fetches cross-port)
// ══════════════════════════════════════════════════════════════════════════════

// Health checks — browser polls these to show green badges
app.get('/proxy/health/auth', async (req, res) => {
  try { const r = await req(AUTH+'/.well-known/openid-configuration'); res.json({ ok: r.status===200 }); }
  catch { res.json({ ok: false }); }
});
app.get('/proxy/health/api', async (req, res) => {
  try { const r = await req(API+'/api/status'); res.json({ ok: r.status===200 }); }
  catch { res.json({ ok: false }); }
});

// OAuth flow start — generates PKCE + state, returns redirect URL to browser
app.get('/proxy/oauth/start', (req2, res) => {
  const mode       = req2.query.mode || 'secure';
  const scopes     = req2.query.scopes || 'openid profile email read:posts';
  const appType    = req2.query.app || '';
  const isSecure   = mode !== 'vulnerable';
  const clientId   = appType === 'malicious' ? 'malicious-app' : CID;

  const csrf     = isSecure ? crypto.randomBytes(16).toString('hex') : 'nosec';
  const nonce    = crypto.randomBytes(16).toString('hex');
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge= crypto.createHash('sha256').update(verifier).digest('base64url');
  const sid      = crypto.randomUUID();
  // Encode session_id inside state so it survives the auth-server redirect
  const state    = `${csrf}|${sid}`;

  sessions.set(sid, { csrf, nonce, verifier, mode });

  const p = new URLSearchParams({
    response_type: 'code', client_id: clientId,
    redirect_uri: CB, scope: scopes, nonce, mode, state,
    ...(isSecure ? { code_challenge: challenge, code_challenge_method: 'S256' } : {})
  });

  res.json({
    redirect:   `${AUTH}/oauth/authorize?${p}`,
    session_id: sid,
    state:      csrf,
    pkce_verifier: verifier,
    pkce_challenge: challenge
  });
});

// OAuth callback — exchanges code for tokens
app.get('/callback', async (req2, res) => {
  const { code, state: rawState, error } = req2.query;
  if (error) return res.redirect(`/?error=${error}`);

  // Recover session from state
  const [csrf, sid] = (rawState || '').split('|');
  const session = sessions.get(sid) || {};

  if (session.mode !== 'vulnerable' && csrf !== 'nosec' && session.csrf && session.csrf !== csrf)
    return res.redirect('/?error=csrf_detected');

  const params = new URLSearchParams({
    grant_type: 'authorization_code', code, redirect_uri: CB,
    client_id: CID, client_secret: CSECRET,
    ...(session.verifier ? { code_verifier: session.verifier } : {})
  });

  try {
    const r = await req(AUTH+'/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString()
    });
    const tokens = r.json();
    if (tokens.error) return res.redirect(`/?error=${tokens.error}&detail=${encodeURIComponent(tokens.error_description||'')}`);

    const newSid = crypto.randomUUID();
    sessions.set(newSid, { ...tokens, authenticated: true });
    res.redirect(`/?ok=1&sid=${newSid}`);
  } catch (e) {
    res.redirect(`/?error=network&detail=${encodeURIComponent(e.message)}`);
  }
});

// Malicious app landing
app.get('/malicious-callback', (req2, res) => {
  const code = req2.query.code || 'N/A';
  res.send(`<!DOCTYPE html><html><head><title>Attacker Server</title>
<style>body{font-family:sans-serif;background:#1a0a0a;color:#f1f5f9;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center}
.c{background:#2d1515;border:2px solid #ef4444;border-radius:16px;padding:40px;max-width:500px}
h1{color:#ef4444;margin-bottom:16px}code{background:#0f0000;padding:6px 10px;border-radius:4px;font-size:12px;word-break:break-all;display:block;margin:8px 0;color:#fca5a5}
a{display:inline-block;margin-top:20px;background:#ef4444;color:#fff;padding:10px 24px;border-radius:8px;text-decoration:none}</style>
</head><body><div class="c">
<h1>🚨 Consent Phishing Captured</h1>
<p style="color:#94a3b8;margin-bottom:16px">In a real attack, this code is now on the attacker's server:</p>
<code>code = ${code}</code>
<p style="color:#fca5a5;font-size:13px;margin-top:12px">Attacker exchanges this for tokens → persistent access even after password change.</p>
<a href="/">← Back to Lab</a></div></body></html>`);
});

// Session read
app.get('/proxy/session', (req2, res) => {
  const s = sessions.get(req2.query.sid) || {};
  res.json(s);
});

// Client Credentials
app.post('/proxy/client-credentials', async (req2, res) => {
  const scope = (req2.body && req2.body.scope) || 'api:read';
  const p = new URLSearchParams({ grant_type:'client_credentials', client_id:'service-client', client_secret:'service-secret', scope });
  try { const r = await req(AUTH+'/oauth/token', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:p.toString() }); res.json(r.json()); }
  catch (e) { res.json({ error: e.message }); }
});

// Device start
app.post('/proxy/device-start', async (req2, res) => {
  const p = new URLSearchParams({ client_id: CID, scope:'openid profile email' });
  try { const r = await req(AUTH+'/oauth/device', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:p.toString() }); res.json(r.json()); }
  catch (e) { res.json({ error: e.message }); }
});

// Device poll
app.post('/proxy/device-poll', async (req2, res) => {
  const p = new URLSearchParams({ grant_type:'urn:ietf:params:oauth:grant-type:device_code', device_code:req2.body.device_code, client_id:CID });
  try { const r = await req(AUTH+'/oauth/token', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:p.toString() }); res.json(r.json()); }
  catch (e) { res.json({ error: e.message }); }
});

// Refresh token
app.post('/proxy/refresh', async (req2, res) => {
  const { refresh_token, rotate } = req2.body;
  const url = AUTH+'/oauth/token'+(rotate===false||rotate==='false'?'?rotate=false':'');
  const p = new URLSearchParams({ grant_type:'refresh_token', refresh_token, client_id:CID });
  try { const r = await req(url, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:p.toString() }); res.json(r.json()); }
  catch (e) { res.json({ error: e.message }); }
});

// Introspect
app.post('/proxy/introspect', async (req2, res) => {
  const p = new URLSearchParams({ token:req2.body.token, client_id:CID });
  try { const r = await req(AUTH+'/oauth/introspect', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:p.toString() }); res.json(r.json()); }
  catch (e) { res.json({ error: e.message }); }
});

// Revoke
app.post('/proxy/revoke', async (req2, res) => {
  const p = new URLSearchParams({ token:req2.body.token, token_type_hint:req2.body.hint||'', client_id:CID });
  try { const r = await req(AUTH+'/oauth/revoke', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:p.toString() }); res.json(r.json()); }
  catch (e) { res.json({ error: e.message }); }
});

// OIDC Discovery
app.get('/proxy/discovery', async (req2, res) => {
  try { const r = await req(AUTH+'/.well-known/openid-configuration'); res.json(r.json()); }
  catch (e) { res.json({ error: e.message }); }
});

// API proxy — forwards requests to resource server
app.post('/proxy/api', async (req2, res) => {
  const { endpoint, method, token, body: reqBody } = req2.body;
  const headers = { 'Content-Type':'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const opts = { method: method||'GET', headers };
  if ((method==='POST'||method==='PUT') && reqBody) opts.body = JSON.stringify(reqBody);
  try { const r = await req(API+endpoint, opts); res.json({ status:r.status, data:r.json() }); }
  catch (e) { res.json({ error: e.message }); }
});

// Open redirect test proxy
app.post('/proxy/test-redirect', async (req2, res) => {
  const { redirect_uri } = req2.body;
  const qs = new URLSearchParams({ response_type:'code', client_id:CID, redirect_uri, scope:'openid', code_challenge:'abc', code_challenge_method:'S256', mode:'secure' });
  try { const r = await req(AUTH+'/oauth/authorize?'+qs); res.json({ status: r.status }); }
  catch (e) { res.json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// MAIN UI
// ══════════════════════════════════════════════════════════════════════════════
app.get('/', (req2, res) => res.send(HTML));

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OAuth 2.0 Security Lab - github.com/EmadYaY</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg0:#070b11;--bg1:#0d1117;--bg2:#161b22;--bg3:#1c2430;
  --b:#21262d;--t1:#e6edf3;--t2:#8b949e;--t3:#3d444d;
  --blue:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;
  --purple:#bc8cff;--cyan:#79c0ff;--orange:#ffa657;
  --bblue:rgba(88,166,255,.12);--bgreen:rgba(63,185,80,.12);
  --bred:rgba(248,81,73,.12);--byellow:rgba(210,153,34,.12);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:'Space Grotesk',sans-serif;background:var(--bg0);color:var(--t1);font-size:14px;line-height:1.5}
code,pre,.mono{font-family:'JetBrains Mono',monospace}

/* ── Header ── */
.hdr{background:var(--bg1);border-bottom:1px solid var(--b);height:52px;display:flex;align-items:center;padding:0 20px;gap:14px;position:sticky;top:0;z-index:100}
.logo{font-size:16px;font-weight:700;display:flex;align-items:center;gap:8px;white-space:nowrap}
.logo-sub{font-size:11px;color:var(--t3);font-weight:400}
.hdr-right{margin-left:auto;display:flex;gap:8px;align-items:center}
.srv-badge{display:flex;align-items:center;gap:5px;background:var(--bg2);border:1px solid var(--b);border-radius:20px;padding:3px 10px;font-size:11px;color:var(--t2)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--yellow);flex-shrink:0;transition:all .3s}
.dot.on{background:var(--green)!important;box-shadow:0 0 8px var(--green)}
.dot.off{background:var(--red)!important}

/* ── Layout ── */
.layout{display:grid;grid-template-columns:220px 1fr;height:calc(100vh - 52px)}
.sidebar{background:var(--bg1);border-right:1px solid var(--b);padding:10px 6px;overflow-y:auto}
.main{overflow-y:auto;padding:20px 24px}

/* ── Nav ── */
.nav-sec{font-size:10px;font-weight:700;letter-spacing:.1em;color:var(--t3);text-transform:uppercase;padding:12px 10px 4px}
.nav-item{display:flex;align-items:center;gap:8px;padding:7px 10px;border-radius:6px;cursor:pointer;color:var(--t2);font-size:13px;transition:all .1s;border:1px solid transparent;user-select:none;white-space:nowrap}
.nav-item:hover{background:var(--bg2);color:var(--t1)}
.nav-item.active{background:var(--bblue);color:var(--blue);border-color:rgba(88,166,255,.2)}
.ni{font-size:15px;width:20px;text-align:center;flex-shrink:0}
.ntag{margin-left:auto;font-size:10px;font-weight:700;padding:1px 6px;border-radius:10px}
.ntag-r{background:var(--bred);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.ntag-g{background:var(--bgreen);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.ntag-y{background:var(--byellow);color:var(--yellow);border:1px solid rgba(210,153,34,.3)}

/* ── Panel ── */
.panel{display:none}.panel.active{display:block}
.page-title{font-size:18px;font-weight:700;margin-bottom:4px}
.page-sub{color:var(--t2);font-size:13px;margin-bottom:20px}

/* ── Card ── */
.card{background:var(--bg1);border:1px solid var(--b);border-radius:10px;padding:18px;margin-bottom:14px}
.card-hdr{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px}
.card-title{font-size:14px;font-weight:600;margin-bottom:2px}
.card-sub{font-size:12px;color:var(--t2)}
.tag{font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px;white-space:nowrap}
.tg{background:var(--bgreen);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.tr{background:var(--bred);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.tb{background:var(--bblue);color:var(--blue);border:1px solid rgba(88,166,255,.3)}
.ty{background:var(--byellow);color:var(--yellow);border:1px solid rgba(210,153,34,.3)}

/* ── Alerts ── */
.alert{border-radius:6px;padding:10px 14px;margin-bottom:12px;font-size:13px;line-height:1.5}
.ai{background:var(--bblue);border:1px solid rgba(88,166,255,.2);color:var(--cyan)}
.aw{background:var(--byellow);border:1px solid rgba(210,153,34,.2);color:var(--yellow)}
.ae{background:var(--bred);border:1px solid rgba(248,81,73,.2);color:#ffa198}
.as{background:var(--bgreen);border:1px solid rgba(63,185,80,.2);color:#7ee787}

/* ── Buttons ── */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;border:none;font-family:inherit;transition:all .12s;white-space:nowrap}
.btn:disabled{opacity:.5;cursor:not-allowed}
.bb{background:#1f6feb;color:#fff}.bb:hover:not(:disabled){background:#388bfd}
.bg{background:#238636;color:#fff}.bg:hover:not(:disabled){background:#2ea043}
.br{background:#b91c1c;color:#fff}.br:hover:not(:disabled){background:#dc2626}
.bh{background:var(--bg2);color:var(--t2);border:1px solid var(--b)}.bh:hover:not(:disabled){color:var(--t1)}
.by{background:#7d4e08;color:#fff}.by:hover:not(:disabled){background:#9e6a03}

/* ── Form controls ── */
.field{display:flex;flex-direction:column;gap:4px;min-width:0}
.field label{font-size:11px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.06em}
.field input,.field select,.field textarea{background:var(--bg0);border:1px solid var(--b);border-radius:6px;padding:7px 10px;color:var(--t1);font-size:13px;font-family:inherit;outline:none}
.field input:focus,.field select:focus,.field textarea:focus{border-color:var(--blue)}
.field textarea{font-family:'JetBrains Mono',monospace;font-size:12px;resize:vertical;min-height:60px}
.row{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:12px;align-items:flex-end}

/* ── Output / trace ── */
.out-lbl{font-size:11px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px}
.out{background:var(--bg0);border:1px solid var(--b);border-radius:6px;padding:12px;font-family:'JetBrains Mono',monospace;font-size:12px;line-height:1.7;color:var(--t2);white-space:pre-wrap;word-break:break-all;max-height:320px;overflow-y:auto;min-height:50px;display:none}
.out.show{display:block}
.trace-box{margin-top:12px}
.tr-item{display:flex;align-items:baseline;gap:8px;padding:6px 10px;border-radius:5px;margin-bottom:4px;font-size:13px;background:var(--bg2);border-left:3px solid var(--t3)}
.tr-item.ok{border-color:var(--green);background:rgba(63,185,80,.06)}
.tr-item.err{border-color:var(--red);background:rgba(248,81,73,.06)}
.tr-item.warn{border-color:var(--yellow);background:rgba(210,153,34,.06)}
.tr-n{font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;color:var(--blue);flex-shrink:0}
.tok-box{background:var(--bg0);border:1px solid var(--b);border-radius:6px;padding:10px;margin-bottom:8px}
.tok-lbl{font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;margin-bottom:4px}
.tok-val{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--cyan);word-break:break-all;cursor:pointer;line-height:1.5}
.tok-val:hover{color:var(--blue)}

/* ── Tabs ── */
.tabs{display:flex;gap:2px;border-bottom:1px solid var(--b);margin-bottom:14px}
.tab{padding:7px 14px;font-size:13px;cursor:pointer;color:var(--t3);border-bottom:2px solid transparent;transition:all .1s;user-select:none}
.tab:hover{color:var(--t2)}.tab.on{color:var(--blue);border-bottom-color:var(--blue)}
.tabp{display:none}.tabp.on{display:block}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--bg3);border-radius:4px}

/* ── Responsive ── */
@media(max-width:760px){
  .layout{grid-template-columns:1fr}
  .sidebar{display:none}
  .g2{grid-template-columns:1fr}
}
</style>
</head>
<body>

<!-- HEADER -->
<div class="hdr">
  <div class="logo">🔐 <span>OAuth 2.0 Security Lab<span class="logo-sub"> — Interactive Learning</span></span></div>
  <div class="hdr-right">
    <div class="srv-badge"><div class="dot on" id="d0"></div>Client :3000</div>
    <div class="srv-badge"><div class="dot" id="d1"></div>Auth :3001</div>
    <div class="srv-badge"><div class="dot" id="d2"></div>API :3002</div>
  </div>
</div>

<div class="layout">
<!-- SIDEBAR -->
<div class="sidebar">
  <div class="nav-sec">Core Flows</div>
  <div class="nav-item active" data-panel="authcode"><span class="ni">🔑</span>Auth Code + PKCE<span class="ntag ntag-g">Secure</span></div>
  <div class="nav-item" data-panel="cc"><span class="ni">🤖</span>Client Credentials</div>
  <div class="nav-item" data-panel="device"><span class="ni">📺</span>Device Flow</div>
  <div class="nav-item" data-panel="refresh"><span class="ni">♻️</span>Refresh Tokens</div>
  <div class="nav-sec">Vulnerability Lab</div>
  <div class="nav-item" data-panel="csrf"><span class="ni">💥</span>CSRF Attack<span class="ntag ntag-r">CVE</span></div>
  <div class="nav-item" data-panel="implicit"><span class="ni">🔓</span>Implicit Flow<span class="ntag ntag-r">Deprecated</span></div>
  <div class="nav-item" data-panel="redirect"><span class="ni">↗️</span>Open Redirect<span class="ntag ntag-r">Attack</span></div>
  <div class="nav-item" data-panel="phishing"><span class="ni">🎣</span>Consent Phishing<span class="ntag ntag-r">APT29</span></div>
  <div class="nav-sec">Tools</div>
  <div class="nav-item" data-panel="inspector"><span class="ni">🔍</span>Token Inspector</div>
  <div class="nav-item" data-panel="apitester"><span class="ni">⚡</span>API Tester</div>
  <div class="nav-item" data-panel="discovery"><span class="ni">📋</span>OIDC Discovery</div>
</div>

<!-- MAIN CONTENT -->
<div class="main">

<!-- ═══ AUTH CODE ═══ -->
<div class="panel active" id="p-authcode">
  <div class="page-title">Authorization Code + PKCE</div>
  <div class="page-sub">The most secure flow — required for all clients in OAuth 2.1</div>

  <div class="card">
    <div class="card-hdr">
      <div><div class="card-title">Start OAuth Flow</div><div class="card-sub">Generates PKCE verifier/challenge pair and state CSRF token</div></div>
      <span class="tag tg">✅ Most Secure</span>
    </div>
    <div class="alert ai">A <strong>code_verifier</strong> is generated client-side. Even if the auth code is intercepted, it's useless without the verifier. The <strong>state</strong> parameter prevents CSRF.</div>
    <div class="row">
      <div class="field">
        <label>Mode</label>
        <select id="ac-mode">
          <option value="secure">Secure (PKCE + state)</option>
          <option value="vulnerable">Vulnerable (no PKCE, no state)</option>
        </select>
      </div>
      <div class="field" style="flex:1;min-width:200px">
        <label>Scopes</label>
        <input id="ac-scopes" value="openid profile email read:posts">
      </div>
      <button class="btn bb" onclick="startAuthCode()">🔐 Start OAuth Flow</button>
    </div>
    <div id="ac-pkce" style="display:none" class="alert ai">
      <div style="margin-bottom:6px"><strong>PKCE Pair Generated:</strong></div>
      <div style="font-family:monospace;font-size:12px">verifier: <span id="ac-v" style="color:var(--orange)"></span></div>
      <div style="font-family:monospace;font-size:12px">challenge (SHA-256): <span id="ac-c" style="color:var(--green)"></span></div>
    </div>
    <div class="trace-box" id="ac-trace"></div>
  </div>

  <div class="card" id="ac-tokens" style="display:none">
    <div class="card-hdr"><div class="card-title">✅ Tokens Received</div><span class="tag tg">Success</span></div>
    <div class="tok-box">
      <div class="tok-lbl">Access Token <span style="color:var(--t3);font-weight:400">(click to copy)</span></div>
      <div class="tok-val" id="ac-at" onclick="copy(this)"></div>
    </div>
    <div class="tok-box">
      <div class="tok-lbl">Refresh Token</div>
      <div class="tok-val" id="ac-rt" onclick="copy(this)"></div>
    </div>
    <div class="tok-box" id="ac-idt-box" style="display:none">
      <div class="tok-lbl">ID Token (OIDC)</div>
      <div class="tok-val" id="ac-idt" onclick="copy(this)"></div>
    </div>
    <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
      <button class="btn bb" onclick="goToAPI()">⚡ Test in API Tester</button>
      <button class="btn bh" onclick="goToInspector()">🔍 Inspect Token</button>
      <button class="btn br" id="ac-logout" onclick="doLogout()">🚪 Logout & Revoke</button>
    </div>
  </div>
</div>

<!-- ═══ CLIENT CREDENTIALS ═══ -->
<div class="panel" id="p-cc">
  <div class="page-title">Client Credentials</div>
  <div class="page-sub">Machine-to-machine auth — no user involved</div>
  <div class="card">
    <div class="card-hdr"><div class="card-title">Request M2M Token</div><span class="tag tb">Server-to-Server</span></div>
    <div class="alert ai">Used when a service needs to authenticate itself (no user). The client sends its <strong>client_id + client_secret</strong> directly to the token endpoint.</div>
    <div class="row">
      <div class="field">
        <label>Scope</label>
        <select id="cc-scope">
          <option value="api:read">api:read</option>
          <option value="api:write">api:write</option>
          <option value="api:read api:write">api:read api:write</option>
        </select>
      </div>
      <button class="btn bb" onclick="doCC()">🤖 Get Token</button>
    </div>
    <div class="out-lbl">Response</div>
    <div class="out" id="cc-out"></div>
    <div class="trace-box" id="cc-trace"></div>
  </div>
</div>

<!-- ═══ DEVICE FLOW ═══ -->
<div class="panel" id="p-device">
  <div class="page-title">Device Authorization Flow</div>
  <div class="page-sub">For input-constrained devices — Smart TVs, CLI tools, IoT</div>
  <div class="card">
    <div class="card-hdr"><div class="card-title">Simulate Device Flow</div><span class="tag tb">RFC 8628</span></div>
    <div class="alert ai">Device requests a <strong>user_code</strong>, displays it, then polls the token endpoint. User visits a separate URL to approve.</div>
    <div class="row">
      <button class="btn bb" onclick="startDevice()">📺 Start Device Flow</button>
    </div>
    <div id="dev-code-box" style="display:none;background:var(--bg2);border:1px solid var(--b);border-radius:8px;padding:16px;margin-bottom:12px;text-align:center">
      <div style="color:var(--t2);font-size:12px;margin-bottom:8px">Enter this code at the URL below:</div>
      <div id="dev-code" style="font-family:monospace;font-size:28px;font-weight:700;color:var(--yellow);letter-spacing:6px;margin-bottom:8px"></div>
      <div style="font-size:12px;color:var(--t2)">Visit: <a href="http://localhost:3001/device" target="_blank" style="color:var(--blue)">http://localhost:3001/device</a></div>
      <div style="margin-top:10px;display:flex;gap:8px;justify-content:center">
        <button class="btn bg" onclick="pollDevice()">🔄 Poll for Token</button>
      </div>
    </div>
    <div class="out-lbl">Token Response</div>
    <div class="out" id="dev-out"></div>
    <div class="trace-box" id="dev-trace"></div>
  </div>
</div>

<!-- ═══ REFRESH TOKENS ═══ -->
<div class="panel" id="p-refresh">
  <div class="page-title">Refresh Token Rotation</div>
  <div class="page-sub">Secure vs vulnerable refresh token handling</div>
  <div class="g2">
    <div class="card">
      <div class="card-hdr"><div class="card-title">✅ Secure — With Rotation</div><span class="tag tg">Recommended</span></div>
      <div class="alert as">Each refresh issues a <strong>new</strong> refresh token and invalidates the old one. Stolen token detected on reuse.</div>
      <div class="field" style="margin-bottom:10px">
        <label>Refresh Token</label>
        <input id="rt-sec" placeholder="Paste refresh_token from Auth Code flow">
      </div>
      <button class="btn bg" onclick="doRefresh(true)">♻️ Refresh (Rotate)</button>
      <div class="out-lbl" style="margin-top:10px">Response</div>
      <div class="out" id="rt-sec-out"></div>
    </div>
    <div class="card">
      <div class="card-hdr"><div class="card-title">⚠️ Vulnerable — No Rotation</div><span class="tag tr">Insecure</span></div>
      <div class="alert ae">Same refresh token returned forever. A stolen token gives <strong>permanent</strong> access until manually revoked.</div>
      <div class="field" style="margin-bottom:10px">
        <label>Refresh Token</label>
        <input id="rt-vuln" placeholder="Paste refresh_token from Auth Code flow">
      </div>
      <button class="btn by" onclick="doRefresh(false)">♻️ Refresh (No Rotate)</button>
      <div class="out-lbl" style="margin-top:10px">Response</div>
      <div class="out" id="rt-vuln-out"></div>
    </div>
  </div>
  <div class="card">
    <div class="card-title" style="margin-bottom:8px">Token Revocation</div>
    <div class="alert ai">Revoke tokens via <code>RFC 7009</code>. After revocation, the API server rejects the token on next use.</div>
    <div class="row">
      <div class="field" style="flex:1">
        <label>Token to Revoke</label>
        <input id="rv-tok" placeholder="Paste access_token or refresh_token">
      </div>
      <div class="field">
        <label>Type Hint</label>
        <select id="rv-hint"><option value="access_token">access_token</option><option value="refresh_token">refresh_token</option></select>
      </div>
      <button class="btn br" onclick="doRevoke()">🗑️ Revoke</button>
    </div>
    <div class="out-lbl">Response</div>
    <div class="out" id="rv-out"></div>
  </div>
</div>

<!-- ═══ CSRF ═══ -->
<div class="panel" id="p-csrf">
  <div class="page-title">CSRF Attack on OAuth</div>
  <div class="page-sub">How missing state parameter enables session hijacking</div>
  <div class="card">
    <div class="card-hdr"><div class="card-title">How CSRF Works</div><span class="tag tr">CVE-Class</span></div>
    <div class="alert ae"><strong>Attack:</strong> Attacker starts OAuth, gets an auth code, but doesn't complete the flow. Then tricks the victim into submitting the attacker's code to the client. The victim's session becomes linked to the attacker's account.</div>
    <div class="g2">
      <div>
        <div class="card" style="background:var(--bg0)">
          <div class="card-title" style="color:var(--green);margin-bottom:8px">✅ Secure Flow</div>
          <div class="alert as" style="font-size:12px">State = cryptographic random token stored in session. Validated on callback.</div>
          <button class="btn bg" onclick="csrfSecure()">Test Secure Flow</button>
        </div>
      </div>
      <div>
        <div class="card" style="background:var(--bg0)">
          <div class="card-title" style="color:var(--red);margin-bottom:8px">⚠️ Vulnerable Flow</div>
          <div class="alert ae" style="font-size:12px">No state parameter. Server accepts any code with no validation.</div>
          <button class="btn br" onclick="csrfVuln()">Test Vulnerable Flow</button>
        </div>
      </div>
    </div>
    <div class="trace-box" id="csrf-trace"></div>
  </div>
</div>

<!-- ═══ IMPLICIT ═══ -->
<div class="panel" id="p-implicit">
  <div class="page-title">Implicit Flow (Deprecated)</div>
  <div class="page-sub">Removed in OAuth 2.1 — tokens exposed in URL fragment</div>
  <div class="card">
    <div class="card-hdr"><div class="card-title">Why Implicit Flow is Dangerous</div><span class="tag tr">Deprecated</span></div>
    <div class="alert ae">Implicit flow returns the <strong>access_token directly in the URL fragment</strong>: <code>#access_token=SECRET</code>. This means tokens appear in browser history, server logs, and <code>Referer</code> headers.</div>
    <div class="card" style="background:var(--bg0)">
      <div class="out-lbl">Vulnerable URL Pattern</div>
      <div class="out show" style="color:var(--red)">https://app.com/callback#access_token=SECRET_TOKEN&token_type=bearer

Problems:
1. Token in browser history
2. Token in HTTP Referer header when navigating away
3. Token visible to all JavaScript on the page (XSS)
4. No PKCE binding possible

→ Use Authorization Code + PKCE instead</div>
    </div>
    <div class="alert aw" style="margin-top:12px">
      <strong>OAuth 2.1 status:</strong> Implicit Grant is <strong>removed entirely</strong>. All clients must use Authorization Code + PKCE, including SPAs and mobile apps.
    </div>
  </div>
</div>

<!-- ═══ OPEN REDIRECT ═══ -->
<div class="panel" id="p-redirect">
  <div class="page-title">Open Redirect Attack</div>
  <div class="page-sub">Exploiting loose redirect_uri validation to steal auth codes</div>
  <div class="card">
    <div class="card-hdr"><div class="card-title">redirect_uri Bypass Attempts</div><span class="tag tr">Attack</span></div>
    <div class="alert ae">If the auth server uses prefix-matching or wildcards instead of <strong>exact URI matching</strong>, attackers can redirect auth codes to their server.</div>
    <button class="btn br" onclick="testRedirects()">💥 Run Bypass Tests</button>
    <div class="trace-box" id="redir-trace"></div>
  </div>
  <div class="card" style="background:var(--bg0)">
    <div class="out-lbl">Attack Payloads</div>
    <div class="out show">// Registered: http://localhost:3000/callback

// Bypass attempts:
http://localhost:3000/callback.evil.com    ← suffix append
http://localhost:3000/callback/../admin    ← path traversal  
http://evil.com?r=http://localhost:3000/callback  ← parameter injection

// Secure: exact match only
// Only http://localhost:3000/callback is accepted</div>
  </div>
</div>

<!-- ═══ CONSENT PHISHING ═══ -->
<div class="panel" id="p-phishing">
  <div class="page-title">Consent Phishing (APT29/Midnight Blizzard)</div>
  <div class="page-sub">Nation-state attack technique using legitimate OAuth consent</div>
  <div class="card">
    <div class="card-hdr"><div class="card-title">Simulate Consent Phishing</div><span class="tag tr">APT29</span></div>
    <div class="alert ae"><strong>This attack bypasses all credential phishing defenses.</strong> The URL is a real <code>localhost:3001</code> page. The user is tricked into granting excessive permissions to a malicious app disguised as "Microsoft Teams Update Tool".</div>
    <div class="alert aw">Attack flow: Register malicious app → Send phishing link to victim → Victim sees REAL OAuth consent page → Victim clicks Allow → Attacker gets tokens → Persistent access even after password change</div>
    <button class="btn br" onclick="startPhishing()">🎣 Launch Phishing Demo</button>
    <div class="trace-box" id="phish-trace"></div>
  </div>
</div>

<!-- ═══ TOKEN INSPECTOR ═══ -->
<div class="panel" id="p-inspector">
  <div class="page-title">Token Inspector</div>
  <div class="page-sub">Decode and validate JWT tokens</div>
  <div class="card">
    <div class="card-title" style="margin-bottom:10px">Decode JWT</div>
    <div class="field" style="margin-bottom:10px">
      <label>JWT Token</label>
      <textarea id="insp-tok" placeholder="Paste any JWT here..." rows="3"></textarea>
    </div>
    <div class="row">
      <button class="btn bb" onclick="decodeToken()">🔍 Decode</button>
      <button class="btn bh" onclick="introspectToken()">🔎 Introspect (server-side)</button>
    </div>
    <div class="g2" style="margin-top:12px">
      <div>
        <div class="out-lbl">Header + Payload</div>
        <div class="out" id="insp-out"></div>
      </div>
      <div>
        <div class="out-lbl">Server Introspection</div>
        <div class="out" id="insp-intro"></div>
      </div>
    </div>
  </div>
</div>

<!-- ═══ API TESTER ═══ -->
<div class="panel" id="p-apitester">
  <div class="page-title">API Tester</div>
  <div class="page-sub">Test protected endpoints on the Resource Server (port 3002)</div>
  <div class="card">
    <div class="row">
      <div class="field" style="flex:1">
        <label>Endpoint</label>
        <select id="api-ep">
          <option value="/api/status">GET /api/status (public)</option>
          <option value="/api/profile">GET /api/profile (any token)</option>
          <option value="/api/posts">GET /api/posts (read:posts)</option>
          <option value="/api/admin">GET /api/admin (admin scope)</option>
          <option value="/api/debug-token">GET /api/debug-token (any)</option>
        </select>
      </div>
      <div class="field">
        <label>Method</label>
        <select id="api-method">
          <option value="GET">GET</option>
          <option value="POST">POST</option>
        </select>
      </div>
    </div>
    <div class="field" style="margin-bottom:10px">
      <label>Access Token (leave empty for public endpoints)</label>
      <input id="api-tok" placeholder="Paste access_token here">
    </div>
    <button class="btn bb" onclick="callAPI()">⚡ Send Request</button>
    <div class="out-lbl" style="margin-top:12px">Response from Resource Server :3002</div>
    <div class="out" id="api-out"></div>
  </div>
</div>

<!-- ═══ OIDC DISCOVERY ═══ -->
<div class="panel" id="p-discovery">
  <div class="page-title">OIDC Discovery</div>
  <div class="page-sub">Authorization Server metadata at /.well-known/openid-configuration</div>
  <div class="card">
    <button class="btn bb" onclick="loadDiscovery()">📋 Fetch Discovery Document</button>
    <div class="out-lbl" style="margin-top:12px">Discovery Document</div>
    <div class="out" id="disc-out"></div>
  </div>
</div>

</div><!-- /main -->
</div><!-- /layout -->

<script>
// ════════════════════════════════════════════════════════════════════════════
// STATE
// ════════════════════════════════════════════════════════════════════════════
var TOKENS = {};

// ════════════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════════════
window.addEventListener('load', function() {
  // Check if we just came back from OAuth
  var p = new URLSearchParams(location.search);
  if (p.get('ok') === '1') {
    var sid = p.get('sid');
    history.replaceState({}, '', '/');
    fetch('/proxy/session?sid=' + sid)
      .then(function(r){ return r.json(); })
      .then(function(d){
        TOKENS = d;
        if (d.access_token) {
          document.getElementById('ac-at').textContent = d.access_token;
          document.getElementById('ac-rt').textContent = d.refresh_token || '';
          document.getElementById('ac-tokens').style.display = 'block';
          if (d.id_token) {
            document.getElementById('ac-idt').textContent = d.id_token;
            document.getElementById('ac-idt-box').style.display = 'block';
          }
          addTrace('ac-trace', '✅ OAuth flow complete! Access token received.', 'ok');
          addTrace('ac-trace', '→ Scroll down to see your tokens, or use "API Tester" to test them.', 'ok');
          nav('authcode');
        }
      }).catch(function(){});
  }
  if (p.get('error')) {
    history.replaceState({}, '', '/');
    var e = p.get('error');
    var detail = p.get('detail') || '';
    nav('authcode');
    if (e === 'csrf_detected') {
      addTrace('csrf-trace', '🚨 CSRF DETECTED: state mismatch → attack blocked!', 'err');
    } else {
      addTrace('ac-trace', '❌ OAuth error: ' + e + (detail ? ' — ' + detail : ''), 'err');
    }
  }

  // Nav click handlers
  document.querySelectorAll('.nav-item').forEach(function(el) {
    el.addEventListener('click', function() { nav(this.dataset.panel); });
  });

  // Health checks
  checkServers();
  setInterval(checkServers, 10000);
});

// ════════════════════════════════════════════════════════════════════════════
// NAVIGATION
// ════════════════════════════════════════════════════════════════════════════
function nav(id) {
  document.querySelectorAll('.panel').forEach(function(p){ p.classList.remove('active'); });
  document.querySelectorAll('.nav-item').forEach(function(n){ n.classList.remove('active'); });
  var panel = document.getElementById('p-' + id);
  if (panel) panel.classList.add('active');
  var item = document.querySelector('[data-panel="' + id + '"]');
  if (item) item.classList.add('active');
  window.scrollTo(0,0);
}

// ════════════════════════════════════════════════════════════════════════════
// SERVER HEALTH CHECK
// ════════════════════════════════════════════════════════════════════════════
function checkServers() {
  fetch('/proxy/health/auth')
    .then(function(r){ return r.json(); })
    .then(function(d){
      var el = document.getElementById('d1');
      el.classList.toggle('on', !!d.ok);
      el.classList.toggle('off', !d.ok);
    }).catch(function(){
      var el = document.getElementById('d1');
      el.classList.remove('on'); el.classList.add('off');
    });
  fetch('/proxy/health/api')
    .then(function(r){ return r.json(); })
    .then(function(d){
      var el = document.getElementById('d2');
      el.classList.toggle('on', !!d.ok);
      el.classList.toggle('off', !d.ok);
    }).catch(function(){
      var el = document.getElementById('d2');
      el.classList.remove('on'); el.classList.add('off');
    });
}

// ════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════
function addTrace(id, msg, type) {
  var box = document.getElementById(id);
  if (!box) return;
  var d = document.createElement('div');
  d.className = 'tr-item ' + (type||'');
  d.innerHTML = msg;
  box.appendChild(d);
  box.scrollTop = box.scrollHeight;
}
function clearTrace(id) { var el=document.getElementById(id); if(el) el.innerHTML=''; }

function showOut(id, data) {
  var el = document.getElementById(id);
  if (!el) return;
  el.classList.add('show');
  var s = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  // Syntax highlight
  el.innerHTML = s
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"([^"]+)":/g,'<span style="color:var(--cyan)">"$1"</span>:')
    .replace(/: "([^"]*)"/g,': <span style="color:var(--green)">"$1"</span>')
    .replace(/: (-?\d+\.?\d*)/g,': <span style="color:var(--orange)">$1</span>')
    .replace(/: (true|false)/g,': <span style="color:var(--red)">$1</span>');
}

function copy(el) {
  navigator.clipboard.writeText(el.textContent).then(function(){
    var old = el.style.color; el.style.color='var(--green)';
    setTimeout(function(){ el.style.color=old; }, 800);
  });
}

function decodeJWT(tok) {
  try {
    var p = tok.split('.');
    var dec = function(s){ return JSON.parse(atob(s.replace(/-/g,'+').replace(/_/g,'/'))); };
    return { header: dec(p[0]), payload: dec(p[1]) };
  } catch(e) { return null; }
}

// ════════════════════════════════════════════════════════════════════════════
// AUTH CODE + PKCE
// ════════════════════════════════════════════════════════════════════════════
function startAuthCode() {
  clearTrace('ac-trace');
  document.getElementById('ac-tokens').style.display = 'none';
  document.getElementById('ac-pkce').style.display = 'none';

  var mode   = document.getElementById('ac-mode').value;
  var scopes = document.getElementById('ac-scopes').value;
  addTrace('ac-trace', '⏳ Generating PKCE pair and state token...');

  fetch('/proxy/oauth/start?mode=' + mode + '&scopes=' + encodeURIComponent(scopes))
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (d.error) { addTrace('ac-trace', '❌ Error: ' + d.error, 'err'); return; }

      if (mode === 'secure' && d.pkce_verifier) {
        document.getElementById('ac-pkce').style.display = 'block';
        document.getElementById('ac-v').textContent = d.pkce_verifier.slice(0,44) + '...';
        document.getElementById('ac-c').textContent = d.pkce_challenge;
        addTrace('ac-trace', '🔒 PKCE generated — code_challenge sent to auth server', 'ok');
        addTrace('ac-trace', '🔒 state = ' + d.state.slice(0,16) + '... — CSRF protection active', 'ok');
      } else {
        addTrace('ac-trace', '⚠️ Vulnerable mode — no PKCE, no state parameter', 'warn');
      }
      addTrace('ac-trace', '➡️  Redirecting to Authorization Server (port 3001)...');
      setTimeout(function(){ window.location.href = d.redirect; }, 900);
    })
    .catch(function(e){ addTrace('ac-trace', '❌ Failed: ' + e.message, 'err'); });
}

function goToAPI() {
  document.getElementById('api-tok').value = document.getElementById('ac-at').textContent;
  nav('apitester');
}
function goToInspector() {
  document.getElementById('insp-tok').value = document.getElementById('ac-at').textContent;
  nav('inspector');
}
function doLogout() {
  var at = document.getElementById('ac-at').textContent;
  var rt = document.getElementById('ac-rt').textContent;
  var ps = [];
  if (at) ps.push(fetch('/proxy/revoke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:at,hint:'access_token'})}));
  if (rt) ps.push(fetch('/proxy/revoke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:rt,hint:'refresh_token'})}));
  Promise.all(ps).then(function(){
    document.getElementById('ac-tokens').style.display = 'none';
    TOKENS = {};
    addTrace('ac-trace', '✅ Tokens revoked — logged out', 'ok');
  });
}

// ════════════════════════════════════════════════════════════════════════════
// CLIENT CREDENTIALS
// ════════════════════════════════════════════════════════════════════════════
function doCC() {
  var scope = document.getElementById('cc-scope').value;
  clearTrace('cc-trace');
  addTrace('cc-trace', '⏳ Requesting client_credentials token...');
  fetch('/proxy/client-credentials', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scope:scope})})
    .then(function(r){ return r.json(); })
    .then(function(d){
      showOut('cc-out', d);
      if (d.access_token) {
        addTrace('cc-trace', '✅ M2M token issued — no user involved', 'ok');
        addTrace('cc-trace', '🔑 Scope: ' + d.scope, 'ok');
        var dec = decodeJWT(d.access_token);
        if (dec) addTrace('cc-trace', '📦 sub = ' + dec.payload.sub + ' (client identity, not user)', 'ok');
      } else {
        addTrace('cc-trace', '❌ Error: ' + (d.error_description||d.error), 'err');
      }
    }).catch(function(e){ addTrace('cc-trace', '❌ ' + e.message, 'err'); });
}

// ════════════════════════════════════════════════════════════════════════════
// DEVICE FLOW
// ════════════════════════════════════════════════════════════════════════════
var DEV_CODE = null;
function startDevice() {
  clearTrace('dev-trace');
  document.getElementById('dev-code-box').style.display = 'none';
  addTrace('dev-trace', '⏳ Requesting device code...');
  fetch('/proxy/device-start', {method:'POST'})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (d.error) { addTrace('dev-trace', '❌ ' + d.error, 'err'); return; }
      DEV_CODE = d.device_code;
      document.getElementById('dev-code').textContent = d.user_code;
      document.getElementById('dev-code-box').style.display = 'block';
      addTrace('dev-trace', '✅ Device code issued. User code: ' + d.user_code, 'ok');
      addTrace('dev-trace', '→ Open http://localhost:3001/device and enter the code', 'warn');
      addTrace('dev-trace', '→ Then click "Poll for Token" below', 'warn');
    }).catch(function(e){ addTrace('dev-trace', '❌ ' + e.message, 'err'); });
}
function pollDevice() {
  if (!DEV_CODE) { addTrace('dev-trace', '❌ Start device flow first', 'err'); return; }
  addTrace('dev-trace', '⏳ Polling token endpoint...');
  fetch('/proxy/device-poll', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_code:DEV_CODE})})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (d.error === 'authorization_pending') { addTrace('dev-trace', '⏳ Still pending — user hasn\'t approved yet', 'warn'); return; }
      if (d.error === 'access_denied')         { addTrace('dev-trace', '❌ User denied access', 'err'); return; }
      if (d.error === 'expired_token')         { addTrace('dev-trace', '❌ Device code expired', 'err'); return; }
      if (d.access_token) {
        showOut('dev-out', d);
        addTrace('dev-trace', '✅ Token issued! Device is now authenticated.', 'ok');
        DEV_CODE = null;
      } else {
        addTrace('dev-trace', '❌ ' + (d.error_description||d.error||'Unknown error'), 'err');
      }
    }).catch(function(e){ addTrace('dev-trace', '❌ ' + e.message, 'err'); });
}

// ════════════════════════════════════════════════════════════════════════════
// REFRESH TOKENS
// ════════════════════════════════════════════════════════════════════════════
function doRefresh(rotate) {
  var inputId = rotate ? 'rt-sec' : 'rt-vuln';
  var outId   = rotate ? 'rt-sec-out' : 'rt-vuln-out';
  var rt = document.getElementById(inputId).value.trim();
  if (!rt) { alert('Paste a refresh_token first.\\nComplete the Auth Code flow first.'); return; }

  fetch('/proxy/refresh', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({refresh_token:rt,rotate:rotate})})
    .then(function(r){ return r.json(); })
    .then(function(d){
      var el = document.getElementById(outId);
      el.classList.add('show');
      var note = '';
      if (d.rotated === true)  note = '\\n\\n✅ NEW refresh_token issued — old one invalidated';
      if (d.rotated === false) note = '\\n\\n⚠️  SAME token returned — stolen token still works!';
      el.textContent = JSON.stringify(d, null, 2) + note;
    }).catch(function(e){
      document.getElementById(outId).classList.add('show');
      document.getElementById(outId).textContent = '❌ Error: ' + e.message;
    });
}

function doRevoke() {
  var tok  = document.getElementById('rv-tok').value.trim();
  var hint = document.getElementById('rv-hint').value;
  if (!tok) { alert('Paste a token first.'); return; }
  fetch('/proxy/revoke', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:tok,hint:hint})})
    .then(function(r){ return r.json(); })
    .then(function(d){ showOut('rv-out', d); })
    .catch(function(e){ showOut('rv-out', {error:e.message}); });
}

// ════════════════════════════════════════════════════════════════════════════
// CSRF
// ════════════════════════════════════════════════════════════════════════════
function csrfSecure() {
  clearTrace('csrf-trace');
  addTrace('csrf-trace', '🔒 Starting SECURE flow with state parameter...');
  fetch('/proxy/oauth/start?mode=secure&scopes=openid')
    .then(function(r){ return r.json(); })
    .then(function(d){
      addTrace('csrf-trace', '✅ state = ' + d.state.slice(0,20) + '... (stored in server session)', 'ok');
      addTrace('csrf-trace', '✅ On callback: server verifies state matches → CSRF attack blocked', 'ok');
      addTrace('csrf-trace', '→ Redirecting to auth server...', 'warn');
      setTimeout(function(){ window.location.href = d.redirect; }, 800);
    });
}
function csrfVuln() {
  clearTrace('csrf-trace');
  addTrace('csrf-trace', '⚠️  Starting VULNERABLE flow (no state)...', 'warn');
  fetch('/proxy/oauth/start?mode=vulnerable&scopes=openid')
    .then(function(r){ return r.json(); })
    .then(function(d){
      addTrace('csrf-trace', '⚠️  No state parameter — CSRF attack is possible', 'warn');
      addTrace('csrf-trace', '⚠️  Attacker can forge: <img src="/callback?code=ATTACKER_CODE">', 'warn');
      addTrace('csrf-trace', '→ Redirecting to auth server...', 'warn');
      setTimeout(function(){ window.location.href = d.redirect; }, 800);
    });
}

// ════════════════════════════════════════════════════════════════════════════
// OPEN REDIRECT
// ════════════════════════════════════════════════════════════════════════════
function testRedirects() {
  clearTrace('redir-trace');
  var attacks = [
    ['http://localhost:3000/callback.evil.com', 'Suffix append'],
    ['http://localhost:3000/callback/../admin', 'Path traversal'],
    ['http://evil.com?r=http://localhost:3000/callback', 'Parameter injection'],
    ['http://localhost:3000/callback%2fevil', 'URL encoding']
  ];
  addTrace('redir-trace', '⏳ Testing ' + attacks.length + ' redirect_uri bypass attempts...');
  var done = 0;
  attacks.forEach(function(a) {
    var uri = a[0], desc = a[1];
    fetch('/proxy/test-redirect', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({redirect_uri:uri})})
      .then(function(r){ return r.json(); })
      .then(function(d){
        var blocked = d.status === 400;
        addTrace('redir-trace', (blocked ? '✅ BLOCKED (400)' : '🚨 PASSED ('+d.status+')') + ' — ' + desc + ': ' + uri, blocked?'ok':'err');
        done++;
        if (done === attacks.length) addTrace('redir-trace', '✅ All bypass attempts blocked by exact URI matching', 'ok');
      })
      .catch(function(e){ addTrace('redir-trace','❌ Error: '+e.message,'err'); done++; });
  });
}

// ════════════════════════════════════════════════════════════════════════════
// CONSENT PHISHING
// ════════════════════════════════════════════════════════════════════════════
function startPhishing() {
  clearTrace('phish-trace');
  addTrace('phish-trace', '⏳ Starting phishing simulation...');
  fetch('/proxy/oauth/start?mode=vulnerable&scopes=' + encodeURIComponent('openid profile email read:posts write:posts admin') + '&app=malicious')
    .then(function(r){ return r.json(); })
    .then(function(d){
      addTrace('phish-trace', '🎣 Malicious app consent page opening in new tab...', 'warn');
      addTrace('phish-trace', '⚠️  Notice: URL is real localhost:3001 — this bypasses phishing detection', 'warn');
      window.open(d.redirect, '_blank');
    });
}

// ════════════════════════════════════════════════════════════════════════════
// TOKEN INSPECTOR
// ════════════════════════════════════════════════════════════════════════════
function decodeToken() {
  var tok = document.getElementById('insp-tok').value.trim();
  if (!tok) { alert('Paste a JWT first.'); return; }
  var dec = decodeJWT(tok);
  if (!dec) { showOut('insp-out', {error:'Invalid JWT format'}); return; }
  showOut('insp-out', { header: dec.header, payload: dec.payload, note:'Signature NOT verified client-side. Use Introspect for server-side validation.' });
}
function introspectToken() {
  var tok = document.getElementById('insp-tok').value.trim();
  if (!tok) { alert('Paste a JWT first.'); return; }
  fetch('/proxy/introspect', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:tok})})
    .then(function(r){ return r.json(); })
    .then(function(d){ showOut('insp-intro', d); })
    .catch(function(e){ showOut('insp-intro', {error:e.message}); });
}

// ════════════════════════════════════════════════════════════════════════════
// API TESTER
// ════════════════════════════════════════════════════════════════════════════
function callAPI() {
  var ep  = document.getElementById('api-ep').value;
  var method = document.getElementById('api-method').value;
  var tok = document.getElementById('api-tok').value.trim();
  fetch('/proxy/api', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({endpoint:ep,method:method,token:tok||undefined})})
    .then(function(r){ return r.json(); })
    .then(function(d){ showOut('api-out', d); })
    .catch(function(e){ showOut('api-out', {error:e.message}); });
}

// ════════════════════════════════════════════════════════════════════════════
// OIDC DISCOVERY
// ════════════════════════════════════════════════════════════════════════════
function loadDiscovery() {
  fetch('/proxy/discovery')
    .then(function(r){ return r.json(); })
    .then(function(d){ showOut('disc-out', d); })
    .catch(function(e){ showOut('disc-out', {error:e.message}); });
}
</script>
</body></html>`;

app.listen(3000, () => console.log('🌐 Client Application running on http://localhost:3000'));
