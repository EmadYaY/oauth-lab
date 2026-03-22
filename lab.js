'use strict';
const express = require('express');
const crypto  = require('crypto');
const http    = require('http');
const os      = require('os');

// ── Detect host IP dynamically ────────────────────────────────────────────────
function getHostIP() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) return net.address;
    }
  }
  return '127.0.0.1';
}
const HOST = process.env.HOST || getHostIP();
const AUTH_URL   = `http://${HOST}:3001`;
const API_URL    = `http://${HOST}:3002`;
const CLIENT_URL = `http://${HOST}:3000`;

console.log(`\n🌐 Detected host: ${HOST}`);

// ── JWT ───────────────────────────────────────────────────────────────────────
const SECRET = 'oauth-lab-secret-2024';
function b64u(s) {
  return Buffer.from(s).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
}
function signJWT(payload) {
  const h = b64u(JSON.stringify({ alg:'HS256', typ:'JWT' }));
  const p = b64u(JSON.stringify(payload));
  const s = crypto.createHmac('sha256', SECRET).update(`${h}.${p}`).digest('base64')
              .replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  return `${h}.${p}.${s}`;
}
function verifyJWT(token) {
  try {
    const [h,p,s] = token.split('.');
    const expected = crypto.createHmac('sha256', SECRET).update(`${h}.${p}`).digest('base64')
                       .replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
    if (s !== expected) return null;
    const pl = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (pl.exp < Date.now()/1000) return null;
    if (revokedTokens.has(token)) return null;
    return pl;
  } catch { return null; }
}

// ── Data store ────────────────────────────────────────────────────────────────
const USERS = {
  alice: { id:'u1', name:'Alice Smith', email:'alice@example.com', password:'password123', roles:['user'] },
  bob:   { id:'u2', name:'Bob Jones',   email:'bob@example.com',   password:'password123', roles:['user','admin'] },
};
const CLIENTS = {
  'demo-client':    { secret:'demo-secret',    redirectUris:[], scopes:['openid','profile','email','read:posts','write:posts','admin'] },
  'service-client': { secret:'service-secret', redirectUris:[], scopes:['api:read','api:write'] },
  'malicious-app':  { secret:null, name:'MS Teams Update Tool ⚠️', redirectUris:[], scopes:['openid','profile','email','read:posts','write:posts','admin'], isMalicious:true },
};
// redirectUris filled dynamically after HOST is known
function initClients() {
  CLIENTS['demo-client'].redirectUris    = [`${CLIENT_URL}/callback`];
  CLIENTS['malicious-app'].redirectUris  = [`${CLIENT_URL}/malicious-callback`];
}

const authCodes     = new Map();
const refreshTokens = new Map();
const deviceCodes   = new Map();
const userCodes     = new Map();
const revokedTokens = new Set();
const sessions      = new Map();

const posts = [
  { id:'p1', userId:'u1', title:'Hello World',   body:'My first post!',        createdAt:'2025-01-01' },
  { id:'p2', userId:'u1', title:'OAuth is Cool', body:'Learning OAuth 2.0.',   createdAt:'2025-01-05' },
  { id:'p3', userId:'u2', title:'Admin Notes',   body:'SECRET: Maintenance.', createdAt:'2025-01-10' },
];

// ── Token helpers ─────────────────────────────────────────────────────────────
function makeAT(clientId, userId, scope) {
  const now  = Math.floor(Date.now()/1000);
  const user = userId ? Object.values(USERS).find(u => u.id === userId) : null;
  return signJWT({
    iss: AUTH_URL, sub: userId || clientId, aud: API_URL,
    azp: clientId, exp: now+3600, iat: now, jti: crypto.randomUUID(),
    scope: Array.isArray(scope) ? scope.join(' ') : scope,
    ...(user ? { name:user.name, email:user.email, roles:user.roles } : {}),
  });
}
function makeIT(clientId, userId, nonce) {
  const user = Object.values(USERS).find(u => u.id === userId);
  const now  = Math.floor(Date.now()/1000);
  return signJWT({
    iss: AUTH_URL, sub: userId, aud: clientId,
    exp: now+3600, iat: now, ...(nonce ? { nonce } : {}),
    name: user.name, email: user.email, email_verified: true,
  });
}

// ── Internal HTTP helper (server→server) ──────────────────────────────────────
function fetch_(url, opts) {
  opts = opts || {};
  return new Promise((resolve, reject) => {
    const u    = new URL(url);
    const body = opts.body || null;
    const hdrs = Object.assign({}, opts.headers || {});
    if (body) hdrs['Content-Length'] = Buffer.byteLength(body);
    const req = http.request(
      { hostname:u.hostname, port:u.port, path:u.pathname+(u.search||''), method:opts.method||'GET', headers:hdrs },
      res => {
        let d = '';
        res.on('data', c => d += c);
        res.on('end', () => resolve({
          status: res.statusCode,
          json:   () => { try { return JSON.parse(d); } catch { return { error:'parse', raw:d }; } },
        }));
      }
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// AUTH SERVER  :3001
// ══════════════════════════════════════════════════════════════════════════════
const AUTH = express();
AUTH.use(express.json());
AUTH.use(express.urlencoded({ extended: true }));
AUTH.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

AUTH.get('/.well-known/openid-configuration', (req, res) => res.json({
  issuer:                         AUTH_URL,
  authorization_endpoint:         `${AUTH_URL}/oauth/authorize`,
  token_endpoint:                 `${AUTH_URL}/oauth/token`,
  userinfo_endpoint:              `${AUTH_URL}/oauth/userinfo`,
  revocation_endpoint:            `${AUTH_URL}/oauth/revoke`,
  introspection_endpoint:         `${AUTH_URL}/oauth/introspect`,
  device_authorization_endpoint:  `${AUTH_URL}/oauth/device`,
  response_types_supported:       ['code'],
  grant_types_supported:          ['authorization_code','client_credentials','refresh_token','urn:ietf:params:oauth:grant-type:device_code'],
  scopes_supported:               ['openid','profile','email','read:posts','write:posts','admin'],
  code_challenge_methods_supported: ['S256'],
}));

AUTH.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, nonce, mode } = req.query;
  const client  = CLIENTS[client_id];
  const secure  = mode !== 'vulnerable';

  if (!client)
    return res.status(400).json({ error:'invalid_client', error_description:'Unknown client_id' });
  if (secure && !code_challenge)
    return res.status(400).json({ error:'invalid_request', error_description:'code_challenge required (PKCE)' });
  if (secure && !client.redirectUris.includes(redirect_uri))
    return res.status(400).json({ error:'invalid_request', error_description:`redirect_uri not registered. Got: ${redirect_uri}` });
  if (!secure) {
    const base = client.redirectUris[0] ? new URL(client.redirectUris[0]).origin : '';
    if (!redirect_uri || !redirect_uri.startsWith(base))
      return res.status(400).json({ error:'invalid_request', error_description:'redirect_uri mismatch' });
  }

  const allowedScopes = (scope||'').split(' ').filter(s => client.scopes.includes(s));
  const enc = Buffer.from(JSON.stringify({
    client_id, redirect_uri, scope: allowedScopes.join(' '),
    state, code_challenge, code_challenge_method, nonce, mode,
    is_malicious: !!client.isMalicious,
  })).toString('base64url');

  const SCOPE_META = {
    openid:       ['🔑','OpenID','Verify your identity',false],
    profile:      ['👤','Profile','Name & picture',false],
    email:        ['📧','Email','Email address',false],
    'read:posts': ['📖','Read Posts','View your posts',false],
    'write:posts':['✏️','Write Posts','Create & edit posts',false],
    admin:        ['👑','Admin','FULL admin access',true],
  };

  res.send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorization — OAuth Lab</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#0f172a;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:36px;width:100%;max-width:420px;box-shadow:0 20px 40px rgba(0,0,0,.5)}
.badge{display:inline-block;background:#0ea5e9;color:#fff;font-size:11px;font-weight:700;padding:3px 12px;border-radius:99px;margin-bottom:20px}
h2{color:#f1f5f9;font-size:18px;margin-bottom:6px}
.appname{color:#38bdf8;font-size:16px;font-weight:700;margin-bottom:4px}
.appsub{color:#94a3b8;font-size:13px;margin-bottom:16px}
.box-warn{background:#450a0a;border:1px solid #ef4444;border-radius:8px;padding:12px;color:#fca5a5;font-size:13px;margin-bottom:14px}
.box-ok{background:#0c2316;border:1px solid #166534;border-radius:8px;padding:10px 12px;color:#86efac;font-size:12px;margin-bottom:14px}
.hint{background:#0f2235;border:1px solid #1e40af;border-radius:8px;padding:10px 12px;color:#93c5fd;font-size:12px;margin-bottom:16px}
.slabel{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#475569;margin-bottom:10px;margin-top:14px}
.scope-row{display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid #1e293b}
.scope-row:last-child{border:none}
.sico{font-size:16px;flex-shrink:0}
.sname{color:#f1f5f9;font-size:13px;font-weight:500}
.sdesc{color:#64748b;font-size:12px}
.sdanger{background:#7f1d1d;color:#fca5a5;font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;margin-left:6px}
label{display:block;color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin-top:14px;margin-bottom:5px}
input{width:100%;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px 12px;color:#f1f5f9;font-size:14px;outline:none}
input:focus{border-color:#0ea5e9}
.btns{display:flex;gap:10px;margin-top:20px}
.btn{flex:1;padding:12px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:.12s}
.allow{background:#0ea5e9;color:#fff}.allow:hover{background:#0284c7}
.deny{background:#334155;color:#94a3b8}.deny:hover{background:#475569}
#msg{margin-top:12px;text-align:center;font-size:13px;color:#f59e0b;min-height:20px}
</style></head>
<body><div class="card">
  <div class="badge">🔐 Authorization Server — :3001</div>
  <h2>Authorization Request</h2>
  <div class="appname">${client.isMalicious ? '⚠️ ' : ''}${client.name || client_id}</div>
  <div class="appsub">${client.isMalicious ? 'Requesting excessive permissions!' : `Client ID: ${client_id}`}</div>
  ${client.isMalicious ? '<div class="box-warn"><strong>🚨 CONSENT PHISHING SIMULATION</strong><br>Malicious app disguised as a Microsoft tool. Real attack URL would be on a legitimate domain.</div>' : ''}
  ${secure ? '<div class="box-ok">✅ Secure mode — PKCE + exact redirect_uri + state CSRF token</div>' : '<div class="box-warn"><strong>⚠️ Vulnerable mode</strong> — no CSRF protection</div>'}
  <div class="hint">👤 <strong>alice</strong> / password123 &nbsp;|&nbsp; <strong>bob</strong> / password123</div>
  <label>Username</label>
  <input id="usr" value="alice" autocomplete="username">
  <label>Password</label>
  <input id="pwd" type="password" value="password123" autocomplete="current-password">
  <div class="slabel">Requested Permissions</div>
  <div>
    ${allowedScopes.map(s => {
      const [ico, name, desc, danger] = SCOPE_META[s] || ['❓', s, '', false];
      return `<div class="scope-row">
        <div class="sico">${ico}</div>
        <div><div class="sname">${name}${danger ? '<span class="sdanger">HIGH RISK</span>' : ''}</div><div class="sdesc">${desc}</div></div>
      </div>`;
    }).join('')}
  </div>
  <div class="btns">
    <button class="btn deny"  onclick="deny()">Deny</button>
    <button class="btn allow" onclick="allow()">Allow Access</button>
  </div>
  <div id="msg"></div>
</div>
<script>
const D = JSON.parse(atob('${enc}'));
function deny() {
  location.href = D.redirect_uri + '?error=access_denied&state=' + (D.state || '');
}
async function allow() {
  const msg = document.getElementById('msg');
  msg.textContent = 'Authenticating…';
  try {
    const r = await fetch('/oauth/consent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...D,
        username: document.getElementById('usr').value,
        password: document.getElementById('pwd').value,
      }),
    });
    const d = await r.json();
    if (d.redirect) { msg.textContent = '✅ Redirecting…'; location.href = d.redirect; }
    else msg.textContent = '❌ ' + (d.error_description || d.error || 'Login failed');
  } catch(e) { msg.textContent = '❌ Network error: ' + e.message; }
}
</script>
</body></html>`);
});

AUTH.post('/oauth/consent', (req, res) => {
  const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, nonce, username, password, mode } = req.body;
  const user = USERS[username];
  if (!user || user.password !== password)
    return res.json({ error:'access_denied', error_description:'Invalid credentials' });

  const code = crypto.randomBytes(16).toString('hex');
  authCodes.set(code, {
    clientId: client_id, userId: user.id, redirectUri: redirect_uri,
    scope: (scope||'').split(' ').filter(Boolean),
    pkce: { challenge: code_challenge, method: code_challenge_method },
    nonce, exp: Date.now()+60000, used: false, mode,
  });
  setTimeout(() => authCodes.delete(code), 60000);
  let url = `${redirect_uri}?code=${code}`;
  if (state) url += `&state=${encodeURIComponent(state)}`;
  res.json({ redirect: url });
});

AUTH.post('/oauth/token', (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier, refresh_token, scope, device_code } = req.body;

  if (grant_type === 'client_credentials') {
    const cl = CLIENTS[client_id];
    if (!cl || cl.secret !== client_secret)
      return res.status(401).json({ error:'invalid_client' });
    const sc = (scope||'').split(' ').filter(s => cl.scopes.includes(s));
    return res.json({ access_token: makeAT(client_id, null, sc), token_type:'Bearer', expires_in:3600, scope: sc.join(' ') });
  }

  if (grant_type === 'authorization_code') {
    const cd = authCodes.get(code);
    if (!cd)         return res.status(400).json({ error:'invalid_grant', error_description:'Unknown or expired code' });
    if (cd.used)     return res.status(400).json({ error:'invalid_grant', error_description:'Code already used' });
    if (cd.exp < Date.now()) { authCodes.delete(code); return res.status(400).json({ error:'invalid_grant', error_description:'Code expired' }); }
    if (cd.clientId !== client_id)       return res.status(400).json({ error:'invalid_grant', error_description:'client_id mismatch' });
    if (cd.redirectUri !== redirect_uri) return res.status(400).json({ error:'invalid_grant', error_description:'redirect_uri mismatch' });
    if (cd.pkce && cd.pkce.challenge) {
      if (!code_verifier) return res.status(400).json({ error:'invalid_grant', error_description:'code_verifier required' });
      const computed = crypto.createHash('sha256').update(code_verifier).digest('base64url');
      if (computed !== cd.pkce.challenge) return res.status(400).json({ error:'invalid_grant', error_description:'PKCE verification failed' });
    }
    cd.used = true;
    const at = makeAT(client_id, cd.userId, cd.scope);
    const rt = crypto.randomBytes(32).toString('hex');
    refreshTokens.set(rt, { clientId:client_id, userId:cd.userId, scope:cd.scope, exp:Date.now()+86400000*30 });
    const resp = { access_token:at, token_type:'Bearer', expires_in:3600, refresh_token:rt, scope:cd.scope.join(' ') };
    if (cd.scope.includes('openid')) resp.id_token = makeIT(client_id, cd.userId, cd.nonce);
    return res.json(resp);
  }

  if (grant_type === 'refresh_token') {
    const rtd = refreshTokens.get(refresh_token);
    if (!rtd) return res.status(400).json({ error:'invalid_grant', error_description:'Invalid refresh token' });
    if (rtd.exp < Date.now()) { refreshTokens.delete(refresh_token); return res.status(400).json({ error:'invalid_grant', error_description:'Refresh token expired' }); }
    const rotate = req.query.rotate !== 'false';
    const newAt  = makeAT(rtd.clientId, rtd.userId, rtd.scope);
    if (rotate) {
      refreshTokens.delete(refresh_token);
      const nrt = crypto.randomBytes(32).toString('hex');
      refreshTokens.set(nrt, { ...rtd, exp: Date.now()+86400000*30 });
      return res.json({ access_token:newAt, token_type:'Bearer', expires_in:3600, refresh_token:nrt, scope:rtd.scope.join(' '), rotated:true });
    }
    return res.json({ access_token:newAt, token_type:'Bearer', expires_in:3600, refresh_token, scope:rtd.scope.join(' '), rotated:false });
  }

  if (grant_type === 'urn:ietf:params:oauth:grant-type:device_code') {
    const dc = deviceCodes.get(device_code);
    if (!dc) return res.status(400).json({ error:'invalid_grant' });
    if (dc.exp < Date.now()) { deviceCodes.delete(device_code); return res.status(400).json({ error:'expired_token' }); }
    if (dc.status === 'pending') return res.status(400).json({ error:'authorization_pending' });
    if (dc.status === 'denied')  return res.status(400).json({ error:'access_denied' });
    if (dc.status === 'approved') {
      deviceCodes.delete(device_code);
      return res.json({ access_token: makeAT(client_id, dc.userId, dc.scope.split(' ')), token_type:'Bearer', expires_in:3600, scope:dc.scope });
    }
  }

  res.status(400).json({ error:'unsupported_grant_type' });
});

AUTH.post('/oauth/device', (req, res) => {
  const dc = crypto.randomBytes(16).toString('hex');
  const uc = crypto.randomBytes(3).toString('hex').toUpperCase().match(/.{1,4}/g).join('-');
  deviceCodes.set(dc, { clientId:req.body.client_id, scope:req.body.scope||'openid profile', userCode:uc, exp:Date.now()+300000, status:'pending' });
  userCodes.set(uc, dc);
  setTimeout(() => { deviceCodes.delete(dc); userCodes.delete(uc); }, 300000);
  res.json({ device_code:dc, user_code:uc, verification_uri:`${AUTH_URL}/device`, expires_in:300, interval:5 });
});

AUTH.get('/device', (req, res) => {
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Device Auth</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:sans-serif;background:#0f172a;color:#f1f5f9;display:flex;align-items:center;justify-content:center;min-height:100vh}
.c{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:36px;width:340px;text-align:center}
h2{color:#38bdf8;margin-bottom:8px}p{color:#94a3b8;font-size:13px;margin-bottom:16px}
input,select{width:100%;padding:10px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#f1f5f9;font-size:16px;margin:6px 0;text-align:center;outline:none;letter-spacing:3px}
select{letter-spacing:0;text-align:left;font-size:14px}
button{width:100%;padding:11px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;margin-top:6px}
.a{background:#0ea5e9;color:#fff}.d{background:#334155;color:#94a3b8}#m{margin-top:14px;font-size:13px;min-height:20px}</style></head>
<body><div class="c"><h2>Device Authorization</h2><p>Enter the code shown on your device</p>
<input id="uc" placeholder="XXXX-YYYY" value="${req.query.user_code||''}" maxlength="9">
<select id="usr"><option>alice</option><option>bob</option></select>
<button class="a" onclick="go('approve')">✅ Approve</button>
<button class="d" onclick="go('deny')">✗ Deny</button>
<div id="m"></div></div>
<script>
async function go(action) {
  const r = await fetch('/device/approve', { method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ user_code: document.getElementById('uc').value.toUpperCase(), username: document.getElementById('usr').value, action }) });
  const d = await r.json();
  document.getElementById('m').innerHTML = d.success
    ? '<span style="color:#10b981">✅ Approved! Return to your device.</span>'
    : '<span style="color:#ef4444">❌ ' + d.error + '</span>';
}
</script></body></html>`);
});

AUTH.post('/device/approve', (req, res) => {
  const { user_code, username, action } = req.body;
  const dc = userCodes.get(user_code);
  if (!dc) return res.json({ success:false, error:'Invalid or expired code' });
  const d = deviceCodes.get(dc);
  if (!d) return res.json({ success:false, error:'Device code not found' });
  if (action === 'approve') {
    const user = USERS[username];
    if (!user) return res.json({ success:false, error:'User not found' });
    d.status = 'approved'; d.userId = user.id;
  } else { d.status = 'denied'; }
  res.json({ success: true });
});

AUTH.post('/oauth/introspect', (req, res) => {
  const p = verifyJWT(req.body.token);
  if (!p) return res.json({ active: false });
  res.json({ active:true, ...p, token_type:'Bearer' });
});

AUTH.post('/oauth/revoke', (req, res) => {
  const { token, token_type_hint } = req.body;
  if (token_type_hint === 'refresh_token') refreshTokens.delete(token);
  else revokedTokens.add(token);
  res.json({ revoked:true });
});

AUTH.get('/oauth/userinfo', (req, res) => {
  const token = (req.headers.authorization||'').slice(7);
  const p = verifyJWT(token);
  if (!p) return res.status(401).json({ error:'invalid_token' });
  const user = Object.values(USERS).find(u => u.id === p.sub);
  if (!user) return res.status(404).json({ error:'user_not_found' });
  res.json({ sub:user.id, name:user.name, email:user.email, email_verified:true, roles:user.roles });
});

// ══════════════════════════════════════════════════════════════════════════════
// API SERVER  :3002
// ══════════════════════════════════════════════════════════════════════════════
const API = express();
API.use(express.json());
API.use(express.urlencoded({ extended:true }));
API.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

function requireAuth(scope) {
  return (req, res, next) => {
    const token = (req.headers.authorization||'').slice(7);
    if (!token) return res.status(401).json({ error:'unauthorized', error_description:'No Bearer token. Add: Authorization: Bearer <token>' });
    const p = verifyJWT(token);
    if (!p) return res.status(401).json({ error:'invalid_token', error_description:'Token invalid or expired' });
    if (p.iss !== AUTH_URL) return res.status(401).json({ error:'invalid_token', error_description:`Bad issuer. Expected: ${AUTH_URL}` });
    if (p.aud !== API_URL)  return res.status(401).json({ error:'invalid_token', error_description:`Bad audience. Expected: ${API_URL}` });
    if (scope) {
      const granted = (p.scope||'').split(' ');
      if (!granted.includes(scope)) return res.status(403).json({ error:'insufficient_scope', error_description:`Required: ${scope}. Got: ${p.scope}` });
    }
    req.user = p;
    next();
  };
}

API.get('/api/status', (req, res) => res.json({
  status:'ok', server:'Resource API', port:3002,
  message:'Public endpoint — no token required', timestamp: new Date().toISOString(),
}));
API.get('/api/profile', requireAuth(), (req, res) => res.json({
  message:'✅ Authenticated!',
  user: { id:req.user.sub, name:req.user.name, email:req.user.email, roles:req.user.roles },
  token_info: { issuer:req.user.iss, client:req.user.azp, scopes:req.user.scope, expires_at: new Date(req.user.exp*1000).toISOString() },
}));
API.get('/api/posts', requireAuth('read:posts'), (req, res) => {
  const mine = posts.filter(p => p.userId === req.user.sub);
  res.json({ message:'✅ Posts retrieved (read:posts verified)', posts:mine, total:mine.length });
});
API.post('/api/posts', requireAuth('write:posts'), (req, res) => {
  const { title, body } = req.body;
  if (!title) return res.status(400).json({ error:'title_required' });
  const p = { id:'post-'+crypto.randomUUID().slice(0,8), userId:req.user.sub, title, body:body||'', createdAt:new Date().toISOString() };
  posts.push(p);
  res.status(201).json({ message:'✅ Post created (write:posts verified)', post:p });
});
API.get('/api/admin', requireAuth('admin'), (req, res) => res.json({
  message:'✅ Admin access granted', warning:'High-risk scope',
  all_posts: posts, uptime: process.uptime(),
}));
API.get('/api/debug-token', (req, res) => {
  const token = (req.headers.authorization||'').slice(7);
  if (!token) return res.json({ error:'No token' });
  try {
    const [h,p] = token.split('.');
    res.json({ header: JSON.parse(Buffer.from(h,'base64url').toString()), payload: JSON.parse(Buffer.from(p,'base64url').toString()), valid: !!verifyJWT(token) });
  } catch { res.json({ error:'Cannot decode token' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// CLIENT APP + PROXY  :3000
// ══════════════════════════════════════════════════════════════════════════════
const CLIENT = express();
CLIENT.use(express.json());
CLIENT.use(express.urlencoded({ extended:true }));

// ── Proxy helpers ─────────────────────────────────────────────────────────────
CLIENT.get('/proxy/health/auth', async (req, res) => {
  try { const r = await fetch_(`${AUTH_URL}/.well-known/openid-configuration`); res.json({ ok: r.status===200 }); }
  catch { res.json({ ok:false }); }
});
CLIENT.get('/proxy/health/api', async (req, res) => {
  try { const r = await fetch_(`${API_URL}/api/status`); res.json({ ok: r.status===200 }); }
  catch { res.json({ ok:false }); }
});

CLIENT.get('/proxy/oauth/start', (req, res) => {
  const mode    = req.query.mode   || 'secure';
  const scopes  = req.query.scopes || 'openid profile email read:posts';
  const appType = req.query.app    || '';
  const secure  = mode !== 'vulnerable';
  const clientId = appType === 'malicious' ? 'malicious-app' : 'demo-client';

  const csrf      = secure ? crypto.randomBytes(16).toString('hex') : 'nosec';
  const nonce     = crypto.randomBytes(16).toString('hex');
  const verifier  = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const sid       = crypto.randomUUID();
  const state     = `${csrf}|${sid}`;

  sessions.set(sid, { csrf, nonce, verifier, mode });

  const params = new URLSearchParams({
    response_type: 'code', client_id: clientId,
    redirect_uri: `${CLIENT_URL}/callback`,
    scope: scopes, nonce, mode, state,
    ...(secure ? { code_challenge: challenge, code_challenge_method:'S256' } : {}),
  });

  res.json({
    redirect: `${AUTH_URL}/oauth/authorize?${params}`,
    session_id: sid, state: csrf,
    pkce_verifier: verifier, pkce_challenge: challenge,
  });
});

CLIENT.get('/callback', async (req, res) => {
  const { code, state:rawState, error } = req.query;
  if (error) return res.redirect(`/?error=${error}`);

  const [csrf, sid] = (rawState||'').split('|');
  const session = sessions.get(sid) || {};
  if (session.mode !== 'vulnerable' && csrf !== 'nosec' && session.csrf && session.csrf !== csrf)
    return res.redirect('/?error=csrf_detected');

  const params = new URLSearchParams({
    grant_type: 'authorization_code', code,
    redirect_uri: `${CLIENT_URL}/callback`,
    client_id: 'demo-client', client_secret: 'demo-secret',
    ...(session.verifier ? { code_verifier: session.verifier } : {}),
  });

  try {
    const r = await fetch_(`${AUTH_URL}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type':'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    const tokens = r.json();
    if (tokens.error) return res.redirect(`/?error=${tokens.error}&detail=${encodeURIComponent(tokens.error_description||'')}`);
    const newSid = crypto.randomUUID();
    sessions.set(newSid, { ...tokens, authenticated:true });
    res.redirect(`/?ok=1&sid=${newSid}`);
  } catch(e) {
    res.redirect(`/?error=network&detail=${encodeURIComponent(e.message)}`);
  }
});

CLIENT.get('/malicious-callback', (req, res) => {
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Attacker Server</title>
<style>body{font-family:sans-serif;background:#1a0a0a;color:#f1f5f9;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}
.c{background:#2d1515;border:2px solid #ef4444;border-radius:16px;padding:40px;max-width:480px}
h1{color:#ef4444;margin-bottom:16px}code{background:#0f0000;padding:6px 10px;border-radius:4px;font-size:12px;display:block;margin:8px 0;color:#fca5a5;word-break:break-all}
a{display:inline-block;margin-top:20px;background:#ef4444;color:#fff;padding:10px 24px;border-radius:8px;text-decoration:none;font-weight:600}</style></head>
<body><div class="c"><h1>🚨 Consent Phishing — Code Captured!</h1>
<p style="color:#94a3b8;margin-bottom:16px">In a real attack, this code is now on the attacker's server:</p>
<code>code = ${req.query.code||'N/A'}</code>
<p style="font-size:13px;color:#fca5a5;margin-top:12px">Attacker exchanges this for tokens → persistent access even after password change.</p>
<a href="/">← Back to Lab</a></div></body></html>`);
});

CLIENT.get('/proxy/session',    (req, res) => res.json(sessions.get(req.query.sid) || {}));

CLIENT.post('/proxy/client-credentials', async (req, res) => {
  const p = new URLSearchParams({ grant_type:'client_credentials', client_id:'service-client', client_secret:'service-secret', scope:(req.body&&req.body.scope)||'api:read' });
  try { const r = await fetch_(`${AUTH_URL}/oauth/token`, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:p.toString() }); res.json(r.json()); }
  catch(e) { res.json({ error:e.message }); }
});
CLIENT.post('/proxy/device-start', async (req, res) => {
  const p = new URLSearchParams({ client_id:'demo-client', scope:'openid profile email' });
  try { const r = await fetch_(`${AUTH_URL}/oauth/device`, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:p.toString() }); res.json(r.json()); }
  catch(e) { res.json({ error:e.message }); }
});
CLIENT.post('/proxy/device-poll', async (req, res) => {
  const p = new URLSearchParams({ grant_type:'urn:ietf:params:oauth:grant-type:device_code', device_code:req.body.device_code, client_id:'demo-client' });
  try { const r = await fetch_(`${AUTH_URL}/oauth/token`, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:p.toString() }); res.json(r.json()); }
  catch(e) { res.json({ error:e.message }); }
});
CLIENT.post('/proxy/refresh', async (req, res) => {
  const { refresh_token, rotate } = req.body;
  const url = `${AUTH_URL}/oauth/token` + (rotate===false||rotate==='false' ? '?rotate=false' : '');
  const p = new URLSearchParams({ grant_type:'refresh_token', refresh_token, client_id:'demo-client' });
  try { const r = await fetch_(url, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:p.toString() }); res.json(r.json()); }
  catch(e) { res.json({ error:e.message }); }
});
CLIENT.post('/proxy/introspect', async (req, res) => {
  const p = new URLSearchParams({ token:req.body.token, client_id:'demo-client' });
  try { const r = await fetch_(`${AUTH_URL}/oauth/introspect`, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:p.toString() }); res.json(r.json()); }
  catch(e) { res.json({ error:e.message }); }
});
CLIENT.post('/proxy/revoke', async (req, res) => {
  const p = new URLSearchParams({ token:req.body.token, token_type_hint:req.body.hint||'', client_id:'demo-client' });
  try { const r = await fetch_(`${AUTH_URL}/oauth/revoke`, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:p.toString() }); res.json(r.json()); }
  catch(e) { res.json({ error:e.message }); }
});
CLIENT.get('/proxy/discovery', async (req, res) => {
  try { const r = await fetch_(`${AUTH_URL}/.well-known/openid-configuration`); res.json(r.json()); }
  catch(e) { res.json({ error:e.message }); }
});
CLIENT.post('/proxy/api', async (req, res) => {
  const { endpoint, method, token, body:rb } = req.body;
  const headers = { 'Content-Type':'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const opts = { method:method||'GET', headers };
  if (method==='POST' && rb) opts.body = JSON.stringify(rb);
  try { const r = await fetch_(`${API_URL}${endpoint}`, opts); res.json({ status:r.status, data:r.json() }); }
  catch(e) { res.json({ error:e.message }); }
});
CLIENT.post('/proxy/test-redirect', async (req, res) => {
  const qs = new URLSearchParams({ response_type:'code', client_id:'demo-client', redirect_uri:req.body.redirect_uri, scope:'openid', code_challenge:'abc', code_challenge_method:'S256', mode:'secure' });
  try { const r = await fetch_(`${AUTH_URL}/oauth/authorize?${qs}`); res.json({ status:r.status }); }
  catch(e) { res.json({ error:e.message }); }
});

// ── Main UI (injects HOST dynamically) ────────────────────────────────────────
CLIENT.get('/', (req, res) => {
  res.send(buildUI());
});

function buildUI() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OAuth 2.0 Security Lab</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg0:#070b11;--bg1:#0d1117;--bg2:#161b22;--bg3:#1c2430;
  --b:#21262d;--t1:#e6edf3;--t2:#8b949e;--t3:#3d444d;
  --blue:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--cyan:#79c0ff;--orange:#ffa657;
  --bblue:rgba(88,166,255,.12);--bgreen:rgba(63,185,80,.12);--bred:rgba(248,81,73,.12);--byellow:rgba(210,153,34,.12);
}
*{box-sizing:border-box;margin:0;padding:0}html,body{height:100%}
body{font-family:'Inter',sans-serif;background:var(--bg0);color:var(--t1);font-size:14px}
.mono{font-family:'JetBrains Mono',monospace}
/* Header */
.hdr{background:var(--bg1);border-bottom:1px solid var(--b);height:52px;display:flex;align-items:center;padding:0 20px;gap:12px;position:sticky;top:0;z-index:100}
.logo{font-size:16px;font-weight:700;white-space:nowrap}
.hdr-r{margin-left:auto;display:flex;gap:8px}
.sbadge{display:flex;align-items:center;gap:5px;background:var(--bg2);border:1px solid var(--b);border-radius:20px;padding:3px 10px;font-size:11px;color:var(--t2)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--yellow);flex-shrink:0;transition:background .4s,box-shadow .4s}
.dot.on{background:var(--green)!important;box-shadow:0 0 8px var(--green)}
.dot.off{background:var(--red)!important}
/* Layout */
.layout{display:grid;grid-template-columns:210px 1fr;height:calc(100vh - 52px)}
.sidebar{background:var(--bg1);border-right:1px solid var(--b);padding:8px 6px;overflow-y:auto}
.main{overflow-y:auto;padding:20px 24px}
/* Nav */
.ns{font-size:10px;font-weight:700;letter-spacing:.1em;color:var(--t3);text-transform:uppercase;padding:12px 10px 4px}
.ni{display:flex;align-items:center;gap:8px;padding:7px 10px;border-radius:6px;cursor:pointer;color:var(--t2);font-size:13px;border:1px solid transparent;user-select:none;transition:all .1s}
.ni:hover{background:var(--bg2);color:var(--t1)}
.ni.on{background:var(--bblue);color:var(--blue);border-color:rgba(88,166,255,.2)}
.nic{font-size:14px;width:20px;text-align:center;flex-shrink:0}
.ntag{margin-left:auto;font-size:10px;font-weight:700;padding:1px 6px;border-radius:10px}
.nr{background:var(--bred);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.ng{background:var(--bgreen);color:var(--green);border:1px solid rgba(63,185,80,.3)}
/* Panels */
.panel{display:none}.panel.on{display:block}
.ptitle{font-size:18px;font-weight:700;margin-bottom:4px}
.psub{color:var(--t2);font-size:13px;margin-bottom:18px}
/* Cards */
.card{background:var(--bg1);border:1px solid var(--b);border-radius:10px;padding:18px;margin-bottom:14px}
.chdr{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px;gap:12px}
.ctitle{font-size:14px;font-weight:600;margin-bottom:2px}
.csub{font-size:12px;color:var(--t2)}
.tag{font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px;white-space:nowrap}
.tg{background:var(--bgreen);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.tr{background:var(--bred);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.tb{background:var(--bblue);color:var(--blue);border:1px solid rgba(88,166,255,.3)}
.ty{background:var(--byellow);color:var(--yellow);border:1px solid rgba(210,153,34,.3)}
/* Alerts */
.ai{background:var(--bblue);border:1px solid rgba(88,166,255,.2);color:var(--cyan);border-radius:6px;padding:10px 14px;margin-bottom:12px;font-size:13px;line-height:1.5}
.aw{background:var(--byellow);border:1px solid rgba(210,153,34,.2);color:var(--yellow);border-radius:6px;padding:10px 14px;margin-bottom:12px;font-size:13px;line-height:1.5}
.ae{background:var(--bred);border:1px solid rgba(248,81,73,.2);color:#ffa198;border-radius:6px;padding:10px 14px;margin-bottom:12px;font-size:13px;line-height:1.5}
.as{background:var(--bgreen);border:1px solid rgba(63,185,80,.2);color:#7ee787;border-radius:6px;padding:10px 14px;margin-bottom:12px;font-size:13px;line-height:1.5}
/* Buttons */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;border:none;font-family:inherit;transition:.12s;white-space:nowrap}
.btn:disabled{opacity:.5;cursor:not-allowed}
.bb{background:#1f6feb;color:#fff}.bb:hover:not(:disabled){background:#388bfd}
.bg{background:#238636;color:#fff}.bg:hover:not(:disabled){background:#2ea043}
.br{background:#b91c1c;color:#fff}.br:hover:not(:disabled){background:#dc2626}
.bh{background:var(--bg2);color:var(--t2);border:1px solid var(--b)}.bh:hover:not(:disabled){color:var(--t1)}
.by{background:#7d4e08;color:#fff}.by:hover:not(:disabled){background:#9e6a03}
/* Form */
.f{display:flex;flex-direction:column;gap:4px;min-width:0}
.f label{font-size:11px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.06em}
.f input,.f select,.f textarea{background:var(--bg0);border:1px solid var(--b);border-radius:6px;padding:7px 10px;color:var(--t1);font-size:13px;font-family:inherit;outline:none}
.f input:focus,.f select:focus,.f textarea:focus{border-color:var(--blue)}
.f textarea{font-family:'JetBrains Mono',monospace;font-size:12px;resize:vertical;min-height:60px}
.row{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:12px;align-items:flex-end}
/* Output */
.out{background:var(--bg0);border:1px solid var(--b);border-radius:6px;padding:12px;font-family:'JetBrains Mono',monospace;font-size:12px;line-height:1.7;color:var(--t2);white-space:pre-wrap;word-break:break-all;max-height:320px;overflow-y:auto;min-height:50px;display:none;margin-top:8px}
.out.on{display:block}
.olbl{font-size:11px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.06em;margin-top:10px;margin-bottom:4px}
/* Trace */
.titem{padding:6px 10px;border-radius:5px;margin-bottom:4px;font-size:13px;background:var(--bg2);border-left:3px solid var(--t3);line-height:1.4}
.titem.ok{border-color:var(--green);background:rgba(63,185,80,.06)}
.titem.err{border-color:var(--red);background:rgba(248,81,73,.06)}
.titem.warn{border-color:var(--yellow);background:rgba(210,153,34,.06)}
.tbox{margin-top:10px}
/* Token boxes */
.tok{background:var(--bg0);border:1px solid var(--b);border-radius:6px;padding:10px;margin-bottom:8px}
.tlbl{font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;margin-bottom:4px}
.tval{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--cyan);word-break:break-all;cursor:pointer;line-height:1.5}
.tval:hover{color:var(--blue)}
/* Grid */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--bg3);border-radius:4px}
@media(max-width:760px){.layout{grid-template-columns:1fr}.sidebar{display:none}.g2{grid-template-columns:1fr}}
</style>
</head>
<body>

<div class="hdr">
  <div class="logo">🔐 OAuth 2.0 Security Lab</div>
  <div class="hdr-r">
    <div class="sbadge"><div class="dot on"></div>Client :3000</div>
    <div class="sbadge"><div class="dot" id="d1"></div>Auth :3001</div>
    <div class="sbadge"><div class="dot" id="d2"></div>API :3002</div>
  </div>
</div>

<div class="layout">
<div class="sidebar">
  <div class="ns">Core Flows</div>
  <div class="ni on" data-p="authcode"><span class="nic">🔑</span>Auth Code + PKCE<span class="ntag ng">Secure</span></div>
  <div class="ni" data-p="cc"><span class="nic">🤖</span>Client Credentials</div>
  <div class="ni" data-p="device"><span class="nic">📺</span>Device Flow</div>
  <div class="ni" data-p="refresh"><span class="nic">♻️</span>Refresh Tokens</div>
  <div class="ns">Vulnerability Lab</div>
  <div class="ni" data-p="csrf"><span class="nic">💥</span>CSRF Attack<span class="ntag nr">CVE</span></div>
  <div class="ni" data-p="implicit"><span class="nic">🔓</span>Implicit Flow<span class="ntag nr">Deprecated</span></div>
  <div class="ni" data-p="redirect"><span class="nic">↗️</span>Open Redirect<span class="ntag nr">Attack</span></div>
  <div class="ni" data-p="phishing"><span class="nic">🎣</span>Consent Phishing<span class="ntag nr">APT29</span></div>
  <div class="ns">Tools</div>
  <div class="ni" data-p="inspector"><span class="nic">🔍</span>Token Inspector</div>
  <div class="ni" data-p="apitester"><span class="nic">⚡</span>API Tester</div>
  <div class="ni" data-p="discovery"><span class="nic">📋</span>OIDC Discovery</div>
</div>

<div class="main">

<!-- AUTH CODE -->
<div class="panel on" id="p-authcode">
  <div class="ptitle">Authorization Code + PKCE</div>
  <div class="psub">The most secure OAuth 2.0 flow — required for all clients in OAuth 2.1</div>
  <div class="card">
    <div class="chdr"><div><div class="ctitle">Start OAuth Flow</div><div class="csub">Generates PKCE verifier/challenge + state CSRF token server-side</div></div><span class="tag tg">✅ Most Secure</span></div>
    <div class="ai">A <strong>code_verifier</strong> is generated server-side. Even if the auth code is intercepted, it's useless without the verifier. The <strong>state</strong> parameter prevents CSRF.</div>
    <div class="row">
      <div class="f"><label>Mode</label><select id="ac-mode"><option value="secure">Secure (PKCE + state)</option><option value="vulnerable">Vulnerable (no PKCE, no state)</option></select></div>
      <div class="f" style="flex:1;min-width:180px"><label>Scopes</label><input id="ac-scopes" value="openid profile email read:posts"></div>
      <button class="btn bb" onclick="startAuthCode()">🔐 Start OAuth Flow</button>
    </div>
    <div id="ac-pkce" style="display:none" class="ai">
      <strong>PKCE Generated:</strong><br>
      verifier: <span id="ac-v" style="color:var(--orange);font-family:monospace;font-size:12px"></span><br>
      challenge (SHA-256): <span id="ac-c" style="color:var(--green);font-family:monospace;font-size:12px"></span>
    </div>
    <div class="tbox" id="ac-trace"></div>
  </div>
  <div class="card" id="ac-tokens" style="display:none">
    <div class="chdr"><div class="ctitle">✅ Tokens Received</div><span class="tag tg">Success</span></div>
    <div class="tok"><div class="tlbl">Access Token <small style="color:var(--t3)">(click to copy)</small></div><div class="tval" id="ac-at" onclick="cp(this)"></div></div>
    <div class="tok"><div class="tlbl">Refresh Token</div><div class="tval" id="ac-rt" onclick="cp(this)"></div></div>
    <div class="tok" id="ac-idt-box" style="display:none"><div class="tlbl">ID Token (OIDC)</div><div class="tval" id="ac-idt" onclick="cp(this)"></div></div>
    <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
      <button class="btn bb" onclick="goAPI()">⚡ Test in API Tester</button>
      <button class="btn bh" onclick="goInspect()">🔍 Inspect Token</button>
      <button class="btn br" onclick="doLogout()">🚪 Logout & Revoke</button>
    </div>
  </div>
</div>

<!-- CLIENT CREDENTIALS -->
<div class="panel" id="p-cc">
  <div class="ptitle">Client Credentials</div><div class="psub">Machine-to-machine auth — no user involved</div>
  <div class="card">
    <div class="chdr"><div><div class="ctitle">Request M2M Token</div><div class="csub">Service authenticates itself with client_id + client_secret</div></div><span class="tag tb">Server-to-Server</span></div>
    <div class="ai">No user redirect needed. The service sends its <strong>client_id + client_secret</strong> directly to the token endpoint.</div>
    <div class="row">
      <div class="f"><label>Scope</label><select id="cc-scope"><option value="api:read">api:read</option><option value="api:write">api:write</option><option value="api:read api:write">api:read api:write</option></select></div>
      <button class="btn bb" onclick="doCC()">🤖 Get Token</button>
    </div>
    <div class="olbl">Response</div><div class="out" id="cc-out"></div>
    <div class="tbox" id="cc-trace"></div>
  </div>
</div>

<!-- DEVICE FLOW -->
<div class="panel" id="p-device">
  <div class="ptitle">Device Authorization Flow</div><div class="psub">For input-constrained devices — Smart TVs, CLI tools, IoT (RFC 8628)</div>
  <div class="card">
    <div class="chdr"><div><div class="ctitle">Simulate Device Flow</div><div class="csub">Device gets a user_code, shows it, then polls for the token</div></div><span class="tag tb">RFC 8628</span></div>
    <div class="ai">Device requests a <strong>user_code</strong>, displays it on screen, then polls the token endpoint. User visits a separate URL to approve.</div>
    <button class="btn bb" onclick="startDevice()">📺 Start Device Flow</button>
    <div id="dev-box" style="display:none;background:var(--bg2);border:1px solid var(--b);border-radius:8px;padding:20px;margin-top:12px;text-align:center">
      <div style="color:var(--t2);font-size:12px;margin-bottom:10px">Enter this code at the URL below:</div>
      <div id="dev-code" style="font-family:monospace;font-size:32px;font-weight:700;color:var(--yellow);letter-spacing:8px;margin-bottom:10px"></div>
      <div style="font-size:12px;color:var(--t2)">Visit: <a id="dev-link" href="#" target="_blank" style="color:var(--blue)"></a></div>
      <button class="btn bg" style="margin-top:14px" onclick="pollDevice()">🔄 Poll for Token</button>
    </div>
    <div class="olbl">Token Response</div><div class="out" id="dev-out"></div>
    <div class="tbox" id="dev-trace"></div>
  </div>
</div>

<!-- REFRESH TOKENS -->
<div class="panel" id="p-refresh">
  <div class="ptitle">Refresh Token Rotation</div><div class="psub">Secure vs vulnerable refresh token handling</div>
  <div class="g2">
    <div class="card">
      <div class="chdr"><div class="ctitle">✅ With Rotation</div><span class="tag tg">Secure</span></div>
      <div class="as">New refresh token issued each time. Old one invalidated — theft detected on reuse.</div>
      <div class="f" style="margin-bottom:10px"><label>Refresh Token</label><input id="rt-sec" placeholder="Paste refresh_token from Auth Code flow"></div>
      <button class="btn bg" onclick="doRefresh(true)">♻️ Refresh (Rotate)</button>
      <div class="out" id="rt-sec-out"></div>
    </div>
    <div class="card">
      <div class="chdr"><div class="ctitle">⚠️ No Rotation</div><span class="tag tr">Vulnerable</span></div>
      <div class="ae">Same token returned forever. Stolen token = permanent access until manual revocation.</div>
      <div class="f" style="margin-bottom:10px"><label>Refresh Token</label><input id="rt-vuln" placeholder="Paste refresh_token from Auth Code flow"></div>
      <button class="btn by" onclick="doRefresh(false)">♻️ Refresh (No Rotate)</button>
      <div class="out" id="rt-vuln-out"></div>
    </div>
  </div>
  <div class="card">
    <div class="ctitle" style="margin-bottom:10px">Token Revocation (RFC 7009)</div>
    <div class="ai">Revoke access or refresh tokens. API rejects revoked tokens on next use.</div>
    <div class="row">
      <div class="f" style="flex:1"><label>Token</label><input id="rv-tok" placeholder="Paste token to revoke"></div>
      <div class="f"><label>Type</label><select id="rv-hint"><option value="access_token">access_token</option><option value="refresh_token">refresh_token</option></select></div>
      <button class="btn br" onclick="doRevoke()">🗑️ Revoke</button>
    </div>
    <div class="olbl">Response</div><div class="out" id="rv-out"></div>
  </div>
</div>

<!-- CSRF -->
<div class="panel" id="p-csrf">
  <div class="ptitle">CSRF Attack on OAuth</div><div class="psub">Missing state parameter enables session hijacking</div>
  <div class="card">
    <div class="chdr"><div class="ctitle">CSRF Protection Demo</div><span class="tag tr">CVE-Class</span></div>
    <div class="ae"><strong>Attack:</strong> Attacker starts OAuth, gets auth code, but doesn't complete the flow. Tricks victim into submitting attacker's code. Victim's session links to attacker's account.</div>
    <div class="g2" style="margin-top:12px">
      <div style="background:var(--bg0);border:1px solid var(--b);border-radius:8px;padding:14px">
        <div style="color:var(--green);font-weight:600;margin-bottom:8px">✅ Secure Flow</div>
        <div class="as" style="font-size:12px;margin-bottom:10px">state = random CSRF token stored in session, verified on callback</div>
        <button class="btn bg" onclick="csrfTest('secure')">Test Secure Flow</button>
      </div>
      <div style="background:var(--bg0);border:1px solid var(--b);border-radius:8px;padding:14px">
        <div style="color:var(--red);font-weight:600;margin-bottom:8px">⚠️ Vulnerable Flow</div>
        <div class="ae" style="font-size:12px;margin-bottom:10px">No state parameter — CSRF attack is possible</div>
        <button class="btn br" onclick="csrfTest('vulnerable')">Test Vulnerable</button>
      </div>
    </div>
    <div class="tbox" id="csrf-trace"></div>
  </div>
</div>

<!-- IMPLICIT -->
<div class="panel" id="p-implicit">
  <div class="ptitle">Implicit Flow (Deprecated)</div><div class="psub">Removed in OAuth 2.1 — tokens in URL fragment</div>
  <div class="card">
    <div class="chdr"><div class="ctitle">Why Implicit Flow is Dangerous</div><span class="tag tr">Removed in OAuth 2.1</span></div>
    <div class="ae">Implicit flow returns <strong>access_token directly in the URL fragment</strong>: <code style="background:rgba(0,0,0,.3);padding:2px 6px;border-radius:4px">#access_token=SECRET</code>. Tokens leak into browser history, server logs, and Referer headers.</div>
    <div class="out on mono" style="margin-top:12px;color:var(--t2)">https://app.com/callback#access_token=SECRET&token_type=bearer

Problems:
1. Token stored in browser history
2. Token leaks in HTTP Referer header on external navigation
3. Token readable by ALL JavaScript on the page (XSS risk)
4. No PKCE binding possible

→ OAuth 2.1 mandates Authorization Code + PKCE for all clients</div>
  </div>
</div>

<!-- OPEN REDIRECT -->
<div class="panel" id="p-redirect">
  <div class="ptitle">Open Redirect Attack</div><div class="psub">Exploiting loose redirect_uri validation to steal auth codes</div>
  <div class="card">
    <div class="chdr"><div class="ctitle">redirect_uri Bypass Tests</div><span class="tag tr">Attack</span></div>
    <div class="ae">Prefix-matching or wildcard validation allows attackers to redirect auth codes to their own server.</div>
    <button class="btn br" onclick="testRedirects()">💥 Run All Bypass Tests</button>
    <div class="tbox" id="redir-trace"></div>
  </div>
  <div class="out on mono">Registered: ${CLIENT_URL}/callback

Attack payloads tested:
  ${CLIENT_URL}/callback.evil.com   ← suffix append
  ${CLIENT_URL}/callback/../admin   ← path traversal
  http://evil.com?r=${CLIENT_URL}/callback  ← param injection
  ${CLIENT_URL}/callback%2fevil     ← URL encoding

Secure: exact URI match only — all above are blocked</div>
</div>

<!-- PHISHING -->
<div class="panel" id="p-phishing">
  <div class="ptitle">Consent Phishing (APT29)</div><div class="psub">Nation-state attack using legitimate OAuth consent pages</div>
  <div class="card">
    <div class="chdr"><div class="ctitle">Consent Phishing Simulation</div><span class="tag tr">APT29 / Midnight Blizzard</span></div>
    <div class="ae"><strong>This bypasses all credential phishing defenses.</strong> The URL is a real OAuth consent page on <code style="background:rgba(0,0,0,.3);padding:2px 6px;border-radius:4px">${HOST}:3001</code>. User is tricked into granting excessive permissions to a malicious app.</div>
    <div class="aw">Even after password change, the OAuth grant persists. Attacker retains access indefinitely via the refresh token.</div>
    <button class="btn br" onclick="startPhishing()">🎣 Launch Phishing Demo</button>
    <div class="tbox" id="phish-trace"></div>
  </div>
</div>

<!-- INSPECTOR -->
<div class="panel" id="p-inspector">
  <div class="ptitle">Token Inspector</div><div class="psub">Decode and validate JWT tokens</div>
  <div class="card">
    <div class="f" style="margin-bottom:10px"><label>JWT Token</label><textarea id="insp-tok" placeholder="Paste any JWT here..." rows="3"></textarea></div>
    <div class="row">
      <button class="btn bb" onclick="decodeToken()">🔍 Decode (client-side)</button>
      <button class="btn bh" onclick="introspectToken()">🔎 Introspect (server-side)</button>
    </div>
    <div class="g2">
      <div><div class="olbl">Header + Payload</div><div class="out" id="insp-out"></div></div>
      <div><div class="olbl">Server Introspection</div><div class="out" id="insp-intro"></div></div>
    </div>
  </div>
</div>

<!-- API TESTER -->
<div class="panel" id="p-apitester">
  <div class="ptitle">API Tester</div><div class="psub">Test protected endpoints on the Resource Server (port 3002)</div>
  <div class="card">
    <div class="row">
      <div class="f" style="flex:1"><label>Endpoint</label>
        <select id="api-ep">
          <option value="/api/status">GET /api/status (public)</option>
          <option value="/api/profile">GET /api/profile (any token)</option>
          <option value="/api/posts">GET /api/posts (read:posts)</option>
          <option value="/api/admin">GET /api/admin (admin scope)</option>
          <option value="/api/debug-token">GET /api/debug-token</option>
        </select>
      </div>
      <div class="f"><label>Method</label><select id="api-method"><option value="GET">GET</option><option value="POST">POST</option></select></div>
    </div>
    <div class="f" style="margin-bottom:10px"><label>Access Token (empty for public endpoints)</label><input id="api-tok" placeholder="Paste access_token here"></div>
    <button class="btn bb" onclick="callAPI()">⚡ Send Request</button>
    <div class="olbl">Response from Resource Server :3002</div><div class="out" id="api-out"></div>
  </div>
</div>

<!-- DISCOVERY -->
<div class="panel" id="p-discovery">
  <div class="ptitle">OIDC Discovery</div><div class="psub">Authorization Server metadata — <code style="font-size:12px">${AUTH_URL}/.well-known/openid-configuration</code></div>
  <div class="card">
    <button class="btn bb" onclick="loadDiscovery()">📋 Fetch Discovery Document</button>
    <div class="olbl">Discovery Document</div><div class="out" id="disc-out"></div>
  </div>
</div>

</div></div>

<script>
var TOKENS = {}, DEV_CODE = null;

window.addEventListener('load', function() {
  var p = new URLSearchParams(location.search);
  if (p.get('ok') === '1') {
    var sid = p.get('sid');
    history.replaceState({}, '', '/');
    fetch('/proxy/session?sid=' + sid).then(function(r){ return r.json(); }).then(function(d){
      TOKENS = d;
      if (d.access_token) {
        document.getElementById('ac-at').textContent = d.access_token;
        document.getElementById('ac-rt').textContent = d.refresh_token || '';
        document.getElementById('ac-tokens').style.display = 'block';
        if (d.id_token) { document.getElementById('ac-idt').textContent = d.id_token; document.getElementById('ac-idt-box').style.display = 'block'; }
        addT('ac-trace', '✅ OAuth flow complete! Tokens received.', 'ok');
        addT('ac-trace', '→ Click "Test in API Tester" to call the Resource Server with your token.', 'ok');
        nav('authcode');
      }
    }).catch(function(){});
  }
  if (p.get('error')) {
    history.replaceState({}, '', '/');
    var e = p.get('error'), det = p.get('detail') || '';
    if (e === 'csrf_detected') { nav('csrf'); addT('csrf-trace', '🚨 CSRF DETECTED: state mismatch → attack blocked!', 'err'); }
    else { nav('authcode'); addT('ac-trace', '❌ Error: ' + e + (det ? ' — ' + det : ''), 'err'); }
  }
  document.querySelectorAll('.ni').forEach(function(el) {
    el.addEventListener('click', function() { nav(this.dataset.p); });
  });
  checkServers();
  setInterval(checkServers, 8000);
});

function nav(id) {
  document.querySelectorAll('.panel').forEach(function(p){ p.classList.remove('on'); });
  document.querySelectorAll('.ni').forEach(function(n){ n.classList.remove('on'); });
  var panel = document.getElementById('p-' + id); if (panel) panel.classList.add('on');
  var item  = document.querySelector('[data-p="' + id + '"]'); if (item) item.classList.add('on');
  window.scrollTo(0, 0);
}

function checkServers() {
  fetch('/proxy/health/auth').then(function(r){ return r.json(); }).then(function(d){ dot('d1', d.ok); }).catch(function(){ dot('d1', false); });
  fetch('/proxy/health/api' ).then(function(r){ return r.json(); }).then(function(d){ dot('d2', d.ok); }).catch(function(){ dot('d2', false); });
}
function dot(id, ok) {
  var el = document.getElementById(id); if (!el) return;
  el.classList.toggle('on', ok); el.classList.toggle('off', !ok);
}

function addT(id, msg, type) {
  var b = document.getElementById(id); if (!b) return;
  var d = document.createElement('div'); d.className = 'titem ' + (type||''); d.innerHTML = msg; b.appendChild(d);
}
function clearT(id) { var el = document.getElementById(id); if (el) el.innerHTML = ''; }

function showOut(id, data) {
  var el = document.getElementById(id); if (!el) return;
  el.classList.add('on');
  var s = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  el.innerHTML = s
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"([^"]+)":/g, '<span style="color:var(--cyan)">"$1"</span>:')
    .replace(/: "([^"]*)"/g, ': <span style="color:var(--green)">"$1"</span>')
    .replace(/: (-?\\d+\\.?\\d*)/g, ': <span style="color:var(--orange)">$1</span>')
    .replace(/: (true|false)/g, ': <span style="color:var(--red)">$1</span>');
}

function cp(el) {
  navigator.clipboard.writeText(el.textContent).then(function(){
    var o = el.style.color; el.style.color = 'var(--green)';
    setTimeout(function(){ el.style.color = o; }, 800);
  });
}

function decodeJWT(t) {
  try {
    var p = t.split('.');
    var d = function(s){ return JSON.parse(atob(s.replace(/-/g,'+').replace(/_/g,'/'))); };
    return { header: d(p[0]), payload: d(p[1]) };
  } catch { return null; }
}

// ── Auth Code ─────────────────────────────────────────────────────────────────
function startAuthCode() {
  clearT('ac-trace');
  document.getElementById('ac-tokens').style.display = 'none';
  document.getElementById('ac-pkce').style.display = 'none';
  var mode = document.getElementById('ac-mode').value;
  var scopes = document.getElementById('ac-scopes').value;
  addT('ac-trace', '⏳ Generating PKCE pair and state token...');
  fetch('/proxy/oauth/start?mode=' + mode + '&scopes=' + encodeURIComponent(scopes))
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (d.error) { addT('ac-trace', '❌ Error: ' + d.error, 'err'); return; }
      if (mode === 'secure' && d.pkce_verifier) {
        document.getElementById('ac-pkce').style.display = 'block';
        document.getElementById('ac-v').textContent = d.pkce_verifier.slice(0,44) + '...';
        document.getElementById('ac-c').textContent = d.pkce_challenge;
        addT('ac-trace', '🔒 PKCE generated — code_challenge sent to auth server', 'ok');
        addT('ac-trace', '🔒 state = ' + d.state.slice(0,20) + '... (CSRF protection active)', 'ok');
      } else {
        addT('ac-trace', '⚠️ Vulnerable mode — no PKCE, no state parameter', 'warn');
      }
      addT('ac-trace', '➡️ Redirecting to Authorization Server...');
      setTimeout(function(){ window.location.href = d.redirect; }, 900);
    })
    .catch(function(e){ addT('ac-trace', '❌ ' + e.message, 'err'); });
}
function goAPI()     { document.getElementById('api-tok').value = document.getElementById('ac-at').textContent; nav('apitester'); }
function goInspect() { document.getElementById('insp-tok').value = document.getElementById('ac-at').textContent; nav('inspector'); }
function doLogout() {
  var at = document.getElementById('ac-at').textContent, rt = document.getElementById('ac-rt').textContent;
  var ps = [];
  if (at) ps.push(fetch('/proxy/revoke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:at,hint:'access_token'})}));
  if (rt) ps.push(fetch('/proxy/revoke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:rt,hint:'refresh_token'})}));
  Promise.all(ps).then(function(){ document.getElementById('ac-tokens').style.display='none'; TOKENS={}; addT('ac-trace','✅ Tokens revoked — logged out','ok'); });
}

// ── Client Credentials ────────────────────────────────────────────────────────
function doCC() {
  clearT('cc-trace'); addT('cc-trace','⏳ Requesting M2M token...');
  fetch('/proxy/client-credentials',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scope:document.getElementById('cc-scope').value})})
    .then(function(r){ return r.json(); })
    .then(function(d){
      showOut('cc-out', d);
      if (d.access_token) {
        addT('cc-trace','✅ M2M token issued — no user involved','ok');
        addT('cc-trace','🔑 Scope: '+d.scope,'ok');
        var dec = decodeJWT(d.access_token);
        if (dec) addT('cc-trace','📦 sub = '+dec.payload.sub+' (client identity, not a user)','ok');
      } else addT('cc-trace','❌ '+(d.error_description||d.error),'err');
    }).catch(function(e){ addT('cc-trace','❌ '+e.message,'err'); });
}

// ── Device Flow ───────────────────────────────────────────────────────────────
function startDevice() {
  clearT('dev-trace'); document.getElementById('dev-box').style.display = 'none';
  addT('dev-trace','⏳ Requesting device code...');
  fetch('/proxy/device-start',{method:'POST'})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (d.error) { addT('dev-trace','❌ '+d.error,'err'); return; }
      DEV_CODE = d.device_code;
      document.getElementById('dev-code').textContent = d.user_code;
      var link = document.getElementById('dev-link');
      link.href = d.verification_uri; link.textContent = d.verification_uri;
      document.getElementById('dev-box').style.display = 'block';
      addT('dev-trace','✅ Device code issued. User code: '+d.user_code,'ok');
      addT('dev-trace','→ Open the link above and enter the code, then click Poll','warn');
    }).catch(function(e){ addT('dev-trace','❌ '+e.message,'err'); });
}
function pollDevice() {
  if (!DEV_CODE) { addT('dev-trace','❌ Start device flow first','err'); return; }
  addT('dev-trace','⏳ Polling token endpoint...');
  fetch('/proxy/device-poll',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_code:DEV_CODE})})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (d.error==='authorization_pending') { addT('dev-trace',"⏳ Still pending — user hasn't approved yet",'warn'); return; }
      if (d.error==='access_denied')   { addT('dev-trace','❌ User denied','err'); return; }
      if (d.error==='expired_token')   { addT('dev-trace','❌ Code expired','err'); return; }
      if (d.access_token) { showOut('dev-out',d); addT('dev-trace','✅ Token issued! Device authenticated.','ok'); DEV_CODE=null; }
      else addT('dev-trace','❌ '+(d.error_description||d.error||'Unknown error'),'err');
    }).catch(function(e){ addT('dev-trace','❌ '+e.message,'err'); });
}

// ── Refresh Tokens ────────────────────────────────────────────────────────────
function doRefresh(rotate) {
  var inputId = rotate ? 'rt-sec' : 'rt-vuln', outId = rotate ? 'rt-sec-out' : 'rt-vuln-out';
  var rt = document.getElementById(inputId).value.trim();
  if (!rt) { alert('Paste a refresh_token first.\\nRun Auth Code flow first to get one.'); return; }
  fetch('/proxy/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({refresh_token:rt,rotate:rotate})})
    .then(function(r){ return r.json(); })
    .then(function(d){
      var el = document.getElementById(outId); el.classList.add('on');
      var note = '';
      if (d.rotated===true)  note = '\\n\\n✅ NEW refresh_token issued — old one invalidated';
      if (d.rotated===false) note = '\\n\\n⚠️  SAME token returned — stolen token still works!';
      el.textContent = JSON.stringify(d,null,2)+note;
    }).catch(function(e){ var el=document.getElementById(outId);el.classList.add('on');el.textContent='❌ '+e.message; });
}
function doRevoke() {
  var tok = document.getElementById('rv-tok').value.trim(), hint = document.getElementById('rv-hint').value;
  if (!tok) { alert('Paste a token first.'); return; }
  fetch('/proxy/revoke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:tok,hint:hint})})
    .then(function(r){ return r.json(); }).then(function(d){ showOut('rv-out',d); }).catch(function(e){ showOut('rv-out',{error:e.message}); });
}

// ── CSRF ──────────────────────────────────────────────────────────────────────
function csrfTest(mode) {
  clearT('csrf-trace');
  addT('csrf-trace', '⏳ Starting '+(mode==='secure'?'SECURE':'VULNERABLE')+' flow...', mode==='secure'?'ok':'warn');
  fetch('/proxy/oauth/start?mode='+mode+'&scopes=openid')
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (mode==='secure') {
        addT('csrf-trace','🔒 state = '+d.state.slice(0,20)+'... (stored in server session)','ok');
        addT('csrf-trace','✅ Callback will verify state → CSRF blocked','ok');
      } else {
        addT('csrf-trace','⚠️ No state — attacker can inject their auth code','warn');
      }
      setTimeout(function(){ window.location.href = d.redirect; }, 800);
    });
}

// ── Open Redirect ─────────────────────────────────────────────────────────────
function testRedirects() {
  clearT('redir-trace'); addT('redir-trace','⏳ Testing redirect_uri bypass attempts...');
  var HOST_ORIGIN = window.location.origin;
  var attacks = [
    [HOST_ORIGIN+'/callback.evil.com','Suffix append'],
    [HOST_ORIGIN+'/callback/../admin','Path traversal'],
    ['http://evil.com?r='+HOST_ORIGIN+'/callback','Parameter injection'],
    [HOST_ORIGIN+'/callback%2fevil','URL encoding'],
  ];
  var done = 0;
  attacks.forEach(function(a) {
    fetch('/proxy/test-redirect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({redirect_uri:a[0]})})
      .then(function(r){ return r.json(); })
      .then(function(d){
        var blocked = d.status===400;
        addT('redir-trace',(blocked?'✅ BLOCKED (400)':'🚨 PASSED ('+d.status+')')+' — '+a[1]+': <code style="font-family:monospace;font-size:11px">'+a[0]+'</code>', blocked?'ok':'err');
        done++; if(done===attacks.length) addT('redir-trace','✅ All bypass attempts blocked by exact URI matching','ok');
      }).catch(function(e){ addT('redir-trace','❌ '+e.message,'err'); done++; });
  });
}

// ── Phishing ──────────────────────────────────────────────────────────────────
function startPhishing() {
  clearT('phish-trace'); addT('phish-trace','⏳ Starting phishing simulation...');
  fetch('/proxy/oauth/start?mode=vulnerable&scopes='+encodeURIComponent('openid profile email read:posts write:posts admin')+'&app=malicious')
    .then(function(r){ return r.json(); })
    .then(function(d){
      addT('phish-trace','🎣 Malicious consent page opening in new tab...','warn');
      addT('phish-trace','⚠️ Notice: URL is real port 3001 — bypasses phishing URL detection!','warn');
      window.open(d.redirect,'_blank');
    });
}

// ── Inspector ─────────────────────────────────────────────────────────────────
function decodeToken() {
  var tok = document.getElementById('insp-tok').value.trim();
  if (!tok) { alert('Paste a JWT first.'); return; }
  var dec = decodeJWT(tok);
  if (!dec) { showOut('insp-out',{error:'Invalid JWT format'}); return; }
  showOut('insp-out',{header:dec.header,payload:dec.payload,note:'Signature NOT verified client-side — use Introspect for server validation'});
}
function introspectToken() {
  var tok = document.getElementById('insp-tok').value.trim();
  if (!tok) { alert('Paste a JWT first.'); return; }
  fetch('/proxy/introspect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:tok})})
    .then(function(r){ return r.json(); }).then(function(d){ showOut('insp-intro',d); }).catch(function(e){ showOut('insp-intro',{error:e.message}); });
}

// ── API Tester ────────────────────────────────────────────────────────────────
function callAPI() {
  var ep=document.getElementById('api-ep').value, method=document.getElementById('api-method').value, tok=document.getElementById('api-tok').value.trim();
  fetch('/proxy/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({endpoint:ep,method:method,token:tok||undefined})})
    .then(function(r){ return r.json(); }).then(function(d){ showOut('api-out',d); }).catch(function(e){ showOut('api-out',{error:e.message}); });
}

// ── Discovery ─────────────────────────────────────────────────────────────────
function loadDiscovery() {
  fetch('/proxy/discovery').then(function(r){ return r.json(); }).then(function(d){ showOut('disc-out',d); }).catch(function(e){ showOut('disc-out',{error:e.message}); });
}
</script>
</body></html>`;
}

// ── Start all three servers ───────────────────────────────────────────────────
initClients();
AUTH.listen(3001,   () => console.log(`🔐 Auth Server  → ${AUTH_URL}`));
API.listen(3002,    () => console.log(`🛡️  Resource API → ${API_URL}`));
CLIENT.listen(3000, () => console.log(`🌐 Client App   → ${CLIENT_URL}`));
console.log(`\n✅ All servers up. Open: ${CLIENT_URL}\n`);
console.log(`\n << OAuth 2.0 Security Lab | github.com/EmadYaY >>);