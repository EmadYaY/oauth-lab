/**
 * OAuth 2.0 / OIDC Authorization Server — Port 3001
 * https://github.com/EmadYaY
 */
const express = require('express');
const crypto  = require('crypto');
const app     = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ── In-memory store ──────────────────────────────────────────────────────────
const USERS = {
  alice: { id: 'user-001', name: 'Alice Smith',  email: 'alice@example.com', password: 'password123', roles: ['user'] },
  bob:   { id: 'user-002', name: 'Bob Jones',    email: 'bob@example.com',   password: 'password123', roles: ['user','admin'] },
};

const CLIENTS = {
  'demo-client': {
    id: 'demo-client', secret: 'demo-secret', name: 'OAuth Lab Client',
    redirectUris: ['http://localhost:3000/callback'],
    scopes: ['openid','profile','email','read:posts','write:posts','admin'],
    type: 'public'
  },
  'service-client': {
    id: 'service-client', secret: 'service-secret', name: 'Backend Service',
    redirectUris: [],
    scopes: ['api:read','api:write'],
    type: 'confidential'
  },
  'malicious-app': {
    id: 'malicious-app', secret: null, name: 'Microsoft Teams Update Tool ⚠️',
    redirectUris: ['http://localhost:3000/malicious-callback'],
    scopes: ['openid','profile','email','read:posts','write:posts','admin'],
    type: 'public', isMalicious: true
  }
};

const authCodes    = new Map();
const refreshTokens = new Map();
const deviceCodes  = new Map();
const userCodes    = new Map();
const revokedTokens = new Set();

// ── JWT helpers ──────────────────────────────────────────────────────────────
const JWT_SECRET = 'lab-secret-key-change-in-production-use-RS256';

function b64url(s) {
  return Buffer.from(s).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
}
function signJWT(payload) {
  const h   = b64url(JSON.stringify({ alg:'HS256', typ:'JWT', kid:'lab-key-001' }));
  const p   = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest('base64')
                .replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  return `${h}.${p}.${sig}`;
}
function verifyJWT(token) {
  try {
    const [h, p, s] = token.split('.');
    const exp = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest('base64')
                  .replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
    if (s !== exp) return null;
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (payload.exp < Math.floor(Date.now()/1000)) return null;
    if (revokedTokens.has(token)) return null;
    return payload;
  } catch { return null; }
}
function makeAccessToken(clientId, userId, scope, ttl=3600) {
  const now  = Math.floor(Date.now()/1000);
  const user = userId ? Object.values(USERS).find(u => u.id === userId) : null;
  return signJWT({
    iss: 'http://localhost:3001',
    sub: userId || clientId,
    aud: 'http://localhost:3002',
    azp: clientId,
    exp: now + ttl, iat: now,
    jti: crypto.randomUUID(),
    scope: Array.isArray(scope) ? scope.join(' ') : scope,
    ...(user ? { name: user.name, email: user.email, roles: user.roles } : {})
  });
}
function makeIdToken(clientId, userId, nonce) {
  const user = Object.values(USERS).find(u => u.id === userId);
  const now  = Math.floor(Date.now()/1000);
  return signJWT({
    iss: 'http://localhost:3001', sub: userId, aud: clientId,
    exp: now+3600, iat: now,
    ...(nonce ? { nonce } : {}),
    name: user.name, email: user.email, email_verified: true
  });
}

// ── OIDC Discovery ───────────────────────────────────────────────────────────
app.get('/.well-known/openid-configuration', (req, res) => res.json({
  issuer: 'http://localhost:3001',
  authorization_endpoint:       'http://localhost:3001/oauth/authorize',
  token_endpoint:                'http://localhost:3001/oauth/token',
  userinfo_endpoint:             'http://localhost:3001/oauth/userinfo',
  revocation_endpoint:           'http://localhost:3001/oauth/revoke',
  introspection_endpoint:        'http://localhost:3001/oauth/introspect',
  device_authorization_endpoint: 'http://localhost:3001/oauth/device',
  jwks_uri:                      'http://localhost:3001/.well-known/jwks.json',
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code','client_credentials','refresh_token','urn:ietf:params:oauth:grant-type:device_code'],
  scopes_supported: ['openid','profile','email','read:posts','write:posts','admin'],
  code_challenge_methods_supported: ['S256'],
}));

// ── Authorization endpoint ───────────────────────────────────────────────────
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, nonce, mode } = req.query;
  const client   = CLIENTS[client_id];
  const isSecure = mode !== 'vulnerable';

  if (!client)
    return res.status(400).json({ error:'invalid_client', error_description:'Unknown client_id' });

  if (isSecure && !code_challenge)
    return res.status(400).json({ error:'invalid_request', error_description:'code_challenge required (PKCE mandatory)' });

  // redirect_uri validation
  if (isSecure) {
    if (!client.redirectUris.includes(redirect_uri))
      return res.status(400).json({ error:'invalid_request', error_description:`redirect_uri not registered. Got: ${redirect_uri}` });
  } else {
    const ok = client.redirectUris.some(u => redirect_uri && redirect_uri.startsWith(u.split('/callback')[0]));
    if (!ok) return res.status(400).json({ error:'invalid_request', error_description:'redirect_uri mismatch' });
  }

  const allowedScopes = (scope||'').split(' ').filter(s => client.scopes.includes(s));
  const payload = JSON.stringify({
    client_id, redirect_uri, scope: allowedScopes.join(' '), state,
    code_challenge, code_challenge_method, nonce, mode,
    is_malicious: !!client.isMalicious
  });
  const enc = Buffer.from(payload).toString('base64url');

  const scopeLabels = {
    openid:      ['🔑','OpenID','Verify your identity',false],
    profile:     ['👤','Profile','Read your name & picture',false],
    email:       ['📧','Email','Read your email address',false],
    'read:posts':['📖','Read Posts','View your posts',false],
    'write:posts':['✏️','Write Posts','Create & edit posts on your behalf',false],
    admin:       ['👑','Admin Access','FULL admin access to all data',true],
  };

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorization — OAuth Lab</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:36px;width:100%;max-width:420px;box-shadow:0 25px 50px rgba(0,0,0,.5)}
.badge{display:inline-block;background:#0ea5e9;color:#fff;font-size:11px;font-weight:700;letter-spacing:.06em;padding:3px 10px;border-radius:99px;margin-bottom:20px}
h2{color:#f1f5f9;font-size:18px;margin-bottom:6px}
.app{color:#38bdf8;font-size:17px;font-weight:700;margin-bottom:4px}
.sub{color:#94a3b8;font-size:13px;margin-bottom:20px}
.warn{background:#450a0a;border:1px solid #ef4444;border-radius:8px;padding:12px;color:#fca5a5;font-size:13px;margin-bottom:16px}
.warn strong{display:block;margin-bottom:4px}
.info{background:#0c1a2e;border:1px solid #1e40af;border-radius:8px;padding:8px 12px;color:#93c5fd;font-size:12px;margin-bottom:16px}
.hint{background:#0c2316;border:1px solid #166534;border-radius:8px;padding:8px 12px;color:#86efac;font-size:12px;margin-bottom:16px}
.scopes{margin-bottom:20px}
.slabel{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:#475569;margin-bottom:10px}
.scope{display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid #1e293b}
.scope:last-child{border:none}
.si{font-size:16px;flex-shrink:0;margin-top:1px}
.sn{color:#f1f5f9;font-size:13px;font-weight:500}
.sd{color:#64748b;font-size:12px}
.danger{background:#7f1d1d;color:#fca5a5;font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;margin-left:6px}
label{display:block;color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin-bottom:5px;margin-top:14px}
input{width:100%;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:9px 12px;color:#f1f5f9;font-size:14px;outline:none}
input:focus{border-color:#0ea5e9}
.btns{display:flex;gap:10px;margin-top:20px}
.btn{flex:1;padding:11px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer}
.allow{background:#0ea5e9;color:#fff}.allow:hover{background:#0284c7}
.deny{background:#334155;color:#94a3b8}.deny:hover{background:#475569}
#msg{margin-top:12px;font-size:13px;color:#f59e0b;text-align:center;min-height:20px}
</style>
</head>
<body>
<div class="card">
  <div class="badge">🔐 Authorization Server — Port 3001</div>
  <h2>Authorization Request</h2>
  <div class="app">${client.isMalicious ? '⚠️ ' : ''}${client.name}</div>
  <div class="sub">${client.isMalicious ? 'This app is requesting excessive permissions!' : 'Client ID: '+client_id}</div>
  ${client.isMalicious ? `<div class="warn"><strong>🚨 CONSENT PHISHING SIMULATION</strong>This malicious app mimics a legitimate tool to steal your tokens via the real OAuth consent page.</div>` : ''}
  ${isSecure ? `<div class="hint">✅ Secure mode — PKCE + exact redirect_uri validation + state CSRF check</div>` : `<div class="warn"><strong>⚠️ Vulnerable mode</strong>CSRF state not enforced, loose redirect_uri validation</div>`}
  <div class="hint">👤 Accounts: <strong>alice</strong> or <strong>bob</strong> — password: <strong>password123</strong></div>
  <label>Username</label>
  <input id="u" value="alice" placeholder="alice or bob">
  <label>Password</label>
  <input id="p" type="password" value="password123">
  <div class="scopes">
    <div class="slabel" style="margin-top:16px">Requested Permissions</div>
    ${allowedScopes.map(s => {
      const [icon,name,desc,danger] = scopeLabels[s] || ['❓',s,'',false];
      return `<div class="scope"><div class="si">${icon}</div><div><div class="sn">${name}${danger?'<span class="danger">HIGH RISK</span>':''}</div><div class="sd">${desc}</div></div></div>`;
    }).join('')}
  </div>
  <div class="btns">
    <button class="btn deny" onclick="deny()">Deny</button>
    <button class="btn allow" onclick="allow()">Allow Access</button>
  </div>
  <div id="msg"></div>
</div>
<script>
const D = JSON.parse(atob('${enc}'));
function deny(){window.location.href=D.redirect_uri+'?error=access_denied&state='+(D.state||'');}
async function allow(){
  document.getElementById('msg').textContent='Authenticating…';
  const r=await fetch('/oauth/consent',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({...D,username:document.getElementById('u').value,password:document.getElementById('p').value})});
  const d=await r.json();
  if(d.redirect){document.getElementById('msg').textContent='✅ Redirecting…';window.location.href=d.redirect;}
  else{document.getElementById('msg').textContent='❌ '+(d.error_description||d.error||'Login failed');}
}
</script>
</body></html>`);
});

// ── Consent POST ─────────────────────────────────────────────────────────────
app.post('/oauth/consent', (req, res) => {
  const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, nonce, username, password, mode } = req.body;
  const user = USERS[username];
  if (!user || user.password !== password)
    return res.json({ error:'access_denied', error_description:'Invalid credentials' });

  const code   = crypto.randomBytes(16).toString('hex');
  const scopes = (scope||'').split(' ').filter(Boolean);
  authCodes.set(code, {
    clientId: client_id, userId: user.id, redirectUri: redirect_uri,
    scope: scopes, pkce: { challenge: code_challenge, method: code_challenge_method },
    nonce, exp: Date.now()+60000, used: false, mode
  });
  setTimeout(() => authCodes.delete(code), 60000);

  let url = `${redirect_uri}?code=${code}`;
  if (state) url += `&state=${encodeURIComponent(state)}`;
  res.json({ redirect: url });
});

// ── Token endpoint ───────────────────────────────────────────────────────────
app.post('/oauth/token', (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret,
          code_verifier, refresh_token, scope, device_code } = req.body;

  // Client Credentials
  if (grant_type === 'client_credentials') {
    const client = CLIENTS[client_id];
    if (!client || client.secret !== client_secret)
      return res.status(401).json({ error:'invalid_client' });
    const scopes = (scope||'').split(' ').filter(s => client.scopes.includes(s));
    return res.json({ access_token: makeAccessToken(client_id, null, scopes), token_type:'Bearer', expires_in:3600, scope:scopes.join(' ') });
  }

  // Authorization Code
  if (grant_type === 'authorization_code') {
    const cd = authCodes.get(code);
    if (!cd)           return res.status(400).json({ error:'invalid_grant', error_description:'Unknown or expired code' });
    if (cd.used)       return res.status(400).json({ error:'invalid_grant', error_description:'Code already used' });
    if (cd.exp < Date.now()) { authCodes.delete(code); return res.status(400).json({ error:'invalid_grant', error_description:'Code expired' }); }
    if (cd.clientId !== client_id)       return res.status(400).json({ error:'invalid_grant', error_description:'client_id mismatch' });
    if (cd.redirectUri !== redirect_uri) return res.status(400).json({ error:'invalid_grant', error_description:'redirect_uri mismatch' });

    if (cd.pkce && cd.pkce.challenge) {
      if (!code_verifier) return res.status(400).json({ error:'invalid_grant', error_description:'code_verifier required' });
      const computed = crypto.createHash('sha256').update(code_verifier).digest('base64url');
      if (computed !== cd.pkce.challenge) return res.status(400).json({ error:'invalid_grant', error_description:'PKCE verification failed' });
    }

    cd.used = true;
    const at = makeAccessToken(client_id, cd.userId, cd.scope);
    const rt = crypto.randomBytes(32).toString('hex');
    refreshTokens.set(rt, { clientId: client_id, userId: cd.userId, scope: cd.scope, exp: Date.now()+86400000*30 });

    const resp = { access_token:at, token_type:'Bearer', expires_in:3600, refresh_token:rt, scope:cd.scope.join(' ') };
    if (cd.scope.includes('openid')) resp.id_token = makeIdToken(client_id, cd.userId, cd.nonce);
    return res.json(resp);
  }

  // Refresh Token
  if (grant_type === 'refresh_token') {
    const rtd = refreshTokens.get(refresh_token);
    if (!rtd) return res.status(400).json({ error:'invalid_grant', error_description:'Invalid refresh token' });
    if (rtd.exp < Date.now()) { refreshTokens.delete(refresh_token); return res.status(400).json({ error:'invalid_grant', error_description:'Refresh token expired' }); }

    const rotate = req.query.rotate !== 'false';
    const newAt  = makeAccessToken(rtd.clientId, rtd.userId, rtd.scope);

    if (rotate) {
      refreshTokens.delete(refresh_token);
      const newRt = crypto.randomBytes(32).toString('hex');
      refreshTokens.set(newRt, { ...rtd, exp: Date.now()+86400000*30 });
      return res.json({ access_token:newAt, token_type:'Bearer', expires_in:3600, refresh_token:newRt, scope:rtd.scope.join(' '), rotated:true });
    }
    return res.json({ access_token:newAt, token_type:'Bearer', expires_in:3600, refresh_token:refresh_token, scope:rtd.scope.join(' '), rotated:false });
  }

  // Device Code
  if (grant_type === 'urn:ietf:params:oauth:grant-type:device_code') {
    const dc = deviceCodes.get(device_code);
    if (!dc)                    return res.status(400).json({ error:'invalid_grant' });
    if (dc.exp < Date.now())    { deviceCodes.delete(device_code); return res.status(400).json({ error:'expired_token' }); }
    if (dc.status === 'pending') return res.status(400).json({ error:'authorization_pending' });
    if (dc.status === 'denied')  return res.status(400).json({ error:'access_denied' });
    if (dc.status === 'approved') {
      deviceCodes.delete(device_code);
      return res.json({ access_token: makeAccessToken(client_id, dc.userId, dc.scope.split(' ')), token_type:'Bearer', expires_in:3600, scope:dc.scope });
    }
  }

  res.status(400).json({ error:'unsupported_grant_type' });
});

// ── Device Authorization ─────────────────────────────────────────────────────
app.post('/oauth/device', (req, res) => {
  const { client_id, scope } = req.body;
  const deviceCode = crypto.randomBytes(16).toString('hex');
  const userCode   = crypto.randomBytes(3).toString('hex').toUpperCase().match(/.{1,4}/g).join('-');
  deviceCodes.set(deviceCode, { clientId:client_id, scope:scope||'openid profile', userCode, exp:Date.now()+300000, status:'pending' });
  userCodes.set(userCode, deviceCode);
  setTimeout(() => { deviceCodes.delete(deviceCode); userCodes.delete(userCode); }, 300000);
  res.json({ device_code:deviceCode, user_code:userCode, verification_uri:'http://localhost:3001/device', verification_uri_complete:`http://localhost:3001/device?user_code=${userCode}`, expires_in:300, interval:5 });
});

app.get('/device', (req, res) => {
  const uc = req.query.user_code || '';
  res.send(`<!DOCTYPE html><html><head><title>Device Auth</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:sans-serif;background:#0f172a;color:#f1f5f9;display:flex;align-items:center;justify-content:center;min-height:100vh}
.c{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:36px;width:360px;text-align:center}
h2{color:#38bdf8;margin-bottom:8px}p{color:#94a3b8;font-size:13px;margin-bottom:16px}
input,select{width:100%;padding:10px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#f1f5f9;font-size:14px;margin:6px 0;letter-spacing:2px;text-align:center;outline:none}
select{letter-spacing:0;text-align:left}
button{width:100%;padding:11px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;margin-top:8px}
.a{background:#0ea5e9;color:#fff}.d{background:#334155;color:#94a3b8}
#m{margin-top:14px;font-size:13px;min-height:20px}</style></head>
<body><div class="c">
<h2>Device Authorization</h2><p>Enter the code shown on your device</p>
<input id="uc" placeholder="XXXX-YYYY" value="${uc}" maxlength="9">
<select id="usr"><option>alice</option><option>bob</option></select>
<button class="a" onclick="go('approve')">✅ Approve</button>
<button class="d" onclick="go('deny')">✗ Deny</button>
<div id="m"></div></div>
<script>
async function go(action){
  const r=await fetch('/device/approve',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({user_code:document.getElementById('uc').value.toUpperCase(),username:document.getElementById('usr').value,action})});
  const d=await r.json();
  document.getElementById('m').innerHTML=d.success?'<span style="color:#10b981">✅ Done! Return to your device.</span>':'<span style="color:#ef4444">❌ '+d.error+'</span>';
}
</script></body></html>`);
});

app.post('/device/approve', (req, res) => {
  const { user_code, username, action } = req.body;
  const dc = userCodes.get(user_code);
  if (!dc) return res.json({ success:false, error:'Invalid or expired code' });
  const d = deviceCodes.get(dc);
  if (!d)  return res.json({ success:false, error:'Device code not found' });
  if (action === 'approve') {
    const user = USERS[username];
    if (!user) return res.json({ success:false, error:'User not found' });
    d.status = 'approved'; d.userId = user.id;
  } else { d.status = 'denied'; }
  res.json({ success:true });
});

// ── Introspection ────────────────────────────────────────────────────────────
app.post('/oauth/introspect', (req, res) => {
  const p = verifyJWT(req.body.token);
  if (!p) return res.json({ active:false });
  res.json({ active:true, ...p, token_type:'Bearer' });
});

// ── Revocation ───────────────────────────────────────────────────────────────
app.post('/oauth/revoke', (req, res) => {
  const { token, token_type_hint } = req.body;
  if (token_type_hint === 'refresh_token') refreshTokens.delete(token);
  else revokedTokens.add(token);
  res.status(200).json({ revoked:true });
});

// ── UserInfo ─────────────────────────────────────────────────────────────────
app.get('/oauth/userinfo', (req, res) => {
  const token = (req.headers.authorization||'').replace('Bearer ','');
  const p = verifyJWT(token);
  if (!p) return res.status(401).json({ error:'invalid_token' });
  const user = Object.values(USERS).find(u => u.id === p.sub);
  if (!user) return res.status(404).json({ error:'user_not_found' });
  res.json({ sub:user.id, name:user.name, email:user.email, email_verified:true, roles:user.roles });
});

module.exports = { verifyJWT, JWT_SECRET };
app.listen(3001, () => console.log('🔐 Authorization Server running on http://localhost:3001'));
