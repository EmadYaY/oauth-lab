/**
 * OAuth 2.0 Resource Server / Protected API — Port 3002
 * Uses only Node.js built-in modules (no node-fetch)
 * https://github.com/EmadYaY
 */
const express = require('express');
const crypto  = require('crypto');
const http    = require('http');
const app     = express();

app.use(express.json());
app.use(express.urlencoded({ extended:true }));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const JWT_SECRET = 'lab-secret-key-change-in-production-use-RS256';
const revokedCache = new Map(); // jti → revoked bool, short-lived

const posts = [
  { id:'post-1', userId:'user-001', title:'Hello World', body:'This is my first post!', createdAt:'2025-01-01' },
  { id:'post-2', userId:'user-001', title:'OAuth is Cool', body:'Learning about OAuth 2.0.', createdAt:'2025-01-05' },
  { id:'post-3', userId:'user-002', title:'Admin Notes', body:'SECRET: Server maintenance Q1.', createdAt:'2025-01-10' },
];

// ── JWT verify ────────────────────────────────────────────────────────────────
function verifyJWT(token) {
  try {
    const [h, p, s] = token.split('.');
    const exp = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest('base64')
                  .replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
    if (s !== exp) return null;
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (payload.exp < Math.floor(Date.now()/1000)) return null;
    return payload;
  } catch { return null; }
}

// ── Introspect via auth-server (built-in http, no node-fetch) ────────────────
function introspect(token) {
  return new Promise((resolve) => {
    const body = `token=${encodeURIComponent(token)}&client_id=api-server`;
    const opts = {
      hostname:'localhost', port:3001, path:'/oauth/introspect', method:'POST',
      headers:{ 'Content-Type':'application/x-www-form-urlencoded', 'Content-Length':Buffer.byteLength(body) }
    };
    const req = http.request(opts, r => {
      let d = '';
      r.on('data', c => d += c);
      r.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve({ active:false }); } });
    });
    req.on('error', () => resolve({ active:false }));
    req.write(body); req.end();
  });
}

// ── Auth middleware ──────────────────────────────────────────────────────────
function requireAuth(scope) {
  return async (req, res, next) => {
    const hdr = req.headers.authorization || '';
    if (!hdr.startsWith('Bearer '))
      return res.status(401).json({ error:'unauthorized', error_description:'No Bearer token provided', hint:'Add: Authorization: Bearer <access_token>' });

    const token   = hdr.slice(7);
    const payload = verifyJWT(token);
    if (!payload)
      return res.status(401).json({ error:'invalid_token', error_description:'Token invalid or expired' });

    if (payload.iss !== 'http://localhost:3001')
      return res.status(401).json({ error:'invalid_token', error_description:'Invalid issuer' });
    if (payload.aud !== 'http://localhost:3002')
      return res.status(401).json({ error:'invalid_token', error_description:'Token not for this audience' });

    // Revocation check via introspection
    const jti = payload.jti || token.slice(-16);
    const cached = revokedCache.get(jti);
    if (cached === undefined) {
      const info = await introspect(token);
      if (!info.active) {
        revokedCache.set(jti, true);
        return res.status(401).json({ error:'invalid_token', error_description:'Token revoked or inactive' });
      }
      revokedCache.set(jti, false);
      setTimeout(() => revokedCache.delete(jti), 30000);
    } else if (cached === true) {
      return res.status(401).json({ error:'invalid_token', error_description:'Token revoked' });
    }

    if (scope) {
      const granted = (payload.scope||'').split(' ');
      if (!granted.includes(scope))
        return res.status(403).json({ error:'insufficient_scope', error_description:`Required: ${scope}. Granted: ${payload.scope}`, required:scope, granted });
    }
    req.user = payload;
    next();
  };
}

// ── Endpoints ────────────────────────────────────────────────────────────────
app.get('/api/status', (req, res) => res.json({
  status:'ok', server:'Resource API Server', port:3002,
  message:'Public endpoint — no token required',
  protected: ['/api/profile','/api/posts','/api/admin'],
  timestamp: new Date().toISOString()
}));

app.get('/api/profile', requireAuth(), (req, res) => res.json({
  message:'✅ Authenticated!',
  user: { id:req.user.sub, name:req.user.name, email:req.user.email, roles:req.user.roles },
  token_info: { issuer:req.user.iss, client:req.user.azp, scopes:req.user.scope,
    issued_at: new Date(req.user.iat*1000).toISOString(),
    expires_at: new Date(req.user.exp*1000).toISOString() }
}));

app.get('/api/posts', requireAuth('read:posts'), (req, res) => {
  const mine = posts.filter(p => p.userId === req.user.sub);
  res.json({ message:'✅ Posts retrieved (read:posts verified)', posts:mine, total:mine.length });
});

app.post('/api/posts', requireAuth('write:posts'), (req, res) => {
  const { title, body } = req.body;
  if (!title) return res.status(400).json({ error:'title_required' });
  const post = { id:`post-${crypto.randomUUID().slice(0,8)}`, userId:req.user.sub, title, body:body||'', createdAt:new Date().toISOString() };
  posts.push(post);
  res.status(201).json({ message:'✅ Post created (write:posts verified)', post });
});

app.get('/api/admin', requireAuth('admin'), (req, res) => res.json({
  message:'✅ Admin access granted',
  warning:'Elevated admin privileges — high-risk scope',
  all_posts: posts,
  system: { uptime: process.uptime() }
}));

app.get('/api/debug-token', (req, res) => {
  const token = (req.headers.authorization||'').slice(7);
  if (!token) return res.json({ error:'No token' });
  try {
    const [h,p] = token.split('.');
    const header  = JSON.parse(Buffer.from(h,'base64url').toString());
    const payload = JSON.parse(Buffer.from(p,'base64url').toString());
    res.json({ header, payload, valid: !!verifyJWT(token), expires_at: payload.exp ? new Date(payload.exp*1000).toISOString() : 'N/A' });
  } catch { res.json({ error:'Cannot decode token' }); }
});

app.listen(3002, () => console.log('🛡️  Resource API Server running on http://localhost:3002'));
