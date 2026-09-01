// Demo/mock server for GUI verification of the <picketlink-admin> element:
// serves the built element plus a fixture admin API on one origin, so the element's
// default relative api-base ("../api/auth/admin") resolves with zero configuration.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';

const DIST = new URL('./dist/picketlink-admin/browser', import.meta.url).pathname;

const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };

const clients = [
  {
    clientId: 'billing-service',
    clientSecret: '********',
    scopes: ['read', 'write'],
    tokenEndpointAuthMethod: 'private_key_jwt',
    allowedAudiences: ['https://api.corp.example'],
    hasJwks: true,
    maxTokenLifetimeSeconds: 300,
  },
  {
    clientId: 'auth-admin',
    clientSecret: '********',
    scopes: ['auth-admin'],
    tokenEndpointAuthMethod: 'client_secret_basic',
    allowedAudiences: [],
    hasJwks: false,
    maxTokenLifetimeSeconds: 0,
  },
];

const policy = {
  defaultAlgorithm: 'RS256',
  defaultLifetimeSeconds: 300,
  maxLifetimeSeconds: 600,
  allowedAlgorithms: ['RS256', 'ES256'],
};

const keys = {
  keystorePath: '/etc/picketlink/keys.p12',
  activeKid: 'pl-signing-11a2',
  keys: [
    { keyId: 'pl-signing-0f31', algorithm: 'RS256', keystoreAlias: 'pl-signing-0f31', active: false, createdAt: 1756000000 },
    { keyId: 'pl-signing-11a2', algorithm: 'RS256', keystoreAlias: 'pl-signing-11a2', active: true, createdAt: 1756600000 },
  ],
};

const tokens = [
  { tokenHash: 'b64urlhash1', clientId: 'billing-service', scopes: 'read', issuedAt: '2026-09-01T07:00:00Z', expiresAt: '2026-09-01T07:05:00Z' },
];

const server = createServer(async (req, res) => {
  const auth = req.headers.authorization || '';
  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname;
  const send = (status, body, type = 'application/json') => {
    res.writeHead(status, { 'Content-Type': type });
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  };

  if (path.startsWith('/api/auth/admin/')) {
    if (!auth.startsWith('Bearer demo-admin-token')) {
      return send(401, { error: 'insufficient scope' });
    }
    if (path === '/api/auth/admin/clients' && req.method === 'GET') return send(200, clients);
    if (path === '/api/auth/admin/policies' && req.method === 'GET') return send(200, policy);
    if (path === '/api/auth/admin/keys' && req.method === 'GET') return send(200, keys);
    if (path === '/api/auth/admin/tokens' && req.method === 'GET') return send(200, tokens);
    return send(404, { error: 'not found' });
  }
  if (path === '/oauth/token' && req.method === 'POST') {
    return send(200, { access_token: 'demo-admin-token', token_type: 'Bearer', expires_in: 300, scope: 'auth-admin' });
  }

  const file = path === '/' ? '/index.html' : path;
  try {
    const body = await readFile(join(DIST, file));
    res.writeHead(200, { 'Content-Type': types[extname(file)] ?? 'application/octet-stream' });
    res.end(body);
  } catch {
    res.writeHead(404); res.end('not found');
  }
});

server.listen(8901, () => console.log('demo server on http://localhost:8901'));
