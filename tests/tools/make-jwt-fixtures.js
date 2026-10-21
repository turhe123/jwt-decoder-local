// Generates the fictional JWT fixtures in tests/fixtures/ (run: node tests/tools/make-jwt-fixtures.js).
// Private keys are generated in memory and discarded; only tokens and public keys are written.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const out = (name, data) => fs.writeFileSync(path.join(__dirname, '..', 'fixtures', name), data);
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const IAT = 1767261600; // 2026-01-01 10:00:00 UTC
const payload = {
  iss: 'lumenfield-auth',
  sub: 'user_4f2a9c71',
  aud: 'lumenfield-dashboard',
  preferred_username: 'maya.rivera',
  name: 'Maya Rivera',
  email: 'maya.rivera@lumenfield.example',
  team: 'Diseño & Café ☕',
  roles: ['editor', 'billing-viewer'],
  scope: 'openid profile reports:read',
  iat: IAT,
  nbf: IAT,
  exp: IAT + 7200,
  jti: '9b1f3c0e-demo-0000-4a6b-sample',
};

function token(header, sign) {
  const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  return `${input}.${b64u(sign(Buffer.from(input)))}`;
}

out('sample.jwt', token({ alg: 'HS256', typ: 'JWT' }, (d) => crypto.createHmac('sha256', 'demo-secret-not-real').update(d).digest()) + '\n');

const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
out('sample-rs256.jwt', token({ alg: 'RS256', typ: 'JWT', kid: 'demo-rsa-1' }, (d) => crypto.sign('sha256', d, rsa.privateKey)) + '\n');
out('sample-rs256.pub.pem', rsa.publicKey.export({ type: 'spki', format: 'pem' }));

const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
out('sample-es256.jwt', token({ alg: 'ES256', typ: 'JWT', kid: 'demo-ec-1' }, (d) => crypto.sign('sha256', d, { key: ec.privateKey, dsaEncoding: 'ieee-p1363' })) + '\n');
out('sample-es256.jwk.json', JSON.stringify({ ...ec.publicKey.export({ format: 'jwk' }), kid: 'demo-ec-1', use: 'sig', alg: 'ES256' }, null, 2) + '\n');
console.log('fixtures written');
