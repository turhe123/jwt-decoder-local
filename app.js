// app.js — JWT Decoder and Inspector (ES module). Everything runs on this device: no network, no storage.
import { toast, downloadBlob, formatBytes } from './site.js';

const $ = (id) => document.getElementById(id);
const tokenInput = $('token');
const results = $('results');
const verifyPanel = $('verify');
const verifyKey = $('verify-key');
const verifyResult = $('verify-result');

const SAMPLE_ISS = 'lumenfield-auth';
const SAMPLE_SECRET = 'demo-secret-not-real';
// Same fictional token as tests/fixtures/sample.jwt, used only if WebCrypto is unavailable to sign a fresh one.
const SAMPLE_FALLBACK = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsdW1lbmZpZWxkLWF1dGgiLCJzdWIiOiJ1c2VyXzRmMmE5YzcxIiwiYXVkIjoibHVtZW5maWVsZC1kYXNoYm9hcmQiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJtYXlhLnJpdmVyYSIsIm5hbWUiOiJNYXlhIFJpdmVyYSIsImVtYWlsIjoibWF5YS5yaXZlcmFAbHVtZW5maWVsZC5leGFtcGxlIiwidGVhbSI6IkRpc2XDsW8gJiBDYWbDqSDimJUiLCJyb2xlcyI6WyJlZGl0b3IiLCJiaWxsaW5nLXZpZXdlciJdLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIHJlcG9ydHM6cmVhZCIsImlhdCI6MTc2NzI2MTYwMCwibmJmIjoxNzY3MjYxNjAwLCJleHAiOjE3NjcyNjg4MDAsImp0aSI6IjliMWYzYzBlLWRlbW8tMDAwMC00YTZiLXNhbXBsZSJ9.vEAwQz95P40ph_ydjAcL5xWW_PYz2q38XP3Fvzt8svU';

const hasCrypto = Boolean(globalThis.crypto && crypto.subtle && window.isSecureContext);

const ALGS = {
  HS256: { kind: 'hmac', hash: 'SHA-256' }, HS384: { kind: 'hmac', hash: 'SHA-384' }, HS512: { kind: 'hmac', hash: 'SHA-512' },
  RS256: { kind: 'rsa', hash: 'SHA-256' }, RS384: { kind: 'rsa', hash: 'SHA-384' }, RS512: { kind: 'rsa', hash: 'SHA-512' },
  PS256: { kind: 'pss', hash: 'SHA-256', salt: 32 }, PS384: { kind: 'pss', hash: 'SHA-384', salt: 48 }, PS512: { kind: 'pss', hash: 'SHA-512', salt: 64 },
  ES256: { kind: 'ec', hash: 'SHA-256', curve: 'P-256', size: 64 },
  ES384: { kind: 'ec', hash: 'SHA-384', curve: 'P-384', size: 96 },
  ES512: { kind: 'ec', hash: 'SHA-512', curve: 'P-521', size: 132 },
};

const CLAIMS = {
  iss: 'Issuer: who created and signed the token.',
  sub: 'Subject: the user or thing the token is about.',
  aud: 'Audience: which service the token is meant for. Others should reject it.',
  exp: 'Expires at: after this moment the token must not be accepted.',
  nbf: 'Not before: the token must not be accepted before this moment.',
  iat: 'Issued at: when the token was created.',
  jti: 'Token ID: a unique id, used to stop the same token being replayed.',
  auth_time: 'When the user actually signed in.',
  azp: 'Authorized party: the client the token was issued to.',
  nonce: 'A one-time value that ties the token to a sign-in request.',
  scope: 'Permissions granted to the token, separated by spaces.',
  scp: 'Permissions granted to the token.',
  roles: 'Roles assigned to the user.',
  groups: 'Groups the user belongs to.',
  name: 'Full display name.',
  given_name: 'First name.',
  family_name: 'Last name.',
  preferred_username: 'The username the user goes by.',
  email: 'Email address.',
  email_verified: 'Whether the issuer has confirmed the email address.',
  sid: 'Session ID at the issuer.',
  client_id: 'The application the token was issued to.',
  tid: 'Tenant ID.',
  amr: 'How the user authenticated (password, OTP, …).',
  acr: 'Authentication strength level.',
  at_hash: 'Hash of the matching access token.',
  c_hash: 'Hash of the matching authorization code.',
  updated_at: 'When the profile was last updated.',
};
const DATE_CLAIMS = new Set(['exp', 'nbf', 'iat', 'auth_time', 'updated_at']);
const PART_NAMES = ['Header (part 1)', 'Payload (part 2)', 'Signature (part 3)'];

let current = null; // { raw, header, payload, signature, parts } of the token on screen
let lastInput = null;
let ticker = 0;

/* ---------- Encoding helpers ---------- */

class PartError extends Error {}

function cleanToken(raw) {
  const notes = [];
  const note = (n) => { if (!notes.includes(n)) notes.push(n); };
  let t = raw.trim();
  for (let prev = ''; prev !== t;) { // wrappers can come in any order, e.g. "Bearer eyJ…" or Bearer "eyJ…"
    prev = t;
    if (/^authorization\s*:/i.test(t)) { t = t.replace(/^authorization\s*:\s*/i, ''); note('the Authorization: label'); }
    if (/^bearer\s+/i.test(t)) { t = t.replace(/^bearer\s+/i, ''); note('the Bearer prefix'); }
    const q = t.match(/^(["'`])([\s\S]*)\1[,;]?$/);
    if (q) { t = q[2].trim(); note('surrounding quotes'); }
  }
  if (/\s/.test(t)) { t = t.replace(/\s+/g, ''); notes.push('spaces and line breaks'); }
  return { token: t, notes };
}

function b64urlToBytes(seg, label) {
  let s = seg.replace(/=+$/, '');
  const bad = s.match(/[^A-Za-z0-9\-_+/]/);
  if (bad) throw new PartError(`${label} is not valid base64url: it contains "${bad[0]}" at position ${bad.index + 1}.`);
  if (s.length % 4 === 1) throw new PartError(`${label} is not valid base64url: its length (${s.length} characters) is impossible, so part of it was probably cut off.`);
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  s += '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const utf8 = new TextDecoder('utf-8', { fatal: true });
const enc = new TextEncoder();

function decodeJsonPart(seg, label) {
  if (!seg) throw new PartError(`${label} is empty.`);
  const bytes = b64urlToBytes(seg, label);
  let text;
  try { text = utf8.decode(bytes); } catch { throw new PartError(`${label} decodes, but the result is not UTF-8 text.`); }
  try {
    const value = JSON.parse(text);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new PartError(`${label} is JSON, but not an object { … }.`);
    return value;
  } catch (err) {
    if (err instanceof PartError) throw err;
    throw new PartError(`${label} decodes, but is not valid JSON (${err.message}). Text starts with: ${text.slice(0, 40)}`);
  }
}

/* ---------- Formatting ---------- */

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

function highlightJson(value) {
  const pre = el('pre', 'code jwt-json');
  const json = JSON.stringify(value, null, 2);
  const re = /("(?:\\.|[^\\"])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
  let last = 0;
  for (const m of json.matchAll(re)) {
    if (m.index > last) pre.append(json.slice(last, m.index));
    const cls = m[1] ? (m[2] ? 'j-key' : 'j-str') : m[3] ? 'j-lit' : 'j-num';
    pre.append(el('span', cls, m[1] || m[0]));
    if (m[2]) pre.append(m[2]);
    last = m.index + m[0].length;
  }
  pre.append(json.slice(last));
  return pre;
}

const localFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'long' });
const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

function utcString(d) {
  return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
}

function relative(ms) {
  const abs = Math.abs(ms) / 1000;
  const units = [['year', 31536000], ['month', 2592000], ['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]];
  for (const [unit, secs] of units) {
    if (abs >= secs || unit === 'second') return rtf.format(Math.trunc(ms / 1000 / secs), unit);
  }
  return '';
}

function plural(n, word) { return `${n} ${word}${n === 1 ? '' : 's'}`; }

// "2 hours", "1 hour 59 minutes", "3 days 4 hours" — two largest units, truncated (never rounded up).
function duration(ms) {
  let s = Math.max(0, Math.floor(ms / 1000));
  const parts = [];
  for (const [word, secs] of [['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]]) {
    const n = Math.floor(s / secs);
    s -= n * secs;
    if (n || parts.length) parts.push([n, word]);
  }
  const top = parts.slice(0, 2).filter(([n], i) => n || i === 0);
  return top.length ? top.map(([n, w]) => plural(n, w)).join(' ') : '0 seconds';
}

function clock(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return `${h}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
}

/* ---------- Decoding ---------- */

function decode(raw) {
  const { token, notes } = cleanToken(raw);
  const parts = token.split('.');
  const warnings = [];
  if (notes.length) warnings.push({ level: 'info', text: `Cleaned up ${notes.join(', ')} before decoding.` });

  if (parts.length === 5) {
    const header = decodeJsonPart(parts[0], 'Header (part 1)');
    return { token, parts, header, encrypted: true, warnings: [...warnings, { level: 'warn', text: `This looks like an encrypted token (JWE, five parts${header.enc ? `, ${header.enc}` : ''}). Only the header can be shown; the claims are encrypted and need the recipient's private key.` }] };
  }
  if (parts.length !== 3 && parts.length !== 2) {
    throw new PartError(`A JWT has three parts separated by dots (header.payload.signature), but this has ${parts.length === 1 ? 'no dots' : `${parts.length} parts`}.`);
  }
  const header = decodeJsonPart(parts[0], PART_NAMES[0]);
  const payload = decodeJsonPart(parts[1], PART_NAMES[1]);
  const signature = parts[2] ? b64urlToBytes(parts[2], PART_NAMES[2]) : new Uint8Array();

  const alg = String(header.alg ?? '');
  if (!header.alg) warnings.push({ level: 'warn', text: 'The header has no "alg", so nobody can tell how it was meant to be signed.' });
  else if (alg.toLowerCase() === 'none') warnings.push({ level: 'danger', text: 'alg is "none": this token is not signed, so anyone could have written it. Servers must reject it.' });
  else if (!ALGS[alg]) warnings.push({ level: 'warn', text: `Algorithm ${alg} cannot be verified here; decoding still works.` });
  if (alg && alg.toLowerCase() !== 'none' && !signature.length) warnings.push({ level: 'danger', text: `The header says ${alg}, but the signature part is missing.` });
  if (!('exp' in payload)) warnings.push({ level: 'warn', text: 'There is no exp claim, so this token never expires on its own. Long-lived tokens are risky if leaked.' });
  for (const k of DATE_CLAIMS) {
    const v = payload[k];
    if (typeof v === 'number' && v > 1e11) warnings.push({ level: 'warn', text: `${k} is ${v}, which is far in the future. It looks like milliseconds instead of seconds (${utcString(new Date(v))} if read as milliseconds).` });
    else if (k in payload && typeof v !== 'number') warnings.push({ level: 'warn', text: `${k} should be a number of seconds, but it is ${JSON.stringify(v)}.` });
  }
  return { token, parts, header, payload, signature, warnings };
}

/* ---------- Rendering ---------- */

function copyButton(label, getText) {
  const b = el('button', 'btn btn--small', label);
  b.type = 'button';
  b.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(getText()); toast('Copied to the clipboard'); }
    catch { toast('Copy was blocked by the browser. Select the text and copy it by hand.'); }
  });
  return b;
}

function partCard(kind, title, sub, body, copy) {
  const card = el('section', `jwt-part jwt-part--${kind}`);
  const head = el('div', 'jwt-part__head');
  const h = el('h3', 'jwt-part__title', title);
  head.append(h);
  if (sub) head.append(el('span', 'jwt-part__sub', sub));
  if (copy) head.append(copy);
  card.append(head, body);
  return card;
}

function statusOf(payload, now = Date.now()) {
  const exp = typeof payload.exp === 'number' ? payload.exp * 1000 : null;
  const nbf = typeof payload.nbf === 'number' ? payload.nbf * 1000 : null;
  if (nbf != null && now < nbf) return { state: 'pending', label: `Not valid yet, starts in ${duration(nbf - now)}`, clock: clock(nbf - now) };
  if (exp != null && now >= exp) return { state: 'expired', label: `Expired ${relative(exp - now)}`, clock: '' };
  if (exp != null) return { state: 'valid', label: `Valid for ${duration(exp - now)}`, clock: clock(exp - now) };
  return { state: 'valid', label: 'Valid, no expiry set', clock: '' };
}

function renderStatus() {
  const chip = document.getElementById('jwt-status');
  if (!chip || !current?.payload) return;
  const s = statusOf(current.payload);
  chip.dataset.state = s.state;
  chip.querySelector('.jwt-status__label').textContent = s.label;
  chip.querySelector('.jwt-status__clock').textContent = s.clock;
  document.querySelectorAll('[data-rel]').forEach((n) => { n.textContent = relative(Number(n.dataset.rel) - Date.now()); });
}

function claimValue(key, value) {
  const cell = el('td', 'jwt-claims__value');
  if (DATE_CLAIMS.has(key) && typeof value === 'number') {
    const d = new Date(value * 1000);
    if (Number.isNaN(d.getTime())) { cell.append(el('code', '', String(value))); return cell; }
    cell.append(el('strong', 'jwt-date', localFmt.format(d)));
    cell.append(el('span', 'jwt-date__utc', utcString(d)));
    const rel = el('span', 'jwt-date__rel', relative(d.getTime() - Date.now()));
    rel.dataset.rel = String(d.getTime());
    cell.append(rel, el('code', 'jwt-date__raw', String(value)));
    return cell;
  }
  cell.append(el('code', '', typeof value === 'string' ? value : JSON.stringify(value)));
  return cell;
}

function claimsTable(payload) {
  const wrap = el('div', 'table-wrap');
  const table = el('table', 'jwt-claims');
  const cap = el('caption', 'visually-hidden', 'Claims in the payload');
  const thead = el('thead');
  const hr = el('tr');
  ['Claim', 'Value', 'Meaning'].forEach((t) => { const th = el('th', '', t); th.scope = 'col'; hr.append(th); });
  thead.append(hr);
  const tbody = el('tbody');
  for (const [k, v] of Object.entries(payload)) {
    const tr = el('tr');
    tr.dataset.claim = k;
    const th = el('th', '', k);
    th.scope = 'row';
    tr.append(th, claimValue(k, v), el('td', 'jwt-claims__meaning', CLAIMS[k] || 'Custom claim set by the issuer.'));
    tbody.append(tr);
  }
  table.append(cap, thead, tbody);
  wrap.append(table);
  return wrap;
}

function encodedView(parts) {
  const pre = el('pre', 'jwt-encoded');
  pre.setAttribute('aria-label', 'Encoded token, colored by part');
  const kinds = parts.length === 5 ? ['header', 'payload', 'payload', 'payload', 'signature'] : ['header', 'payload', 'signature'];
  parts.forEach((p, i) => {
    if (i) pre.append(el('span', 'jwt-dot', '.'));
    pre.append(el('span', `jwt-seg jwt-seg--${kinds[i]}`, p));
  });
  return pre;
}

function alertFor(w) {
  const cls = { info: 'alert', warn: 'alert alert--warn', danger: 'alert alert--error' }[w.level];
  return el('p', cls, w.text);
}

function showError(message) {
  current = null;
  clearInterval(ticker);
  verifyPanel.hidden = true;
  const box = el('div', 'alert alert--error');
  box.setAttribute('role', 'alert');
  box.append(el('strong', '', 'Could not decode this token. '), message);
  results.replaceChildren(box);
}

function render(data) {
  current = data;
  clearInterval(ticker);
  const frag = document.createDocumentFragment();
  for (const w of data.warnings) frag.append(alertFor(w));

  const bar = el('div', 'jwt-bar');
  if (data.payload) {
    const chip = el('div', 'jwt-status');
    chip.id = 'jwt-status';
    chip.append(el('span', 'jwt-status__dot'), el('span', 'jwt-status__label'), el('span', 'jwt-status__clock'));
    bar.append(chip);
  }
  bar.append(el('span', 'chip', data.header.alg ? `alg ${data.header.alg}` : 'no alg'));
  if (data.header.typ) bar.append(el('span', 'chip chip--muted', `typ ${data.header.typ}`));
  bar.append(el('span', 'jwt-bar__size', formatBytes(data.token.length)));
  const dl = el('button', 'btn btn--small jwt-bar__dl', 'Download decoded JSON');
  dl.type = 'button';
  dl.id = 'download-json';
  dl.addEventListener('click', downloadDecoded);
  bar.append(dl);
  frag.append(bar, encodedView(data.parts));

  const grid = el('div', 'jwt-parts');
  grid.append(partCard('header', 'Header', 'algorithm and token type', highlightJson(data.header), copyButton('Copy header', () => JSON.stringify(data.header, null, 2))));
  if (data.encrypted) {
    const info = el('p', 'jwt-part__note', `Encrypted key, IV, ciphertext and tag: ${data.parts.slice(1).map((p) => `${p.length} chars`).join(', ')}. The claims cannot be read without the private key.`);
    grid.append(partCard('payload', 'Payload', 'encrypted', info, null));
  } else {
    grid.append(partCard('payload', 'Payload', 'the claims', highlightJson(data.payload), copyButton('Copy payload', () => JSON.stringify(data.payload, null, 2))));
    const sig = el('div', 'jwt-sig');
    sig.append(el('code', 'jwt-sig__value', data.parts[2] || '(empty)'));
    sig.append(el('p', 'jwt-part__note', data.signature.length ? `${data.signature.length} bytes. Open "Verify the signature" below to check it.` : 'No signature.'));
    grid.append(partCard('signature', 'Signature', 'base64url', sig, copyButton('Copy signature', () => data.parts[2] || '')));
  }
  frag.append(grid);

  if (data.payload) {
    frag.append(el('h3', 'jwt-subtitle', 'Claims explained'), claimsTable(data.payload));
    frag.append(el('p', 'jwt-note', 'Times use this device\'s clock. Servers often allow a minute or two of clock skew, so a token right at its exp or nbf may still be accepted or refused.'));
  }
  results.replaceChildren(frag);
  if (data.payload) { renderStatus(); ticker = setInterval(renderStatus, 1000); }
  setupVerify(data);
  results.firstElementChild?.scrollIntoView({ block: 'nearest' });
}

function update() {
  const raw = tokenInput.value;
  if (raw === lastInput) return;
  lastInput = raw;
  verifyResult.replaceChildren();
  if (!raw.trim()) { current = null; clearInterval(ticker); results.replaceChildren(); verifyPanel.hidden = true; return; }
  try { render(decode(raw)); }
  catch (err) { showError(err instanceof PartError ? err.message : `Unexpected problem: ${err.message}`); }
}

function downloadDecoded() {
  if (!current) return;
  const out = { header: current.header };
  if (current.payload) out.payload = current.payload;
  if (current.parts[2] && !current.encrypted) out.signature = current.parts[2];
  const blob = new Blob([JSON.stringify(out, null, 2) + '\n'], { type: 'application/json' });
  const name = typeof current.payload?.sub === 'string' ? current.payload.sub.replace(/[^\w.-]+/g, '_').slice(0, 40) : '';
  downloadBlob(blob, `jwt-decoded${name ? `-${name}` : ''}.json`);
}

/* ---------- Verification ---------- */

function setupVerify(data) {
  const alg = String(data.header.alg || '');
  const spec = ALGS[alg];
  verifyPanel.hidden = data.encrypted || !spec;
  $('verify-alg').textContent = alg;
  $('verify-unavailable').hidden = hasCrypto;
  $('verify-btn').disabled = !hasCrypto;
  if (!spec) return;
  const isHmac = spec.kind === 'hmac';
  $('verify-key-label').textContent = isHmac ? 'Shared secret' : 'Public key (PEM or JWK)';
  $('verify-key-hint').textContent = isHmac
    ? 'The secret the issuer signed with. A JWK with "kty": "oct" also works.'
    : 'Paste -----BEGIN PUBLIC KEY-----, an RSA public key, a certificate, a JWK or a JWKS. The matching kid is picked from a JWKS.';
  verifyKey.placeholder = isHmac ? 'your-256-bit-secret' : '-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----';
  $('verify-b64-wrap').hidden = !isHmac;
  $('demo-secret-btn').hidden = !(isHmac && data.payload?.iss === SAMPLE_ISS);
}

function pemToDer(pem) {
  const m = pem.match(/-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/);
  if (!m) throw new Error('The PEM key is incomplete: the BEGIN and END lines do not match.');
  const body = m[2].replace(/[^A-Za-z0-9+/=]/g, '');
  const bin = atob(body);
  const der = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return { type: m[1], der };
}

// Minimal DER reading/writing, enough to pull a public key out of a certificate or wrap a PKCS#1 RSA key.
function derRead(buf, pos) {
  const tag = buf[pos];
  let len = buf[pos + 1];
  let off = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[off + i];
    off += n;
  }
  return { tag, start: pos, body: off, end: off + len };
}

function derLen(n) {
  if (n < 0x80) return [n];
  const bytes = [];
  while (n) { bytes.unshift(n & 0xff); n >>= 8; }
  return [0x80 | bytes.length, ...bytes];
}

function derWrap(tag, content) {
  return Uint8Array.from([tag, ...derLen(content.length), ...content]);
}

function spkiFromCert(der) {
  const cert = derRead(der, 0);
  const tbs = derRead(der, cert.body);
  let p = tbs.body;
  let f = derRead(der, p);
  if (f.tag === 0xa0) { p = f.end; } // optional version
  for (let i = 0; i < 5; i++) { f = derRead(der, p); p = f.end; } // serial, sigAlg, issuer, validity, subject
  f = derRead(der, p);
  return der.slice(f.start, f.end);
}

function rsaPkcs1ToSpki(pkcs1) {
  const algId = Uint8Array.from([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
  const bitString = derWrap(0x03, Uint8Array.from([0x00, ...pkcs1]));
  return derWrap(0x30, Uint8Array.from([...algId, ...bitString]));
}

function algParams(spec) {
  if (spec.kind === 'rsa') return { name: 'RSASSA-PKCS1-v1_5', hash: spec.hash };
  if (spec.kind === 'pss') return { name: 'RSA-PSS', hash: spec.hash };
  return { name: 'ECDSA', namedCurve: spec.curve };
}

async function importVerifyKey(text, spec, kid, b64) {
  const trimmed = text.trim();
  if (spec.kind === 'hmac') {
    let raw;
    if (trimmed.startsWith('{')) {
      const jwk = pickJwk(JSON.parse(trimmed), kid);
      if (jwk.kty !== 'oct' || !jwk.k) throw new Error('This JWK is not a shared secret (it needs "kty": "oct" and "k").');
      raw = b64urlToBytes(jwk.k, 'The JWK "k" value');
    } else if (b64) {
      raw = b64urlToBytes(text.trim(), 'The secret');
    } else {
      raw = enc.encode(text); // the secret is used exactly as typed
    }
    if (!raw.length) throw new Error('Enter the shared secret first.');
    return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: spec.hash }, false, ['verify']);
  }
  if (!trimmed) throw new Error('Paste the public key first.');
  if (trimmed.startsWith('{')) {
    let parsed;
    try { parsed = JSON.parse(trimmed); } catch (err) { throw new Error(`The JWK is not valid JSON (${err.message}).`); }
    const { d, p, q, dp, dq, qi, alg, key_ops, use, ext, ...pub } = pickJwk(parsed, kid);
    const wantKty = spec.kind === 'ec' ? 'EC' : 'RSA';
    if (pub.kty !== wantKty) throw new Error(`The token uses an ${wantKty} algorithm, but this JWK is "kty": "${pub.kty}".`);
    if (spec.kind === 'ec' && pub.crv !== spec.curve) throw new Error(`The token needs a ${spec.curve} key, but this JWK is ${pub.crv}.`);
    return crypto.subtle.importKey('jwk', { ...pub, ext: true }, { ...algParams(spec), hash: spec.hash }, false, ['verify']);
  }
  if (!trimmed.includes('-----BEGIN')) throw new Error('This does not look like a PEM key (-----BEGIN PUBLIC KEY-----) or a JWK ({ … }).');
  const { type, der } = pemToDer(trimmed);
  let spki;
  if (type === 'PUBLIC KEY') spki = der;
  else if (type === 'RSA PUBLIC KEY') spki = rsaPkcs1ToSpki(der);
  else if (type === 'CERTIFICATE') spki = spkiFromCert(der);
  else if (type.includes('PRIVATE')) throw new Error('That is a private key. Paste the matching public key instead, and keep the private key secret.');
  else throw new Error(`"${type}" keys are not supported. Paste a PUBLIC KEY, RSA PUBLIC KEY, CERTIFICATE or a JWK.`);
  return crypto.subtle.importKey('spki', spki, { ...algParams(spec), hash: spec.hash }, false, ['verify']);
}

function pickJwk(obj, kid) {
  if (Array.isArray(obj.keys)) {
    if (!obj.keys.length) throw new Error('The JWKS has no keys.');
    const hit = obj.keys.find((k) => kid && k.kid === kid);
    if (kid && !hit) throw new Error(`No key in the JWKS has kid "${kid}" from the token header.`);
    return hit || obj.keys[0];
  }
  return obj;
}

async function verify() {
  verifyResult.replaceChildren();
  if (!current || current.encrypted) return;
  const alg = String(current.header.alg || '');
  const spec = ALGS[alg];
  if (!spec || !hasCrypto) return;
  let secret = verifyKey.value;
  const btn = $('verify-btn');
  btn.disabled = true;
  const show = (ok, title, detail) => {
    const box = el('div', ok ? 'alert alert--ok' : 'alert alert--error');
    box.id = 'verify-status';
    box.append(el('strong', '', title));
    if (detail) box.append(' ', detail);
    verifyResult.replaceChildren(box);
  };
  try {
    const key = await importVerifyKey(secret, spec, current.header.kid, $('verify-b64').checked);
    const data = enc.encode(`${current.parts[0]}.${current.parts[1]}`);
    if (spec.kind === 'ec' && current.signature.length !== spec.size) {
      show(false, 'Signature invalid.', `An ${alg} signature must be ${spec.size} bytes (raw r and s), but this one is ${current.signature.length}.`);
      return;
    }
    const params = spec.kind === 'hmac' ? 'HMAC'
      : spec.kind === 'rsa' ? 'RSASSA-PKCS1-v1_5'
        : spec.kind === 'pss' ? { name: 'RSA-PSS', saltLength: spec.salt }
          : { name: 'ECDSA', hash: spec.hash };
    const ok = await crypto.subtle.verify(params, key, current.signature, data);
    if (ok) show(true, 'Signature verified.', `The token was signed with this ${spec.kind === 'hmac' ? 'secret' : 'key'} and has not been changed. ${current.payload?.exp ? 'Check the expiry above too.' : ''}`);
    else show(false, 'Signature invalid.', spec.kind === 'hmac' ? 'The secret is wrong, or the token was changed after signing.' : 'This key did not sign the token, or the token was changed after signing.');
  } catch (err) {
    show(false, 'Could not check the signature.', err.name === 'DataError' || err.name === 'NotSupportedError' ? `The key could not be used for ${alg}. ${err.message}` : err.message);
  } finally {
    secret = null; // drop our copy of the secret as soon as it has been used
    btn.disabled = !hasCrypto;
  }
}

/* ---------- Sample, clipboard, keyboard ---------- */

async function makeSample() {
  if (!hasCrypto) return SAMPLE_FALLBACK;
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = {
    iss: SAMPLE_ISS, sub: 'user_4f2a9c71', aud: 'lumenfield-dashboard', preferred_username: 'maya.rivera',
    name: 'Maya Rivera', email: 'maya.rivera@lumenfield.example', team: 'Diseño & Café ☕',
    roles: ['editor', 'billing-viewer'], scope: 'openid profile reports:read',
    iat: now, nbf: now, exp: now + 7200, jti: '9b1f3c0e-demo-0000-4a6b-sample',
  };
  const input = `${bytesToB64url(enc.encode(JSON.stringify(header)))}.${bytesToB64url(enc.encode(JSON.stringify(payload)))}`;
  const key = await crypto.subtle.importKey('raw', enc.encode(SAMPLE_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(input)));
  return `${input}.${bytesToB64url(sig)}`;
}

function setToken(text) {
  tokenInput.value = text;
  update();
}

$('sample-btn').addEventListener('click', async () => {
  setToken(await makeSample());
  toast(`Sample loaded. Its demo secret is ${SAMPLE_SECRET}`);
});

$('paste-btn').addEventListener('click', async () => {
  try {
    const text = await navigator.clipboard.readText();
    if (!text.trim()) { toast('The clipboard is empty.'); return; }
    setToken(text);
  } catch {
    tokenInput.focus();
    toast('The browser blocked clipboard access. Press Ctrl or ⌘ + V to paste.');
  }
});

$('clear-btn').addEventListener('click', () => {
  setToken('');
  verifyKey.value = '';
  tokenInput.focus();
});

$('demo-secret-btn').addEventListener('click', () => { verifyKey.value = SAMPLE_SECRET; $('verify-b64').checked = false; verify(); });
$('verify-btn').addEventListener('click', verify);
verifyKey.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); verify(); } });
verifyKey.addEventListener('input', () => verifyResult.replaceChildren());
$('verify-b64').addEventListener('change', () => verifyResult.replaceChildren());
tokenInput.addEventListener('input', update);

const isEditable = (n) => n && (n.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(n.tagName));
// Ctrl/⌘ + V anywhere on the page focuses the box, so the browser's own paste lands in it.
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === 'v' && !isEditable(document.activeElement)) {
    tokenInput.focus();
    tokenInput.select();
  }
});
document.addEventListener('paste', (e) => {
  if (isEditable(e.target)) return;
  const text = e.clipboardData?.getData('text');
  if (text) { e.preventDefault(); setToken(text); tokenInput.focus(); }
});

if (!hasCrypto) $('verify-unavailable').hidden = false;

// Called by the factory's screenshot script: decodes the bundled fictional sample and verifies it.
window.__demo = async () => {
  const res = await fetch('./tests/fixtures/sample.jwt');
  setToken(await res.text());
  verifyPanel.open = true;
  verifyKey.value = SAMPLE_SECRET;
  await verify();
};

export { decode, cleanToken, statusOf };
