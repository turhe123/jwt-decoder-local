// smoke.spec.js — tool-specific checks for JWT Decoder and Inspector, using the fictional tokens in tests/fixtures/
// (regenerate with: node tests/tools/make-jwt-fixtures.js).
const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');
const SAMPLE = fixture('sample.jwt').trim();
const IAT_MS = 1767261600 * 1000; // iat of every fixture token; exp is two hours later

async function paste(page, token) {
  await page.fill('#token', token);
  await expect(page.locator('#results .jwt-part--payload')).toBeVisible();
}

async function verifyWith(page, key) {
  await page.locator('#verify > summary').click();
  await page.fill('#verify-key', key);
  await page.click('#verify-btn');
  return page.locator('#verify-status');
}

test.describe('JWT Decoder and Inspector', () => {
  test('pasting the sample token shows the header and payload as formatted JSON', async ({ page }) => {
    await page.goto('./');
    await paste(page, SAMPLE);
    const header = page.locator('.jwt-part--header pre');
    const payload = page.locator('.jwt-part--payload pre');
    await expect(header).toHaveText('{\n  "alg": "HS256",\n  "typ": "JWT"\n}');
    const text = await payload.textContent();
    expect(text).toContain('\n  "preferred_username": "maya.rivera",\n');
    expect(JSON.parse(text).roles).toEqual(['editor', 'billing-viewer']);
    // non-ASCII claim values survive base64url -> bytes -> UTF-8
    await expect(payload).toContainText('Diseño & Café ☕');
    await expect(page.locator('.jwt-part--signature code')).toHaveText(SAMPLE.split('.')[2]);
    await expect(page.locator('#verify')).toBeVisible();
    await expect(page.locator('#verify')).not.toHaveAttribute('open', '');
  });

  test('Bearer prefix, quotes and line breaks are cleaned up', async ({ page }) => {
    await page.goto('./');
    const messy = `  "Bearer ${SAMPLE.slice(0, 50)}\n${SAMPLE.slice(50)}"  `;
    await paste(page, messy);
    await expect(page.locator('#results')).toContainText('Cleaned up');
    await expect(page.locator('.jwt-part--header pre')).toContainText('"HS256"');
  });

  test('exp is a readable date and the status says expired', async ({ page }) => {
    await page.goto('./');
    await paste(page, SAMPLE);
    const exp = page.locator('tr[data-claim="exp"]');
    await expect(exp.locator('.jwt-date__utc')).toHaveText('2026-01-01 12:00:00 UTC');
    await expect(exp.locator('.jwt-date')).toContainText('2026');
    await expect(exp).toContainText('Expires at');
    await expect(page.locator('#jwt-status')).toHaveAttribute('data-state', 'expired');
    await expect(page.locator('#jwt-status')).toContainText(/Expired .*ago/);
  });

  test('a fresh token says valid for 2 hours with a countdown', async ({ page }) => {
    await page.clock.install({ time: new Date(IAT_MS) });
    await page.goto('./');
    await paste(page, SAMPLE);
    const chip = page.locator('#jwt-status');
    await expect(chip).toHaveAttribute('data-state', 'valid');
    await expect(chip.locator('.jwt-status__label')).toHaveText(/^Valid for (2 hours|1 hour 59 minutes)$/);
    await expect(chip.locator('.jwt-status__clock')).toHaveText(/^(2:00:00|1:59:\d\d)$/);
    await page.clock.runFor(3 * 60 * 1000);
    await expect(chip.locator('.jwt-status__label')).toHaveText(/^Valid for 1 hour 5\d minutes$/);
    await expect(page.locator('tr[data-claim="exp"] .jwt-date__rel')).toHaveText(/in (2|1) hours?/);
  });

  test('Load sample creates a valid token whose demo secret verifies', async ({ page }) => {
    await page.goto('./');
    await page.click('#sample-btn');
    await expect(page.locator('#jwt-status')).toHaveAttribute('data-state', 'valid');
    await expect(page.locator('#jwt-status')).toContainText(/Valid for (2 hours|1 hour 59 minutes)/);
    await page.locator('#verify > summary').click();
    await page.click('#demo-secret-btn');
    await expect(page.locator('#verify-status')).toContainText('Signature verified');
  });

  test('the correct shared secret shows signature verified', async ({ page }) => {
    await page.goto('./');
    await paste(page, SAMPLE);
    await expect(page.locator('#verify-key-label')).toHaveText('Shared secret');
    const status = await verifyWith(page, 'demo-secret-not-real');
    await expect(status).toHaveClass(/alert--ok/);
    await expect(status).toContainText('Signature verified');
  });

  test('a wrong secret shows signature invalid', async ({ page }) => {
    await page.goto('./');
    await paste(page, SAMPLE);
    const status = await verifyWith(page, 'demo-secret-not-real!');
    await expect(status).toHaveClass(/alert--error/);
    await expect(status).toContainText('Signature invalid');
  });

  test('a tampered payload fails verification with the right secret', async ({ page }) => {
    await page.goto('./');
    const [h, p, s] = SAMPLE.split('.');
    const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url')), roles: ['admin'] })).toString('base64url');
    await paste(page, `${h}.${forged}.${s}`);
    await expect(await verifyWith(page, 'demo-secret-not-real')).toContainText('Signature invalid');
  });

  test('RS256 verifies with a PEM public key and ES256 with a JWK', async ({ page }) => {
    await page.goto('./');
    await paste(page, fixture('sample-rs256.jwt').trim());
    await expect(page.locator('#verify-key-label')).toHaveText('Public key (PEM or JWK)');
    await expect(await verifyWith(page, fixture('sample-rs256.pub.pem'))).toContainText('Signature verified');

    await paste(page, fixture('sample-es256.jwt').trim());
    await page.fill('#verify-key', fixture('sample-es256.jwk.json'));
    await page.click('#verify-btn');
    await expect(page.locator('#verify-status')).toContainText('Signature verified');
    // the RSA key must not verify the EC token
    await page.fill('#verify-key', fixture('sample-rs256.pub.pem'));
    await page.click('#verify-btn');
    await expect(page.locator('#verify-status')).toHaveClass(/alert--error/);
  });

  test('a malformed token names the broken part', async ({ page }) => {
    await page.goto('./');
    const [h, p, s] = SAMPLE.split('.');
    const error = page.locator('#results .alert--error');

    await page.fill('#token', `${h}.${p.slice(0, 20)}!!${p.slice(22)}.${s}`);
    await expect(error).toContainText('Payload (part 2) is not valid base64url');

    await page.fill('#token', `${Buffer.from('{"alg":"HS256",').toString('base64url')}.${p}.${s}`);
    await expect(error).toContainText('Header (part 1) decodes, but is not valid JSON');

    await page.fill('#token', `${h}.${p}.${s}$`);
    await expect(error).toContainText('Signature (part 3) is not valid base64url');

    await page.fill('#token', 'just-some-text');
    await expect(error).toContainText('three parts separated by dots');
    await expect(page.locator('#verify')).toBeHidden();
  });

  test('warnings for alg none, missing exp, millisecond dates and encrypted tokens', async ({ page }) => {
    await page.goto('./');
    const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    await paste(page, `${enc({ alg: 'none' })}.${enc({ sub: 'demo', iat: 1767261600000 })}.`);
    const results = page.locator('#results');
    await expect(results).toContainText('alg is "none"');
    await expect(results).toContainText('There is no exp claim');
    await expect(results).toContainText('looks like milliseconds');

    await page.fill('#token', `${enc({ alg: 'RSA-OAEP', enc: 'A256GCM' })}.a2V5.aXY.Y2lwaGVy.dGFn`);
    await expect(results).toContainText('encrypted token (JWE');
    await expect(page.locator('.jwt-part--header pre')).toContainText('A256GCM');
  });

  test('Ctrl/Cmd+V on the page pastes into the box', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.goto('./');
    await page.evaluate((t) => navigator.clipboard.writeText(t), SAMPLE);
    await page.locator('h1').click();
    await page.keyboard.press('ControlOrMeta+V');
    await expect(page.locator('#token')).toBeFocused();
    await expect(page.locator('#token')).toHaveValue(SAMPLE);
    await expect(page.locator('.jwt-part--payload pre')).toContainText('maya.rivera');
  });

  test('downloads the decoded header and payload as JSON', async ({ page }) => {
    await page.goto('./');
    await paste(page, SAMPLE);
    const [download] = await Promise.all([page.waitForEvent('download'), page.click('#download-json')]);
    expect(download.suggestedFilename()).toBe('jwt-decoded-user_4f2a9c71.json');
    const data = JSON.parse(fs.readFileSync(await download.path(), 'utf8'));
    expect(data.header).toEqual({ alg: 'HS256', typ: 'JWT' });
    expect(data.payload.exp).toBe(1767268800);
    expect(data.signature).toBe(SAMPLE.split('.')[2]);
  });

  test('works at 390px wide with no horizontal scroll', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('./');
    await expect(page.locator('#token')).toBeInViewport();
    await expect(page.locator('#paste-btn')).toBeInViewport();
    await paste(page, SAMPLE);
    await page.locator('#verify > summary').click();
    await page.fill('#verify-key', 'demo-secret-not-real');
    await page.click('#verify-btn');
    await expect(page.locator('#verify-status')).toContainText('Signature verified');
    const widths = await page.evaluate(() => ({ doc: document.documentElement.scrollWidth, win: window.innerWidth }));
    expect(widths.doc).toBeLessThanOrEqual(widths.win + 1);
    for (const sel of ['.jwt-part--payload', '.jwt-claims', '#verify']) {
      const box = await page.locator(sel).boundingBox();
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(391);
    }
  });

  test('__demo shows a decoded, verified token and nothing is stored', async ({ page }) => {
    await page.goto('./');
    await page.evaluate(() => window.__demo());
    await expect(page.locator('.jwt-part--payload pre')).toContainText('maya.rivera');
    await expect(page.locator('#verify-status')).toContainText('Signature verified');
    const stored = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }));
    expect(stored).not.toContain('eyJ');
  });
});
