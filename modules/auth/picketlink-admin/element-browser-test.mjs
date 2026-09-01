/**
 * Full browser automation for the <picketlink-admin> element (PL-106): drives a real
 * Chromium against the local demo stack (http://localhost:8901 — served by demo-server.mjs,
 * fixture API, no external network) and verifies every screen renders live data, plus the
 * hash-routing isolation guarantee. Runs headless; wrap in `xvfb-run` for headed runs.
 *
 * Usage: npm run demo &  # then: npm run test:browser
 */
import { chromium } from 'playwright-core';

const BASE = process.env.PICKETLINK_ADMIN_DEMO ?? 'http://localhost:8901';
const CHROMIUM = process.env.PICKETLINK_CHROMIUM ?? '/usr/bin/chromium';

const failures = [];
function check(name, condition) {
  console.log((condition ? 'PASS ' : 'FAIL ') + name);
  if (!condition) {
    failures.push(name);
  }
}

const browser = await chromium.launch({
  executablePath: CHROMIUM,
  headless: true,
  args: ['--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage'],
});
try {
  const page = await browser.newPage();
  page.on('pageerror', (error) => console.log('PAGE-ERROR:', error.message));
  await page.goto(BASE + '/', { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('picketlink-admin', { timeout: 10_000 });

  // --- Clients screen: live fixture data, masked secrets
  await page.waitForSelector('plk-clients-page table', { timeout: 10_000 });
  const clientsText = await page.locator('plk-clients-page').innerText();
  check('clients page renders fixture row (billing-service)', clientsText.includes('billing-service'));
  check('clients page renders auth method', clientsText.includes('private_key_jwt'));
  check('clients page renders audience pinning', clientsText.includes('https://api.corp.example'));
  check('clients page never displays secret material',
      !clientsText.includes('demo-secret') && !clientsText.includes('smoke-secret'));
  check('clients page exposes rotate/delete actions',
      clientsText.includes('Rotate secret') && clientsText.includes('Delete'));
  check('create-client form present', await page.locator('plk-clients-page form').count() === 1);

  // --- hash routing + host isolation: navigate to each section via the nav links
  const navTo = async (href) => {
    await page.click(`picketlink-admin a[href="${href}"]`);
    await page.waitForTimeout(500);
  };

  await navTo('#/keys');
  await page.waitForSelector('plk-keys-page table', { timeout: 10_000 });
  const keysText = await page.locator('plk-keys-page').innerText();
  check('keys page renders fixture keys', keysText.includes('pl-signing-0f31')
      && keysText.includes('pl-signing-11a2'));
  check('keys page marks the active key', /\(active\)/.test(keysText));
  check('keys page offers rotation', keysText.includes('Rotate signing key'));

  await navTo('#/policies');
  await page.waitForSelector('plk-policies-page form', { timeout: 10_000 });
  const policyValues = await page.locator('plk-policies-page input')
      .evaluateAll((els) => els.map((e) => e.value));
  check('policies page renders the algorithm allow-list',
      policyValues[0].includes('RS256') && policyValues[0].includes('ES256'));
  check('policies page renders default algorithm', policyValues[1] === 'RS256');
  check('policies page renders lifetime caps',
      policyValues[2] === '300' && policyValues[3] === '600');

  await navTo('#/tokens');
  await page.waitForSelector('plk-tokens-page table', { timeout: 10_000 });
  const tokensText = await page.locator('plk-tokens-page').innerText();
  check('tokens page renders hashed token records', tokensText.includes('b64urlhash1'));
  check('tokens page shows client + scopes', tokensText.includes('billing-service'));
  check('tokens page never shows raw JWTs', !/eyJ/.test(tokensText));

  // --- the route-management guarantee: only the fragment ever changes
  const url = new URL(page.url());
  check('hash routing active (#/tokens)', url.hash === '#/tokens');
  check('host path untouched by element routing', url.pathname === '/');

  // --- screenshots for visual evidence
  for (const route of ['clients', 'policies', 'keys', 'tokens']) {
    await page.click(`picketlink-admin a[href="#/${route}"]`);
    await page.waitForTimeout(400);
    await page.screenshot({ path: `/tmp/picketlink-admin-${route}.png` });
  }
  console.log('screenshots: /tmp/picketlink-admin-{clients,policies,keys,tokens}.png');
} finally {
  await browser.close();
}

console.log(failures.length === 0 ? 'ALL BROWSER CHECKS PASSED'
    : failures.length + ' CHECK(S) FAILED');
process.exit(failures.length === 0 ? 0 : 1);
