#!/usr/bin/env node
// Walk every Scalar sidebar entry on the deployed GitHub Pages site,
// verify each link's hash target resolves to a real element id. Catches
// heading-slug mismatches (the `__selectFields` regression class).
//
// Usage:  node scripts/check-sidebar.mjs [url]
// Default URL: https://ftnt-dspille.github.io/fortisoar-api-docs/

import { chromium } from 'playwright';

const url = (process.argv[2] || 'https://ftnt-dspille.github.io/fortisoar-api-docs/').replace(/\/+$/, '') + '/';

const browser = await chromium.launch();
const page = await (await browser.newContext()).newPage();

console.log(`Loading ${url}`);
await page.goto(url, { waitUntil: 'networkidle' });
await page.waitForSelector('aside a[href*="#"]', { timeout: 30_000 });

const entries = await page.$$eval('aside a[href*="#"]', as =>
  as.map(a => ({
    href: a.getAttribute('href'),
    text: (a.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 80),
  }))
);

const broken = [];
for (const { href, text } of entries) {
  const hash = href.split('#')[1];
  if (!hash) continue;
  const exists = await page.evaluate(h => !!document.getElementById(h), hash);
  if (!exists) broken.push({ hash, text });
}

await browser.close();

console.log(`Sidebar entries checked: ${entries.length}`);
console.log(`Broken anchors:          ${broken.length}`);
if (broken.length) {
  console.log();
  for (const b of broken) console.log(`  X #${b.hash}  (sidebar: "${b.text}")`);
  process.exit(1);
}
console.log('All sidebar anchors resolve.');
