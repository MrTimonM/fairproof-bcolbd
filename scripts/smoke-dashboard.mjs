#!/usr/bin/env node
/**
 * Load the dashboard in a real browser and assert that it renders.
 *
 * This exists because `npm run dashboard:build` has twice reported success on
 * a page that came up blank. A bundler resolves modules; it does not run them.
 * Both failures — an unparseable favicon data URI, and circomlibjs reaching for
 * Node's `Buffer` — were warnings at build time and fatal at load time.
 *
 * So: open every workspace, assert each one mounted something, and fail on any
 * console error. A console error here is not a style question. It means a
 * module threw, and in a single-page app one module throwing takes the whole
 * screen with it.
 *
 *   npm run dashboard:dev        # in another terminal
 *   npm run test:ui
 *
 * Needs a browser once:
 *   npm i --no-save puppeteer && npx puppeteer browsers install chrome-headless-shell
 */
const URL = process.env.DASHBOARD_URL ?? "http://127.0.0.1:5173/";

let puppeteer;
try {
  puppeteer = (await import("puppeteer")).default;
} catch {
  console.error(
    "puppeteer is not installed. This check is deliberately not a hard\n" +
      "dependency — it downloads a browser. To run it:\n\n" +
      "  npm i --no-save puppeteer\n" +
      "  npx puppeteer browsers install chrome-headless-shell\n",
  );
  process.exit(2);
}

/** Every workspace, and something each one must have rendered. */
const WORKSPACES = [
  { tab: "Public", expect: "Ongoing tenders" },
  { tab: "Bidder", expect: "Available tenders" },
  { tab: "Certifying body", expect: "Issue a credential" },
  { tab: "Authority", expect: "Create tender" },
  { tab: "Auditor", expect: "Verification" },
];

let browser;
try {
  browser = await puppeteer.launch({
    browser: "chrome",
    headless: "shell",
    args: ["--no-sandbox"],
  });
} catch (err) {
  // Usually a puppeteer upgrade that now wants a different browser build than
  // the one in the cache. The raw stack trace buries the one useful sentence.
  console.error(`could not start a browser: ${err.message.split("\n")[0]}\n`);
  console.error("  npx puppeteer browsers install chrome-headless-shell\n");
  process.exit(2);
}
const page = await browser.newPage();
await page.setViewport({ width: 1440, height: 1000 });

const errors = [];
page.on("console", (m) => {
  if (m.type() === "error") errors.push(m.text());
});
page.on("pageerror", (e) => errors.push(`uncaught: ${e.message}`));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const pass = (t, d = "") => console.log(`  PASS  ${t}${d ? `  ${d}` : ""}`);
const fail = (t, d = "") => {
  failures++;
  console.log(`  FAIL  ${t}${d ? `  ${d}` : ""}`);
};

try {
  await page.goto(URL, { waitUntil: "networkidle2", timeout: 60000 });
} catch (err) {
  console.error(`could not open ${URL} — is \`npm run dashboard:dev\` running?`);
  console.error(`  ${err.message}`);
  await browser.close();
  process.exit(1);
}
await sleep(4000);

// The blank-page check, stated as its own assertion because it is the failure
// this script exists for.
const mounted = await page.evaluate(() => {
  const root = document.getElementById("root");
  return { children: root?.children.length ?? 0, text: document.body.innerText.length };
});
if (mounted.children > 0 && mounted.text > 500) {
  pass("the app mounted", `${mounted.text} characters rendered`);
} else {
  fail("the app mounted", `root has ${mounted.children} children, ${mounted.text} characters`);
}

for (const w of WORKSPACES) {
  const before = errors.length;
  const clicked = await page.evaluate((tab) => {
    const b = [...document.querySelectorAll(".role-tab")].find((x) => x.innerText.includes(tab));
    if (!b) return false;
    b.click();
    return true;
  }, w.tab);
  if (!clicked) {
    fail(`${w.tab}: no such workspace tab`);
    continue;
  }
  await sleep(3500);

  const body = await page.evaluate(() => document.body.innerText);
  if (body.includes(w.expect)) {
    const cards = await page.evaluate(() => document.querySelectorAll(".card").length);
    pass(`${w.tab} rendered`, `${cards} cards`);
  } else {
    fail(`${w.tab} rendered`, `expected to find "${w.expect}"`);
  }
  if (errors.length > before) {
    fail(`${w.tab} is free of console errors`, `${errors.length - before} new`);
  }
}

// The word the interface must never use. Checked here rather than by grep so
// it covers text the components generate at runtime.
const said = await page.evaluate(() => /\bdemo\b/i.test(document.body.innerText));
if (said) fail('the interface never says "demo"');
else pass('the interface never says "demo"');

console.log("");
if (errors.length) {
  console.log(`${errors.length} console error(s):`);
  for (const e of errors.slice(0, 12)) console.log(`  ✕ ${e.slice(0, 240)}`);
}

await browser.close();

if (failures || errors.length) {
  console.log(`\nDASHBOARD SMOKE TEST FAILED — ${failures} assertion(s), ${errors.length} console error(s)`);
  process.exit(1);
}
console.log("THE DASHBOARD RENDERS, EVERY WORKSPACE, WITH NO CONSOLE ERRORS");
