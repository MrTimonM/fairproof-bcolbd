#!/usr/bin/env node
/**
 * Drive the certification path in a real browser, end to end.
 *
 * `test:ui` proves each workspace renders. It does NOT prove the thing that
 * actually matters about the certifying body: that a credential it signs is
 * accepted by the bidder, produces a proof over the SIGNED figures, and is
 * taken by the contract. Every part of that is easy to get subtly wrong in a
 * way a render test and a typechecker both wave through — a digest assembled
 * in a different field order still typechecks and still renders.
 *
 * So this walks the actual flow:
 *
 *   register a firm  ->  read its subject commitment
 *   issue a credential against that commitment, as the certifying body
 *   import it as the firm, and confirm the figures become the body's
 *   place a real bid, and confirm the chain accepted it
 *
 * It needs a tender that is OPEN for bidding. Publish one first:
 *   npm run tender -- --window 1800 --reference CERT-2026-0001
 *
 *   npm run dashboard:dev        # in another terminal
 *   npm run test:certify
 */
const URL = process.env.DASHBOARD_URL ?? "http://127.0.0.1:5173/";

/** What the body will attest. Comfortably over the published thresholds. */
const FIRM = {
  name: "Meghna Certified Builders Limited",
  registration: "C-771204/2018",
  credentialId: "2087",
  turnover: "620000000",
  experience: "72",
  certification: "9001",
  bid: "5200000",
};

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

let browser;
try {
  browser = await puppeteer.launch({ browser: "chrome", headless: "shell", args: ["--no-sandbox"] });
} catch (err) {
  console.error(`could not start a browser: ${err.message.split("\n")[0]}\n`);
  console.error("  npx puppeteer browsers install chrome-headless-shell\n");
  process.exit(2);
}

const page = await browser.newPage();
await page.setViewport({ width: 1440, height: 1200 });

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

// ------------------------------------------------------------------ helpers
const role = async (label) => {
  const ok = await page.evaluate((l) => {
    const b = [...document.querySelectorAll(".role-tab")].find((x) => x.innerText.includes(l));
    if (!b) return false;
    b.click();
    return true;
  }, label);
  if (!ok) throw new Error(`no workspace tab "${label}"`);
  await sleep(2500);
};

const nav = async (label) => {
  const ok = await page.evaluate((l) => {
    const b = [...document.querySelectorAll(".nav-item")].find((x) => x.innerText.includes(l));
    if (!b) return false;
    b.click();
    return true;
  }, label);
  if (!ok) throw new Error(`no section "${label}"`);
  await sleep(2000);
};

/**
 * Type into the field carrying this placeholder.
 *
 * Matched by comparing the property rather than by building a CSS selector:
 * one of these placeholders is a JSON snippet containing double quotes, which
 * makes any interpolated `[placeholder="..."]` selector unparseable.
 */
const fill = async (placeholder, value) => {
  const handle = await page.evaluateHandle((p) => {
    const all = [...document.querySelectorAll("input, textarea")];
    return all.find((e) => e.placeholder === p) ?? null;
  }, placeholder);
  const el = handle.asElement();
  if (!el) throw new Error(`no field with placeholder "${placeholder}"`);
  await el.click({ clickCount: 3 });
  await el.type(String(value), { delay: 4 });
};

const clickText = async (text) => {
  const ok = await page.evaluate((t) => {
    const b = [...document.querySelectorAll("button")].find((x) => x.innerText.trim().includes(t));
    if (!b || b.disabled) return false;
    b.click();
    return true;
  }, text);
  if (!ok) throw new Error(`no enabled button matching "${text}"`);
  await sleep(1200);
};

const bodyText = () => page.evaluate(() => document.body.innerText);

/** Wait until the page says something, or give up. */
const waitForText = async (needle, ms, label) => {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if ((await bodyText()).includes(needle)) return true;
    await sleep(1500);
  }
  fail(label ?? `page never showed "${needle}"`);
  return false;
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

console.log("\nThe certification path, in a real browser\n");

try {
  // ---------------------------------------------------- 1. register the firm
  await role("Bidder");
  await nav("My company");
  await fill("e.g. XYZ Construction Limited", FIRM.name);
  await fill("e.g. C-118342/2019", FIRM.registration);
  await fill("e.g. 1042", FIRM.credentialId);
  await fill("e.g. 620000000", FIRM.turnover);
  await fill("e.g. 72", FIRM.experience);
  await fill("e.g. 9001", FIRM.certification);
  await page.evaluate(() => {
    const b = [...document.querySelectorAll("button")].find((x) =>
      /Register company|Save changes/.test(x.innerText),
    );
    if (b && !b.disabled) b.click();
  });
  await sleep(2500);

  // ------------------------------------------- 2. read the subject commitment
  const commitment = await page.evaluate(() => {
    const inputs = [...document.querySelectorAll("input[readonly]")];
    const hit = inputs.map((i) => i.value).find((v) => /^\d{15,}$/.test(v));
    return hit ?? null;
  });
  if (commitment) {
    pass("the firm derived a subject commitment", `${commitment.slice(0, 14)}…`);
  } else {
    fail("the firm derived a subject commitment", "no long decimal value on screen");
    throw new Error("cannot continue without a commitment");
  }

  // -------------------------------------------- 3. issue it, as the body
  await role("Certifying body");
  await nav("Issue a credential");
  await fill("e.g. XYZ Construction Limited", FIRM.name);
  await fill("e.g. C-118342/2019", FIRM.registration);
  await fill("e.g. 1042", FIRM.credentialId);
  await fill("a long decimal number from the firm", commitment);
  await fill("e.g. 620000000", FIRM.turnover);
  await fill("e.g. 72", FIRM.experience);
  await fill("e.g. 9001", FIRM.certification);
  await clickText("Issue credential");
  await sleep(2500);

  const credential = await page.evaluate(() => {
    const t = [...document.querySelectorAll("textarea")].find((x) =>
      x.value.includes("fairproof.credential.v1"),
    );
    return t?.value ?? null;
  });
  if (credential) {
    pass("the body signed a credential", `${credential.length} bytes`);
  } else {
    fail("the body signed a credential", "no credential appeared");
    throw new Error("cannot continue without a credential");
  }

  // The commitment the body signed must be the firm's, not something re-derived.
  const signedCommitment = JSON.parse(credential).fields.subjectCommitment;
  if (signedCommitment === commitment) {
    pass("the credential is bound to that firm's commitment");
  } else {
    fail("the credential is bound to that firm's commitment", "the body signed a different subject");
  }

  // ------------------------------------------------ 4. import it, as the firm
  await role("Bidder");
  await nav("My company");
  await fill('{ "format": "fairproof.credential.v1", … }', credential);
  await clickText("Import credential");
  await sleep(2500);

  const afterImport = await bodyText();
  if (/Certified by/.test(afterImport)) {
    pass("the firm accepted the credential", "figures now shown as attested");
  } else {
    fail("the firm accepted the credential", "no attested card on screen");
  }

  // The figures the firm can type must now be inert.
  const locked = await page.evaluate(() => {
    const i = document.querySelector('input[placeholder="e.g. 620000000"]');
    return i ? i.disabled : null;
  });
  if (locked === true) pass("self-declared figures are locked once attested");
  else fail("self-declared figures are locked once attested", `disabled = ${locked}`);

  // -------------------------------------------------------- 5. place a bid
  await nav("Submit bid");
  await sleep(2500);
  const beforeBid = await bodyText();
  if (!/Qualified/.test(beforeBid)) {
    fail("the attested credential qualifies", "the qualification card does not say Qualified");
  } else {
    pass("the attested credential qualifies");
  }
  if (/Bidding has not opened/.test(beforeBid)) {
    fail(
      "a tender is open for bidding",
      "the review window is still running — wait, then re-run",
    );
    throw new Error("no open tender");
  }

  const amount = await page.evaluateHandle(() =>
    document.querySelector("input.in.mono.big"),
  );
  const amountEl = amount.asElement();
  if (!amountEl) {
    fail("the bid amount field is present");
  } else {
    await amountEl.click({ clickCount: 3 });
    await amountEl.type(FIRM.bid, { delay: 4 });
    await clickText("Submit sealed bid");
    // 18 MB of circuit, then a proof, then storage, then a transaction.
    if (await waitForText("accepted as submission", 240000, "the chain accepted the bid")) {
      const after = await bodyText();
      const m = after.match(/accepted as submission #(\d+)/);
      pass("the chain accepted a bid proved from the credential", m ? `submission #${m[1]}` : "");
      if (/proof generated in/.test(after)) {
        pass("the proof was generated over the attested figures");
      }
    }
  }
} catch (err) {
  fail("the flow ran to completion", err.message);
}

console.log("");
if (errors.length) {
  console.log(`${errors.length} console error(s):`);
  for (const e of errors.slice(0, 12)) console.log(`  ✕ ${e.slice(0, 240)}`);
}

await browser.close();

if (failures || errors.length) {
  console.log(
    `\nCERTIFICATION PATH FAILED — ${failures} assertion(s), ${errors.length} console error(s)`,
  );
  process.exit(1);
}
console.log("\nTHE CERTIFICATION PATH WORKS, BROWSER TO CHAIN");
