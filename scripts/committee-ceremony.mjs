#!/usr/bin/env node
/**
 * The tender committee-key ceremony. Development plan Section 12.2.
 *
 * Deals a 3-of-5 threshold ElGamal key for one tender with Feldman verifiable
 * secret sharing, hands each member their share, and prints the arguments the
 * authority passes to `TenderRegistry.setCommitteeKey`.
 *
 * THIS IS THE OPENING THRESHOLD (3-of-5), not the storage quorum (2-of-3).
 * The two are separate mechanisms and must never be described with one
 * number; see docs/cryptography.md Section 6.
 *
 * WHAT THE CEREMONY GUARANTEES
 *
 * Feldman VSS publishes commitments to the dealer's polynomial, so the
 * dealing is verifiable by anyone. `TenderRegistry.setCommitteeKey` performs
 * that verification ON-CHAIN: it rejects a public key that is not a
 * prime-order subgroup point, a public key that is not commitment C_0, and any
 * member share that is not the committed polynomial's value at that member's
 * index. So a dishonest dealer cannot deal inconsistent shares, cannot publish
 * a key the shares are unable to open, and cannot hand a member someone
 * else's share.
 *
 * WHAT IT DOES NOT GUARANTEE
 *
 * The dealer knows the tender secret `x` while this script runs. That is the
 * trusted-dealer limitation whitepaper Section 19.1 already concedes ("full
 * DKG ... production design until implemented"). The residual is exactly one
 * thing and it must be labelled everywhere the threshold is shown:
 * "verifiable threshold opening with a trusted dealer (prototype); production
 * requires DKG".
 *
 * The destruction step below is real - the secret is overwritten and never
 * written to disk - but a script cannot prove it destroyed something. Only a
 * DKG, where no party ever holds `x`, removes the assumption.
 */
import { mkdirSync, writeFileSync, readFileSync, existsSync, chmodSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  COMMITTEE_SIZE,
  COMMITTEE_THRESHOLD,
  dealCommitteeKey,
  expectedPublicShare,
  initBabyjub,
  mulBase,
  pointsEqual,
  isInPrimeSubgroup,
  verifyDealing,
  verifyShare,
} from "@fairproof/crypto";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");

/**
 * Shares live outside the repository tree's tracked content and the directory
 * is gitignored. They are per-tender ephemeral secrets, not long-lived keys,
 * but a share on disk is still a share: two of these plus one more opens
 * every bid in the tender.
 */
const shareRoot = join(repoRoot, "infrastructure", "committee-shares");

const point = (p) => ({ x: p.x.toString(), y: p.y.toString() });

function usage() {
  console.log(
    [
      "usage: committee-ceremony <command> [args]",
      "",
      "  deal <tenderId> [--members a,b,c,d,e]",
      "        Deal a 3-of-5 key for the tender. Writes one share file per",
      "        member and a public arguments file. The secret is destroyed",
      "        before the script exits.",
      "",
      "  verify <tenderId> <memberIndex>",
      "        What a committee member runs on their own machine: check that",
      "        the share they were given really is the committed",
      "        polynomial's value at their index.",
      "",
      "  show <tenderId>",
      "        Print the public setCommitteeKey arguments. Contains no secret.",
    ].join("\n"),
  );
}

await initBabyjub();

const [cmd, tenderId, ...rest] = process.argv.slice(2);

if (!cmd || !tenderId) {
  usage();
  process.exit(cmd ? 1 : 0);
}

const tenderDir = join(shareRoot, tenderId.replace(/[^A-Za-z0-9._-]/g, "_"));
const publicPath = join(tenderDir, "committee-public.json");
const sharePath = (i) => join(tenderDir, `member-${i}.share.json`);

// --------------------------------------------------------------------- deal

if (cmd === "deal") {
  if (existsSync(publicPath)) {
    console.error(
      `refusing to re-deal: ${publicPath} exists.\n` +
        `A second dealing would produce a different key while members still ` +
        `hold shares of the first, and the tender can only pin one. Delete the ` +
        `directory deliberately if this is a fresh start.`,
    );
    process.exit(1);
  }

  const membersArg = rest.find((a) => a.startsWith("--members="));
  const members = membersArg
    ? membersArg.slice("--members=".length).split(",").map((s) => s.trim())
    : [];
  if (members.length && members.length !== COMMITTEE_SIZE) {
    console.error(`--members needs exactly ${COMMITTEE_SIZE} addresses`);
    process.exit(1);
  }

  console.log(`FairProof committee-key ceremony - tender ${tenderId}`);
  console.log(`threshold ${COMMITTEE_THRESHOLD} of ${COMMITTEE_SIZE} (whitepaper Section 6)\n`);

  const dealt = dealCommitteeKey();

  // Every check the contract will perform, run here first, so a bad dealing
  // fails at the desk instead of as a revert whose reason has to be decoded.
  const { ok, problems } = verifyDealing(dealt);
  if (!ok) {
    console.error("the dealing failed its own verification:");
    for (const p of problems) console.error(`  - ${p}`);
    process.exit(1);
  }
  if (!isInPrimeSubgroup(dealt.publicKey)) {
    console.error("the public key is not in the prime-order subgroup");
    process.exit(1);
  }
  console.log("dealing verified locally (all contract checks pass)");

  mkdirSync(tenderDir, { recursive: true });

  for (const s of dealt.shares) {
    const file = sharePath(s.index);
    writeFileSync(
      file,
      JSON.stringify(
        {
          $warning:
            "SECRET. This is one share of a tender opening key. Three shares " +
            "open every bid in the tender. Do not copy, email, or commit it.",
          tenderId,
          memberIndex: s.index,
          memberAddress: members[s.index - 1] ?? null,
          share: s.share.toString(),
          publicShare: point(s.publicShare),
          threshold: dealt.threshold,
          size: dealt.size,
          commitments: dealt.commitments.map(point),
          verifyWith: `node scripts/committee-ceremony.mjs verify ${tenderId} ${s.index}`,
        },
        null,
        2,
      ) + "\n",
    );
    chmodSync(file, 0o600);
    console.log(`  share ${s.index} -> ${file.replace(repoRoot + "/", "")}`);
  }

  writeFileSync(
    publicPath,
    JSON.stringify(
      {
        $comment:
          "PUBLIC. The arguments for TenderRegistry.setCommitteeKey. Contains " +
          "no secret: every value here is published on-chain at activation " +
          "and is what makes the opening ceremony independently verifiable.",
        tenderId,
        threshold: dealt.threshold,
        size: dealt.size,
        publicKey: point(dealt.publicKey),
        commitments: dealt.commitments.map(point),
        members: members.length ? members : null,
        memberPublicShares: dealt.shares.map((s) => ({
          index: s.index,
          address: members[s.index - 1] ?? null,
          publicShare: point(s.publicShare),
        })),
        dealtAt: new Date().toISOString(),
        limitation:
          "Trusted dealer: this script knew the tender secret while it ran. " +
          "Production requires DKG (whitepaper Section 19.1).",
      },
      null,
      2,
    ) + "\n",
  );
  console.log(`  public  -> ${publicPath.replace(repoRoot + "/", "")}`);

  // ---- destruction ------------------------------------------------------
  //
  // Overwrite every copy of the secret material this process holds. The
  // BigInts themselves are immutable and garbage-collected, so this is a
  // best-effort measure and is described as one: what actually matters is
  // that the secret was never written to disk and never left this process.
  let secret = dealt.secret;
  secret = 0n;
  dealt.secret = 0n;
  for (const s of dealt.shares) s.share = 0n;
  void secret;

  console.log("\nDESTRUCTION: the tender secret x has been discarded.");
  console.log("  - x was never written to disk and never left this process.");
  console.log("  - the shares on disk cannot reconstruct x unless three are combined.");
  console.log("  - a script cannot PROVE destruction. Only DKG removes the assumption.");
  console.log("\nNext: the authority calls setCommitteeKey with the public arguments,");
  console.log("      and the contract verifies the dealing before accepting it.");
  process.exit(0);
}

// ------------------------------------------------------------------- verify

if (cmd === "verify") {
  const index = Number(rest[0] ?? tenderId);
  const file = sharePath(index);
  if (!existsSync(file)) {
    console.error(`no share file at ${file}`);
    process.exit(1);
  }
  const s = JSON.parse(readFileSync(file, "utf8"));
  const commitments = s.commitments.map((c) => ({ x: BigInt(c.x), y: BigInt(c.y) }));
  const share = {
    index: s.memberIndex,
    share: BigInt(s.share),
    publicShare: { x: BigInt(s.publicShare.x), y: BigInt(s.publicShare.y) },
  };

  // Three values, because there are two independent things to check and a
  // report that prints only one comparison can say REJECTED while showing
  // two numbers that match - which sends the reader looking in the wrong
  // place.
  const expected = expectedPublicShare(share.index, commitments);
  const derived = mulBase(share.share);
  const commitmentsAgree = pointsEqual(share.publicShare, expected);
  const shareAgrees = pointsEqual(derived, share.publicShare);
  const good = verifyShare(share, commitments);

  console.log(`member ${share.index}, tender ${s.tenderId}`);
  const label = (t) => `  ${t.padEnd(32)} = `;
  console.log(label(`Y_${share.index} from the commitments`) + expected.x);
  console.log(label(`Y_${share.index} as published`) + share.publicShare.x);
  console.log(label("share * G") + derived.x);
  console.log("");
  console.log(
    `  published Y_${share.index} matches the commitments: ${commitmentsAgree ? "yes" : "NO"}`,
  );
  console.log(
    `  the secret share matches published Y_${share.index}: ${shareAgrees ? "yes" : "NO"}`,
  );

  if (good) {
    console.log("\nSHARE VERIFIED against the published commitments");
  } else {
    console.log("\nSHARE REJECTED");
    if (!commitmentsAgree) {
      console.log(
        "  The published Y_i is not the committed polynomial's value at your " +
          "index. This is a dishonest or broken DEALING.",
      );
    }
    if (!shareAgrees) {
      console.log(
        "  Your secret share does not correspond to the published Y_i. Either " +
          "you were given the wrong share, or the share file has been altered.",
      );
    }
    console.log(
      "  Do NOT proceed: raise it publicly. The same commitment check runs " +
        "on-chain, so an activation carrying a bad Y_i would be rejected too - " +
        "but a wrong SECRET share is invisible on-chain and only surfaces as a " +
        "failed opening, which is why you must check it here.",
    );
  }
  process.exit(good ? 0 : 1);
}

// --------------------------------------------------------------------- show

if (cmd === "show") {
  if (!existsSync(publicPath)) {
    console.error(`no dealing at ${publicPath}`);
    process.exit(1);
  }
  console.log(readFileSync(publicPath, "utf8"));
  process.exit(0);
}

usage();
process.exit(1);
