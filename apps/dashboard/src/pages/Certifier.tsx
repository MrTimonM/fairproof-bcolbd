/**
 * Certifying body — the accredited auditor that attests a firm's figures.
 *
 * This workspace exists to make one separation visible: the body that vouches
 * for a firm's finances is NOT the office that buys from it. An ICAB-registered
 * audit firm already holds these books; procurement's problem was never that
 * nobody had checked them, it was that proving it to a buyer meant handing them
 * over. Here the body signs the figures once, and the firm proves them to any
 * tender without the buyer ever seeing one.
 *
 * What this body can and cannot do is worth stating on the page, because it is
 * the question a sceptical reader arrives with:
 *
 *   - it never learns which tenders the firm bids on;
 *   - it cannot bid as the firm, because the subject secret stays with the firm;
 *   - it cannot approve or refuse anyone's participation — only attest figures.
 *     Whether those figures qualify is decided by the tender's frozen rules.
 */
import { useEffect, useState } from "react";
import { initEddsa, initPoseidon } from "@fairproof/crypto";
import { CONFIG, contract, formatBdt, formatTime } from "../lib/chain";
import { describe, usePoll } from "../lib/hooks";
import { issuerRegistry } from "../lib/prover";
import {
  encodeAttestation,
  issueCredential,
  type CredentialFieldSet,
} from "../lib/attestation";
import { Card, ChainFact, CheckList, Field, Hash, Masthead, Note, Stat, Stats } from "../components/kit";
import { Icon } from "../components/Icon";
import type { RoleProps } from "../App";

/**
 * The epoch credentials are issued against.
 *
 * It must match the epoch a tender names, because the circuit constrains the
 * two to be equal — a credential from the wrong epoch is not a weaker proof,
 * it is no proof. The Authority workspace publishes tenders at this same
 * epoch, so the constant is shared rather than guessed.
 */
const EPOCH = 21n;
const SCHEMA_VERSION = 1n;

export default function Certifier({ section }: RoleProps) {
  /**
   * The registry keys need the EdDSA backend up, so they cannot be derived
   * during render — doing so threw on first paint and blanked the workspace.
   */
  const [registry, setRegistry] = useState<ReturnType<typeof issuerRegistry> | null>(null);
  useEffect(() => {
    let alive = true;
    (async () => {
      await initPoseidon();
      await initEddsa();
      if (alive) setRegistry(issuerRegistry());
    })().catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  // What the chain says about this body, read rather than asserted.
  const accreditation = usePoll(async () => {
    const reg = contract("IssuerRegistry");
    // getIssuer REVERTS for an unknown id rather than reporting absence.
    let issuer: { label: string; active: boolean; pubKeyX: bigint; pubKeyY: bigint } | null = null;
    try {
      const i = await reg.getIssuer(0);
      issuer = { label: i.label, active: i.active, pubKeyX: i.pubKeyX, pubKeyY: i.pubKeyY };
    } catch {
      issuer = null;
    }
    return {
      issuer,
      currentEpoch: Number(await reg.currentEpoch()),
      registryRoot: (await reg.issuerRegistryRoot(EPOCH).catch(() => null)) as string | null,
    };
  }, 8000);

  // ---------------------------------------------------------------- the form
  const [firmName, setFirmName] = useState("");
  const [registrationNumber, setRegistrationNumber] = useState("");
  const [credentialId, setCredentialId] = useState("");
  const [turnover, setTurnover] = useState("");
  const [experience, setExperience] = useState("");
  const [certCode, setCertCode] = useState("");
  const [commitment, setCommitment] = useState("");
  const [validDays, setValidDays] = useState("365");

  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState<{ text: string; id: string; firm: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const problems: string[] = [];
  if (firmName.trim().length < 3) problems.push("Name the firm being certified.");
  if (registrationNumber.trim().length < 3) problems.push("Give the firm's registration number.");
  if (!/^\d+$/.test(credentialId.trim())) problems.push("Give the credential a numeric id.");
  if (!/^\d+$/.test(turnover.trim())) problems.push("State the audited annual turnover.");
  if (!/^\d+$/.test(experience.trim())) problems.push("State the relevant experience in months.");
  if (!/^\d+$/.test(certCode.trim())) problems.push("State the certification code held.");
  if (!/^\d+$/.test(commitment.trim()))
    problems.push("Paste the subject commitment the firm gave you.");
  if (!/^\d+$/.test(validDays.trim()) || Number(validDays) < 1)
    problems.push("Set how long this attestation stays valid.");

  async function issue() {
    setBusy(true);
    setError(null);
    setIssued(null);
    setCopied(false);
    try {
      await initPoseidon();
      await initEddsa();
      const now = BigInt(Math.floor(Date.now() / 1000));
      const until = now + BigInt(validDays) * 86400n;
      const fields: CredentialFieldSet = {
        schemaVersion: SCHEMA_VERSION,
        subjectCommitment: BigInt(commitment.trim()),
        annualTurnover: BigInt(turnover),
        relevantExperience: BigInt(experience),
        certificationCode: BigInt(certCode),
        certValidUntil: until,
        credentialValidUntil: until,
        credentialId: BigInt(credentialId),
        issuerEpoch: EPOCH,
        issuedAt: now,
      };
      const reg = registry ?? issuerRegistry();
      const att = issueCredential(
        reg.issuerPriv,
        reg.issuerKey,
        accreditation.data?.issuer?.label ?? "Accredited certifying body",
        fields,
        { firmName: firmName.trim(), registrationNumber: registrationNumber.trim() },
      );
      setIssued({ text: encodeAttestation(att), id: credentialId, firm: firmName.trim() });
    } catch (err) {
      setError(describe(err));
    } finally {
      setBusy(false);
    }
  }

  // ------------------------------------------------------------ this body
  if (section === "accreditation") {
    const a = accreditation.data;
    return (
      <>
        <Masthead eyebrow="Certifying body" title="This body">
          A firm's figures are worth something only because an accredited body stands
          behind them. Here is what the chain says about this one.
        </Masthead>

        <Card
          title={a?.issuer?.label ?? "Not registered"}
          sub="Accredited by the council, not self-declared."
          chain={
            <>
              <ChainFact k="Registry root, epoch 21">
                {a?.registryRoot ? <Hash v={a.registryRoot} lead={10} tail={6} /> : "—"}
              </ChainFact>
              <ChainFact k="Current epoch">
                <span className="mono num">{a?.currentEpoch ?? "—"}</span>
              </ChainFact>
            </>
          }
        >
          <Stats n={3}>
            <Stat k="Accredited" v={a?.issuer ? "Yes" : "No"} s="in the on-chain registry" />
            <Stat k="Status" v={a?.issuer?.active ? "Active" : "Inactive"} s="set by the council" />
            <Stat k="Credential epoch" v="21" s="the epoch tenders name" />
          </Stats>

          <Note tone="accent" icon="info">
            <strong>Accreditation takes three of the four council members.</strong> The
            regulator, the procuring entity, the independent auditor and the chamber of
            commerce each hold one vote, behind a timelock — so no single office can
            appoint the body that vouches for bidders, and none can quietly remove it.
          </Note>

          <div style={{ marginTop: 18 }}>
            <CheckList
              items={[
                {
                  label: "This body never learns which tenders a firm bids on",
                  state: "pass",
                  value: "By construction",
                },
                {
                  label: "This body cannot bid as a firm it certified",
                  state: "pass",
                  value: "No subject secret",
                },
                {
                  label: "This body cannot approve or refuse participation",
                  state: "pass",
                  value: "Only attests figures",
                },
              ]}
            />
          </div>
        </Card>

        <Card title="What this body signs" sub="Ten values, and nothing else.">
          <p className="small muted" style={{ marginTop: 0 }}>
            The signature covers a Poseidon digest over the schema version, a commitment
            to the firm's secret, the audited turnover, the relevant experience, the
            certification code, both validity dates, the credential id, the epoch and the
            time of issue. The firm's <em>name</em> is deliberately outside the digest —
            it is descriptive, and a legal name is the issuer's business to check, not a
            circuit's.
          </p>
          <ChainFact k="Issuer key x">
            <span className="mono">
              {registry ? `${registry.issuerKey.x.toString().slice(0, 18)}…` : "—"}
            </span>
          </ChainFact>
        </Card>
      </>
    );
  }

  // ---------------------------------------------------------------- issuing
  return (
    <>
      <Masthead eyebrow="Certifying body" title="Issue a credential">
        Attest a firm's audited figures once. It can then prove them to any tender,
        without a buying authority ever seeing one of them.
      </Masthead>

      <Note tone="accent" icon="info">
        <strong>The firm gives you a subject commitment, not a secret.</strong> It
        generates a secret in its own browser and hands you only{" "}
        <code>Poseidon(secret)</code>. You sign that alongside the figures, which binds
        this credential to that firm and to nobody else — and leaves you unable to bid
        in its name. The firm finds the value on its <strong>My company</strong> screen.
      </Note>

      <div className="grid2">
        <Card title="The firm" sub="As it appears on your audit.">
          <Field label="Legal name">
            <input
              className="in"
              placeholder="e.g. XYZ Construction Limited"
              value={firmName}
              onChange={(e) => setFirmName(e.target.value)}
              disabled={busy}
            />
          </Field>
          <Field label="Registration number">
            <input
              className="in mono"
              placeholder="e.g. C-118342/2019"
              value={registrationNumber}
              onChange={(e) => setRegistrationNumber(e.target.value)}
              disabled={busy}
            />
          </Field>
          <Field label="Credential id" hint="Your own reference for this attestation.">
            <input
              className="in mono"
              placeholder="e.g. 1042"
              value={credentialId}
              onChange={(e) => setCredentialId(e.target.value.replace(/\D/g, ""))}
              disabled={busy}
            />
          </Field>
          <Field
            label="Subject commitment"
            hint="Pasted from the firm. Reveals nothing about its secret."
          >
            <input
              className="in mono"
              placeholder="a long decimal number from the firm"
              value={commitment}
              onChange={(e) => setCommitment(e.target.value.replace(/[^\d]/g, ""))}
              disabled={busy}
            />
          </Field>
        </Card>

        <Card title="What you are attesting" sub="These are the figures the proof will use.">
          <Field
            label="Audited annual turnover (BDT)"
            hint={turnover ? formatBdt(BigInt(turnover || "0")) : "As audited."}
          >
            <input
              className="in mono big"
              placeholder="e.g. 620000000"
              value={turnover}
              onChange={(e) => setTurnover(e.target.value.replace(/\D/g, ""))}
              disabled={busy}
            />
          </Field>
          <div className="row2">
            <Field label="Relevant experience (months)">
              <input
                className="in mono"
                placeholder="e.g. 72"
                value={experience}
                onChange={(e) => setExperience(e.target.value.replace(/\D/g, ""))}
                disabled={busy}
              />
            </Field>
            <Field label="Certification code held">
              <input
                className="in mono"
                placeholder="e.g. 9001"
                value={certCode}
                onChange={(e) => setCertCode(e.target.value.replace(/\D/g, ""))}
                disabled={busy}
              />
            </Field>
          </div>
          <Field
            label="Valid for"
            hint={
              /^\d+$/.test(validDays) && Number(validDays) > 0
                ? `Days. Lapses ${formatTime(
                    Math.floor(Date.now() / 1000) + Number(validDays) * 86400,
                  )}.`
                : "Days from now."
            }
          >
            <input
              className="in mono"
              value={validDays}
              onChange={(e) => setValidDays(e.target.value.replace(/\D/g, ""))}
              disabled={busy}
            />
          </Field>
          <Note tone="wait" icon="clock">
            <strong>Validity is checked at a tender's deadline, not at submission.</strong>{" "}
            A credential that lapses before a deadline cannot win that tender, however
            early the bid was placed.
          </Note>
        </Card>
      </div>

      <Card title="Sign it">
        {problems.length ? (
          <Note tone="wait" icon="alert">
            {problems[0]}
          </Note>
        ) : null}
        {error ? (
          <Note tone="bad" icon="cross">
            {error}
          </Note>
        ) : null}

        <button
          className="btn primary lg"
          disabled={busy || problems.length > 0}
          onClick={issue}
        >
          {busy ? (
            <>
              <span className="spin" /> Signing…
            </>
          ) : (
            <>
              <Icon name="seal" size={17} /> Issue credential
            </>
          )}
        </button>

        {issued ? (
          <div style={{ marginTop: 20 }}>
            <Note tone="good" icon="check">
              <strong>
                Credential #{issued.id} issued to {issued.firm}.
              </strong>{" "}
              Give this to the firm — by email, file or print. It carries no secret, so
              it does not need a protected channel; it is useless to anyone who does not
              already hold the matching secret.
            </Note>
            <textarea
              className="in mono"
              readOnly
              rows={12}
              value={issued.text}
              style={{ marginTop: 12, width: "100%", resize: "vertical" }}
              onFocus={(e) => e.currentTarget.select()}
            />
            <button
              className="btn"
              style={{ marginTop: 10 }}
              onClick={() => {
                navigator.clipboard?.writeText(issued.text).then(
                  () => setCopied(true),
                  () => setCopied(false),
                );
              }}
            >
              <Icon name="copy" size={16} /> {copied ? "Copied" : "Copy credential"}
            </button>
          </div>
        ) : null}
      </Card>

      <Card title="What this does not do" sub="Worth being exact about.">
        <p className="small muted" style={{ marginTop: 0 }}>
          Signing attests that <em>this body examined these figures and found them
          true</em>. It does not make them true, and no zero-knowledge proof can. The
          trust here is the same trust a procuring office already places in an audited
          statement today — the difference is that the office no longer has to receive
          one to act on it. That residual is stated in{" "}
          <code>docs/cryptography.md</code> rather than hidden.
        </p>
      </Card>
    </>
  );
}
