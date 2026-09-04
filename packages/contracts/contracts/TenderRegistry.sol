// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IFairProofErrors} from "./interfaces/IFairProofErrors.sol";
import {BabyJubjub} from "./lib/BabyJubjub.sol";
import {FairProofEncoding} from "./lib/FairProofEncoding.sol";
import {Governance} from "./Governance.sol";
import {IssuerRegistry} from "./IssuerRegistry.sol";

/**
 * @notice The slice of EligibilityVerifier this contract needs.
 * @dev A narrow interface rather than an import, so the two modules are not
 *      circularly dependent: the verifier reads tender state, and the tender
 *      only asks the verifier one yes/no question at activation.
 */
interface IVerifierVersionRegistry {
    function isVersionRegistered(uint32 version) external view returns (bool);
}

/**
 * @title TenderRegistry
 * @notice Tender lifecycle, the frozen rulesHash, the committee key, and the
 *         contract-enforced public rule-review window.
 *
 * @dev Development plan Sections 9.2 and 9.2.1.
 *
 * @dev HOW rulesHash IS RECOMPUTED ON-CHAIN.
 *
 *      Whitepaper Section 4 fixes
 *          rulesHash = keccak256(JCS(schemaVersion, tenderId, requirements,
 *                                selectionRule, tieBreakRule, biddingStart,
 *                                deadline, disclosurePolicy, issuerEpoch),
 *                                revocationPolicy, contingencyPolicy,
 *                                verifierVersion)
 *      using RFC 8785 JSON canonicalization, and states the document "can be
 *      re-hashed by any verifier".
 *
 *      Solidity cannot parse JSON, so it cannot canonicalize a document
 *      itself. Rather than silently substituting ABI encoding for JCS - which
 *      would make the on-chain value differ from the published formula - the
 *      authority submits the canonical JCS bytes and this contract STORES
 *      them and computes `keccak256(document)` itself. That is a genuine
 *      on-chain recomputation of exactly the whitepaper's value: nobody has
 *      to trust a hash the authority supplied.
 *
 *      The contract separately stores the structured fields it must enforce
 *      (window, thresholds, policies, verifier version) and computes a
 *      `fieldsDigest` over them.
 *
 *      RESIDUAL, STATED PLAINLY: the contract cannot verify that the stored
 *      document PARSES to the stored structured fields, because that requires
 *      JSON parsing. A dishonest authority could store a document that reads
 *      differently from the fields the contract enforces. This is detected by
 *      the independent verifier (plan Section 16.6 check 1), which re-parses
 *      the document and compares field by field, and it is detectable by
 *      anyone, because both values are public. It must be listed as a PARTIAL
 *      row in the traceability table, not presented as fully on-chain.
 */
contract TenderRegistry is IFairProofErrors {
    /// @notice Tender lifecycle. Plan Section 9.2.
    enum State {
        NONE,
        DRAFT,
        ACTIVE,
        CLOSED,
        OPENING,
        AWARDED,
        CANCELLED
    }

    /// @notice Opening committee threshold. Whitepaper Section 6: 3-of-5.
    uint8 public constant COMMITTEE_THRESHOLD = 3;
    uint8 public constant COMMITTEE_SIZE = 5;

    /**
     * @notice The public rule-review window, in three layers.
     *
     * @dev Whitepaper Table 11 offers this as the mitigation for
     *      unfair-but-immutable rules: "a mandatory public rule-review window
     *      before bidding opens". Enforcing it in the contract turns that
     *      promise into a mechanism.
     *
     *      The appropriate length is genuinely a policy question - a small
     *      works tender and a national infrastructure tender should not be
     *      forced to share one value - so it is per-tender. But it cannot be
     *      the authority's unilateral choice either, or the authority would
     *      pick the minimum every time and the mitigation would be toothless.
     *
     *      Hence three layers, so an authority can always grant MORE review
     *      time and never less:
     *
     *        1. ABSOLUTE_MIN_REVIEW_WINDOW - a hard constant in code. No
     *           deployment, council or authority can go below it.
     *        2. minReviewWindow - the policy floor, set by the council under
     *           3-of-4 with a timelock and an on-chain reason. A policy
     *           parameter that can never change is its own problem, so this
     *           one moves - but only through governance, never by the
     *           authority whose tender it constrains.
     *        3. Tender.reviewWindow - chosen per tender by the authority in
     *           DRAFT, required to be >= minReviewWindow, and covered by the
     *           frozen fields digest so it is publicly verifiable like every
     *           other rule.
     *
     *      The prototype's floor is short so the workflow is demonstrable in
     *      one sitting. Do not describe a sixty-second floor as
     *      production-ready; the production value belongs in the governance
     *      charter and the documentation.
     */
    uint64 public constant ABSOLUTE_MIN_REVIEW_WINDOW = 60;

    /// @notice Council-set policy floor. Always >= ABSOLUTE_MIN_REVIEW_WINDOW.
    uint64 public minReviewWindow;

    /// @notice Eligibility requirements, enforced by the contract and circuit.
    struct Requirements {
        uint64 turnoverThreshold; // BDT taka
        uint32 experienceMonths;
        uint64 certificationCode;
    }

    /// @notice The tender committee's ElGamal key material. Plan Section 12.2.
    struct CommitteeKey {
        /// @dev Tender public key Y = x*G on BabyJubjub.
        uint256 yX;
        uint256 yY;
        /// @dev Per-member public shares Y_i = x_i*G, used to verify DLEQ.
        uint256[COMMITTEE_SIZE] memberX;
        uint256[COMMITTEE_SIZE] memberY;
        /// @dev Feldman VSS commitments C_0..C_2 (threshold 3).
        uint256[COMMITTEE_THRESHOLD] commitmentX;
        uint256[COMMITTEE_THRESHOLD] commitmentY;
        bool set;
    }

    /**
     * @notice The structured rule fields the contract enforces.
     * @dev Grouped into a struct rather than passed as separate parameters:
     *      twelve arguments exceeded the EVM stack depth, and `viaIR` is not
     *      an option here because it inflates the linked Poseidon libraries
     *      past the EIP-170 contract-size limit (docs/stage0-evidence.md).
     */
    struct RuleFields {
        Requirements requirements;
        uint64 biddingStart;
        uint64 deadline;
        bytes32 requiredIssuerId;
        uint64 issuerEpoch;
        uint32 schemaVersion;
        uint32 verifierVersion;
        uint8 disclosurePolicy;
        uint8 awardRule;
        uint8 tieBreakRule;
        uint8 contingencyPolicy;
        /// @dev Per-tender review window. Must be >= minReviewWindow.
        uint64 reviewWindow;
    }

    struct Tender {
        State state;
        string tenderIdString;
        uint256 tenderIdField;
        address authority;
        /// @dev keccak256 of the stored canonical rule document.
        bytes32 rulesHash;
        /// @dev keccak256 over the structured fields the contract enforces.
        bytes32 fieldsDigest;
        uint64 activatedAt;
        uint64 biddingStart;
        uint64 deadline;
        bytes32 requiredIssuerId;
        uint64 issuerEpoch;
        uint32 schemaVersion;
        uint32 verifierVersion;
        uint8 disclosurePolicy;
        uint8 awardRule;
        uint8 tieBreakRule;
        uint8 contingencyPolicy;
        uint64 reviewWindow;
        Requirements requirements;
    }

    Governance public immutable governance;
    IssuerRegistry public immutable issuerRegistry;

    mapping(bytes32 => Tender) private _tenders;
    mapping(bytes32 => CommitteeKey) private _committeeKeys;
    /// @dev The canonical JCS rule document, stored so rulesHash is
    ///      recomputable on-chain and by any outside verifier.
    mapping(bytes32 => bytes) private _ruleDocuments;
    mapping(bytes32 => address[COMMITTEE_SIZE]) private _committeeMembers;

    bytes32[] private _tenderIds;

    /**
     * @notice The verifier version registry consulted at activation.
     *
     * @dev Optional (zero disables the check) so the registry can be deployed
     *      and wired after the tender module, which is the actual deployment
     *      order.
     *
     *      Why the check exists at all: `verifierVersion` is frozen into the
     *      fields digest at activation and there is deliberately no way to
     *      edit an active tender. Activating a tender that pins a version
     *      nobody has registered therefore produces a tender that is
     *      permanently unbiddable and can only be cancelled - a liveness
     *      failure created by a typo, discovered by the first bidder.
     */
    address public verifierVersionRegistry;

    /// @notice Addresses permitted to create tenders. Whitepaper Table 8:
    ///         "Multisig TENDER_AUTHORITY addresses create tenders".
    mapping(address => bool) public isTenderAuthority;

    error NotDraft(bytes32 tenderId, State actual);
    error NotActive(bytes32 tenderId, State actual);
    error EmptyRuleDocument();
    error CommitteeKeyNotSet(bytes32 tenderId);
    error CommitteeKeyAlreadySet(bytes32 tenderId);
    error DuplicateCommitteeMember(address member);
    error ZeroCommitteeMember(uint8 index);
    error InvalidCommitteePoint(uint8 index);
    error CommitteeKeyNotOnCurve(uint256 yX, uint256 yY);
    error CommitteeKeyNotInSubgroup(uint256 yX, uint256 yY);
    error CommitteeKeyNotCommitment0(uint256 yX, uint256 yY);
    error InconsistentFeldmanShare(uint8 memberIndex);
    error InvalidFeldmanCommitment(uint8 index);
    error InvalidRequirements();
    error TenderIdMismatch(uint256 expected, uint256 actual);
    error AuthorityAlreadySet(address authority);
    error ReviewWindowBelowMinimum(uint64 requested, uint64 minimum);
    error ReviewWindowNotSet(bytes32 tenderId);
    error InvalidState(bytes32 tenderId, State from, State to);
    error VerifierVersionNotRegistered(uint32 version);

    event TenderAuthoritySet(address indexed authority, bool allowed);
    event VerifierVersionRegistrySet(address indexed registry);
    event MinReviewWindowChanged(uint64 from, uint64 to, string reason);
    event TenderCreated(bytes32 indexed tenderId, string tenderIdString, address indexed authority);
    event RuleDocumentSet(bytes32 indexed tenderId, bytes32 rulesHash, uint256 documentLength);
    event CommitteeKeySet(bytes32 indexed tenderId, uint256 yX, uint256 yY, uint8 t, uint8 n);
    event TenderActivated(
        bytes32 indexed tenderId,
        bytes32 rulesHash,
        bytes32 fieldsDigest,
        uint64 activatedAt,
        uint64 biddingStart,
        uint64 deadline
    );
    event TenderClosed(bytes32 indexed tenderId, bytes32 deadlineRevocationRoot, uint64 closedAt);
    event TenderCancelled(bytes32 indexed tenderId, string reason, uint64 cancelledAt);
    event TenderStateChanged(bytes32 indexed tenderId, State from, State to);

    modifier onlyCouncil() {
        if (!governance.isCouncilMember(msg.sender)) revert NotCouncilMember(msg.sender);
        _;
    }

    modifier onlyAuthorityOf(bytes32 tenderId) {
        if (_tenders[tenderId].authority != msg.sender) revert NotAuthority(msg.sender);
        _;
    }

    modifier notPaused() {
        if (governance.paused()) revert SystemPaused();
        _;
    }

    constructor(
        Governance governance_,
        IssuerRegistry issuerRegistry_,
        uint64 initialMinReviewWindow
    ) {
        if (initialMinReviewWindow < ABSOLUTE_MIN_REVIEW_WINDOW) {
            revert ReviewWindowBelowMinimum(
                initialMinReviewWindow,
                ABSOLUTE_MIN_REVIEW_WINDOW
            );
        }
        governance = governance_;
        issuerRegistry = issuerRegistry_;
        minReviewWindow = initialMinReviewWindow;
    }

    /**
     * @notice Change the policy floor on the review window.
     * @dev Council only, with a mandatory reason. Raising it constrains future
     *      tenders more; lowering it can never pass the hard constant.
     *
     *      Tenders already ACTIVE are unaffected: each stores its own frozen
     *      `reviewWindow`, so a floor change cannot retroactively alter a
     *      running tender. Whitepaper Section 14: "No action rewrites an
     *      active tender's rules or verifier."
     */
    function setMinReviewWindow(uint64 window, string calldata reason)
        external
        onlyCouncil
    {
        if (window < ABSOLUTE_MIN_REVIEW_WINDOW) {
            revert ReviewWindowBelowMinimum(window, ABSOLUTE_MIN_REVIEW_WINDOW);
        }
        if (bytes(reason).length == 0) revert ReasonRequired();
        uint64 from = minReviewWindow;
        minReviewWindow = window;
        emit MinReviewWindowChanged(from, window, reason);
    }

    // ------------------------------------------------------------- authorities

    /**
     * @notice Wire the verifier version registry. Council only.
     * @dev Re-settable, because a verifier registry redeployment must not
     *      strand the tender module. It cannot affect an ACTIVE tender: the
     *      check runs once, at activation, and each tender's pinned version
     *      is already frozen in its fields digest.
     */
    function setVerifierVersionRegistry(address registry) external onlyCouncil {
        verifierVersionRegistry = registry;
        emit VerifierVersionRegistrySet(registry);
    }

    function setTenderAuthority(address authority, bool allowed) external onlyCouncil {
        isTenderAuthority[authority] = allowed;
        emit TenderAuthoritySet(authority, allowed);
    }

    // ------------------------------------------------------------------ create

    /**
     * @notice Create a tender in DRAFT.
     * @dev The derived `tenderIdField` is computed on-chain from the string,
     *      so the value the circuit binds to cannot be spoofed by the
     *      authority supplying an unrelated field element.
     */
    function createTender(string calldata tenderIdString) external notPaused returns (bytes32) {
        if (!isTenderAuthority[msg.sender]) revert NotAuthority(msg.sender);

        bytes32 tenderId = keccak256(abi.encodePacked(tenderIdString));
        if (_tenders[tenderId].state != State.NONE) revert TenderAlreadyExists(tenderId);

        Tender storage t = _tenders[tenderId];
        t.state = State.DRAFT;
        t.tenderIdString = tenderIdString;
        t.tenderIdField = FairProofEncoding.tenderIdField(tenderIdString);
        t.authority = msg.sender;
        _tenderIds.push(tenderId);

        emit TenderCreated(tenderId, tenderIdString, msg.sender);
        emit TenderStateChanged(tenderId, State.NONE, State.DRAFT);
        return tenderId;
    }

    // -------------------------------------------------------------- draft edits

    /**
     * @notice Store the canonical JCS rule document. DRAFT only.
     * @dev The contract computes rulesHash from these bytes itself.
     */
    function setRuleDocument(bytes32 tenderId, bytes calldata canonicalDocument)
        external
        onlyAuthorityOf(tenderId)
        notPaused
    {
        Tender storage t = _tenders[tenderId];
        if (t.state != State.DRAFT) revert RulesFrozen(tenderId);
        if (canonicalDocument.length == 0) revert EmptyRuleDocument();

        _ruleDocuments[tenderId] = canonicalDocument;
        bytes32 h = keccak256(canonicalDocument);
        t.rulesHash = h;

        emit RuleDocumentSet(tenderId, h, canonicalDocument.length);
    }

    /// @notice Set the structured, contract-enforced rule fields. DRAFT only.
    function setRuleFields(bytes32 tenderId, RuleFields calldata f)
        external
        onlyAuthorityOf(tenderId)
        notPaused
    {
        Tender storage t = _tenders[tenderId];
        if (t.state != State.DRAFT) revert RulesFrozen(tenderId);
        if (f.deadline <= f.biddingStart) {
            revert InvalidBiddingWindow(f.biddingStart, f.deadline);
        }
        // A zero threshold would make the eligibility predicate vacuous.
        if (f.requirements.turnoverThreshold == 0 || f.requirements.certificationCode == 0) {
            revert InvalidRequirements();
        }
        // The authority may grant MORE review time than the policy floor,
        // never less.
        if (f.reviewWindow < minReviewWindow) {
            revert ReviewWindowBelowMinimum(f.reviewWindow, minReviewWindow);
        }

        t.reviewWindow = f.reviewWindow;
        t.requirements = f.requirements;
        t.biddingStart = f.biddingStart;
        t.deadline = f.deadline;
        t.requiredIssuerId = f.requiredIssuerId;
        t.issuerEpoch = f.issuerEpoch;
        t.schemaVersion = f.schemaVersion;
        t.verifierVersion = f.verifierVersion;
        t.disclosurePolicy = f.disclosurePolicy;
        t.awardRule = f.awardRule;
        t.tieBreakRule = f.tieBreakRule;
        t.contingencyPolicy = f.contingencyPolicy;
    }

    /**
     * @notice Set the tender committee key. DRAFT only, one-shot.
     * @dev Plan Section 12.2: the key is dealt at activation by a Feldman VSS
     *      ceremony and the dealer's secret destroyed. The BIDDER MUST NOT be
     *      the dealer: if a bidder split its own data-encryption key it could
     *      hand out inconsistent shares and make its own bid permanently
     *      un-openable, breaking the completeness argument the award proof
     *      depends on.
     */
    function setCommitteeKey(
        bytes32 tenderId,
        uint256 yX,
        uint256 yY,
        address[COMMITTEE_SIZE] calldata members,
        uint256[COMMITTEE_SIZE] calldata memberX,
        uint256[COMMITTEE_SIZE] calldata memberY,
        uint256[COMMITTEE_THRESHOLD] calldata commitmentX,
        uint256[COMMITTEE_THRESHOLD] calldata commitmentY
    ) external onlyAuthorityOf(tenderId) notPaused {
        Tender storage t = _tenders[tenderId];
        if (t.state != State.DRAFT) revert RulesFrozen(tenderId);
        if (_committeeKeys[tenderId].set) revert CommitteeKeyAlreadySet(tenderId);
        // ---- the dealing is verified ON-CHAIN, not merely recorded ------
        //
        // Feldman VSS makes a dealing publicly checkable: given the
        // commitments C_0..C_2 to the dealer's polynomial coefficients,
        // anyone can confirm that a published member share is the correct
        // evaluation of that polynomial. Doing it here rather than leaving it
        // to members turns "a dishonest dealer is detectable" into "a
        // dishonest dealer is rejected".
        //
        // What this does NOT do is hide the secret from the dealer. This is a
        // trusted-dealer ceremony (whitepaper Section 19.1 concedes DKG is
        // production design), so the residual is narrowed to exactly one
        // thing: the dealer briefly knew x. It can no longer deal
        // inconsistent shares, claim a public key the shares cannot open, or
        // hand a member someone else's share.

        // Y must be a real subgroup point. `inCurve` alone is not enough:
        // the group order is 8 * SUB_ORDER, and encrypting to a point with a
        // small-order component leaks information about the plaintext. Every
        // bidder encrypts to this key, so the check happens before any of
        // them can.
        // Two checks, in this order, with distinct errors: a point that is
        // not on the curve at all should not be reported as a subgroup
        // failure, and rejecting it first also avoids paying for a 251-bit
        // scalar multiplication to learn something cheap arithmetic already
        // decided.
        if (!BabyJubjub.inCurve(yX, yY)) revert CommitteeKeyNotOnCurve(yX, yY);
        if (!BabyJubjub.isInPrimeSubgroup(yX, yY)) {
            revert CommitteeKeyNotInSubgroup(yX, yY);
        }

        uint256[] memory cx = new uint256[](COMMITTEE_THRESHOLD);
        uint256[] memory cy = new uint256[](COMMITTEE_THRESHOLD);
        for (uint8 j = 0; j < COMMITTEE_THRESHOLD; j++) {
            if (!BabyJubjub.inCurve(commitmentX[j], commitmentY[j])) {
                revert InvalidFeldmanCommitment(j);
            }
            cx[j] = commitmentX[j];
            cy[j] = commitmentY[j];
        }

        // C_0 = a_0 * G and a_0 IS the secret, so C_0 must equal Y. If these
        // differed, bidders would encrypt to a key the shares cannot open and
        // every bid in the tender would be permanently unopenable.
        if (cx[0] != yX || cy[0] != yY) revert CommitteeKeyNotCommitment0(yX, yY);

        for (uint8 i = 0; i < COMMITTEE_SIZE; i++) {
            if (members[i] == address(0)) revert ZeroCommitteeMember(i);
            if (!BabyJubjub.inCurve(memberX[i], memberY[i])) {
                revert InvalidCommitteePoint(i);
            }
            for (uint8 j = 0; j < i; j++) {
                // A duplicate member would let one person hold two of the
                // three shares needed to open.
                if (members[j] == members[i]) revert DuplicateCommitteeMember(members[i]);
            }
            // Member indices are 1-BASED. Index 0 evaluates the polynomial at
            // zero, which is the secret itself, so no member may hold it.
            BabyJubjub.Proj memory expected =
                BabyJubjub.expectedPublicShare(cx, cy, uint256(i) + 1);
            if (!BabyJubjub.equalsAffine(expected, memberX[i], memberY[i])) {
                revert InconsistentFeldmanShare(i + 1);
            }
        }

        CommitteeKey storage k = _committeeKeys[tenderId];
        k.yX = yX;
        k.yY = yY;
        k.memberX = memberX;
        k.memberY = memberY;
        k.commitmentX = commitmentX;
        k.commitmentY = commitmentY;
        k.set = true;
        _committeeMembers[tenderId] = members;

        emit CommitteeKeySet(tenderId, yX, yY, COMMITTEE_THRESHOLD, COMMITTEE_SIZE);
    }

    // ---------------------------------------------------------------- activate

    /**
     * @notice Activate and FREEZE the tender. Irreversible.
     *
     * @param expectedRulesHash The hash the authority believes it is freezing.
     *        Checked against the contract's own recomputation, so activation
     *        cannot succeed against a document the authority did not intend.
     */
    function activateTender(bytes32 tenderId, bytes32 expectedRulesHash)
        external
        onlyAuthorityOf(tenderId)
        notPaused
    {
        Tender storage t = _tenders[tenderId];
        if (t.state != State.DRAFT) revert NotDraft(tenderId, t.state);

        // Every required field must be present. Activating a half-built
        // tender would freeze an incomplete rule set.
        bytes memory doc = _ruleDocuments[tenderId];
        if (doc.length == 0) revert EmptyRuleDocument();
        if (t.deadline == 0 || t.biddingStart == 0) {
            revert InvalidBiddingWindow(t.biddingStart, t.deadline);
        }
        if (t.requirements.turnoverThreshold == 0) revert InvalidRequirements();
        if (!_committeeKeys[tenderId].set) revert CommitteeKeyNotSet(tenderId);

        // Refuse to freeze a pin that cannot be honoured. See
        // `verifierVersionRegistry`.
        address vreg = verifierVersionRegistry;
        if (
            vreg != address(0) &&
            !IVerifierVersionRegistry(vreg).isVersionRegistered(t.verifierVersion)
        ) {
            revert VerifierVersionNotRegistered(t.verifierVersion);
        }

        // Recompute rulesHash on-chain from the stored document. This is the
        // whitepaper's exact value, and nobody has to trust the authority for
        // it.
        bytes32 recomputed = keccak256(doc);
        if (recomputed != expectedRulesHash) {
            revert RulesHashMismatch(expectedRulesHash, recomputed);
        }
        t.rulesHash = recomputed;

        uint64 nowTs = uint64(block.timestamp);

        // The mandatory public rule-review window (whitepaper Table 11),
        // using this tender's own window. Re-checked against the policy floor
        // here as well as in setRuleFields, so a floor RAISED between
        // drafting and activation still applies.
        if (t.reviewWindow == 0) revert ReviewWindowNotSet(tenderId);
        if (t.reviewWindow < minReviewWindow) {
            revert ReviewWindowBelowMinimum(t.reviewWindow, minReviewWindow);
        }
        uint64 earliest = nowTs + t.reviewWindow;
        if (t.biddingStart < earliest) {
            revert ReviewWindowTooShort(t.biddingStart, earliest);
        }
        if (t.deadline <= t.biddingStart) {
            revert InvalidBiddingWindow(t.biddingStart, t.deadline);
        }

        t.activatedAt = nowTs;
        t.fieldsDigest = _computeFieldsDigest(t);
        t.state = State.ACTIVE;

        emit TenderActivated(
            tenderId,
            t.rulesHash,
            t.fieldsDigest,
            nowTs,
            t.biddingStart,
            t.deadline
        );
        emit TenderStateChanged(tenderId, State.DRAFT, State.ACTIVE);
    }

    /// @dev Canonical digest over the structured fields the contract enforces.
    function _computeFieldsDigest(Tender storage t) private view returns (bytes32) {
        // Two-stage encode: a single abi.encode over all fourteen fields
        // exceeded the stack depth. The nesting is fixed and documented, so
        // the digest stays reproducible off-chain.
        bytes32 a = keccak256(
            abi.encode(
                "FairProof:ruleFields:v1",
                t.tenderIdField,
                t.requirements.turnoverThreshold,
                t.requirements.experienceMonths,
                t.requirements.certificationCode,
                t.biddingStart,
                t.deadline
            )
        );
        bytes32 b = keccak256(
            abi.encode(
                t.requiredIssuerId,
                t.issuerEpoch,
                t.schemaVersion,
                t.verifierVersion,
                t.disclosurePolicy,
                t.awardRule,
                t.tieBreakRule,
                t.contingencyPolicy,
                t.reviewWindow
            )
        );
        return keccak256(abi.encode(a, b));
    }

    // ------------------------------------------------------------------- close

    /**
     * @notice Close the tender after the deadline and pin the deadline
     *         revocation root.
     * @dev Permissionless on purpose: anybody may close a tender whose
     *      deadline has passed. If only the authority could close, it could
     *      stall a tender it disliked by simply never closing it.
     */
    function closeTender(bytes32 tenderId) external notPaused {
        Tender storage t = _tenders[tenderId];
        if (t.state != State.ACTIVE) revert NotActive(tenderId, t.state);
        if (block.timestamp < t.deadline) {
            revert DeadlineNotReached(t.deadline, uint64(block.timestamp));
        }

        t.state = State.CLOSED;

        // Whitepaper Section 5: pin the deadline root so "unrevoked at
        // deadline" is not inferred from an older submission snapshot.
        bytes32 root = issuerRegistry.pinDeadlineRevocationRoot(tenderId);

        emit TenderClosed(tenderId, root, uint64(block.timestamp));
        emit TenderStateChanged(tenderId, State.ACTIVE, State.CLOSED);
    }

    // ------------------------------------------------------------------ cancel

    /**
     * @notice Cancel a tender with a recorded reason. Council, 3-of-4 gated.
     * @dev Whitepaper Section 14 commits to "cancellation and versioned
     *      reissue" instead of in-place amendment, and Section 14 again:
     *      "The prototype supports no in-place deadline extension: an outage
     *      invokes cancellation and versioned reissue under the precommitted
     *      contingency policy."
     *
     *      Cancellation is NOT a rewrite: it terminates the tender and
     *      records why. There is deliberately no function here that edits an
     *      active tender's rules, deadline or verifier version.
     */
    function cancelTender(bytes32 tenderId, string calldata reason) external onlyCouncil {
        Tender storage t = _tenders[tenderId];
        State from = t.state;
        if (from == State.NONE) revert TenderNotFound(tenderId);
        if (from == State.AWARDED || from == State.CANCELLED) {
            revert InvalidState(tenderId, from, State.CANCELLED);
        }
        if (bytes(reason).length == 0) revert ReasonRequired();

        t.state = State.CANCELLED;
        emit TenderCancelled(tenderId, reason, uint64(block.timestamp));
        emit TenderStateChanged(tenderId, from, State.CANCELLED);
    }

    // ------------------------------------------------------------------- views

    function getTender(bytes32 tenderId) external view returns (Tender memory) {
        if (_tenders[tenderId].state == State.NONE) revert TenderNotFound(tenderId);
        return _tenders[tenderId];
    }

    function getRuleDocument(bytes32 tenderId) external view returns (bytes memory) {
        return _ruleDocuments[tenderId];
    }

    /// @notice Recompute rulesHash from the stored document. Anyone may call.
    function recomputeRulesHash(bytes32 tenderId) external view returns (bytes32) {
        return keccak256(_ruleDocuments[tenderId]);
    }

    function getCommitteeKey(bytes32 tenderId) external view returns (CommitteeKey memory) {
        if (!_committeeKeys[tenderId].set) revert CommitteeKeyNotSet(tenderId);
        return _committeeKeys[tenderId];
    }

    function getCommitteeMembers(bytes32 tenderId)
        external
        view
        returns (address[COMMITTEE_SIZE] memory)
    {
        return _committeeMembers[tenderId];
    }

    function getState(bytes32 tenderId) external view returns (State) {
        return _tenders[tenderId].state;
    }

    /// @notice True while the bidding window is open. Used by SealedBid.
    function isBiddingOpen(bytes32 tenderId) external view returns (bool) {
        Tender storage t = _tenders[tenderId];
        return
            t.state == State.ACTIVE &&
            block.timestamp >= t.biddingStart &&
            block.timestamp < t.deadline;
    }

    function tenderCount() external view returns (uint256) {
        return _tenderIds.length;
    }

    function tenderIdAt(uint256 index) external view returns (bytes32) {
        return _tenderIds[index];
    }
}
