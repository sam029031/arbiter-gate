// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

/// @title AuditRegistry
/// @notice Append-only, on-chain record of ARBITER Gate audit results on ME Network.
///
/// A record says: "this auditor address, at this block time, registered this verdict for the
/// code with this hash, and these are the hashes of the evidence files". The contract cannot
/// tell whether a verdict is right; that is decided off-chain by re-running the evidence, and a
/// reader decides which auditor addresses to trust. What the contract does enforce:
///   - a record is internally consistent (a proven exploit must come with an exploit hash, and
///     nothing else may carry one; a derived record must come from the same auditor);
///   - records are never edited or deleted;
///   - `deployAudited` deploys only the exact audited creation bytecode, never for a record that
///     proved an attack or could not finish, and never for bytecode the same auditor has
///     recorded as exploitable;
///   - the link between a gated deployment and its record is written by the contract itself.
///
/// There is deliberately no "safe" field. Verdict 1 means "no provable attack was found", which
/// is not the same as "safe".
contract AuditRegistry {
    // ---------------------------------------------------------------- verdicts (gate exit code)
    uint8 public constant VERDICT_UNDETERMINED = 0; // audit did not finish (exit 2)
    uint8 public constant VERDICT_NO_PROVEN_EXPLOIT = 1; // no provable attack found (exit 0)
    uint8 public constant VERDICT_STATIC_HINT = 2; // static-tool hints only, nothing proven (exit 0)
    uint8 public constant VERDICT_PROVEN_EXPLOIT = 3; // an attack was executed and proven (exit 1)

    // ---------------------------------------------------------------- predicate class of a proof
    uint8 public constant PRED_NONE = 0;
    uint8 public constant PRED_LOOSE = 1; // eth_profit / token_profit / state_change
    uint8 public constant PRED_STRICT = 2; // victim_loss (with conservation) / liveness_broken

    // ---------------------------------------------------------------- how a deployment was linked
    uint8 public constant LINK_NONE = 0;
    uint8 public constant LINK_CLAIMED = 1; // the auditor says this address runs the audited code
    uint8 public constant LINK_GATED = 2; // this contract deployed the exact audited bytecode

    uint256 public constant MAX_MODEL_BYTES = 64;
    uint256 public constant MAX_URI_BYTES = 256;

    /// @notice What the registrant supplies. Everything else in a Record is filled by the contract.
    struct RecordInput {
        bytes32 sourceHash; // sha256 of the audited Solidity source file (sha256sum-compatible)
        bytes32 initcodeHash; // keccak256 of the creation bytecode incl. constructor args; 0 = none
        uint8 verdict; // VERDICT_*
        uint8 predicateClass; // PRED_*; non-zero only for a proven exploit
        uint8 evidenceTier; // evidence ladder 1..3 for a proven exploit, else 0
        bytes32 gateJsonHash; // sha256 of gate.json
        bytes32 exploitHash; // sha256 of the proven exploit source; non-zero only for a proven exploit
        bytes32 patchHash; // sha256 of the patch: suggested (verdict 3) or applied (derived record)
        uint256 parentId; // record this one derives from (patched version -> original); 0 = none
        bytes20 toolCommit; // git commit of the ARBITER Gate code that produced the result
        string model; // model name, at most MAX_MODEL_BYTES bytes
        string evidenceURI; // "https://..." folder with the evidence bundle, or empty
    }

    struct Record {
        RecordInput input;
        address auditor; // msg.sender of register()
        uint64 timestamp; // block.timestamp of register()
        address deployed; // first linked address (gated or claimed); 0 if none
        bytes32 runtimeCodeHash; // codehash of `deployed` at link time
        uint8 linkKind; // LINK_* of the first link
    }

    uint256 public recordCount;
    mapping(uint256 => Record) private _records;
    mapping(bytes32 => uint256[]) private _bySource;
    mapping(bytes32 => uint256[]) private _byInitcode;
    mapping(bytes32 => uint256[]) private _byCodehash;
    mapping(uint256 => uint256[]) private _children;
    mapping(uint256 => address[]) private _deployments; // every gated deployment of a record
    mapping(address => uint256) private _gatedOf; // address -> record that deployed it (gated only)
    mapping(address => uint256[]) private _claimsOf; // address -> records whose auditor claims it
    mapping(address => mapping(bytes32 => uint256)) private _latest; // auditor -> sourceHash -> id
    mapping(address => mapping(bytes32 => bool)) private _provenInit; // auditor -> initcode -> proven

    event Registered(
        uint256 indexed id, bytes32 indexed sourceHash, address indexed auditor, uint8 verdict, uint256 parentId
    );
    event Linked(uint256 indexed id, address indexed deployed, bytes32 runtimeCodeHash, uint8 linkKind);

    error ZeroSourceHash();
    error OutOfRange();
    error InconsistentProof();
    error BadParent();
    error TooLong();
    error BadURI();
    error UnknownRecord(uint256 id);
    error NotAuditor();
    error AlreadyLinked();
    error NotDeployable(uint8 verdict);
    error ContradictsProvenRecord();
    error NoCode();
    error InitcodeMismatch();
    error AddressTaken();
    error DeployFailed();

    // ======================================================================== writes

    /// @notice Append a record. Returns its id (ids start at 1).
    function register(RecordInput calldata input) external returns (uint256 id) {
        if (input.sourceHash == bytes32(0)) revert ZeroSourceHash();
        if (input.verdict > VERDICT_PROVEN_EXPLOIT || input.predicateClass > PRED_STRICT || input.evidenceTier > 3) {
            revert OutOfRange();
        }
        if (input.verdict == VERDICT_PROVEN_EXPLOIT) {
            if (input.predicateClass == PRED_NONE || input.exploitHash == bytes32(0) || input.evidenceTier == 0) {
                revert InconsistentProof();
            }
        } else if (input.predicateClass != PRED_NONE || input.exploitHash != bytes32(0) || input.evidenceTier != 0) {
            revert InconsistentProof();
        }
        if (input.parentId != 0) {
            // A derived (patched) record comes from the same auditor, names its patch, and audits
            // different source than its parent.
            if (input.parentId > recordCount || input.patchHash == bytes32(0)) revert BadParent();
            Record storage parent = _records[input.parentId];
            if (parent.auditor != msg.sender || parent.input.sourceHash == input.sourceHash) revert BadParent();
        }
        if (bytes(input.model).length > MAX_MODEL_BYTES || bytes(input.evidenceURI).length > MAX_URI_BYTES) {
            revert TooLong();
        }
        if (!_validURI(bytes(input.evidenceURI))) revert BadURI();

        id = ++recordCount;
        Record storage r = _records[id];
        RecordInput storage s = r.input;
        s.sourceHash = input.sourceHash;
        s.initcodeHash = input.initcodeHash;
        s.verdict = input.verdict;
        s.predicateClass = input.predicateClass;
        s.evidenceTier = input.evidenceTier;
        s.gateJsonHash = input.gateJsonHash;
        s.exploitHash = input.exploitHash;
        s.patchHash = input.patchHash;
        s.parentId = input.parentId;
        s.toolCommit = input.toolCommit;
        s.model = input.model;
        s.evidenceURI = input.evidenceURI;
        r.auditor = msg.sender;
        r.timestamp = uint64(block.timestamp);

        _bySource[input.sourceHash].push(id);
        _latest[msg.sender][input.sourceHash] = id;
        if (input.initcodeHash != bytes32(0)) {
            _byInitcode[input.initcodeHash].push(id);
            if (input.verdict == VERDICT_PROVEN_EXPLOIT) _provenInit[msg.sender][input.initcodeHash] = true;
        }
        if (input.parentId != 0) _children[input.parentId].push(id);
        emit Registered(id, input.sourceHash, msg.sender, input.verdict, input.parentId);
    }

    /// @notice The auditor of `id` says `deployed` runs the audited code. The contract records the
    /// address's current code hash; it does not prove the code came from the audited source
    /// (compare runtimeCodeHash with a local build). Claims are not exclusive: several auditors
    /// may claim the same address, and a claim never blocks a gated deployment.
    function linkDeployment(uint256 id, address deployed) external {
        Record storage r = _record(id);
        if (msg.sender != r.auditor) revert NotAuditor();
        _requireDeployableVerdict(r);
        if (r.linkKind != LINK_NONE) revert AlreadyLinked();
        if (deployed.code.length == 0) revert NoCode();
        bytes32 h = deployed.codehash;
        r.deployed = deployed;
        r.runtimeCodeHash = h;
        r.linkKind = LINK_CLAIMED;
        _claimsOf[deployed].push(id);
        _byCodehash[h].push(id);
        emit Linked(id, deployed, h, LINK_CLAIMED);
    }

    /// @notice Deploy the exact audited creation bytecode with CREATE2 and link it to `id`.
    /// Anyone may call this: the audit record, not the caller, authorises the bytecode. The
    /// address depends on (id, caller, salt), so nobody can take another caller's address or
    /// attach a different record to it. A record may be deployed any number of times.
    /// Inside the deployed constructor msg.sender is this registry, so contracts that take their
    /// owner from msg.sender should receive the owner as a constructor argument instead.
    function deployAudited(uint256 id, bytes calldata initcode, bytes32 salt) external returns (address deployed) {
        Record storage r = _record(id);
        _requireDeployableVerdict(r);
        bytes32 expected = r.input.initcodeHash;
        if (expected == bytes32(0) || keccak256(initcode) != expected) revert InitcodeMismatch();
        if (_provenInit[r.auditor][expected]) revert ContradictsProvenRecord();
        bytes32 bound = _boundSalt(id, msg.sender, salt);
        // A CREATE2 collision would burn all forwarded gas; fail cheaply instead.
        if (_predict(expected, bound).code.length != 0) revert AddressTaken();

        bytes memory code = initcode;
        assembly ("memory-safe") {
            deployed := create2(0, add(code, 0x20), mload(code), bound)
        }
        if (deployed == address(0) || deployed.code.length == 0) revert DeployFailed();

        bytes32 h = deployed.codehash;
        _gatedOf[deployed] = id;
        _deployments[id].push(deployed);
        if (r.linkKind == LINK_NONE) {
            r.deployed = deployed;
            r.runtimeCodeHash = h;
            r.linkKind = LINK_GATED;
            _byCodehash[h].push(id);
        }
        emit Linked(id, deployed, h, LINK_GATED);
    }

    // ======================================================================== reads

    function getRecord(uint256 id) external view returns (Record memory) {
        return _record(id);
    }

    /// @notice Record that deployed `deployed` through deployAudited, or 0. Only gated
    /// deployments appear here; claims are in claimsOf.
    function deploymentOf(address deployed) external view returns (uint256) {
        return _gatedOf[deployed];
    }

    /// @notice Records whose auditor claimed `deployed` via linkDeployment (unverified claims).
    function claimsOf(address deployed) external view returns (uint256[] memory) {
        return _claimsOf[deployed];
    }

    /// @notice Every address deployed from record `id` through deployAudited.
    function deploymentsOf(uint256 id) external view returns (address[] memory) {
        return _deployments[id];
    }

    /// @notice Latest record `auditor` registered for `sourceHash`, or 0. Use this when you trust
    /// a specific auditor: other registrants cannot crowd it out.
    function latestRecord(address auditor, bytes32 sourceHash) external view returns (uint256) {
        return _latest[auditor][sourceHash];
    }

    /// @notice True when `deployed` still runs the code that was linked to its record. Can turn
    /// false on chains with SELFDESTRUCT (ME's EVM is London-level).
    function isLinkCurrent(uint256 id) external view returns (bool) {
        Record storage r = _record(id);
        return r.linkKind != LINK_NONE && r.deployed.code.length != 0 && r.deployed.codehash == r.runtimeCodeHash;
    }

    /// @notice Address `deployAudited(id, initcode, salt)` sent by `caller` will produce.
    function predictAddress(uint256 id, address caller, bytes32 salt) external view returns (address) {
        return _predict(_record(id).input.initcodeHash, _boundSalt(id, caller, salt));
    }

    // Index views. Anyone can append to these lists, so each comes with a count and a paged read;
    // the whole-list variants are a convenience for short lists.
    function recordsBySource(bytes32 sourceHash) external view returns (uint256[] memory) {
        return _bySource[sourceHash];
    }

    function recordsByInitcode(bytes32 initcodeHash) external view returns (uint256[] memory) {
        return _byInitcode[initcodeHash];
    }

    /// @notice Records linked to some deployment whose runtime code hash is `runtimeCodeHash`.
    /// Runtime code does not cover constructor arguments or storage, so this is a hint, not an
    /// audit lookup for an arbitrary address; use deploymentOf / claimsOf for that.
    function recordsByCodehash(bytes32 runtimeCodeHash) external view returns (uint256[] memory) {
        return _byCodehash[runtimeCodeHash];
    }

    function childrenOf(uint256 id) external view returns (uint256[] memory) {
        return _children[id];
    }

    function recordsBySourceCount(bytes32 sourceHash) external view returns (uint256) {
        return _bySource[sourceHash].length;
    }

    function recordsBySourcePage(bytes32 sourceHash, uint256 start, uint256 count)
        external
        view
        returns (uint256[] memory)
    {
        return _page(_bySource[sourceHash], start, count);
    }

    function recordsByInitcodeCount(bytes32 initcodeHash) external view returns (uint256) {
        return _byInitcode[initcodeHash].length;
    }

    function recordsByInitcodePage(bytes32 initcodeHash, uint256 start, uint256 count)
        external
        view
        returns (uint256[] memory)
    {
        return _page(_byInitcode[initcodeHash], start, count);
    }

    function childrenCount(uint256 id) external view returns (uint256) {
        return _children[id].length;
    }

    function childrenPage(uint256 id, uint256 start, uint256 count) external view returns (uint256[] memory) {
        return _page(_children[id], start, count);
    }

    // ======================================================================== internals

    function _record(uint256 id) private view returns (Record storage r) {
        if (id == 0 || id > recordCount) revert UnknownRecord(id);
        r = _records[id];
    }

    function _requireDeployableVerdict(Record storage r) private view {
        uint8 v = r.input.verdict;
        if (v != VERDICT_NO_PROVEN_EXPLOIT && v != VERDICT_STATIC_HINT) revert NotDeployable(v);
    }

    function _boundSalt(uint256 id, address caller, bytes32 salt) private pure returns (bytes32) {
        return keccak256(abi.encode(id, caller, salt));
    }

    function _predict(bytes32 initcodeHash, bytes32 bound) private view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), bound, initcodeHash)))));
    }

    function _page(uint256[] storage list, uint256 start, uint256 count) private view returns (uint256[] memory out) {
        uint256 n = list.length;
        if (start >= n) return new uint256[](0);
        uint256 end = start + count < n ? start + count : n;
        out = new uint256[](end - start);
        for (uint256 i = start; i < end; i++) {
            out[i - start] = list[i];
        }
    }

    /// Empty, or "https://" followed by printable ASCII without quotes, angle brackets or
    /// backslashes, so a page that renders the link cannot be tricked into javascript: URLs or
    /// broken markup.
    function _validURI(bytes memory u) private pure returns (bool) {
        if (u.length == 0) return true;
        bytes memory p = "https://";
        if (u.length <= p.length) return false;
        for (uint256 i = 0; i < p.length; i++) {
            if (u[i] != p[i]) return false;
        }
        for (uint256 i = p.length; i < u.length; i++) {
            bytes1 c = u[i];
            if (c <= 0x20 || c >= 0x7f || c == '"' || c == "'" || c == "<" || c == ">" || c == "\\" || c == "`") {
                return false;
            }
        }
        return true;
    }
}
