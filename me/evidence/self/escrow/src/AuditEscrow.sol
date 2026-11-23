// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {AuditRegistry} from "./AuditRegistry.sol";

/// @title AuditEscrow
/// @notice Pay for an ARBITER Gate audit in MEC (the chain's native coin).
///
/// A requester locks a fee for one source hash and names the auditor address. The auditor
/// settles the request with one of its own registry records made after the request:
///   - the audit finished (verdict 1, 2 or 3) -> the auditor is paid;
///   - the audit did not finish (verdict 0)   -> the requester is refunded.
/// If the auditor does not settle within the deadline plus a grace period, anyone can return the
/// fee to the requester. The fee never depends on which conclusion the audit reached, so an
/// auditor gains nothing by reporting a more favourable verdict. Each record settles at most one
/// request.
contract AuditEscrow {
    AuditRegistry public immutable registry;

    uint64 public constant MIN_TTL = 1 hours;
    uint64 public constant MAX_TTL = 30 days;
    /// Time after the deadline in which the auditor may still settle with a record made before
    /// the deadline. Settlement and expiry never overlap.
    uint64 public constant SETTLE_GRACE = 1 hours;

    uint8 public constant STATUS_NONE = 0;
    uint8 public constant STATUS_OPEN = 1;
    uint8 public constant STATUS_PAID = 2; // fee went to the auditor
    uint8 public constant STATUS_REFUNDED = 3; // fee went back to the requester

    struct Request {
        address requester;
        address auditor;
        bytes32 sourceHash;
        uint128 fee;
        uint64 createdAt;
        uint64 deadline; // the record must be registered by this time
        uint8 status;
        uint256 minRecordId; // only records registered after the request count
        uint256 recordId; // record that settled it; 0 if refunded after expiry
    }

    uint256 public requestCount;
    mapping(uint256 => Request) private _requests;
    mapping(uint256 => uint256) private _settledBy; // record id -> request id

    event Requested(
        uint256 indexed requestId,
        address indexed requester,
        address indexed auditor,
        bytes32 sourceHash,
        uint256 fee,
        uint64 deadline
    );
    event Settled(
        uint256 indexed requestId, uint256 indexed recordId, address indexed recipient, uint256 amount, bool refunded
    );
    event Expired(uint256 indexed requestId, address indexed requester, uint256 amount);

    error NoFee();
    error FeeTooLarge();
    error ZeroSourceHash();
    error ZeroAuditor();
    error BadTtl();
    error UnknownRequest(uint256 requestId);
    error NotOpen();
    error NotAuditor();
    error WrongAuditor();
    error WrongSource();
    error RecordTooOld();
    error OutsideWindow();
    error RecordAlreadyUsed(uint256 requestId);
    error NotExpired();
    error TransferFailed();

    constructor(AuditRegistry registry_) {
        registry = registry_;
    }

    /// @notice Lock `msg.value` as the fee for auditing `sourceHash`, to be done by `auditor`
    /// within `ttl` seconds.
    function request(bytes32 sourceHash, address auditor, uint64 ttl) external payable returns (uint256 requestId) {
        if (msg.value == 0) revert NoFee();
        if (msg.value > type(uint128).max) revert FeeTooLarge();
        if (sourceHash == bytes32(0)) revert ZeroSourceHash();
        if (auditor == address(0)) revert ZeroAuditor();
        if (ttl < MIN_TTL || ttl > MAX_TTL) revert BadTtl();

        requestId = ++requestCount;
        uint64 deadline = uint64(block.timestamp) + ttl;
        _requests[requestId] = Request({
            requester: msg.sender,
            auditor: auditor,
            sourceHash: sourceHash,
            fee: uint128(msg.value),
            createdAt: uint64(block.timestamp),
            deadline: deadline,
            status: STATUS_OPEN,
            minRecordId: registry.recordCount() + 1,
            recordId: 0
        });
        emit Requested(requestId, msg.sender, auditor, sourceHash, msg.value, deadline);
    }

    /// @notice The auditor settles an open request with one of its records.
    function settle(uint256 requestId, uint256 recordId) external {
        Request storage q = _open(requestId);
        if (msg.sender != q.auditor) revert NotAuditor();
        if (block.timestamp > uint256(q.deadline) + SETTLE_GRACE) revert OutsideWindow();
        if (_settledBy[recordId] != 0) revert RecordAlreadyUsed(_settledBy[recordId]);
        if (recordId < q.minRecordId) revert RecordTooOld();

        AuditRegistry.Record memory r = registry.getRecord(recordId);
        if (r.auditor != q.auditor) revert WrongAuditor();
        if (r.input.sourceHash != q.sourceHash) revert WrongSource();
        if (r.timestamp > q.deadline) revert OutsideWindow();

        bool refunded = r.input.verdict == registry.VERDICT_UNDETERMINED();
        address recipient = refunded ? q.requester : q.auditor;
        uint256 amount = q.fee;

        // effects before the transfer
        q.status = refunded ? STATUS_REFUNDED : STATUS_PAID;
        q.recordId = recordId;
        _settledBy[recordId] = requestId;
        emit Settled(requestId, recordId, recipient, amount, refunded);

        _send(recipient, amount);
    }

    /// @notice After the deadline and the grace period, an unsettled request's fee goes back to
    /// the requester. Anyone may call this.
    function refundExpired(uint256 requestId) external {
        Request storage q = _open(requestId);
        if (block.timestamp <= uint256(q.deadline) + SETTLE_GRACE) revert NotExpired();
        uint256 amount = q.fee;
        address requester = q.requester;
        q.status = STATUS_REFUNDED;
        emit Expired(requestId, requester, amount);
        _send(requester, amount);
    }

    function getRequest(uint256 requestId) external view returns (Request memory) {
        if (requestId == 0 || requestId > requestCount) revert UnknownRequest(requestId);
        return _requests[requestId];
    }

    /// @notice Request id settled by `recordId`, or 0.
    function settledBy(uint256 recordId) external view returns (uint256) {
        return _settledBy[recordId];
    }

    function _open(uint256 requestId) private view returns (Request storage q) {
        if (requestId == 0 || requestId > requestCount) revert UnknownRequest(requestId);
        q = _requests[requestId];
        if (q.status != STATUS_OPEN) revert NotOpen();
    }

    function _send(address to, uint256 amount) private {
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }
}
