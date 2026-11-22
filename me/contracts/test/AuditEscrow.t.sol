// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuditRegistry} from "../src/AuditRegistry.sol";
import {AuditEscrow} from "../src/AuditEscrow.sol";

/// Auditor contract whose receive() tries to settle/refund again while being paid.
contract GreedyAuditor {
    AuditEscrow public escrow;
    AuditRegistry public reg;
    uint256 public reqId;
    uint256 public recId;
    uint256 public reentryAttempts;
    bool public reentrySucceeded;

    constructor(AuditEscrow e, AuditRegistry r) {
        escrow = e;
        reg = r;
    }

    function registerRecord(AuditRegistry.RecordInput calldata input) external returns (uint256) {
        return reg.register(input);
    }

    function settle(uint256 q, uint256 r) external {
        reqId = q;
        recId = r;
        escrow.settle(q, r);
    }

    receive() external payable {
        reentryAttempts++;
        try escrow.settle(reqId, recId) {
            reentrySucceeded = true;
        } catch {}
        try escrow.refundExpired(reqId) {
            reentrySucceeded = true;
        } catch {}
    }
}

contract RevertingRequester {
    function ask(AuditEscrow e, bytes32 src, address auditor) external payable returns (uint256) {
        return e.request{value: msg.value}(src, auditor, 1 days);
    }
    // no receive(): refunds to this contract fail
}

contract AuditEscrowTest is Test {
    AuditRegistry reg;
    AuditEscrow escrow;
    address requester = makeAddr("requester");
    address auditor = makeAddr("auditor");
    address other = makeAddr("other");
    bytes32 constant SRC = keccak256("contract source");
    uint256 constant FEE = 0.05 ether;

    function setUp() public {
        reg = new AuditRegistry();
        escrow = new AuditEscrow(reg);
        vm.deal(requester, 10 ether);
        vm.warp(1_700_000_000);
    }

    function _input(uint8 verdict, bytes32 src) internal pure returns (AuditRegistry.RecordInput memory r) {
        r.sourceHash = src;
        r.verdict = verdict;
        r.model = "arbiter-gpt";
        if (verdict == 3) {
            r.predicateClass = 2;
            r.evidenceTier = 3;
            r.exploitHash = keccak256("exploit");
        }
    }

    function _request() internal returns (uint256 id) {
        vm.prank(requester);
        id = escrow.request{value: FEE}(SRC, auditor, 1 days);
    }

    function _record(address who, uint8 verdict, bytes32 src) internal returns (uint256) {
        vm.prank(who);
        return reg.register(_input(verdict, src));
    }

    function _settle(uint256 q, uint256 r) internal {
        vm.prank(auditor);
        escrow.settle(q, r);
    }

    // ------------------------------------------------------------------ request

    function test_request_storesAndHoldsFee() public {
        reg.register(_input(1, SRC)); // record 1 exists before the request
        uint256 id = _request();
        assertEq(id, 1);
        assertEq(address(escrow).balance, FEE);
        AuditEscrow.Request memory q = escrow.getRequest(id);
        assertEq(q.requester, requester);
        assertEq(q.auditor, auditor);
        assertEq(q.sourceHash, SRC);
        assertEq(q.fee, FEE);
        assertEq(q.createdAt, 1_700_000_000);
        assertEq(q.deadline, 1_700_000_000 + 1 days);
        assertEq(q.status, escrow.STATUS_OPEN());
        assertEq(q.minRecordId, 2);
    }

    function test_request_validation() public {
        vm.startPrank(requester);
        vm.expectRevert(AuditEscrow.NoFee.selector);
        escrow.request(SRC, auditor, 1 days);
        vm.expectRevert(AuditEscrow.ZeroSourceHash.selector);
        escrow.request{value: 1}(bytes32(0), auditor, 1 days);
        vm.expectRevert(AuditEscrow.ZeroAuditor.selector);
        escrow.request{value: 1}(SRC, address(0), 1 days);
        vm.expectRevert(AuditEscrow.BadTtl.selector);
        escrow.request{value: 1}(SRC, auditor, 59 minutes);
        vm.expectRevert(AuditEscrow.BadTtl.selector);
        escrow.request{value: 1}(SRC, auditor, 31 days);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------ settle

    function test_settle_paysAuditorForEveryFinishedVerdict() public {
        for (uint8 v = 1; v <= 3; v++) {
            uint256 q = _request();
            vm.warp(block.timestamp + 10 minutes);
            uint256 r = _record(auditor, v, SRC);
            uint256 before = auditor.balance;
            _settle(q, r);
            assertEq(auditor.balance - before, FEE, "auditor paid regardless of conclusion");
            assertEq(escrow.getRequest(q).status, escrow.STATUS_PAID());
            assertEq(escrow.getRequest(q).recordId, r);
            assertEq(escrow.settledBy(r), q);
        }
        assertEq(address(escrow).balance, 0);
    }

    function test_settle_refundsWhenAuditDidNotFinish() public {
        uint256 q = _request();
        uint256 r = _record(auditor, 0, SRC);
        uint256 before = requester.balance;
        _settle(q, r);
        assertEq(requester.balance - before, FEE);
        assertEq(escrow.getRequest(q).status, escrow.STATUS_REFUNDED());
    }

    /// Review finding: the choice of record belongs to the auditor, not to whoever calls first.
    function test_settle_onlyByTheNamedAuditor() public {
        uint256 q = _request();
        uint256 r = _record(auditor, 1, SRC);
        vm.prank(requester);
        vm.expectRevert(AuditEscrow.NotAuditor.selector);
        escrow.settle(q, r);
        vm.prank(other);
        vm.expectRevert(AuditEscrow.NotAuditor.selector);
        escrow.settle(q, r);
        _settle(q, r);
    }

    function test_settle_rejectsWrongRecordAuditorSourceOrLateRecord() public {
        uint256 q = _request();

        uint256 byOther = _record(other, 1, SRC);
        vm.prank(auditor);
        vm.expectRevert(AuditEscrow.WrongAuditor.selector);
        escrow.settle(q, byOther);

        uint256 wrongSrc = _record(auditor, 1, keccak256("another source"));
        vm.prank(auditor);
        vm.expectRevert(AuditEscrow.WrongSource.selector);
        escrow.settle(q, wrongSrc);

        vm.warp(block.timestamp + 1 days + 1);
        uint256 late = _record(auditor, 1, SRC); // registered after the deadline
        vm.prank(auditor);
        vm.expectRevert(AuditEscrow.OutsideWindow.selector);
        escrow.settle(q, late);
    }

    /// Review finding: a record made in the same block but before the request does not count.
    function test_settle_rejectsRecordMadeBeforeRequestEvenInSameBlock() public {
        uint256 early = _record(auditor, 1, SRC);
        uint256 q = _request(); // same block.timestamp
        vm.prank(auditor);
        vm.expectRevert(AuditEscrow.RecordTooOld.selector);
        escrow.settle(q, early);
    }

    /// Review finding: settlement and expiry never overlap.
    function test_settleGraceThenExpiry() public {
        uint256 q = _request();
        vm.warp(block.timestamp + 1 days); // exactly at the deadline
        uint256 r = _record(auditor, 1, SRC);
        vm.warp(block.timestamp + 1 hours); // end of grace
        vm.expectRevert(AuditEscrow.NotExpired.selector);
        escrow.refundExpired(q);
        _settle(q, r); // still allowed

        uint256 q2 = _request();
        vm.warp(block.timestamp + 1 days + 1 hours + 1);
        uint256 r2 = _record(auditor, 1, SRC);
        vm.prank(auditor);
        vm.expectRevert(AuditEscrow.OutsideWindow.selector);
        escrow.settle(q2, r2);
        escrow.refundExpired(q2);
    }

    function test_settle_oneRecordPaysOnce() public {
        uint256 q1 = _request();
        uint256 q2 = _request();
        uint256 r = _record(auditor, 1, SRC);
        _settle(q1, r);
        vm.prank(auditor);
        vm.expectRevert(abi.encodeWithSelector(AuditEscrow.RecordAlreadyUsed.selector, q1));
        escrow.settle(q2, r);
        vm.prank(auditor);
        vm.expectRevert(AuditEscrow.NotOpen.selector);
        escrow.settle(q1, r);
    }

    function test_settle_unknownIds() public {
        vm.expectRevert(abi.encodeWithSelector(AuditEscrow.UnknownRequest.selector, 1));
        escrow.settle(1, 1);
        uint256 q = _request();
        vm.prank(auditor);
        vm.expectRevert(abi.encodeWithSelector(AuditRegistry.UnknownRecord.selector, 5));
        escrow.settle(q, 5);
    }

    function test_settle_reentrantAuditorGetsPaidOnce() public {
        GreedyAuditor g = new GreedyAuditor(escrow, reg);
        vm.prank(requester);
        uint256 q = escrow.request{value: FEE}(SRC, address(g), 1 days);
        vm.prank(requester);
        escrow.request{value: FEE}(SRC, address(g), 1 days); // a second open request, same source
        uint256 r = g.registerRecord(_input(1, SRC));
        g.settle(q, r);
        assertEq(address(g).balance, FEE);
        assertEq(g.reentryAttempts(), 1);
        assertFalse(g.reentrySucceeded());
        assertEq(address(escrow).balance, FEE); // the other request's fee is untouched
    }

    // ------------------------------------------------------------------ refundExpired

    function test_refundExpired_onlyAfterDeadlineAndGrace() public {
        uint256 q = _request();
        vm.warp(block.timestamp + 1 days + 1 hours);
        vm.expectRevert(AuditEscrow.NotExpired.selector);
        escrow.refundExpired(q);
        vm.warp(block.timestamp + 1);
        uint256 before = requester.balance;
        vm.prank(other); // anyone may trigger the refund
        escrow.refundExpired(q);
        assertEq(requester.balance - before, FEE);
        vm.expectRevert(AuditEscrow.NotOpen.selector);
        escrow.refundExpired(q);
    }

    function test_refundExpired_cannotAfterSettle() public {
        uint256 q = _request();
        uint256 r = _record(auditor, 2, SRC);
        _settle(q, r);
        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(AuditEscrow.NotOpen.selector);
        escrow.refundExpired(q);
    }

    function test_failedRefundTransferRevertsAndKeepsRequestOpen() public {
        RevertingRequester rr = new RevertingRequester();
        vm.deal(address(rr), 1 ether);
        uint256 q = rr.ask{value: FEE}(escrow, SRC, auditor);
        uint256 r = _record(auditor, 0, SRC);
        vm.prank(auditor);
        vm.expectRevert(AuditEscrow.TransferFailed.selector);
        escrow.settle(q, r);
        assertEq(escrow.getRequest(q).status, escrow.STATUS_OPEN());
        assertEq(address(escrow).balance, FEE);
    }

    // ------------------------------------------------------------------ fuzz

    function testFuzz_feeConservation(uint96 fee, uint8 verdict) public {
        verdict = uint8(bound(verdict, 0, 3));
        vm.assume(fee > 0);
        vm.deal(requester, uint256(fee));
        vm.prank(requester);
        uint256 q = escrow.request{value: fee}(SRC, auditor, 1 hours);
        uint256 r = _record(auditor, verdict, SRC);
        uint256 a0 = auditor.balance;
        uint256 q0 = requester.balance;
        _settle(q, r);
        uint256 paid = (auditor.balance - a0) + (requester.balance - q0);
        assertEq(paid, fee);
        assertEq(address(escrow).balance, 0);
        if (verdict == 0) assertEq(requester.balance - q0, fee);
        else assertEq(auditor.balance - a0, fee);
    }
}
