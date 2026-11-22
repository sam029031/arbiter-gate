// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuditRegistry} from "../src/AuditRegistry.sol";

contract Dummy {
    uint256 public immutable x;

    constructor(uint256 x_) {
        x = x_;
    }
}

/// Constructor that re-enters the registry and tries to deploy the same record again.
contract ReentrantChild {
    constructor(AuditRegistry reg, uint256 id, bytes memory otherInitcode) {
        reg.deployAudited(id, otherInitcode, bytes32(uint256(99)));
    }
}

contract AuditRegistryTest is Test {
    AuditRegistry reg;
    address auditor = makeAddr("auditor");
    address stranger = makeAddr("stranger");
    address deployer = makeAddr("deployer");

    bytes32 constant SRC = keccak256("source v1");
    bytes32 constant SRC2 = keccak256("source v2 (patched)");
    bytes32 constant GATE = keccak256("gate.json");
    bytes32 constant EXPLOIT = keccak256("exploit.sol");
    bytes32 constant PATCH = keccak256("patch.diff");

    event Registered(
        uint256 indexed id, bytes32 indexed sourceHash, address indexed auditor, uint8 verdict, uint256 parentId
    );
    event Linked(uint256 indexed id, address indexed deployed, bytes32 runtimeCodeHash, uint8 linkKind);

    function setUp() public {
        reg = new AuditRegistry();
    }

    // ------------------------------------------------------------------ helpers

    function _input(uint8 verdict) internal pure returns (AuditRegistry.RecordInput memory r) {
        r.sourceHash = SRC;
        r.verdict = verdict;
        r.gateJsonHash = GATE;
        r.toolCommit = bytes20(uint160(0x66a8f21));
        r.model = "arbiter-gpt";
        r.evidenceURI = "https://example.invalid/evidence/1/";
        if (verdict == 3) {
            r.predicateClass = 2;
            r.evidenceTier = 3;
            r.exploitHash = EXPLOIT;
            r.patchHash = PATCH;
        }
    }

    function _dummyInitcode(uint256 x) internal pure returns (bytes memory) {
        return abi.encodePacked(type(Dummy).creationCode, abi.encode(x));
    }

    function _registerDeployable(address who, bytes memory initcode) internal returns (uint256 id) {
        AuditRegistry.RecordInput memory r = _input(1);
        r.initcodeHash = keccak256(initcode);
        vm.prank(who);
        id = reg.register(r);
    }

    // ------------------------------------------------------------------ register

    function test_register_assignsSequentialIdsAndFillsContractFields() public {
        vm.warp(1_700_000_000);
        vm.expectEmit(true, true, true, true);
        emit Registered(1, SRC, auditor, 3, 0);
        vm.prank(auditor);
        uint256 id = reg.register(_input(3));
        assertEq(id, 1);
        assertEq(reg.recordCount(), 1);

        AuditRegistry.Record memory rec = reg.getRecord(1);
        assertEq(rec.auditor, auditor);
        assertEq(rec.timestamp, 1_700_000_000);
        assertEq(rec.input.sourceHash, SRC);
        assertEq(rec.input.verdict, 3);
        assertEq(rec.input.predicateClass, 2);
        assertEq(rec.input.evidenceTier, 3);
        assertEq(rec.input.exploitHash, EXPLOIT);
        assertEq(rec.input.patchHash, PATCH);
        assertEq(rec.input.gateJsonHash, GATE);
        assertEq(rec.input.model, "arbiter-gpt");
        assertEq(rec.deployed, address(0));
        assertEq(rec.linkKind, 0);

        vm.prank(stranger);
        assertEq(reg.register(_input(1)), 2);
        uint256[] memory ids = reg.recordsBySource(SRC);
        assertEq(ids.length, 2);
        assertEq(ids[0], 1);
        assertEq(ids[1], 2);
        assertEq(reg.latestRecord(auditor, SRC), 1);
        assertEq(reg.latestRecord(stranger, SRC), 2);
        assertEq(reg.latestRecord(deployer, SRC), 0);
    }

    function test_register_rejectsZeroSourceHash() public {
        AuditRegistry.RecordInput memory r = _input(1);
        r.sourceHash = bytes32(0);
        vm.expectRevert(AuditRegistry.ZeroSourceHash.selector);
        reg.register(r);
    }

    function test_register_rejectsOutOfRange() public {
        AuditRegistry.RecordInput memory r = _input(1);
        r.verdict = 4;
        vm.expectRevert(AuditRegistry.OutOfRange.selector);
        reg.register(r);

        r = _input(3);
        r.predicateClass = 3;
        vm.expectRevert(AuditRegistry.OutOfRange.selector);
        reg.register(r);

        r = _input(3);
        r.evidenceTier = 4;
        vm.expectRevert(AuditRegistry.OutOfRange.selector);
        reg.register(r);
    }

    function test_register_provenExploitNeedsPredicateExploitAndTier() public {
        AuditRegistry.RecordInput memory r = _input(3);
        r.predicateClass = 0;
        vm.expectRevert(AuditRegistry.InconsistentProof.selector);
        reg.register(r);

        r = _input(3);
        r.exploitHash = bytes32(0);
        vm.expectRevert(AuditRegistry.InconsistentProof.selector);
        reg.register(r);

        r = _input(3);
        r.evidenceTier = 0;
        vm.expectRevert(AuditRegistry.InconsistentProof.selector);
        reg.register(r);
    }

    function test_register_otherVerdictsMustNotCarryProof() public {
        for (uint8 v = 0; v < 3; v++) {
            AuditRegistry.RecordInput memory r = _input(v);
            r.exploitHash = EXPLOIT;
            vm.expectRevert(AuditRegistry.InconsistentProof.selector);
            reg.register(r);

            r = _input(v);
            r.predicateClass = 1;
            vm.expectRevert(AuditRegistry.InconsistentProof.selector);
            reg.register(r);

            r = _input(v);
            r.evidenceTier = 1;
            vm.expectRevert(AuditRegistry.InconsistentProof.selector);
            reg.register(r);
        }
    }

    function test_register_parentChain() public {
        vm.prank(auditor);
        uint256 original = reg.register(_input(3));

        AuditRegistry.RecordInput memory child = _input(1);
        child.sourceHash = SRC2;
        child.parentId = original;
        child.patchHash = PATCH;
        vm.prank(auditor);
        uint256 c = reg.register(child);

        uint256[] memory kids = reg.childrenOf(original);
        assertEq(kids.length, 1);
        assertEq(kids[0], c);
        assertEq(reg.childrenCount(original), 1);
        assertEq(reg.getRecord(c).input.parentId, original);
    }

    function test_register_parentRules() public {
        AuditRegistry.RecordInput memory r = _input(1);
        r.sourceHash = SRC2;
        r.patchHash = PATCH;
        r.parentId = 1; // nothing registered yet
        vm.expectRevert(AuditRegistry.BadParent.selector);
        vm.prank(auditor);
        reg.register(r);

        vm.prank(auditor);
        reg.register(_input(3)); // record 1

        // same source as the parent
        AuditRegistry.RecordInput memory same = _input(1);
        same.parentId = 1;
        same.patchHash = PATCH;
        vm.expectRevert(AuditRegistry.BadParent.selector);
        vm.prank(auditor);
        reg.register(same);

        // a derived record must name its patch
        AuditRegistry.RecordInput memory noPatch = _input(1);
        noPatch.sourceHash = SRC2;
        noPatch.parentId = 1;
        vm.expectRevert(AuditRegistry.BadParent.selector);
        vm.prank(auditor);
        reg.register(noPatch);

        // another registrant cannot hang records under someone else's audit
        vm.expectRevert(AuditRegistry.BadParent.selector);
        vm.prank(stranger);
        reg.register(r);

        vm.prank(auditor);
        reg.register(r); // the auditor itself may
    }

    function test_register_rejectsLongStrings() public {
        AuditRegistry.RecordInput memory r = _input(1);
        r.model = string(new bytes(65));
        vm.expectRevert(AuditRegistry.TooLong.selector);
        reg.register(r);

        r = _input(1);
        r.evidenceURI = string(abi.encodePacked("https://", new bytes(249)));
        vm.expectRevert(AuditRegistry.TooLong.selector);
        reg.register(r);

        r = _input(1);
        r.model = string(new bytes(64));
        bytes memory u = new bytes(248);
        for (uint256 i = 0; i < u.length; i++) {
            u[i] = "a";
        }
        r.evidenceURI = string(abi.encodePacked("https://", u)); // 256 bytes: limits are inclusive
        reg.register(r);
    }

    function test_register_evidenceURIMustBeHttpsAndPlain() public {
        string[6] memory bad = [
            "javascript:alert(1)",
            "http://example.com/e/",
            "https://",
            "https://a b",
            "https://x/\"><script>",
            "ipfs://bafy"
        ];
        for (uint256 i = 0; i < bad.length; i++) {
            AuditRegistry.RecordInput memory r = _input(1);
            r.evidenceURI = bad[i];
            vm.expectRevert(AuditRegistry.BadURI.selector);
            reg.register(r);
        }
        AuditRegistry.RecordInput memory ok = _input(1);
        ok.evidenceURI = "";
        reg.register(ok);
        ok.evidenceURI = "https://raw.githubusercontent.com/o/r/b/me/evidence/1/";
        reg.register(ok);
    }

    function test_getRecord_unknownIdReverts() public {
        vm.expectRevert(abi.encodeWithSelector(AuditRegistry.UnknownRecord.selector, 0));
        reg.getRecord(0);
        vm.expectRevert(abi.encodeWithSelector(AuditRegistry.UnknownRecord.selector, 1));
        reg.getRecord(1);
    }

    // ------------------------------------------------------------------ deployAudited

    function test_deployAudited_deploysExactBytecodeAndLinks() public {
        bytes memory init = _dummyInitcode(42);
        uint256 id = _registerDeployable(auditor, init);
        bytes32 salt = bytes32(uint256(7));
        address predicted = reg.predictAddress(id, deployer, salt);

        vm.prank(deployer); // anyone may deploy what was audited
        address d = reg.deployAudited(id, init, salt);

        assertEq(d, predicted);
        assertEq(Dummy(d).x(), 42);
        AuditRegistry.Record memory rec = reg.getRecord(id);
        assertEq(rec.deployed, d);
        assertEq(rec.runtimeCodeHash, d.codehash);
        assertEq(rec.linkKind, reg.LINK_GATED());
        assertEq(reg.deploymentOf(d), id);
        assertTrue(reg.isLinkCurrent(id));
        uint256[] memory byCode = reg.recordsByCodehash(d.codehash);
        assertEq(byCode.length, 1);
        assertEq(byCode[0], id);
        address[] memory deps = reg.deploymentsOf(id);
        assertEq(deps.length, 1);
        assertEq(deps[0], d);
    }

    function test_deployAudited_emitsLinked() public {
        bytes memory init = _dummyInitcode(1);
        uint256 id = _registerDeployable(auditor, init);
        address predicted = reg.predictAddress(id, address(this), bytes32(0));
        vm.expectEmit(true, true, false, false);
        emit Linked(id, predicted, bytes32(0), 2);
        reg.deployAudited(id, init, bytes32(0));
    }

    function test_deployAudited_rejectsDifferentBytecode() public {
        uint256 id = _registerDeployable(auditor, _dummyInitcode(42));
        bytes memory other = _dummyInitcode(43); // different constructor argument
        vm.expectRevert(AuditRegistry.InitcodeMismatch.selector);
        reg.deployAudited(id, other, bytes32(0));
    }

    function test_deployAudited_rejectsRecordWithoutInitcodeHash() public {
        vm.prank(auditor);
        uint256 id = reg.register(_input(1)); // initcodeHash = 0
        vm.expectRevert(AuditRegistry.InitcodeMismatch.selector);
        reg.deployAudited(id, "", bytes32(0));
    }

    function test_deployAudited_blocksProvenExploitAndUndetermined() public {
        bytes memory init = _dummyInitcode(1);

        AuditRegistry.RecordInput memory proven = _input(3);
        proven.initcodeHash = keccak256(init);
        uint256 a = reg.register(proven);
        vm.expectRevert(abi.encodeWithSelector(AuditRegistry.NotDeployable.selector, 3));
        reg.deployAudited(a, init, bytes32(0));

        AuditRegistry.RecordInput memory undetermined = _input(0);
        undetermined.initcodeHash = keccak256(init);
        uint256 b = reg.register(undetermined);
        vm.expectRevert(abi.encodeWithSelector(AuditRegistry.NotDeployable.selector, 0));
        reg.deployAudited(b, init, bytes32(0));
    }

    function test_deployAudited_auditorCannotContradictItsOwnProof() public {
        bytes memory init = _dummyInitcode(1);
        AuditRegistry.RecordInput memory proven = _input(3);
        proven.initcodeHash = keccak256(init);
        vm.prank(auditor);
        uint256 p = reg.register(proven);

        // the same auditor later records verdict 1 for identical bytecode: not deployable
        uint256 ok = _registerDeployable(auditor, init);
        vm.expectRevert(AuditRegistry.ContradictsProvenRecord.selector);
        reg.deployAudited(ok, init, bytes32(0));

        // a different auditor's verdict-1 record still deploys (readers see both records)
        uint256 other = _registerDeployable(stranger, init);
        reg.deployAudited(other, init, bytes32(0));
        uint256[] memory sameCode = reg.recordsByInitcode(keccak256(init));
        assertEq(sameCode.length, 3);
        assertEq(sameCode[0], p);
        assertEq(reg.recordsByInitcodeCount(keccak256(init)), 3);
    }

    function test_deployAudited_staticHintIsDeployable() public {
        bytes memory init = _dummyInitcode(5);
        AuditRegistry.RecordInput memory r = _input(2);
        r.initcodeHash = keccak256(init);
        uint256 id = reg.register(r);
        address d = reg.deployAudited(id, init, bytes32(0));
        assertEq(reg.deploymentOf(d), id);
    }

    function test_deployAudited_manyDeploymentsPerRecord() public {
        bytes memory init = _dummyInitcode(1);
        uint256 id = _registerDeployable(auditor, init);
        address d1 = reg.deployAudited(id, init, bytes32(0));
        vm.prank(stranger);
        address d2 = reg.deployAudited(id, init, bytes32(0)); // another caller: another address
        address d3 = reg.deployAudited(id, init, bytes32(uint256(1)));
        assertTrue(d1 != d2 && d2 != d3 && d1 != d3);
        assertEq(reg.deploymentOf(d1), id);
        assertEq(reg.deploymentOf(d2), id);
        assertEq(reg.deploymentOf(d3), id);
        assertEq(reg.deploymentsOf(id).length, 3);
        assertEq(reg.getRecord(id).deployed, d1); // the record keeps its first link
        assertEq(reg.recordsByCodehash(d1.codehash).length, 1);
    }

    function test_deployAudited_sameCallerSameSaltTwiceFailsCheaply() public {
        bytes memory init = _dummyInitcode(1);
        uint256 id = _registerDeployable(auditor, init);
        reg.deployAudited(id, init, bytes32(0));
        vm.expectRevert(AuditRegistry.AddressTaken.selector);
        reg.deployAudited(id, init, bytes32(0));
    }

    /// Review finding (front-running): a copycat record with the same initcode hash cannot take
    /// the address the honest deployer planned, nor attach itself to it.
    function test_deployAudited_copycatRecordCannotTakePlannedAddress() public {
        bytes memory init = _dummyInitcode(7);
        uint256 honest = _registerDeployable(auditor, init);
        bytes32 salt = bytes32(uint256(5));
        address planned = reg.predictAddress(honest, deployer, salt);

        uint256 copycat = _registerDeployable(stranger, init);
        vm.prank(stranger);
        address taken = reg.deployAudited(copycat, init, salt); // same salt, copied from the mempool
        assertTrue(taken != planned);

        vm.prank(deployer);
        address d = reg.deployAudited(honest, init, salt);
        assertEq(d, planned);
        assertEq(reg.deploymentOf(planned), honest);
    }

    /// Review finding (griefing): a third party deploying the record with its own salt neither
    /// blocks the deployer nor lands on the deployer's address.
    function test_deployAudited_strangerCannotBurnTheRecord() public {
        bytes memory init = _dummyInitcode(8);
        uint256 id = _registerDeployable(auditor, init);
        address planned = reg.predictAddress(id, deployer, bytes32(0));
        vm.prank(stranger, stranger);
        reg.deployAudited(id, init, bytes32(uint256(0xbad)));
        vm.prank(deployer);
        assertEq(reg.deployAudited(id, init, bytes32(0)), planned);
    }

    function test_deployAudited_reentrantConstructorFails() public {
        bytes memory inner = _dummyInitcode(9);
        AuditRegistry.RecordInput memory r = _input(1);
        uint256 expectedId = reg.recordCount() + 1;
        bytes memory outer =
            abi.encodePacked(type(ReentrantChild).creationCode, abi.encode(address(reg), expectedId, inner));
        r.initcodeHash = keccak256(outer);
        uint256 id = reg.register(r);
        assertEq(id, expectedId);
        // the inner call fails InitcodeMismatch (inner != outer), so the whole deployment fails
        vm.expectRevert(AuditRegistry.DeployFailed.selector);
        reg.deployAudited(id, outer, bytes32(0));
        assertEq(reg.getRecord(id).linkKind, 0);
        assertEq(reg.deploymentsOf(id).length, 0);
    }

    // ------------------------------------------------------------------ linkDeployment (claims)

    function test_linkDeployment_auditorClaimsExistingCode() public {
        Dummy d = new Dummy(3);
        vm.prank(auditor);
        uint256 id = reg.register(_input(1));
        vm.prank(auditor);
        reg.linkDeployment(id, address(d));
        AuditRegistry.Record memory rec = reg.getRecord(id);
        assertEq(rec.deployed, address(d));
        assertEq(rec.runtimeCodeHash, address(d).codehash);
        assertEq(rec.linkKind, reg.LINK_CLAIMED());
        assertEq(reg.deploymentOf(address(d)), 0); // claims never fill the gated slot
        uint256[] memory claims = reg.claimsOf(address(d));
        assertEq(claims.length, 1);
        assertEq(claims[0], id);
        assertTrue(reg.isLinkCurrent(id));
    }

    function test_linkDeployment_onlyAuditor() public {
        Dummy d = new Dummy(3);
        vm.prank(auditor);
        uint256 id = reg.register(_input(1));
        vm.prank(stranger);
        vm.expectRevert(AuditRegistry.NotAuditor.selector);
        reg.linkDeployment(id, address(d));
    }

    function test_linkDeployment_rejectsEoaProvenAndSecondLink() public {
        Dummy d = new Dummy(3);
        vm.startPrank(auditor);
        uint256 ok = reg.register(_input(1));
        vm.expectRevert(AuditRegistry.NoCode.selector);
        reg.linkDeployment(ok, stranger);

        uint256 proven = reg.register(_input(3));
        vm.expectRevert(abi.encodeWithSelector(AuditRegistry.NotDeployable.selector, 3));
        reg.linkDeployment(proven, address(d));

        reg.linkDeployment(ok, address(d));
        vm.expectRevert(AuditRegistry.AlreadyLinked.selector);
        reg.linkDeployment(ok, address(d));
        vm.stopPrank();
    }

    /// Review finding (squatting): an early claim by someone else does not lock out the real
    /// auditor or a gated deployment.
    function test_linkDeployment_claimsAreNotExclusive() public {
        Dummy d = new Dummy(3);
        vm.prank(stranger);
        uint256 squat = reg.register(_input(1));
        vm.prank(stranger);
        reg.linkDeployment(squat, address(d));

        vm.prank(auditor);
        uint256 real = reg.register(_input(2));
        vm.prank(auditor);
        reg.linkDeployment(real, address(d));
        assertEq(reg.claimsOf(address(d)).length, 2);

        bytes memory init = _dummyInitcode(3);
        uint256 gated = _registerDeployable(auditor, init);
        address g = reg.deployAudited(gated, init, bytes32(0));
        assertEq(reg.deploymentOf(g), gated);
    }

    // ------------------------------------------------------------------ paging

    function test_paging() public {
        for (uint256 i = 0; i < 5; i++) {
            reg.register(_input(1));
        }
        assertEq(reg.recordsBySourceCount(SRC), 5);
        uint256[] memory p = reg.recordsBySourcePage(SRC, 1, 2);
        assertEq(p.length, 2);
        assertEq(p[0], 2);
        assertEq(p[1], 3);
        assertEq(reg.recordsBySourcePage(SRC, 4, 10).length, 1);
        assertEq(reg.recordsBySourcePage(SRC, 9, 10).length, 0);
        assertEq(reg.childrenPage(1, 0, 10).length, 0);
        assertEq(reg.recordsByInitcodePage(bytes32(0), 0, 10).length, 0); // zero hashes are not indexed
    }

    // ------------------------------------------------------------------ fuzz

    function testFuzz_registerRules(uint8 verdict, uint8 pred, uint8 tier, bool hasExploit) public {
        AuditRegistry.RecordInput memory r = _input(1);
        r.verdict = verdict;
        r.predicateClass = pred;
        r.evidenceTier = tier;
        r.exploitHash = hasExploit ? EXPLOIT : bytes32(0);

        bool inRange = verdict <= 3 && pred <= 2 && tier <= 3;
        bool consistent = verdict == 3 ? (pred != 0 && hasExploit && tier != 0) : (pred == 0 && !hasExploit && tier == 0);
        if (!inRange) {
            vm.expectRevert(AuditRegistry.OutOfRange.selector);
        } else if (!consistent) {
            vm.expectRevert(AuditRegistry.InconsistentProof.selector);
        }
        reg.register(r);
    }

    function testFuzz_onlyVerdict1and2Deploy(uint8 verdict) public {
        verdict = uint8(bound(verdict, 0, 3));
        bytes memory init = _dummyInitcode(uint256(verdict));
        AuditRegistry.RecordInput memory r = _input(verdict);
        r.initcodeHash = keccak256(init);
        uint256 id = reg.register(r);
        if (verdict == 1 || verdict == 2) {
            reg.deployAudited(id, init, bytes32(0));
        } else {
            vm.expectRevert(abi.encodeWithSelector(AuditRegistry.NotDeployable.selector, verdict));
            reg.deployAudited(id, init, bytes32(0));
        }
    }

    function testFuzz_addressIsBoundToRecordCallerAndSalt(address a, address b, bytes32 s1, bytes32 s2) public {
        vm.assume(a != b);
        bytes memory init = _dummyInitcode(11);
        uint256 id1 = _registerDeployable(auditor, init);
        uint256 id2 = _registerDeployable(stranger, init);
        assertTrue(reg.predictAddress(id1, a, s1) != reg.predictAddress(id2, a, s1));
        assertTrue(reg.predictAddress(id1, a, s1) != reg.predictAddress(id1, b, s1));
        if (s1 != s2) assertTrue(reg.predictAddress(id1, a, s1) != reg.predictAddress(id1, a, s2));
    }
}
