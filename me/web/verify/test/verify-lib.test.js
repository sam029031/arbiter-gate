// Unit tests for verify-lib.js (no network, no browser):  node --test me/web/verify/test/
// vectors.json is encoded by Foundry `cast` (python3 me/scripts/verify_page_fixture.py --vectors …).
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const L = require("../verify-lib.js");

const REPO = path.resolve(__dirname, "../../../..");
const V = JSON.parse(fs.readFileSync(path.join(__dirname, "vectors.json"), "utf8"));

test("verdict labels are the gate's own labels (arbiter/verdict.py)", () => {
  const src = fs.readFileSync(path.join(REPO, "arbiter/arbiter/verdict.py"), "utf8");
  const label = (k) => src.match(new RegExp(`^\\s+${k}: "([^"]+)",`, "m"))[1];
  assert.equal(L.verdictInfo(3).label, label("PROVEN"));
  assert.equal(L.verdictInfo(2).label, label("STATIC_HINT"));
  assert.equal(L.verdictInfo(1).label, label("NO_PROVABLE"));
  assert.equal(L.verdictInfo(0).label, label("NOT_EXECUTED"));
  assert.match(L.verdictInfo(9).label, /未知/);
});

test("no label calls anything safe (only the negation 不等於安全 is allowed)", () => {
  const tables = [L.VERDICTS, L.PREDICATES, L.TIERS, L.LINKS, L.ESCROW_STATUS];
  for (const t of tables) {
    for (const v of Object.values(t)) {
      for (const s of [v.label, v.desc || ""]) {
        assert.equal(s.replace(/不等於安全/g, "").includes("安全"), false, s);
        assert.equal(/CLEAR|首創/.test(s), false, s);
      }
    }
  }
});

test("selectors and event topics match cast, for every function the page calls", () => {
  assert.deepEqual(Object.keys(L.FUNCS).sort(), Object.keys(V.selectors).sort());
  assert.deepEqual(Object.keys(L.FUNC_SIGS).sort(), Object.keys(V.selectors).sort());
  for (const [fn, sel] of Object.entries(V.selectors)) assert.equal(L.FUNCS[fn][0], sel, fn);
  for (const [ev, topic] of Object.entries(V.topics)) assert.equal(L.TOPICS[ev], topic, ev);
  // the v2 selectors named in the build brief
  assert.equal(L.FUNCS.claimsOf[0], "0x01d81d92");
  assert.equal(L.FUNCS.deploymentsOf[0], "0x096ffd3d");
});

test("encodeCall matches cast calldata and rejects bad arguments", () => {
  for (const c of V.calls) assert.equal(L.encodeCall(c.fn, c.args), c.hex, c.fn);
  assert.throws(() => L.encodeCall("getRecord", []));
  assert.throws(() => L.encodeCall("deploymentOf", ["0x1234"]));
  assert.throws(() => L.encodeCall("latestRecord", [V.meAddresses[0].hex, "0x12"]));
  assert.throws(() => L.encodeCall("getRecord", ["-1"]));
  assert.throws(() => L.encodeCall("nope", []));
});

test("decodeRecord decodes cast-encoded records (UTF-8 strings, empty strings)", () => {
  for (const { hex, expect } of V.records) {
    const r = L.decodeRecord(hex);
    assert.deepEqual(r.input, expect.input);
    assert.equal(r.auditor, expect.auditor.toLowerCase());
    assert.equal(r.timestamp, expect.timestamp);
    assert.equal(r.deployed, expect.deployed.toLowerCase());
    assert.equal(r.runtimeCodeHash, expect.runtimeCodeHash);
    assert.equal(r.linkKind, expect.linkKind);
  }
});

test("decodeRequest (escrow v2: minRecordId before recordId), arrays, numbers, bools", () => {
  const { hex, expect } = V.requests[0];
  const q = L.decodeRequest(hex);
  assert.equal(q.requester, expect.requester.toLowerCase());
  assert.equal(q.auditor, expect.auditor.toLowerCase());
  assert.equal(q.sourceHash, expect.sourceHash);
  assert.equal(q.fee, BigInt(expect.fee));
  for (const k of ["createdAt", "deadline", "status", "minRecordId", "recordId"]) assert.equal(q[k], expect[k], k);
  assert.throws(() => L.decodeRequest(hex.slice(0, 2 + 64 * 8)), /長度/); // a v1 (8-field) request is refused
  for (const a of V.uintArrays) assert.deepEqual(L.decodeUintArray(a.hex), a.expect);
  for (const a of V.addressArrays) assert.deepEqual(L.decodeAddressArray(a.hex), a.expect.map((x) => x.toLowerCase()));
  for (const b of V.bools) assert.equal(L.decodeBool(b.hex), b.expect);
  assert.throws(() => L.decodeBool("0x" + "0".repeat(63) + "2"));
  assert.equal(L.decodeNumber("0x" + "0".repeat(62) + "2a"), 42);
});

test("decoders refuse junk instead of inventing values", () => {
  assert.throws(() => L.decodeRecord("0x"), /空資料/);
  assert.throws(() => L.decodeRecord("0x1234"));
  assert.throws(() => L.decodeRecord(V.records[0].hex.slice(0, 300)));
  assert.throws(() => L.decodeUintArray("0x" + "0".repeat(62) + "20" + "f".repeat(64)));
  assert.throws(() => L.decodeNumber("not hex"));
});

test("decodeLog reads Registered / Linked / Settled and ignores others", () => {
  for (const { topics, data, expect } of V.logs) {
    const got = L.decodeLog({ topics, data });
    for (const [k, v] of Object.entries(expect)) {
      const want = typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v) ? v.toLowerCase()
        : k === "amount" ? BigInt(v) : v;
      assert.deepEqual(got[k], want, k);
    }
  }
  assert.equal(L.decodeLog({ topics: ["0x" + "12".repeat(32)], data: "0x" }), null);
  assert.equal(L.decodeLog({ topics: [L.TOPICS.Registered], data: "0x" }), null); // missing topics
  assert.equal(L.decodeLog(null), null);
});

test("sha256Hex (WebCrypto) matches Python hashlib", async () => {
  for (const { text, hex } of V.sha256) {
    assert.equal(await L.sha256Hex(new TextEncoder().encode(text)), hex);
  }
});

test("me1 addresses round-trip and bad checksums are refused", () => {
  for (const { hex, me } of V.meAddresses) {
    assert.equal(L.toMeAddress(hex), me);
    assert.equal(L.fromMeAddress(me), hex.toLowerCase());
    assert.equal(L.fromMeAddress(me.toUpperCase()), hex.toLowerCase());
    const bad = me.slice(0, -1) + (me.endsWith("q") ? "p" : "q");
    assert.equal(L.fromMeAddress(bad), null);
  }
  assert.equal(L.toMeAddress("0x12"), null);
});

test("classifyQuery: id, address, me1, hash, junk", () => {
  assert.deepEqual(L.classifyQuery(" 12 "), { kind: "record", id: 12 });
  assert.deepEqual(L.classifyQuery("#3"), { kind: "record", id: 3 });
  assert.equal(L.classifyQuery("0").kind, "invalid");
  const a = V.meAddresses[0];
  assert.deepEqual(L.classifyQuery(a.hex), { kind: "address", value: a.hex.toLowerCase() });
  assert.deepEqual(L.classifyQuery(a.hex.slice(2)), { kind: "address", value: a.hex.toLowerCase() });
  assert.deepEqual(L.classifyQuery(a.me), { kind: "address", value: a.hex.toLowerCase(), from: "me1" });
  assert.equal(L.classifyQuery("0x" + "AB".repeat(32)).kind, "hash");
  assert.equal(L.classifyQuery("0x1234").kind, "invalid");
  assert.equal(L.classifyQuery("hello").kind, "invalid");
  assert.equal(L.classifyQuery("").kind, "empty");
});

test("parseParams keeps valid deep links and reports the rest", () => {
  const reg = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
  const p = L.parseParams(`?rpc=${encodeURIComponent("http://127.0.0.1:8745")}&registry=${reg}&record=2&theme=dark`);
  assert.equal(p.net, "custom");
  assert.equal(p.rpc, "http://127.0.0.1:8745");
  assert.equal(p.registry, reg);
  assert.equal(p.record, 2);
  assert.equal(p.theme, "dark");
  assert.deepEqual(p.warnings, []);
  const q = L.parseParams("?net=mainnet&escrow=0x12&tx=0x34&rpc=javascript:alert(1)&theme=pink");
  assert.equal(q.net, undefined);
  assert.equal(q.escrow, undefined);
  assert.equal(q.tx, undefined);
  assert.equal(q.rpc, undefined);
  assert.equal(q.theme, undefined);
  assert.equal(q.warnings.length, 4);
  assert.equal(L.parseParams("?net=anvil").net, "anvil");
});

test("parseDeployment reads me/deployments/<network>.json", () => {
  const json = {
    network: "anvil", chainId: 31337,
    registry: { address: "0x5FbDB2315678afecb367f032d93F642f64180aa3", codehash: "0x" + "ab".repeat(32), tx: "0x" + "cd".repeat(32), block: 12 },
    escrow: { address: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512" },
    auditors: [{ address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", name: "示範稽核者" }, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", { address: "nope" }],
    publicToolCommits: ["eb3af189e9abcb2e3e8617233575b7370210286b", "0xABCDEF", 7],
  };
  const d = L.parseDeployment(json);
  assert.equal(d.registry, "0x5fbdb2315678afecb367f032d93f642f64180aa3");
  assert.equal(d.escrow, "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512");
  assert.equal(d.chainId, 31337);
  assert.equal(d.registryCodehash, "0x" + "ab".repeat(32));
  assert.equal(d.registryBlock, 12);
  assert.equal(d.auditors.length, 2);
  assert.deepEqual(d.publicToolCommits, ["eb3af189e9abcb2e3e8617233575b7370210286b"]);
  assert.equal(L.auditorName("0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266".replace("0X", "0x"), d.auditors), "示範稽核者");
  assert.equal(L.auditorName("0x70997970c51812dc3a010c7d01b50e0d17dc79c8", d.auditors), "已列出的稽核者");
  assert.equal(L.auditorName("0x" + "11".repeat(20), d.auditors), null);
  assert.equal(L.parseDeployment({ registry: "0x5FbDB2315678afecb367f032d93F642f64180aa3" }).escrow, null);
  assert.throws(() => L.parseDeployment({ network: "me-testnet" }), /registry/);
  assert.throws(() => L.parseDeployment(null));
});

test("commitLink only for commits the deployment file lists as public", () => {
  const pub = ["eb3af189e9abcb2e3e8617233575b7370210286b"];
  assert.equal(L.commitLink("0xEB3AF189E9ABCB2E3E8617233575B7370210286B".replace("0XEB", "0xeb"), pub),
    "https://github.com/sam029031/arbiter-gate/commit/eb3af189e9abcb2e3e8617233575b7370210286b");
  assert.equal(L.commitLink("0x" + "12".repeat(20), pub), null);
  assert.equal(L.commitLink("0x" + "00".repeat(20), pub), null);
  assert.equal(L.commitLink("0xeb3af189e9abcb2e3e8617233575b7370210286b", undefined), null);
});

test("explorerUrl: Cosmos tx hashes, me1 account pages, blocks (the ME explorer's own routes)", () => {
  const base = "https://www.explorer-testnet.me/";
  const cosmos = "a6b03922fa00284a224a1c4f62e7ed0e24e8f56e266e4bfdd602ce62a29f6e0e";
  assert.equal(L.explorerUrl(base, "tx", cosmos),
    `https://www.explorer-testnet.me/zh-TW/transactions/${cosmos.toUpperCase()}?netType=hub`);
  const a = V.meAddresses[0];
  assert.equal(L.explorerUrl(base, "address", a.hex), `https://www.explorer-testnet.me/zh-TW/accountDetails/${a.me}`);
  assert.equal(L.explorerUrl("https://www.explorer-testnet.me", "block", 5435992),
    "https://www.explorer-testnet.me/zh-TW/blocks/5435992?netType=hub");
  // the explorer does not index 0x hashes, so an EVM hash never becomes a tx link
  assert.equal(L.explorerUrl(base, "tx", "0x" + cosmos), null);
  assert.equal(L.explorerUrl(base, "tx", "0x12"), null);
  assert.equal(L.explorerUrl(base, "address", "0x12"), null);
  assert.equal(L.explorerUrl(base, "block", -1), null);
  assert.equal(L.explorerUrl(base, "nope", cosmos), null);
  assert.equal(L.explorerUrl(null, "tx", cosmos), null);
  assert.equal(L.explorerUrl("http://www.explorer-testnet.me", "tx", cosmos), null);
  assert.equal(L.explorerUrl("https://www.explorer-testnet.me/x?y", "tx", cosmos), null);
  assert.equal(L.explorerUrl("javascript:alert(1)//", "tx", cosmos), null);
});

// trimmed from a real ME Hub tx_search response (2026-11-22)
const EVM_TX = "0x59ff81116a4dc5574974e562fad35432b14745caedde57c5e65ce0b813c9bb4d";
const TX_SEARCH = { jsonrpc: "2.0", id: -1, result: { total_count: "1", txs: [{
  hash: "A6B03922FA00284A224A1C4F62E7ED0E24E8F56E266E4BFDD602CE62A29F6E0E", height: "5435992", index: 0,
  tx_result: { code: 0, events: [
    { type: "tx", attributes: [{ key: "fee", value: "1umec", index: true }] },
    { type: "ethereum_tx", attributes: [{ key: "ethereumTxHash", value: EVM_TX, index: true },
                                        { key: "txIndex", value: "0", index: true }] }] } }] } };

test("cosmosTxSearchUrl / parseTxSearch: EVM hash -> the Cosmos tx the explorer indexes", () => {
  const hub = "https://beta-hub-26657.explorer-testnet.me";
  const url = L.cosmosTxSearchUrl(hub + "/", EVM_TX.toUpperCase().replace("0X", "0x"));
  assert.equal(url, `${hub}/tx_search?query=${encodeURIComponent(`"ethereum_tx.ethereumTxHash='${EVM_TX}'"`)}&per_page=1`);
  assert.equal(new URL(url).searchParams.get("query"), `"ethereum_tx.ethereumTxHash='${EVM_TX}'"`);
  assert.equal(L.cosmosTxSearchUrl(hub, "0x12"), null);
  assert.equal(L.cosmosTxSearchUrl("javascript:alert(1)", EVM_TX), null);
  assert.deepEqual(L.parseTxSearch(TX_SEARCH, EVM_TX), { hash: TX_SEARCH.result.txs[0].hash, height: 5435992 });
  // a result for another EVM tx, a malformed hash, an empty or broken body: no link
  assert.equal(L.parseTxSearch(TX_SEARCH, "0x" + "11".repeat(32)), null);
  const bad = JSON.parse(JSON.stringify(TX_SEARCH));
  bad.result.txs[0].hash = "<b>x</b>";
  assert.equal(L.parseTxSearch(bad, EVM_TX), null);
  assert.equal(L.parseTxSearch({ result: { txs: [] } }, EVM_TX), null);
  assert.equal(L.parseTxSearch({ error: { message: "x" } }, EVM_TX), null);
  assert.equal(L.parseTxSearch(null, EVM_TX), null);
});

test("selfCheckCommand: cast receipt with the page's RPC, quoted when needed", () => {
  assert.equal(L.selfCheckCommand(EVM_TX, "https://beta-hub-8545.explorer-testnet.me"),
    `cast receipt ${EVM_TX} --rpc-url https://beta-hub-8545.explorer-testnet.me`);
  assert.equal(L.selfCheckCommand(EVM_TX, "http://127.0.0.1:8741"), `cast receipt ${EVM_TX} --rpc-url http://127.0.0.1:8741`);
  assert.equal(L.selfCheckCommand(EVM_TX, "https://x.example/rpc?a=1&b=2"),
    `cast receipt ${EVM_TX} --rpc-url 'https://x.example/rpc?a=1&b=2'`);
  assert.equal(L.selfCheckCommand("0x12", "https://x.example"), null);
  assert.equal(L.selfCheckCommand(EVM_TX, "javascript:alert(1)"), null);
});

test("findBlockByTime finds the first block at a timestamp in O(log n) lookups", async () => {
  const chains = {
    uniform: (n) => 1000 + 5 * n,
    uneven: (n) => (n < 600000 ? 1000 + n : 601000 + 30 * (n - 600000)), // block time changes
    repeated: (n) => 1000 + Math.floor(n / 4), // several blocks per second (anvil)
  };
  for (const [name, ts] of Object.entries(chains)) {
    for (const target of [0, 17, 999999, 1999998]) {
      let calls = 0;
      const getTs = async (n) => { calls++; return ts(n); };
      const t = ts(target);
      const got = await L.findBlockByTime(t, 0, 2000000, getTs);
      assert.ok(ts(got) >= t && (got === 0 || ts(got - 1) < t), `${name} ${target} -> ${got}`);
      assert.ok(calls <= 66, `${name}: ${calls} lookups`);
    }
  }
  assert.equal(await L.findBlockByTime(5, 0, 10, async (n) => 100 + n), 0); // older than the range
  assert.equal(await L.findBlockByTime(500, 0, 10, async (n) => 100 + n), null); // newer than the chain
});

test("logWindows splits a range into node-sized windows", () => {
  assert.deepEqual(L.logWindows(5, 25000, 10000, 8), [[5, 10004], [10005, 20004], [20005, 25000]]);
  assert.deepEqual(L.logWindows(5, 25000, 10000, 2), [[5, 10004], [10005, 20004]]);
  assert.deepEqual(L.logWindows(30, 20, 10000, 8), []);
});

test("evidenceLocation: https folders, manifest URLs, loopback http only", () => {
  let e = L.evidenceLocation("https://example.org/ev/r1/");
  assert.deepEqual([e.ok, e.manifest, e.base], [true, "https://example.org/ev/r1/manifest.json", "https://example.org/ev/r1/"]);
  e = L.evidenceLocation("https://example.org/ev/r1");
  assert.equal(e.manifest, "https://example.org/ev/r1/manifest.json");
  e = L.evidenceLocation("https://example.org/ev/r1/manifest.json#x");
  assert.deepEqual([e.manifest, e.base], ["https://example.org/ev/r1/manifest.json", "https://example.org/ev/r1/"]);
  assert.equal(L.evidenceLocation("http://127.0.0.1:8750/evidence/r1/").ok, true);
  assert.equal(L.evidenceLocation("http://example.org/ev/").reason, "scheme");
  assert.equal(L.evidenceLocation("ipfs://bafy/x").reason, "ipfs");
  assert.equal(L.evidenceLocation("").reason, "empty");
  assert.equal(L.evidenceLocation("not a url").reason, "invalid");
  assert.equal(L.evidenceLocation("https://u:p@example.org/ev/").reason, "credentials");
  assert.equal(L.evidenceLocation("javascript:alert(1)").reason, "scheme");
});

test("bundle file names stay inside the bundle folder", () => {
  const base = "https://example.org/ev/r1/";
  assert.equal(L.bundleFileUrl(base, "gate.json"), base + "gate.json");
  assert.equal(L.bundleFileUrl(base, "src/證據 1.sol"), base + "src/%E8%AD%89%E6%93%9A%201.sol");
  for (const bad of ["../x", "/etc/passwd", "https://evil.example/x", "a/../../b", "a\\b", "", "a//b", "./a", "x?y=1", "%2e%2e/x"]) {
    assert.equal(L.bundleFileUrl(base, bad), null, bad);
  }
});

test("guessRole / roleOf: both role spellings, record.py's extra files", () => {
  assert.equal(L.guessRole("gate.json"), "gateJson");
  assert.equal(L.guessRole("patch.diff"), "patch");
  assert.equal(L.guessRole("DemoVaultExploit.t.sol"), "exploit");
  assert.equal(L.guessRole("poc/Attack.sol"), "exploit");
  assert.equal(L.guessRole("exploit/Drain.sol"), "exploit");
  assert.equal(L.guessRole("DemoVault.patched.sol"), "source");
  assert.equal(L.guessRole("src/DemoVault.sol"), "source");
  assert.equal(L.guessRole("parent_src/DemoVault.sol"), "parentSource");
  assert.equal(L.guessRole("regression.zip"), "regression");
  assert.equal(L.guessRole("compiler.json"), "compiler");
  assert.equal(L.guessRole("README.md"), null);
  assert.equal(L.roleOf({ name: "x.bin", role: "exploit" }), "exploit");
  assert.equal(L.roleOf({ name: "x.json", role: "gate_json" }), "gateJson");
  assert.equal(L.roleOf({ name: "x.json", role: "gateJson" }), "gateJson");
  assert.equal(L.roleOf({ name: "a/DemoVault.sol", role: "parent_source" }), "parentSource");
  assert.equal(L.roleOf({ name: "gate.json", role: "toString" }), "gateJson");
  assert.equal(L.roleOf({ name: "gate.json", role: "__proto__" }), "gateJson");
});

test("manifestSchemaProblem accepts both manifest schemas", () => {
  assert.equal(L.manifestSchemaProblem({ schema: "arbiter-me-evidence/0.1", files: [] }), null);
  assert.equal(L.manifestSchemaProblem({ schema: "arbiter-evidence/0.1", files: [] }), null);
  assert.equal(L.manifestSchemaProblem({ schema: "other/9", files: [] }), "other/9");
  assert.match(L.manifestSchemaProblem({ files: [] }), /沒有 schema/);
});

const H = (b) => "0x" + b.repeat(32);
const INPUT = { sourceHash: H("11"), gateJsonHash: H("33"), exploitHash: H("44"), patchHash: H("00") };

test("compareEvidence: all files match the record", () => {
  const files = [
    { name: "gate.json", sha256: H("33"), manifestSha256: H("33") },
    { name: "Vault.sol", role: "source", sha256: H("11") },
    { name: "Exploit.t.sol", sha256: H("44"), manifestSha256: H("44") },
    { name: "notes.md", sha256: H("99") },
  ];
  const c = L.compareEvidence(INPUT, files);
  assert.equal(c.ok, true);
  assert.deepEqual(c.rows.map((r) => r.onchain), ["match", "match", "match", "none"]);
  assert.deepEqual(c.fields.map((f) => [f.field, f.status]), [["sourceHash", "match"], ["gateJsonHash", "match"], ["exploitHash", "match"]]);
});

test("compareEvidence: an altered file, a missing file, a manifest mismatch, a fetch error", () => {
  const c = L.compareEvidence(INPUT, [
    { name: "gate.json", sha256: H("34"), manifestSha256: H("33") },
    { name: "Vault.sol", sha256: H("11"), manifestSha256: H("12") },
    { name: "patch.diff", sha256: H("55") },
    { name: "Exploit.t.sol", error: "HTTP 404" },
  ]);
  assert.equal(c.ok, false);
  assert.deepEqual(c.rows.map((r) => [r.onchain, r.manifest]),
    [["mismatch", "mismatch"], ["match", "mismatch"], ["absent", null], ["error", null]]);
  assert.deepEqual(c.fields.map((f) => f.status), ["match", "mismatch", "missing"]);
});

test("compareEvidence: a record.py bundle of a patched record (parent source and exploit, extra files)", () => {
  const child = { sourceHash: H("21"), gateJsonHash: H("23"), exploitHash: H("00"), patchHash: H("25") };
  const parent = { id: 1, input: { sourceHash: H("11"), gateJsonHash: H("33"), exploitHash: H("44"), patchHash: H("25") } };
  const files = [
    { name: "compiler.json", role: "compiler", sha256: H("c0"), manifestSha256: H("c0") },
    { name: "exploit/Drain.t.sol", role: "exploit", sha256: H("44"), manifestSha256: H("44") },
    { name: "gate.json", role: "gate_json", sha256: H("23"), manifestSha256: H("23") },
    { name: "parent_src/Vault.sol", role: "parent_source", sha256: H("11"), manifestSha256: H("11") },
    { name: "patch.diff", role: "patch", sha256: H("25"), manifestSha256: H("25") },
    { name: "regression.zip", role: "regression", sha256: H("e0"), manifestSha256: H("e0") },
    { name: "src/Vault.sol", role: "source", sha256: H("21"), manifestSha256: H("21") },
  ];
  const c = L.compareEvidence(child, files, parent);
  assert.equal(c.ok, true);
  assert.deepEqual(c.rows.map((r) => [r.from, r.onchain, r.manifest]), [
    [null, "none", "match"], ["parent", "match", "match"], ["record", "match", "match"], ["parent", "match", "match"],
    ["record", "match", "match"], [null, "none", "match"], ["record", "match", "match"]]);
  assert.deepEqual(c.rows.map((r) => r.label), ["編譯設定", "上一版（#1）的攻擊程式", "gate.json（稽核結果）",
    "上一版（#1）的原始碼", "修補", "回歸測試專案", "原始碼"]);
  assert.deepEqual(c.fields.map((f) => [f.field, f.status]), [["sourceHash", "match"], ["gateJsonHash", "match"], ["patchHash", "match"]]);

  // without the parent, parent_src/ is only listed and the exploit has no on-chain hash to meet
  const alone = L.compareEvidence(child, files, null);
  assert.equal(alone.ok, true);
  assert.deepEqual(alone.rows.slice(1, 4).map((r) => r.onchain), ["absent", "match", "none"]);

  // a different parent source, or an altered regression.zip, is caught
  const swapped = files.map((f) => (f.role === "parent_source" ? { ...f, sha256: H("12"), manifestSha256: H("12") } : f));
  assert.equal(L.compareEvidence(child, swapped, parent).ok, false);
  const altered = files.map((f) => (f.role === "regression" ? { ...f, sha256: H("e1") } : f));
  const a = L.compareEvidence(child, altered, parent);
  assert.equal(a.ok, false);
  assert.deepEqual(a.rows.find((r) => r.role === "regression").manifest, "mismatch");
});

test("matchFields finds which record hash a dropped file equals", () => {
  assert.deepEqual(L.matchFields(INPUT, H("44").toUpperCase().replace("0X", "0x")), ["exploitHash"]);
  assert.deepEqual(L.matchFields(INPUT, H("00")), []);
  assert.deepEqual(L.matchFields(INPUT, H("77")), []);
});

test("provenanceSteps: proven -> patch -> re-audit -> deploy, plus children", () => {
  const rec = (verdict, parentId, extra = {}) => ({
    input: { verdict, parentId, patchHash: parentId ? H("55") : H("00") }, timestamp: 100,
    deployed: "0x" + "00".repeat(20), linkKind: 0, ...extra,
  });
  const steps = L.provenanceSteps([
    { id: 1, record: rec(3, 0) },
    { id: 2, record: rec(1, 1, { deployed: "0x" + "ab".repeat(20), linkKind: 2 }), current: true },
    { id: 5, record: rec(1, 2), child: true },
  ]);
  assert.deepEqual(steps.map((s) => s.type), ["record", "patch", "record", "deploy", "patch", "record"]);
  assert.deepEqual(steps.filter((s) => s.type === "record").map((s) => [s.id, s.stage, s.current, s.child]),
    [[1, "稽核", false, false], [2, "重新稽核", true, false], [5, "重新稽核", false, true]]);
  assert.equal(steps[3].linkKind, 2);
  assert.deepEqual(L.provenanceSteps([{ id: 4, record: rec(2, 0), current: true }]).map((s) => s.type), ["record"]);
  // the current record lists every gated deployment; a claim is its own step
  const two = ["0x" + "ab".repeat(20), "0x" + "cd".repeat(20)];
  const gated = L.provenanceSteps([{ id: 2, record: rec(1, 0, { deployed: two[0], linkKind: 2 }), current: true, deployments: two }]);
  assert.deepEqual(gated.map((s) => [s.type, s.linkKind, s.count]), [["record", undefined, undefined], ["deploy", 2, 2]]);
  const claimed = L.provenanceSteps([{ id: 4, record: rec(2, 0, { deployed: two[1], linkKind: 1 }), current: true, deployments: [] }]);
  assert.deepEqual(claimed.map((s) => [s.type, s.linkKind, s.address]), [["record", undefined, undefined], ["deploy", 1, two[1]]]);
});

test("link labels: a claim says it did not go through the gate", () => {
  assert.equal(L.linkInfo(1).label, "稽核者自行宣告（未經閘門部署，只能比對程式碼雜湊）");
  assert.equal(L.linkInfo(2).label, "由 AuditRegistry 依稽核過的 bytecode 部署");
  assert.equal(L.SETTLE_GRACE, 3600);
});

test("formatUnits / time formatting", () => {
  assert.equal(L.formatUnits(10n ** 16n), "0.01");
  assert.equal(L.formatUnits(0n), "0");
  assert.equal(L.formatUnits(1234567890123456789n), "1.234567");
  assert.equal(L.formatUnits(5n * 10n ** 18n), "5");
  assert.equal(L.isoUtc(1763740800), "2025-11-21T16:00:00Z");
  assert.match(L.formatTime(1763740800), /2025\/11\/22 00:00:00（UTC\+8）/);
});

test("sameHash ignores case and refuses zero or missing hashes", () => {
  assert.equal(L.sameHash(H("ab"), H("AB").replace("0xAB", "0xab").toUpperCase().replace("0X", "0x")), true);
  assert.equal(L.sameHash(H("00"), H("00")), false);
  assert.equal(L.sameHash(undefined, H("11")), false);
  assert.equal(L.sameHash("zz", "zz"), false);
});
