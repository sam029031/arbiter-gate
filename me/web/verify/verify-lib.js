/* ARBITER Gate 紀錄驗證頁：純函式（不碰 DOM、不連網路）。
 * The page loads this as window.VerifyLib; node's test runner loads it with require().
 * Everything that reads chain data treats it as untrusted: decoders bound-check every offset,
 * and nothing here builds HTML. */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.VerifyLib = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // ------------------------------------------------------------------ labels (zh-TW)
  // Verdict labels are the gate's own (arbiter/arbiter/verdict.py LABELS); the unit test
  // checks they stay identical. There is deliberately no "safe" label.
  const VERDICTS = {
    3: { label: "已證實可攻擊（擋部署）", short: "已證實可攻擊", tone: "red", key: "proven_exploitable",
         desc: "AI 寫出的攻擊程式，在系統訂的判定條件下真的成立。AuditRegistry 拒絕部署這份程式碼。" },
    2: { label: "靜態工具提示但未證實", short: "靜態工具提示", tone: "amber", key: "static_hint_unproven",
         desc: "AI 沒有寫出成立的攻擊，但自動掃描工具（Slither）標出可疑處。提示不是證據。" },
    1: { label: "未發現可證明攻擊（不等於安全）", short: "未發現可證明攻擊", tone: "blue", key: "no_provable_attack",
         desc: "這次稽核沒有找到能證明的攻擊。這是「沒找到」，不是「沒有漏洞」。" },
    0: { label: "無法判定（稽核未完成）", short: "無法判定", tone: "mute", key: "not_executed",
         desc: "稽核沒有跑完（例如無法編譯、連線中斷），不能當成通過，也不能部署。" },
  };
  const PREDICATES = {
    0: { label: "無", desc: "沒有已證實的攻擊，所以沒有判定條件。" },
    1: { label: "寬鬆", desc: "以攻擊者獲利或合約狀態被改變來判定（eth_profit、token_profit、state_change），看不出一定有人受損。" },
    2: { label: "嚴格", desc: "以有人真的受損來判定：有攻擊時受害者領回的比沒攻擊時少，而且差額在攻擊者手上（victim_loss），或合約被弄到無法正常使用（liveness_broken）。" },
  };
  const TIERS = {
    0: { label: "無", desc: "沒有已證實的攻擊，所以沒有證據等級。" },
    1: { label: "第 1 階：合成層", desc: "在測試框架裡證實：攻擊在系統準備好的環境中成立。" },
    2: { label: "第 2 階：獨立專案", desc: "攻擊被抽成獨立的 Foundry 專案，別人拿去也能重跑出同樣結果。" },
    3: { label: "第 3 階：本地真鏈", desc: "在私人區塊鏈上用真的交易重播：要當誰就要有私鑰，要花錢就要有餘額，每筆都付 gas。" },
  };
  const LINKS = {
    0: { label: "尚未部署", short: "尚未部署", desc: "這筆紀錄還沒有連結任何部署地址。" },
    1: { label: "稽核者自行宣告（未經閘門部署，只能比對程式碼雜湊）", short: "稽核者自行宣告",
         desc: "稽核者把在別處部署的地址連到這筆紀錄。AuditRegistry 只記下那個地址當時的程式碼雜湊，不證明它是從稽核過的原始碼編譯出來的；任何稽核者都能宣告任何地址，同一個地址也可能有好幾筆宣告。" },
    2: { label: "由 AuditRegistry 依稽核過的 bytecode 部署", short: "AuditRegistry 部署",
         desc: "這些地址是 AuditRegistry 自己用稽核過的建立程式碼（initcode 雜湊相符）以 CREATE2 部署的，中間沒有人能換掉程式碼。同一筆紀錄可以部署很多次，每次都是同一份 bytecode。" },
  };
  const ESCROW_STATUS = {
    0: { label: "不存在", tone: "mute" },
    1: { label: "等待稽核", tone: "amber" },
    2: { label: "已付給稽核者", tone: "sys" },
    3: { label: "已退回申請人", tone: "mute" },
  };
  const FIELD_LABELS = {
    sourceHash: "原始碼",
    initcodeHash: "建立程式碼（initcode）",
    gateJsonHash: "gate.json（稽核結果）",
    exploitHash: "攻擊程式",
    patchHash: "修補",
    runtimeCodeHash: "部署後的程式碼",
  };
  // AuditEscrow: the auditor may still settle this long after the deadline; refunds start after it.
  const SETTLE_GRACE = 3600;

  // Evidence manifests. me/arbiter_me/record.py writes "arbiter-me-evidence/0.1" with snake_case
  // roles (gate_json, parent_source); the first bundles used "arbiter-evidence/0.1" and gateJson.
  const MANIFEST_SCHEMAS = ["arbiter-me-evidence/0.1", "arbiter-evidence/0.1"];
  const ROLE_ALIASES = {
    gate_json: "gateJson", gateJson: "gateJson", source: "source", exploit: "exploit", patch: "patch",
    parent_source: "parentSource", parentSource: "parentSource", regression: "regression", compiler: "compiler",
  };
  // sha256 fields an evidence file can be compared with (initcode/runtime hashes are keccak256)
  const ROLE_FIELDS = { source: "sourceHash", gateJson: "gateJsonHash", exploit: "exploitHash", patch: "patchHash" };
  // files without a hash of their own on chain: compared with the manifest (parent_source also
  // with the parent record's sourceHash)
  const EXTRA_ROLES = { parentSource: "上一版原始碼", regression: "回歸測試專案", compiler: "編譯設定" };

  function lookup(table, v, kind) {
    return table[v] || { label: `未知的${kind}代碼 ${v}`, tone: "mute", desc: "這個頁面不認得這個代碼。" };
  }
  const verdictInfo = (v) => lookup(VERDICTS, v, "判定");
  const predicateInfo = (v) => lookup(PREDICATES, v, "謂詞等級");
  const tierInfo = (v) => lookup(TIERS, v, "證據等級");
  const linkInfo = (v) => lookup(LINKS, v, "連結方式");
  const escrowStatusInfo = (v) => lookup(ESCROW_STATUS, v, "託管狀態");

  // ------------------------------------------------------------------ hex
  const strip0x = (h) => (/^0x/i.test(h) ? h.slice(2) : h);
  const isAddress = (s) => typeof s === "string" && /^0x[0-9a-fA-F]{40}$/.test(s);
  const isBytes32 = (s) => typeof s === "string" && /^0x[0-9a-fA-F]{64}$/.test(s);
  const isZeroHex = (h) => typeof h === "string" && /^0x0*$/i.test(h);
  const normHex = (h) => "0x" + strip0x(String(h)).toLowerCase();
  /** Two hashes are the same, and neither is missing or all zero. */
  function sameHash(a, b) {
    if (typeof a !== "string" || typeof b !== "string" || isZeroHex(a) || isZeroHex(b)) return false;
    return /^0x[0-9a-f]+$/i.test(a) && normHex(a) === normHex(b);
  }
  function bytesToHex(bytes) {
    let out = "0x";
    for (const b of bytes) out += b.toString(16).padStart(2, "0");
    return out;
  }
  function hexToBytes(hex) {
    const h = strip0x(hex);
    if (h.length % 2 || /[^0-9a-f]/i.test(h)) throw new Error("不是十六進位字串");
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }
  function shortHex(h, head = 6, tail = 4) {
    const s = String(h);
    return s.length <= head + tail + 3 ? s : `${s.slice(0, head)}…${s.slice(-tail)}`;
  }
  /** sha256 of bytes (ArrayBuffer / typed array) as 0x-prefixed lowercase hex. */
  async function sha256Hex(data, subtle) {
    const s = subtle || (globalThis.crypto && globalThis.crypto.subtle);
    if (!s) throw new Error("這個瀏覽器不支援 WebCrypto（需要 https 或 localhost）");
    return bytesToHex(new Uint8Array(await s.digest("SHA-256", data)));
  }

  // ------------------------------------------------------------------ ABI (only what the page needs)
  // Selectors and event topics are keccak256 values computed with Foundry `cast`; the unit test
  // re-checks them against vectors.json, and the page re-checks them with ethers at start-up.
  // Lists anyone can append to (records by source or initcode) are read through the contract's
  // count + page views, so a flood of records cannot make the page fail.
  const FUNCS = {
    recordCount: ["0x900407bc", []],
    getRecord: ["0x03e9e609", ["uint256"]],
    recordsBySourceCount: ["0xab93585a", ["bytes32"]],
    recordsBySourcePage: ["0x88f9963a", ["bytes32", "uint256", "uint256"]],
    recordsByInitcodeCount: ["0x474ed5e3", ["bytes32"]],
    recordsByInitcodePage: ["0xe5364d11", ["bytes32", "uint256", "uint256"]],
    recordsByCodehash: ["0x21c14920", ["bytes32"]],
    childrenOf: ["0x6f19951c", ["uint256"]],
    deploymentOf: ["0x325d43c6", ["address"]],
    deploymentsOf: ["0x096ffd3d", ["uint256"]],
    claimsOf: ["0x01d81d92", ["address"]],
    latestRecord: ["0x2e9878a3", ["address", "bytes32"]],
    isLinkCurrent: ["0x5202b6dc", ["uint256"]],
    settledBy: ["0x034728a0", ["uint256"]],
    getRequest: ["0xc58343ef", ["uint256"]],
    requestCount: ["0x5badbe4c", []],
    registry: ["0x7b103999", []],
  };
  const FUNC_SIGS = {
    recordCount: "recordCount()", getRecord: "getRecord(uint256)",
    recordsBySourceCount: "recordsBySourceCount(bytes32)",
    recordsBySourcePage: "recordsBySourcePage(bytes32,uint256,uint256)",
    recordsByInitcodeCount: "recordsByInitcodeCount(bytes32)",
    recordsByInitcodePage: "recordsByInitcodePage(bytes32,uint256,uint256)",
    recordsByCodehash: "recordsByCodehash(bytes32)", childrenOf: "childrenOf(uint256)",
    deploymentOf: "deploymentOf(address)", deploymentsOf: "deploymentsOf(uint256)", claimsOf: "claimsOf(address)",
    latestRecord: "latestRecord(address,bytes32)", isLinkCurrent: "isLinkCurrent(uint256)",
    settledBy: "settledBy(uint256)", getRequest: "getRequest(uint256)", requestCount: "requestCount()",
    registry: "registry()",
  };
  const TOPICS = {
    Registered: "0x23d63f1a16d51b58c456caadf3f89d6b688ca4de7733c0bd93f02634717a265a",
    Linked: "0xc60dbe230823659866ba35fa4db934c12e713db1f867c73ee65c9fdbf094044e",
    Requested: "0x4cfd69661e9438fcbeacf399fdfa395030b9bc3ae91b0d962e73feee901f702a",
    Settled: "0x28a6c19885d00afe0e46b0e4d166455e5382102b7e05a6798ed31971f03496f1",
  };
  const EVENT_SIGS = {
    Registered: "Registered(uint256,bytes32,address,uint8,uint256)",
    Linked: "Linked(uint256,address,bytes32,uint8)",
    Requested: "Requested(uint256,address,address,bytes32,uint256,uint64)",
    Settled: "Settled(uint256,uint256,address,uint256,bool)",
  };
  const MAX_U256 = (1n << 256n) - 1n;
  const ENC = {
    uint256(v) {
      const n = BigInt(v);
      if (n < 0n || n > MAX_U256) throw new RangeError("uint256 超出範圍");
      return n.toString(16).padStart(64, "0");
    },
    address(v) {
      if (!isAddress(v)) throw new TypeError("不是 0x 地址");
      return strip0x(v).toLowerCase().padStart(64, "0");
    },
    bytes32(v) {
      if (!isBytes32(v)) throw new TypeError("不是 32 位元組雜湊");
      return strip0x(v).toLowerCase();
    },
  };
  function encodeCall(fn, args = []) {
    const spec = FUNCS[fn];
    if (!spec) throw new Error(`unknown function ${fn}`);
    const [selector, types] = spec;
    if (args.length !== types.length) throw new Error(`${fn} takes ${types.length} argument(s)`);
    return selector + types.map((t, i) => ENC[t](args[i])).join("");
  }

  function abiData(hex) {
    if (typeof hex !== "string" || !/^0x[0-9a-fA-F]*$/.test(hex)) throw new Error("RPC 回傳的不是十六進位資料");
    const h = hex.slice(2).toLowerCase();
    if (!h.length) throw new Error("RPC 回傳空資料（地址上可能不是這份合約）");
    return h;
  }
  function wordAt(h, off) {
    const s = h.slice(off * 2, off * 2 + 64);
    if (!Number.isSafeInteger(off) || off < 0 || s.length !== 64) throw new Error("ABI 資料長度不符");
    return s;
  }
  const uintAt = (h, off) => BigInt("0x" + wordAt(h, off));
  function numAt(h, off) {
    const v = uintAt(h, off);
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("ABI 數值超出範圍");
    return Number(v);
  }
  const addressAt = (h, off) => "0x" + wordAt(h, off).slice(24);
  const bytes32At = (h, off) => "0x" + wordAt(h, off);
  const bytes20At = (h, off) => "0x" + wordAt(h, off).slice(0, 40);
  function stringAt(h, off) {
    const len = numAt(h, off);
    const hex = h.slice((off + 32) * 2, (off + 32 + len) * 2);
    if (hex.length !== len * 2) throw new Error("ABI 字串長度不符");
    return new TextDecoder("utf-8").decode(hexToBytes(hex));
  }

  /** getRecord(uint256) return data -> plain object (addresses lowercase, ids as numbers). */
  function decodeRecord(hex) {
    const h = abiData(hex);
    const r = numAt(h, 0); // offset of the Record tuple
    const i = r + numAt(h, r); // offset of the RecordInput tuple
    const input = {
      sourceHash: bytes32At(h, i),
      initcodeHash: bytes32At(h, i + 32),
      verdict: numAt(h, i + 64),
      predicateClass: numAt(h, i + 96),
      evidenceTier: numAt(h, i + 128),
      gateJsonHash: bytes32At(h, i + 160),
      exploitHash: bytes32At(h, i + 192),
      patchHash: bytes32At(h, i + 224),
      parentId: numAt(h, i + 256),
      toolCommit: bytes20At(h, i + 288),
      model: stringAt(h, i + numAt(h, i + 320)),
      evidenceURI: stringAt(h, i + numAt(h, i + 352)),
    };
    return {
      input,
      auditor: addressAt(h, r + 32),
      timestamp: numAt(h, r + 64),
      deployed: addressAt(h, r + 96),
      runtimeCodeHash: bytes32At(h, r + 128),
      linkKind: numAt(h, r + 160),
    };
  }
  /** escrow getRequest(uint256) return data (a static tuple, encoded in place; v2 has minRecordId). */
  function decodeRequest(hex) {
    const h = abiData(hex);
    return {
      requester: addressAt(h, 0),
      auditor: addressAt(h, 32),
      sourceHash: bytes32At(h, 64),
      fee: uintAt(h, 96),
      createdAt: numAt(h, 128),
      deadline: numAt(h, 160),
      status: numAt(h, 192),
      minRecordId: numAt(h, 224),
      recordId: numAt(h, 256),
    };
  }
  const MAX_ARRAY = 5000;
  function decodeArray(hex, read) {
    const h = abiData(hex);
    const off = numAt(h, 0);
    const n = numAt(h, off);
    if (n > MAX_ARRAY) throw new Error("清單太長");
    const out = [];
    for (let k = 0; k < n; k++) out.push(read(h, off + 32 + 32 * k));
    return out;
  }
  const decodeUintArray = (hex) => decodeArray(hex, numAt);
  const decodeAddressArray = (hex) => decodeArray(hex, addressAt);
  const decodeNumber = (hex) => numAt(abiData(hex), 0);
  const decodeAddress = (hex) => addressAt(abiData(hex), 0);
  function decodeBool(hex) {
    const v = uintAt(abiData(hex), 0);
    if (v > 1n) throw new Error("ABI 布林值不是 0 或 1");
    return v === 1n;
  }

  /** One receipt log -> {event, ...} for the registry/escrow events, or null. */
  function decodeLog(log) {
    if (!log || !Array.isArray(log.topics) || !log.topics.length) return null;
    const t = log.topics.map((x) => String(x).toLowerCase());
    const topicNum = (k) => numAt(abiData(t[k]), 0);
    const topicAddr = (k) => addressAt(abiData(t[k]), 0);
    try {
      const d = abiData(log.data && log.data !== "0x" ? log.data : "0x" + "0".repeat(64));
      switch (t[0]) {
        case TOPICS.Registered:
          return { event: "Registered", id: topicNum(1), sourceHash: t[2], auditor: topicAddr(3),
                   verdict: numAt(d, 0), parentId: numAt(d, 32) };
        case TOPICS.Linked:
          return { event: "Linked", id: topicNum(1), deployed: topicAddr(2), runtimeCodeHash: bytes32At(d, 0),
                   linkKind: numAt(d, 32) };
        case TOPICS.Requested:
          return { event: "Requested", requestId: topicNum(1), requester: topicAddr(2), auditor: topicAddr(3),
                   sourceHash: bytes32At(d, 0), fee: uintAt(d, 32), deadline: numAt(d, 64) };
        case TOPICS.Settled:
          return { event: "Settled", requestId: topicNum(1), recordId: topicNum(2), recipient: topicAddr(3),
                   amount: uintAt(d, 0), refunded: uintAt(d, 32) !== 0n };
        default:
          return null;
      }
    } catch (e) {
      return null; // a log with our topic but the wrong shape is not one of ours
    }
  }

  // ------------------------------------------------------------------ ME addresses (bech32, BIP-173)
  const B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  function polymod(values) {
    const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
      const top = chk >>> 25;
      chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
      for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk = (chk ^ gen[i]) >>> 0;
    }
    return chk;
  }
  const hrpExpand = (hrp) => [...hrp].map((c) => c.charCodeAt(0) >> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));
  function convertBits(data, from, to, pad) {
    let acc = 0, bits = 0;
    const out = [], maxv = (1 << to) - 1;
    for (const v of data) {
      if (v < 0 || v >> from) return null;
      acc = (acc << from) | v;
      bits += from;
      while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
    }
    if (pad) { if (bits) out.push((acc << (to - bits)) & maxv); }
    else if (bits >= from || ((acc << (to - bits)) & maxv)) return null;
    return out;
  }
  /** 0x address -> me1… (the form ME's faucet and Cosmos explorer show). */
  function toMeAddress(addr) {
    if (!isAddress(addr)) return null;
    const data = convertBits(hexToBytes(addr), 8, 5, true);
    const pm = polymod(hrpExpand("me").concat(data, [0, 0, 0, 0, 0, 0])) ^ 1;
    const check = [0, 1, 2, 3, 4, 5].map((i) => (pm >>> (5 * (5 - i))) & 31);
    return "me1" + data.concat(check).map((d) => B32[d]).join("");
  }
  /** me1… -> 0x address (lowercase), or null when the checksum or length is wrong. */
  function fromMeAddress(s) {
    if (typeof s !== "string" || (s !== s.toLowerCase() && s !== s.toUpperCase())) return null;
    const a = s.toLowerCase();
    if (!a.startsWith("me1") || a.length < 9 || a.length > 90) return null;
    const vals = [];
    for (const c of a.slice(3)) { const v = B32.indexOf(c); if (v < 0) return null; vals.push(v); }
    if (polymod(hrpExpand("me").concat(vals)) !== 1) return null;
    const bytes = convertBits(vals.slice(0, -6), 5, 8, false);
    return bytes && bytes.length === 20 ? bytesToHex(bytes) : null;
  }

  // ------------------------------------------------------------------ input and URL parameters
  /** What the person typed into the lookup box. */
  function classifyQuery(raw) {
    const s = String(raw || "").trim();
    if (!s) return { kind: "empty" };
    const id = s.replace(/^#/, "");
    if (/^\d+$/.test(id)) {
      const n = Number(id);
      return Number.isSafeInteger(n) && n > 0 ? { kind: "record", id: n } : { kind: "invalid", reason: "紀錄編號從 1 開始" };
    }
    if (/^me1/i.test(s)) {
      const hex = fromMeAddress(s);
      return hex ? { kind: "address", value: hex, from: "me1" } : { kind: "invalid", reason: "me1 地址的檢查碼不對" };
    }
    const h = /^0x/i.test(s) ? "0x" + s.slice(2) : "0x" + s;
    if (/^0x[0-9a-fA-F]{40}$/.test(h)) return { kind: "address", value: h.toLowerCase() };
    if (/^0x[0-9a-fA-F]{64}$/.test(h)) return { kind: "hash", value: h.toLowerCase() };
    if (/^0x[0-9a-fA-F]+$/.test(h)) return { kind: "invalid", reason: "長度不對：地址是 40 個十六進位字元，交易雜湊是 64 個" };
    return { kind: "invalid", reason: "看不懂這個輸入" };
  }

  const NETWORK_KEYS = ["me-testnet", "anvil", "custom"];
  /** URL parameters -> validated settings; anything malformed is dropped and reported. */
  function parseParams(search) {
    const p = new URLSearchParams(search || "");
    const out = { warnings: [] };
    const net = p.get("net");
    if (net) NETWORK_KEYS.includes(net) ? (out.net = net) : out.warnings.push(`不認得的網路「${net}」`);
    const rpc = p.get("rpc");
    if (rpc) {
      const ok = rpcUrlOk(rpc);
      ok ? ((out.rpc = rpc), (out.net = "custom")) : out.warnings.push("rpc 參數不是 http(s) 網址");
    }
    for (const k of ["registry", "escrow", "address"]) {
      const v = p.get(k);
      if (!v) continue;
      const q = classifyQuery(v);
      q.kind === "address" ? (out[k] = q.value) : out.warnings.push(`${k} 參數不是地址`);
    }
    const rec = p.get("record");
    if (rec) {
      const q = classifyQuery(rec);
      q.kind === "record" ? (out.record = q.id) : out.warnings.push("record 參數不是紀錄編號");
    }
    for (const k of ["tx", "source"]) {
      const v = p.get(k);
      if (!v) continue;
      isBytes32(v) ? (out[k] = v.toLowerCase()) : out.warnings.push(`${k} 參數不是 32 位元組雜湊`);
    }
    const theme = p.get("theme");
    if (theme === "dark" || theme === "light") out.theme = theme;
    return out;
  }
  function rpcUrlOk(s) {
    try {
      const u = new URL(s);
      return (u.protocol === "https:" || u.protocol === "http:") && !u.username && !u.password;
    } catch (e) {
      return false;
    }
  }

  // ------------------------------------------------------------------ deployments json
  /** me/deployments/<network>.json -> what the page uses. Throws on a file of another shape. */
  function parseDeployment(json) {
    if (!json || typeof json !== "object") throw new Error("部署紀錄不是 JSON 物件");
    const addr = (v) => (typeof v === "string" ? v : v && v.address);
    const registry = addr(json.registry);
    if (!isAddress(registry)) throw new Error("部署紀錄裡沒有 registry 地址");
    const escrow = addr(json.escrow);
    const auditors = (Array.isArray(json.auditors) ? json.auditors : [])
      .map((a) => (typeof a === "string" ? { address: a, name: "" } : a || {}))
      .filter((a) => isAddress(a.address))
      .map((a) => ({ address: a.address.toLowerCase(), name: typeof a.name === "string" ? a.name : "" }));
    const commits = (Array.isArray(json.publicToolCommits) ? json.publicToolCommits : [])
      .filter((c) => typeof c === "string" && /^(0x)?[0-9a-fA-F]{40}$/.test(c))
      .map((c) => strip0x(c).toLowerCase());
    return {
      network: typeof json.network === "string" ? json.network : "",
      chainId: Number.isSafeInteger(json.chainId) ? json.chainId : null,
      registry: registry.toLowerCase(),
      escrow: isAddress(escrow) ? escrow.toLowerCase() : null,
      registryCodehash: json.registry && isBytes32(json.registry.codehash) ? json.registry.codehash.toLowerCase() : null,
      escrowCodehash: json.escrow && isBytes32(json.escrow.codehash) ? json.escrow.codehash.toLowerCase() : null,
      registryTx: json.registry && isBytes32(json.registry.tx) ? json.registry.tx.toLowerCase() : null,
      registryBlock: json.registry && Number.isSafeInteger(json.registry.block) ? json.registry.block : null,
      deployedAt: typeof json.deployedAt === "string" ? json.deployedAt : "",
      auditors,
      publicToolCommits: commits,
    };
  }
  function auditorName(addr, auditors) {
    if (!isAddress(addr) || !Array.isArray(auditors)) return null;
    const hit = auditors.find((a) => a.address === addr.toLowerCase());
    return hit ? hit.name || "已列出的稽核者" : null;
  }
  const TOOL_REPO = "https://github.com/sam029031/arbiter-gate";
  /** Link a tool commit only when the deployment file says that commit is public. */
  function commitLink(commit, publicCommits) {
    if (typeof commit !== "string" || isZeroHex(commit)) return null;
    const sha = strip0x(commit).toLowerCase();
    return /^[0-9a-f]{40}$/.test(sha) && (publicCommits || []).includes(sha) ? `${TOOL_REPO}/commit/${sha}` : null;
  }
  // ------------------------------------------------------------------ ME explorer
  // The explorer (a single-page app) indexes Cosmos transactions and me1 addresses, not the 0x
  // forms: a transaction is linked by the Cosmos hash the Hub CometBFT RPC reports for it.
  const isCosmosHash = (s) => typeof s === "string" && /^[0-9A-Fa-f]{64}$/.test(s);
  /** kind "tx": Cosmos tx hash (64 hex, no 0x); "address": 0x address (shown as me1…); "block": height. */
  function explorerUrl(base, kind, value) {
    if (typeof base !== "string" || !/^https:\/\/[^/?#\s]+\/*$/.test(base)) return null;
    const root = base.replace(/\/+$/, "");
    if (kind === "tx") return isCosmosHash(value) ? `${root}/zh-TW/transactions/${value.toUpperCase()}?netType=hub` : null;
    if (kind === "address") {
      const me = toMeAddress(value);
      return me ? `${root}/zh-TW/accountDetails/${me}` : null;
    }
    if (kind === "block") return Number.isSafeInteger(value) && value >= 0 ? `${root}/zh-TW/blocks/${value}?netType=hub` : null;
    return null;
  }
  /** Hub CometBFT RPC query for the Cosmos transaction that carried EVM transaction `evmHash`. */
  function cosmosTxSearchUrl(hub, evmHash) {
    if (!rpcUrlOk(hub) || !isBytes32(evmHash)) return null;
    const q = `"ethereum_tx.ethereumTxHash='${evmHash.toLowerCase()}'"`; // the index is case-sensitive
    return `${hub.replace(/\/+$/, "")}/tx_search?query=${encodeURIComponent(q)}&per_page=1`;
  }
  /** tx_search response -> {hash, height} of the Cosmos tx that carried `evmHash`, or null. */
  function parseTxSearch(json, evmHash) {
    const txs = json && json.result && Array.isArray(json.result.txs) ? json.result.txs : [];
    const want = String(evmHash).toLowerCase();
    const carries = (t) => {
      const events = t.tx_result && t.tx_result.events;
      if (!Array.isArray(events)) return true; // nothing to cross-check against
      return events.some((e) => e && e.type === "ethereum_tx" && Array.isArray(e.attributes) &&
        e.attributes.some((a) => a && a.key === "ethereumTxHash" && String(a.value).toLowerCase() === want));
    };
    for (const t of txs) {
      if (!t || !isCosmosHash(t.hash) || !/^\d{1,15}$/.test(String(t.height)) || !carries(t)) continue;
      return { hash: t.hash.toUpperCase(), height: Number(t.height) };
    }
    return null;
  }
  /** The command anyone can run to read a transaction from the chain without this page. */
  function selfCheckCommand(txHash, rpcUrl) {
    if (!isBytes32(txHash) || !rpcUrlOk(rpcUrl)) return null;
    const url = /^[A-Za-z0-9:/._~%\-[\]]+$/.test(rpcUrl) ? rpcUrl : `'${rpcUrl.replace(/'/g, "'\\''")}'`;
    return `cast receipt ${txHash.toLowerCase()} --rpc-url ${url}`;
  }

  // ------------------------------------------------------------------ finding a record's logs
  /**
   * Smallest block in [lo, hi] whose timestamp is >= ts, or null when block hi is older.
   * getTs(n) -> Promise<timestamp>. Interpolation, with a bisection step whenever it did not
   * halve the range, so uneven block times still take O(log n) lookups.
   */
  async function findBlockByTime(ts, lo, hi, getTs, maxLookups = 64) {
    let a = { n: lo, t: await getTs(lo) };
    if (a.t >= ts) return lo;
    let b = { n: hi, t: await getTs(hi) };
    if (b.t < ts) return null;
    let bisect = false;
    for (let i = 0; b.n - a.n > 1; i++) {
      if (i >= maxLookups) throw new Error("找不到這個時間的區塊");
      const width = b.n - a.n;
      let m = bisect || b.t <= a.t ? a.n + Math.floor(width / 2)
        : a.n + Math.floor(((ts - a.t) / (b.t - a.t)) * width);
      m = Math.min(Math.max(m, a.n + 1), b.n - 1);
      const t = await getTs(m);
      if (t < ts) a = { n: m, t }; else b = { n: m, t };
      bisect = !bisect && (b.n - a.n) * 2 > width;
    }
    return b.n;
  }
  /** [from, to] block windows of at most `size` blocks, starting at `start`, at most `max` of them. */
  function logWindows(start, latest, size, max) {
    const out = [];
    for (let f = start; f <= latest && out.length < max; f += size) out.push([f, Math.min(f + size - 1, latest)]);
    return out;
  }

  // ------------------------------------------------------------------ evidence bundle
  /** Where to fetch an evidence bundle from, given the record's evidenceURI. */
  function evidenceLocation(uri) {
    if (!uri) return { ok: false, reason: "empty", message: "這筆紀錄沒有提供證據位址。" };
    let u;
    try { u = new URL(uri); } catch (e) { return { ok: false, reason: "invalid", message: "證據位址不是有效的網址。" }; }
    if (u.protocol === "ipfs:") return { ok: false, reason: "ipfs", message: "證據放在 IPFS；這個頁面不直接讀 IPFS，請用 IPFS 工具取得檔案後拖進下方比對。" };
    const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname);
    if (!(u.protocol === "https:" || (u.protocol === "http:" && loopback))) {
      return { ok: false, reason: "scheme", message: "只會自動讀取 https 網址的證據（本機測試可用 http://127.0.0.1）。" };
    }
    if (u.username || u.password) return { ok: false, reason: "credentials", message: "證據位址含帳號密碼，不會自動讀取。" };
    u.hash = "";
    let manifest;
    if (/\/manifest\.json$/.test(u.pathname)) manifest = new URL(u.href);
    else {
      if (!u.pathname.endsWith("/")) u.pathname += "/";
      u.search = "";
      manifest = new URL("manifest.json", u);
    }
    const base = new URL(".", manifest).href;
    return { ok: true, base, manifest: manifest.href, host: u.host };
  }
  /** A manifest file name is a plain relative path inside the bundle folder. */
  function safeRelPath(name) {
    return typeof name === "string" && name.length > 0 && name.length <= 200 &&
      !/^[a-z][a-z0-9+.-]*:/i.test(name) && !name.startsWith("/") && !/[\\?#%]/.test(name) &&
      !name.split("/").some((p) => p === "" || p === "." || p === "..");
  }
  function bundleFileUrl(base, name) {
    if (!safeRelPath(name)) return null;
    const url = new URL(name.split("/").map(encodeURIComponent).join("/"), base).href;
    return url.startsWith(base) ? url : null;
  }
  function guessRole(name) {
    const path = String(name).toLowerCase();
    const base = path.split("/").pop();
    if (base === "gate.json") return "gateJson";
    if (base === "compiler.json") return "compiler";
    if (base === "regression.zip") return "regression";
    if (path.startsWith("parent_src/")) return "parentSource";
    if (/\.(diff|patch)$/.test(base)) return "patch";
    if (path.startsWith("exploit/") || /\.t\.sol$/.test(base) || /(exploit|poc|attack)/.test(base)) return "exploit";
    if (base.endsWith(".sol")) return "source";
    return null;
  }
  const own = (obj, k) => typeof k === "string" && Object.prototype.hasOwnProperty.call(obj, k);
  const roleOf = (f) => (own(ROLE_ALIASES, f.role) ? ROLE_ALIASES[f.role] : guessRole(f.name));
  /** null when the manifest's schema is one this page knows, else what it says instead. */
  function manifestSchemaProblem(m) {
    const s = m && m.schema;
    return MANIFEST_SCHEMAS.includes(s) ? null : typeof s === "string" ? s.slice(0, 80) : "（沒有 schema）";
  }

  /**
   * Compare fetched/dropped evidence files with a record (and, for a patched record, its parent:
   * parent_src/ is the parent's source, and the exploit is the parent's when the record has none).
   * files: [{name, role?, sha256 (computed), manifestSha256?, error?}]; parent: {id, input} | null.
   * rows: per file, `from` is record | parent | null (no on-chain hash for it); `onchain` is
   * match | mismatch | absent (the record has no such hash) | none | error; `manifest` is
   * match | mismatch | null; `label` names what it was compared with.
   * fields: per non-zero sha256 field of the record itself, match | mismatch | missing.
   */
  function compareEvidence(input, files, parent) {
    const p = parent && parent.input ? parent : null;
    const rows = files.map((f) => {
      const role = roleOf(f);
      let field = role ? ROLE_FIELDS[role] || null : null;
      let from = field ? "record" : null;
      let expected = field ? input[field] : null;
      if (role === "exploit" && isZeroHex(input.exploitHash) && p && !isZeroHex(p.input.exploitHash)) {
        from = "parent";
        expected = p.input.exploitHash;
      } else if (role === "parentSource" && p) {
        [field, from, expected] = ["sourceHash", "parent", p.input.sourceHash];
      }
      const label = from === "parent" ? `上一版（#${p.id}）的${FIELD_LABELS[field]}`
        : from ? FIELD_LABELS[field] : EXTRA_ROLES[role] || null;
      let onchain;
      if (f.error) onchain = "error";
      else if (!from) onchain = "none";
      else if (isZeroHex(expected)) onchain = "absent";
      else onchain = sameHash(expected, f.sha256) ? "match" : "mismatch";
      const manifest = f.manifestSha256 && !f.error ? (sameHash(f.manifestSha256, f.sha256) ? "match" : "mismatch") : null;
      return { name: f.name, role, field, from, label, expected, sha256: f.sha256 || null, onchain, manifest,
               manifestSha256: f.manifestSha256 || null, error: f.error || null };
    });
    const fields = Object.values(ROLE_FIELDS)
      .filter((field) => !isZeroHex(input[field]))
      .map((field) => {
        const mine = rows.filter((r) => r.from === "record" && r.field === field && r.onchain !== "error");
        const status = mine.some((r) => r.onchain === "match") ? "match" : mine.length ? "mismatch" : "missing";
        return { field, expected: input[field], status, files: mine.map((r) => r.name) };
      });
    const ok = rows.every((r) => r.onchain !== "mismatch" && r.onchain !== "error" && r.manifest !== "mismatch") &&
      fields.every((f) => f.status === "match");
    return { rows, fields, ok };
  }
  /** Which sha256 fields of a record a local file's hash equals. */
  function matchFields(input, hash) {
    return Object.values(ROLE_FIELDS).filter((field) => sameHash(input[field], hash));
  }

  // ------------------------------------------------------------------ provenance
  /**
   * Timeline steps for a record's lineage: ancestors (root first), the record itself, and its
   * direct children. nodes: [{id, record, current?, deployments?}] in that order; children are
   * flagged `child: true`; `deployments` (every gated address, from deploymentsOf) is known for
   * the current record only, the others show their first link. Returns
   * [{type: "record"|"patch"|"deploy", ...}].
   */
  function provenanceSteps(nodes) {
    const steps = [];
    let prev = null;
    for (const n of nodes) {
      const inp = n.record.input;
      if (prev && inp.parentId === prev.id) {
        steps.push({ type: "patch", from: inp.parentId, to: n.id, patchHash: inp.patchHash });
      }
      const stage = inp.parentId ? "重新稽核" : "稽核";
      steps.push({ type: "record", id: n.id, verdict: inp.verdict, stage, current: !!n.current, child: !!n.child,
                   timestamp: n.record.timestamp });
      const gated = Array.isArray(n.deployments) ? n.deployments : null;
      if (gated && gated.length) {
        steps.push({ type: "deploy", id: n.id, address: gated[0], linkKind: 2, count: gated.length });
      }
      const link = n.record.linkKind;
      if ((link === 1 || (link === 2 && !gated)) && !isZeroHex(n.record.deployed)) {
        steps.push({ type: "deploy", id: n.id, address: n.record.deployed, linkKind: link, count: 1 });
      }
      if (!n.child) prev = n;
    }
    return steps;
  }

  // ------------------------------------------------------------------ formatting
  function formatUnits(value, decimals = 18, maxFrac = 6) {
    const v = BigInt(value);
    const neg = v < 0n;
    const a = neg ? -v : v;
    const base = 10n ** BigInt(decimals);
    const whole = a / base;
    let frac = (a % base).toString().padStart(decimals, "0").slice(0, maxFrac).replace(/0+$/, "");
    return (neg ? "-" : "") + whole.toString() + (frac ? "." + frac : "");
  }
  function isoUtc(ts) {
    return new Date(ts * 1000).toISOString().replace(".000Z", "Z");
  }
  /** Block time in Taiwan time (the hackathon's audience), e.g. 2026/11/22 03:12:05（UTC+8）. */
  function formatTime(ts) {
    const d = new Date(ts * 1000);
    const s = new Intl.DateTimeFormat("zh-TW", {
      timeZone: "Asia/Taipei", year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
    }).format(d).replace(/\s+/g, " "); // some ICU versions put a thin space after the date
    return `${s}（UTC+8）`;
  }

  return {
    VERDICTS, PREDICATES, TIERS, LINKS, ESCROW_STATUS, FIELD_LABELS, ROLE_FIELDS, ROLE_ALIASES, EXTRA_ROLES,
    MANIFEST_SCHEMAS, SETTLE_GRACE, FUNCS, FUNC_SIGS, TOPICS, EVENT_SIGS, TOOL_REPO,
    verdictInfo, predicateInfo, tierInfo, linkInfo, escrowStatusInfo,
    strip0x, isAddress, isBytes32, isZeroHex, normHex, sameHash, bytesToHex, hexToBytes, shortHex, sha256Hex,
    encodeCall, decodeRecord, decodeRequest, decodeUintArray, decodeAddressArray, decodeNumber, decodeAddress,
    decodeBool, decodeLog,
    toMeAddress, fromMeAddress, classifyQuery, parseParams, rpcUrlOk,
    parseDeployment, auditorName, commitLink, explorerUrl, cosmosTxSearchUrl, parseTxSearch, selfCheckCommand,
    findBlockByTime, logWindows,
    evidenceLocation, safeRelPath, bundleFileUrl, guessRole, roleOf, manifestSchemaProblem, compareEvidence,
    matchFields, provenanceSteps, formatUnits, isoUtc, formatTime,
  };
});
