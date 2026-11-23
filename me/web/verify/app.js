/* ARBITER Gate 紀錄驗證頁：讀 ME（或任何 EVM RPC）上的 AuditRegistry / AuditEscrow。
 * Read-only: no wallet, no transactions. Chain data, manifests and evidence files are
 * untrusted, so everything is rendered with textContent/DOM nodes, never innerHTML. */
(function () {
  "use strict";
  const L = window.VerifyLib;

  // explorer: the ME explorer (indexes Cosmos tx hashes and me1 addresses); hubRpc: the Hub
  // CometBFT RPC that maps an EVM tx hash to its Cosmos tx hash. Local chains have neither.
  const NETWORKS = {
    "me-testnet": { key: "me-testnet", name: "ME 測試網", rpc: "https://beta-hub-8545.explorer-testnet.me",
                    chainId: 400, explorer: "https://www.explorer-testnet.me",
                    hubRpc: "https://beta-hub-26657.explorer-testnet.me", symbol: "MEC", deployments: "me-testnet" },
    anvil: { key: "anvil", name: "本機 anvil", rpc: "http://127.0.0.1:8545", chainId: 31337, explorer: null,
             hubRpc: null, symbol: "ETH（本機測試幣）", deployments: "anvil" },
    custom: { key: "custom", name: "自訂 RPC", rpc: "", chainId: null, explorer: null, hubRpc: null, symbol: "原生幣",
              deployments: null },
  };
  const KEEP_PARAMS = ["net", "rpc", "registry", "escrow", "theme"];
  const MAX_MANIFEST = 1 << 20; // 1 MB
  const MAX_FILE = 20 << 20; // 20 MB per evidence file
  const MAX_FILES = 50;
  const MAX_DEPLOYMENTS = 20; // gated deployments listed per record
  const MAX_SAME_INIT = 30; // other records for the same bytecode checked for a proven exploit
  const LOG_SPAN = 10000; // ME's eth_getLogs accepts at most 10,000 blocks per query
  const LOG_WINDOWS = 8; // windows scanned after a record's block when a node limits the range

  // Trust (verify-lib "official deployment or not"): rpcOfficial = the node is the network's own
  // (built into the page, or named by the deployment file); file = that deployment file (never one
  // for a node from the URL); trust = L.trustLevel(...); dep = file, only for the official
  // deployment (auditor list, public commits); registryFrom/escrowFrom = "file" | "url".
  const S = { params: {}, net: null, chainId: null, block: null, dep: null, file: null, registry: null, escrow: null,
              count: null, ethers: false, run: 0, cache: new Map(), cosmos: new Map(), rpcOfficial: false, trust: null,
              registryFrom: null, escrowFrom: null, code: null, escrowVerified: false };

  // ------------------------------------------------------------------ DOM helpers
  const $ = (id) => document.getElementById(id);
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid != null && kid !== false) el.append(kid instanceof Node ? kid : String(kid));
    }
    return el;
  }
  const announce = (msg) => { $("sr-status").textContent = ""; setTimeout(() => ($("sr-status").textContent = msg), 30); };
  function extLink(href, text) {
    return href ? h("a", { href, target: "_blank", rel: "noopener noreferrer" }, text) : null;
  }
  function exLink(kind, value, text = "區塊瀏覽器") {
    return extLink(L.explorerUrl(S.net && S.net.explorer, kind, value), text);
  }
  function fmtAddr(a) {
    if (!L.isAddress(a)) return String(a);
    try { return S.ethers ? window.ethers.getAddress(a) : a; } catch (e) { return a; }
  }
  async function copyText(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      const ta = h("textarea", { class: "sr-only", "aria-hidden": "true" });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      try { document.execCommand("copy"); } catch (e2) { /* nothing else to try */ }
      ta.remove();
    }
    if (btn) {
      const old = btn.textContent;
      btn.textContent = "已複製";
      setTimeout(() => (btn.textContent = old), 1400);
    }
    announce("已複製到剪貼簿");
  }
  const copyBtn = (text, label = "複製") =>
    h("button", { type: "button", class: "btn small", "aria-label": `${label}：${text}`,
                  onclick: (e) => copyText(text, e.currentTarget) }, label);
  function hexValue(value, { kind = null, copy = true } = {}) {
    const shown = kind === "address" ? fmtAddr(value) : value;
    return h("span", { class: "inline" }, h("span", { class: "mono" }, shown), copy ? copyBtn(shown) : null,
      kind ? exLink(kind, value) : null);
  }
  const pending = (text) => h("span", { class: "mute small pending" }, text);
  /** The node a reader should ask to check a transaction without this page: on ME (chain 400)
   * always ME's own RPC, never a node the link named. */
  const checkRpc = () => (S.chainId === NETWORKS["me-testnet"].chainId ? NETWORKS["me-testnet"].rpc : S.net.rpc);
  const verified = () => !!(S.trust && S.trust.verified);
  const unvTag = (text = "未驗證") => h("span", { class: "tag unv" }, text);

  /** A transaction: its 0x hash (always, with a copy button), then a link to the ME explorer
   * once the Hub RPC has reported the Cosmos tx the explorer indexes. Without that link (lookup
   * failed, or a local chain), the command that reads the receipt straight from the chain. */
  function txRef(hash) {
    const tail = h("span", { class: "inline" });
    const el = h("span", { class: "txref", "data-tx": hash.toLowerCase() },
      h("span", { class: "inline" }, h("span", { class: "mono", title: hash }, L.shortHex(hash, 10, 8)), copyBtn(hash, "複製雜湊")),
      tail);
    const showCommand = (why) => {
      const cmd = L.selfCheckCommand(hash, checkRpc());
      tail.replaceChildren(h("span", { class: "selfcheck" }, h("span", { class: "mute small" }, why),
        cmd ? h("span", { class: "inline" }, h("code", { class: "mono" }, cmd), copyBtn(cmd, "複製指令")) : null));
    };
    if (!(S.net.hubRpc && S.net.explorer)) {
      showCommand("這條鏈沒有區塊瀏覽器；可以用 Foundry 自己讀這筆交易：");
      return el;
    }
    tail.append(pending("查詢區塊瀏覽器連結…"));
    cosmosTx(hash).then((c) => {
      const url = c && L.explorerUrl(S.net.explorer, "tx", c.hash);
      if (!url) return showCommand("區塊瀏覽器查不到這筆交易的對應紀錄（瀏覽器以 Cosmos 交易雜湊索引）；可以用 Foundry 自己讀：");
      // the explorer is sometimes down: keep the command that reads the receipt from the chain at hand
      const block = L.explorerUrl(S.net.explorer, "block", c.height);
      const cmd = L.selfCheckCommand(hash, checkRpc());
      tail.replaceChildren(extLink(url, "在區塊瀏覽器查看"),
        h("span", { class: "mute small", title: c.hash }, `Cosmos 交易 ${L.shortHex(c.hash, 6, 6)} · `,
          extLink(block, `區塊 #${c.height.toLocaleString("en-US")}`) || `區塊 #${c.height}`),
        cmd ? copyBtn(cmd, "複製 cast 驗證指令") : null);
    });
    return el;
  }
  /** Cosmos tx carrying EVM tx `hash` ({hash, height}) or null; failures are not cached. */
  function cosmosTx(hash) {
    const key = hash.toLowerCase();
    if (!S.cosmos.has(key)) {
      const url = L.cosmosTxSearchUrl(S.net.hubRpc, key);
      const p = (url ? fetchBytes(url, MAX_MANIFEST) : Promise.reject(new Error("no hub")))
        .then((raw) => L.parseTxSearch(JSON.parse(new TextDecoder("utf-8").decode(raw)), key))
        .catch(() => null)
        .then((c) => { if (!c) S.cosmos.delete(key); return c; });
      S.cosmos.set(key, p);
    }
    return S.cosmos.get(key);
  }
  function check(state, title, detail) {
    const icon = { ok: "✓", bad: "✗", warn: "!", na: "–", wait: "…", plan: "○" }[state];
    const word = { ok: "通過", bad: "不符", warn: "注意", na: "略過", wait: "檢查中", plan: "部署後會顯示" }[state];
    return h("li", { class: `check ${state}` }, h("span", { class: "ic", "aria-hidden": "true" }, icon),
      h("div", null, h("b", null, h("span", { class: "sr-only" }, `${word}：`), title), detail ? h("p", null, detail) : null));
  }
  function replaceCheck(li, state, title, detail) {
    const fresh = check(state, title, detail);
    li.replaceWith(fresh);
    return fresh;
  }
  function kv(rows) {
    const dl = h("dl", { class: "kv" });
    for (const r of rows) if (r) dl.append(h("dt", null, r[0]), h("dd", null, r[1]));
    return dl;
  }
  const loading = (text) => h("p", { class: "loading", role: "status" }, text);
  /** Display only: the home view gets the big hero (html.vp-home, also in index.html for the first
      paint); record, address, tx and source views keep the compact phase-1 header. */
  function markView() {
    const p = S.params || {};
    document.documentElement.classList.toggle("vp-home", !(p.record || p.address || p.tx || p.source));
  }
  /** Every view starts with what the page cannot vouch for, when there is anything (trustCard). */
  function setResult(...nodes) {
    markView();
    const box = $("result");
    box.replaceChildren(...[trustCard(), ...nodes].filter(Boolean));
    box.removeAttribute("aria-busy");
  }
  function begin(text) {
    markView();
    const run = ++S.run;
    const box = $("result");
    box.setAttribute("aria-busy", "true");
    box.replaceChildren(h("section", { class: "card" }, loading(text)));
    return run;
  }
  const stale = (run) => run !== S.run;
  function setPill(state, text) {
    const pill = $("net-pill");
    pill.className = `pill ${state}`;
    pill.textContent = text;
    pill.title = text;
  }
  function messageCard(title, ...body) {
    return h("section", { class: "card" }, h("h2", null, title), ...body.map((b) => (typeof b === "string" ? h("p", null, b) : b)));
  }

  // ------------------------------------------------------------------ network
  class UserError extends Error {}
  let rpcId = 0;
  async function rpc(method, params = []) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 20000);
    let res;
    try {
      res = await fetch(S.net.rpc, {
        method: "POST", headers: { "content-type": "application/json" }, cache: "no-store",
        credentials: "omit", referrerPolicy: "no-referrer", signal: ctrl.signal,
        body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params }),
      });
    } catch (e) {
      throw new UserError(`連不上 RPC（${hostOf(S.net.rpc)}）：可能是網路中斷、網址錯誤，或對方不允許網頁跨網域讀取。`);
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) throw new UserError(`RPC 回應 HTTP ${res.status}（${method}）`);
    let body;
    try { body = await res.json(); } catch (e) { throw new UserError("RPC 回傳的不是 JSON"); }
    if (body.error) throw new UserError(`RPC 錯誤（${method}）：${String(body.error.message || "未知錯誤").slice(0, 200)}`);
    return body.result;
  }
  const call = (to, fn, args = []) => rpc("eth_call", [{ to, data: L.encodeCall(fn, args) }, "latest"]);
  function hostOf(url) { try { return new URL(url).host; } catch (e) { return url; } }

  async function getRecord(id) {
    if (!S.cache.has(id)) S.cache.set(id, call(S.registry, "getRecord", [id]).then(L.decodeRecord));
    try { return await S.cache.get(id); } catch (e) { S.cache.delete(id); throw e; }
  }
  async function getCount() {
    S.count = L.decodeNumber(await call(S.registry, "recordCount"));
    return S.count;
  }
  const idList = async (fn, arg) => L.decodeUintArray(await call(S.registry, fn, [arg]));
  /** First `max` ids of an index anyone can append to, plus its length (count + page views). */
  async function idPage(index, arg, max) {
    const total = L.decodeNumber(await call(S.registry, `${index}Count`, [arg]));
    const ids = total ? L.decodeUintArray(await call(S.registry, `${index}Page`, [arg, 0, max])) : [];
    return { ids, total };
  }
  /** A read whose failure should not take the whole view down: {ok, v} or {ok: false, error}. */
  const tryRead = (p) => p.then((v) => ({ ok: true, v }), (e) => ({ ok: false, error: e.message || String(e) }));
  const hexNum = (n) => "0x" + n.toString(16);
  const word = (n) => "0x" + BigInt(n).toString(16).padStart(64, "0");

  async function blockTime(n) {
    const b = await rpc("eth_getBlockByNumber", [hexNum(n), false]);
    if (!b || !b.timestamp) throw new UserError(`節點沒有區塊 #${n}`);
    return parseInt(b.timestamp, 16);
  }
  /**
   * eth_getLogs for one record's events (filter: address + topics). One query over the whole
   * range first (a local chain, or a registry younger than the node's limit); a node that caps
   * the range (ME: 10,000 blocks) is then asked window by window from the block the record was
   * registered in, found from its timestamp, until done(logs) or LOG_WINDOWS windows.
   * where: {timestamp, start?} shared by the queries of one record view.
   */
  async function recordLogs(where, filter, done) {
    const from = S.dep && S.dep.registryBlock != null ? S.dep.registryBlock : 0;
    try {
      return (await rpc("eth_getLogs", [{ ...filter, fromBlock: hexNum(from), toBlock: "latest" }])) || [];
    } catch (e) {
      /* most likely the node's block-range limit: search near the record instead */
    }
    if (!where.start) {
      where.start = (async () => {
        const latest = parseInt(await rpc("eth_blockNumber"), 16);
        return { latest, block: await L.findBlockByTime(where.timestamp, from, latest, blockTime) };
      })();
    }
    const { latest, block } = await where.start;
    const out = [];
    if (block == null) return out;
    for (const [a, b] of L.logWindows(block, latest, LOG_SPAN, LOG_WINDOWS)) {
      out.push(...((await rpc("eth_getLogs", [{ ...filter, fromBlock: hexNum(a), toBlock: hexNum(b) }])) || []));
      if (done(out)) break;
    }
    return out;
  }

  /** Read a response body, refusing more than `cap` bytes. */
  async function readCapped(res, cap) {
    const len = Number(res.headers.get("content-length"));
    if (len > cap) throw new UserError(`檔案太大（${Math.ceil(len / 1048576)} MB，上限 ${cap >> 20} MB）`);
    if (!res.body || !res.body.getReader) return res.arrayBuffer();
    const reader = res.body.getReader();
    const parts = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > cap) { reader.cancel(); throw new UserError(`檔案超過 ${cap >> 20} MB 上限`); }
      parts.push(value);
    }
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return out.buffer;
  }
  async function fetchBytes(url, cap) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 30000);
    try {
      let res;
      try {
        res = await fetch(url, { cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer", signal: ctrl.signal });
      } catch (e) {
        throw new UserError("讀不到（網路錯誤，或對方伺服器不允許跨網域讀取）");
      }
      if (!res.ok) throw new UserError(`HTTP ${res.status}`);
      return await readCapped(res, cap);
    } finally {
      clearTimeout(timer);
    }
  }

  // ------------------------------------------------------------------ start-up
  function selfCheck() {
    // The ABI constants in verify-lib.js were computed with cast; re-derive them with ethers.
    const bad = [];
    for (const [fn, sig] of Object.entries(L.FUNC_SIGS)) {
      if (window.ethers.id(sig).slice(0, 10) !== L.FUNCS[fn][0]) bad.push(sig);
    }
    for (const [ev, sig] of Object.entries(L.EVENT_SIGS)) if (window.ethers.id(sig) !== L.TOPICS[ev]) bad.push(sig);
    return bad;
  }

  async function connect() {
    const p = S.params;
    const key = p.net || "me-testnet";
    S.net = { ...NETWORKS[key], home: key === "custom" ? null : NETWORKS[key] };
    if (key === "custom") S.net.rpc = p.rpc || "";
    Object.assign(S, { chainId: null, block: null, dep: null, file: null, registry: null, escrow: null, count: null,
                       registryMissing: null, registryRefused: null, registryCodehash: null, escrowMismatch: null,
                       escrowRejected: null, escrowIgnored: null, loadError: null, rpcOfficial: key !== "custom",
                       trust: null, registryFrom: null, escrowFrom: null, code: null, escrowVerified: false,
                       cache: new Map(), cosmos: new Map() });
    fillNetForm();
    renderTrust();
    $("hero-net").textContent = `${S.net.name} · AuditRegistry`;
    $("net-info").replaceChildren();
    if (!S.net.rpc) {
      setPill("bad", "沒有 RPC 網址");
      setResult(messageCard("請填入 RPC 網址", "在下方「網路與合約」選擇網路，或填入自訂 RPC 網址。"));
      $("net-details").open = true;
      return;
    }
    const run = begin(`連線到 ${S.net.name}…`);
    setPill("wait", `${S.net.name} · 連線中…`);
    try {
      S.chainId = parseInt(await rpc("eth_chainId"), 16);
      S.block = parseInt(await rpc("eth_blockNumber"), 16);
    } catch (e) {
      if (stale(run)) return;
      setPill("bad", `${S.net.name} · 連線失敗`);
      setResult(messageCard("連線失敗", e.message || String(e)));
      return;
    }
    if (stale(run)) return;
    if (S.net.chainId && S.chainId !== S.net.chainId) {
      setPill("warn", `chainId ${S.chainId}（預期 ${S.net.chainId}）`);
      setResult(messageCard("網路不符", `這個 RPC 回報的 chainId 是 ${S.chainId}，但 ${S.net.name} 應該是 ${S.net.chainId}。為避免讀到別條鏈的資料，頁面不繼續讀取。`));
      return;
    }
    if (key === "custom") {
      // The node says which chain it is, so nothing the page knows about that chain is taken on
      // its word: the deployment file and the network's name apply only when the node is the
      // network's own (its built-in RPC here, or the one the deployment file names: loadContracts).
      // Explorer links still work: they are looked up through the network's own Hub, so they can
      // only lead to real transactions.
      const home = Object.values(NETWORKS).find((n) => n.key !== "custom" && n.chainId === S.chainId);
      if (home) {
        Object.assign(S.net, { home, explorer: home.explorer, hubRpc: home.hubRpc, symbol: home.symbol,
                               deployments: home.deployments });
        if (L.sameRpc(S.net.rpc, home.rpc)) S.rpcOfficial = true;
      }
      S.net.name = `自訂 RPC（chainId ${S.chainId}）`;
    }
    await loadContracts(run);
    if (stale(run)) return;
    if (key === "custom" && S.rpcOfficial && S.net.home) S.net.name = S.net.home.name;
    showPill();
    $("hero-net").textContent = `${S.net.name} · ${S.registryFrom === "url" ? "網址指定的 AuditRegistry" : "AuditRegistry"}`;
    renderTrust();
    renderNetInfo();
    paramWarnings();
    if (!S.registry) return renderNotDeployed();
    await route(run);
  }

  function showPill() {
    const block = `區塊 #${S.block.toLocaleString("en-US")}`;
    const t = S.trust;
    if (S.registryRefused) return setPill("bad", `${S.net.name} · AuditRegistry 程式碼不符`);
    if (!S.rpcOfficial) return setPill("warn", `${S.net.name} · 非官方來源 · ${block}`);
    if (t && !t.official) return setPill("warn", `${S.net.name} · ${t.level === "genuine" ? "非官方部署" : "未驗證"} · ${block}`);
    setPill("ok", `${S.net.name} · ${block}`);
  }

  async function loadDeploymentsFile(name) {
    if (!name) return null;
    const urls = [...new Set([new URL(`../../deployments/${name}.json`, location.href).href,
                              new URL(`/me/deployments/${name}.json`, location.origin).href])];
    for (const url of urls) {
      try {
        const res = await fetch(url, { cache: "no-cache", credentials: "omit" });
        if (!res.ok) continue;
        const dep = L.parseDeployment(await res.json());
        if (dep.chainId !== null && dep.chainId !== S.chainId) continue; // a file for another chain
        return { ...dep, url };
      } catch (e) {
        /* not there, or not a deployment file: try the next location */
      }
    }
    return null;
  }

  const keccak = (code) => (S.ethers && typeof code === "string" && /^0x[0-9a-fA-F]*$/.test(code) ? window.ethers.keccak256(code) : null);

  /**
   * Which registry and escrow to read, and how far the page vouches for them (verify-lib
   * chooseContracts / codeCheck / trustLevel). The official deployment is the deployment file's
   * AuditRegistry, read through the network's own node, whose runtime code hashes to what the
   * file recorded; only then are the file's auditor list and public commits used (S.dep).
   */
  async function loadContracts(run) {
    const file = await loadDeploymentsFile(S.net.deployments);
    if (stale(run)) return;
    // a node named in the URL counts as the network's own only when the deployment file names it
    if (!S.rpcOfficial && file && L.sameRpc(file.rpc, S.net.rpc)) S.rpcOfficial = true;
    const trusted = S.rpcOfficial ? file : null;
    const pick = L.chooseContracts(S.params, trusted);
    Object.assign(S, { file: trusted, registry: pick.registry, registryFrom: pick.registryFrom, escrow: pick.escrow,
                       escrowFrom: pick.escrowFrom, escrowIgnored: pick.ignoredEscrow });
    if (!S.registry) return;
    try {
      const code = await rpc("eth_getCode", [S.registry, "latest"]);
      if (!code || code === "0x") {
        S.registryMissing = S.registry;
        S.registry = null;
        return;
      }
      S.registryCodehash = keccak(code);
      S.code = L.codeCheck(S.registryCodehash, trusted && trusted.registryCodehash);
      S.trust = L.trustLevel({ rpcOfficial: S.rpcOfficial, registryFrom: S.registryFrom, code: S.code });
      if (S.trust.level === "fake") {
        // whatever this contract answers (records, auditors, deployments) could be made up: read nothing
        Object.assign(S, { registryRefused: S.registry, registry: null, escrow: null });
        return;
      }
      S.dep = S.trust.official ? trusted : null;
      await getCount();
      if (S.escrow) await checkEscrow(trusted);
    } catch (e) {
      S.loadError = e.message || String(e);
    }
  }

  /** The escrow must answer registry() with this registry. Beside a verified registry its code
   * must also be AuditEscrow's (the deployment file's hash, with the registry immutable rebound);
   * otherwise it is ignored. Beside an unverified registry it is shown, marked unverified. */
  async function checkEscrow(trusted) {
    let reg = null;
    try { reg = L.decodeAddress(await call(S.escrow, "registry")); } catch (e) { /* not an escrow at all */ }
    if (reg !== S.registry) {
      Object.assign(S, { escrowMismatch: S.escrow, escrow: null });
      return;
    }
    if (!S.trust.verified) return; // S.escrowVerified stays false: shown with an "unverified" mark
    const code = await rpc("eth_getCode", [S.escrow, "latest"]);
    const check = L.codeCheck(keccak(L.rebindRegistry(code, S.registry, trusted.registry)), trusted.escrowCodehash);
    if (check === "match") S.escrowVerified = true;
    else Object.assign(S, { escrowRejected: { address: S.escrow, why: check }, escrow: null });
  }

  // ------------------------------------------------------------------ what the page cannot vouch for
  const homeKey = () => (S.net && S.net.home ? S.net.home.key : "me-testnet");
  const officialLink = (text, cls) =>
    h("a", { href: location.pathname + L.officialSearch(S.params, homeKey()), class: cls }, text);

  /** [{tone: "warn"|"bad", short, text}]: empty for the official deployment (and before connecting). */
  function trustNotes() {
    if (S.chainId == null) return [];
    const notes = [];
    const add = (tone, short, text) => notes.push({ tone, short, text });
    const addr = (a) => fmtAddr(a);
    if (!S.rpcOfficial) {
      add("warn", `網址指定的節點 ${hostOf(S.net.rpc)}`,
        `資料來自網址指定的節點 ${hostOf(S.net.rpc)}，不是頁面內建或部署紀錄檔列出的官方節點；它回傳的紀錄、程式碼和交易都可能是捏造的。`);
    }
    if (S.registryRefused) {
      add("bad", "AuditRegistry 程式碼不符", S.registryFrom === "url"
        ? `網址指定的 AuditRegistry ${addr(S.registryRefused)} 的程式碼雜湊和官方 AuditRegistry 不同：它不是 AuditRegistry，可能是仿冒的合約。頁面不讀取它的任何資料。`
        : `部署紀錄檔裡的 AuditRegistry ${addr(S.registryRefused)} 上的程式碼和紀錄的雜湊不同（測試網可能重置過，或部署紀錄檔過期）；頁面不讀取它的任何資料。`);
    } else if (S.registryFrom === "url" && (S.registry || S.registryMissing)) {
      const a = S.registry || S.registryMissing;
      add("warn", `網址指定的 AuditRegistry ${L.shortHex(addr(a), 8, 6)}`,
        `AuditRegistry ${addr(a)} 由網址指定，不是官方部署紀錄檔裡的合約。` +
        (S.trust && S.trust.level === "genuine"
          ? "它的程式碼和官方 AuditRegistry 相同（確實是 AuditRegistry），但任何人都能自己部署一份，官方的稽核者清單不適用於它。" : ""));
    }
    if (S.trust && S.trust.level === "unverified" && S.rpcOfficial) {
      add("warn", "無法比對 AuditRegistry 的程式碼", !S.ethers
        ? "瀏覽器沒有載入 keccak256 函式庫（ethers），無法比對 AuditRegistry 的程式碼雜湊，所以不能當成官方部署。"
        : S.file ? "部署紀錄檔沒有記下 AuditRegistry 的程式碼雜湊，無法確認它是官方部署。"
          : "這個網路沒有部署紀錄檔，無法比對 AuditRegistry 的程式碼雜湊。");
    }
    if (S.escrow && !S.escrowVerified) {
      add("warn", "未驗證的 AuditEscrow", `AuditEscrow ${addr(S.escrow)}（${S.escrowFrom === "url" ? "網址指定" : "部署紀錄檔"}）` +
        "沒有經過程式碼驗證；付費託管的內容可能是捏造的。");
    }
    if (S.escrowRejected) {
      add("warn", "AuditEscrow 已忽略", `AuditEscrow ${addr(S.escrowRejected.address)} ` + (S.escrowRejected.why === "mismatch"
        ? "的程式碼和官方 AuditEscrow 不同，已忽略。" : "無法比對它的程式碼（部署紀錄檔沒有 AuditEscrow 的程式碼雜湊可比），已忽略。"));
    }
    return notes;
  }

  /** The warning card at the top of every view (setResult). */
  function trustCard() {
    const notes = trustNotes();
    if (!notes.length) return null;
    const t = S.trust;
    const bad = notes.some((n) => n.tone === "bad");
    const title = bad ? (S.registryFrom === "url" ? "警告：網址指定的合約不是 AuditRegistry" : "警告：AuditRegistry 沒有通過程式碼檢查")
      : t && t.official ? "注意" : "非官方來源：頁面沒有替這些資料背書";
    const after = S.registryRefused ? null
      : !verified() ? "所以這一頁不顯示「✓」稽核者標記，判定和部署標成「未驗證」。"
        : !t.official ? "所以這一頁不顯示「✓」稽核者標記。" : null;
    const showLink = S.registryFrom === "url" || !S.rpcOfficial;
    return h("section", { class: `card trustcard ${bad ? "bad" : "warn"}`, "aria-labelledby": "trust-h" },
      h("h2", { id: "trust-h" }, title),
      h("ul", null, notes.map((n) => h("li", null, n.text))),
      after ? h("p", null, after) : null,
      showLink ? h("p", null, officialLink("改用官方設定查看", "btn small")) : null);
  }

  /** The same notes, one line in the page header, on every view. */
  function renderTrust() {
    const el = $("trust");
    const notes = trustNotes();
    el.hidden = !notes.length;
    if (!notes.length) return el.replaceChildren();
    const bad = notes.some((n) => n.tone === "bad");
    el.className = `trust ${bad ? "bad" : "warn"}`;
    const off = !(S.trust && S.trust.official);
    el.replaceChildren(h("div", { class: "wrap trust-in" },
      h("span", null, `${bad ? "✗" : "⚠"} ${off ? "非官方來源" : "注意"}：${notes.map((n) => n.short).join("、")}`),
      off ? officialLink("改用官方設定", null) : null));
  }

  /** Under a record's number: which registry and node it was read from, when not the official ones. */
  function sourceLine() {
    const parts = [];
    if (S.registryFrom === "url" && S.registry) parts.push(`讀自網址指定的 AuditRegistry ${L.shortHex(fmtAddr(S.registry), 8, 6)}`);
    if (!S.rpcOfficial) parts.push(`節點 ${hostOf(S.net.rpc)}（網址指定）`);
    return parts.length ? h("p", { class: "srcline" }, parts.join(" · ")) : null;
  }

  // ------------------------------------------------------------------ routing
  async function route(run) {
    const p = S.params;
    try {
      if (S.loadError) throw new UserError(S.loadError);
      if (p.record) return await showRecord(p.record);
      if (p.address) return await lookupAddress(p.address);
      if (p.tx) return await lookupHash(p.tx);
      if (p.source) return await lookupSource(p.source);
      return await showLatest(run);
    } catch (e) {
      showError(e);
    }
  }
  function showError(e) {
    console.error(e);
    setResult(messageCard("讀取失敗", e instanceof UserError ? e.message : `讀取鏈上資料時發生錯誤：${e.message || e}`));
  }
  function setUrl(extra) {
    const u = new URL(location.href);
    const next = new URLSearchParams();
    for (const k of KEEP_PARAMS) if (u.searchParams.get(k)) next.set(k, u.searchParams.get(k));
    for (const [k, v] of Object.entries(extra || {})) if (v != null) next.set(k, String(v));
    const qs = next.toString();
    const href = u.pathname + (qs ? `?${qs}` : "");
    if (href !== location.pathname + location.search) history.pushState(null, "", href);
    S.params = { ...L.parseParams(location.search) };
  }
  async function lookup(raw) {
    const q = L.classifyQuery(raw);
    $("q-err").textContent = "";
    if (q.kind === "empty" || q.kind === "invalid") {
      $("q-err").textContent = q.kind === "empty" ? "請輸入合約地址、紀錄編號或交易雜湊。" : q.reason;
      $("q").focus();
      return;
    }
    if (!S.registry) {
      $("q-err").textContent = noRegistryText();
      return;
    }
    try {
      if (q.kind === "record") { setUrl({ record: q.id }); await showRecord(q.id); }
      else if (q.kind === "address") { setUrl({ address: q.value }); await lookupAddress(q.value); }
      else { setUrl({ tx: q.value }); await lookupHash(q.value); }
    } catch (e) {
      showError(e);
    }
  }
  const openRecord = (id) => { setUrl({ record: id }); showRecord(id).catch(showError); };
  const noRegistryText = () => (S.registryRefused ? "指定的合約不是 AuditRegistry，無法查詢。"
    : !S.rpcOfficial ? "使用網址指定的節點時，要另外指定 AuditRegistry 地址。" : "目前的網路上沒有 AuditRegistry，無法查詢。");

  // ------------------------------------------------------------------ lookups
  async function lookupAddress(addr) {
    const run = begin(`查詢地址 ${L.shortHex(addr)}…`);
    if (addr === S.registry || addr === S.escrow) {
      if (stale(run)) return;
      return setResult(messageCard(addr === S.registry ? "這是 AuditRegistry 本身" : "這是 AuditEscrow 本身",
        "這是存放稽核紀錄（或託管費用）的合約，不是被稽核的合約。輸入被稽核合約的地址、紀錄編號或交易雜湊來查詢。"));
    }
    // gated deployment first (the registry deployed it), then auditors' claims, then a code-hash hint
    const [id, claims, code] = await Promise.all([call(S.registry, "deploymentOf", [addr]).then(L.decodeNumber),
                                                  tryRead(idList("claimsOf", addr)),
                                                  rpc("eth_getCode", [addr, "latest"])]);
    if (stale(run)) return;
    const claimIds = claims.ok ? claims.v : [];
    if (id) {
      const others = claimIds.filter((c) => c !== id);
      const more = others.length ? `另有 ${others.length} 筆紀錄的稽核者自行宣告這個地址：` +
        `${others.slice(0, 10).map((c) => `#${c}`).join("、")}${others.length > 10 ? "…" : ""}。` : "";
      return showRecord(id, { banner: verified()
        ? `地址 ${fmtAddr(addr)} 是 AuditRegistry 依紀錄 #${id} 稽核過的 bytecode 部署的。${more}`
        : `未驗證的來源回報：地址 ${fmtAddr(addr)} 由紀錄 #${id} 的 bytecode 部署（這個說法沒有經過驗證）。${more}` });
    }
    const hasCode = code && code !== "0x";
    const codeHash = hasCode && S.ethers ? window.ethers.keccak256(code) : null;
    const title = `地址 ${L.shortHex(fmtAddr(addr), 10, 6)}`;
    if (claimIds.length) {
      const list = await recordList(claimIds, run, { extra: (r) => claimNote(r, addr, hasCode, codeHash) });
      if (stale(run)) return;
      return setResult(messageCard(title, hexValue(addr, { kind: "address" }),
        h("p", { class: "notice claim" }, h("b", null, L.linkInfo(1).label)),
        h("p", null, `沒有紀錄經由 AuditRegistry 部署這個地址；下列 ${claimIds.length} 筆紀錄的稽核者自行宣告它執行稽核過的程式碼。` +
          "AuditRegistry 只記下宣告當時這個地址的程式碼雜湊，不證明程式碼是從稽核過的原始碼編譯出來的；任何稽核者都能宣告任何地址。"),
        list));
    }
    let same = { ok: true, v: [] };
    if (codeHash) same = await tryRead(idList("recordsByCodehash", codeHash));
    if (stale(run)) return;
    const body = [
      h("p", null, hasCode ? "這個地址上有合約程式碼，但沒有任何稽核紀錄連結到它。" : "這個地址上沒有合約程式碼（可能是一般帳戶，或合約不存在於這條鏈）。"),
      h("p", { class: "mute small" }, "沒有紀錄不代表合約有問題或沒問題，只代表沒有人透過這個 AuditRegistry 替它留下紀錄。"),
    ];
    if (!claims.ok) body.push(h("p", { class: "notice" }, `讀不到稽核者的宣告清單（claimsOf）：${claims.error}`));
    if (hasCode && !S.ethers) body.push(h("p", { class: "notice" }, "keccak256 函式庫（ethers）沒有載入，無法用程式碼雜湊找相同程式碼的紀錄。"));
    if (same.ok && same.v.length) {
      body.push(h("p", null, `不過，它的程式碼雜湊（${L.shortHex(codeHash, 10, 6)}）和下列紀錄連結的部署完全相同。` +
        "部署後的程式碼不含建構子參數和儲存內容，所以這只是線索，不是這個地址的稽核紀錄："));
      body.push(await recordList(same.v, run));
    }
    if (stale(run)) return;
    setResult(messageCard(title, hexValue(addr, { kind: "address" }), ...body));
  }
  function claimNote(r, addr, hasCode, codeHash) {
    if (r.deployed !== addr) return "";
    if (!hasCode) return " · 地址上現在沒有程式碼";
    if (!codeHash) return "";
    return L.sameHash(r.runtimeCodeHash, codeHash) ? " · 宣告時的程式碼雜湊和地址上現在的相同" : " · 宣告時的程式碼雜湊和地址上現在的不同";
  }

  async function lookupHash(hash) {
    const run = begin("查詢交易…");
    const receipt = await rpc("eth_getTransactionReceipt", [hash]);
    if (stale(run)) return;
    if (receipt) return showTx(hash, receipt, run);
    const [bySource, byCode] = await Promise.all([idPage("recordsBySource", hash, 30),
                                                  tryRead(idList("recordsByCodehash", hash))]);
    if (stale(run)) return;
    const codeIds = byCode.ok ? byCode.v : [];
    if (!bySource.total && !codeIds.length) {
      return setResult(messageCard("找不到", "這不是這條鏈上的交易雜湊，也不是任何紀錄的原始碼 sha256 或部署程式碼雜湊。",
        h("p", { class: "mute small" }, "如果交易剛送出，等幾秒再查一次。")));
    }
    const parts = [];
    if (bySource.total) {
      parts.push(h("p", null, "這是下列紀錄的原始碼 sha256："), await recordList(bySource.ids, run, { total: bySource.total }));
    }
    if (codeIds.length) parts.push(h("p", null, "這是下列紀錄所連結部署的程式碼雜湊："), await recordList(codeIds, run));
    if (stale(run)) return;
    setResult(messageCard("符合的紀錄", hexValue(hash), ...parts));
  }

  async function showTx(hash, receipt, run) {
    const mine = (receipt.logs || []).filter((lg) => {
      const a = String(lg.address).toLowerCase();
      return a === S.registry || a === S.escrow;
    }).map(L.decodeLog).filter(Boolean);
    const ok = receipt.status === "0x1";
    const ids = [...new Set(mine.filter((e) => e.event === "Registered" || e.event === "Linked").map((e) => e.id))];
    const settled = mine.filter((e) => e.event === "Settled");
    const lines = mine.map((e) => {
      if (e.event === "Registered") return `登錄紀錄 #${e.id}（${L.verdictInfo(e.verdict).label}）`;
      if (e.event === "Linked") return `把地址 ${fmtAddr(e.deployed)} 連結到紀錄 #${e.id}（${L.linkInfo(e.linkKind).short}）`;
      if (e.event === "Requested") return `建立付費託管申請 #${e.requestId}（${L.formatUnits(e.fee)} ${S.net.symbol}）`;
      return `以紀錄 #${e.recordId} 結算託管申請 #${e.requestId}：${e.refunded ? "退回申請人" : "付給稽核者"} ${L.formatUnits(e.amount)} ${S.net.symbol}`;
    });
    const summary = lines.length ? `這筆交易${ok ? "" : "（失敗）"}：${lines.join("；")}。` : "";
    if (ids.length === 1) {
      return showRecord(ids[0], { banner: summary, tx: hash });
    }
    if (stale(run)) return;
    const body = [txRef(hash)];
    if (!ok) body.push(h("p", { class: "notice" }, "這筆交易執行失敗（revert），沒有留下任何紀錄。"));
    if (!lines.length) body.push(h("p", null, "這筆交易沒有 AuditRegistry 或 AuditEscrow 的事件。"));
    else body.push(h("ul", null, lines.map((t) => h("li", null, t))));
    if (ids.length) body.push(await recordList(ids, run));
    else if (settled.length) body.push(await recordList([...new Set(settled.map((e) => e.recordId))], run));
    if (stale(run)) return;
    setResult(messageCard("交易內容", ...body));
  }

  async function lookupSource(hash, fileName) {
    const run = begin("用原始碼雜湊查詢…");
    const { ids, total } = await idPage("recordsBySource", hash, 30);
    if (stale(run)) return;
    const what = fileName ? `「${fileName}」的 sha256` : "原始碼 sha256";
    if (total === 1) return showRecord(ids[0], { banner: `${what}只有一筆稽核紀錄：#${ids[0]}。` });
    if (!total) {
      return setResult(messageCard("這份原始碼沒有稽核紀錄", h("p", null, `${what}：`), hexValue(hash),
        h("p", { class: "mute small" }, "雜湊是逐位元組計算的：差一個空白、換行（CRLF 與 LF）或編碼，雜湊就不同。請用稽核時的同一份檔案。")));
    }
    // latestRecord(auditor, source) cannot be crowded out by other registrants
    const latest = S.dep ? await Promise.all(S.dep.auditors.map((a) =>
      call(S.registry, "latestRecord", [a.address, hash]).then(L.decodeNumber).catch(() => 0))) : [];
    const trusted = [...new Set(latest.filter(Boolean))];
    const parts = trusted.length
      ? [h("p", null, "部署紀錄列出的稽核者對這份原始碼的最新紀錄："), await recordList(trusted, run), h("p", null, "全部紀錄（依登錄順序）：")]
      : [];
    const list = await recordList(ids, run, { total });
    if (stale(run)) return;
    setResult(messageCard(`這份原始碼有 ${total} 筆稽核紀錄`, h("p", null, `${what}：`), hexValue(hash),
      h("p", { class: "mute small" }, "同一份原始碼可能被不同稽核者、在不同時間稽核；請看每筆的稽核者與時間。"), ...parts, list));
  }

  async function showLatest(run) {
    const n = S.count;
    if (!n) {
      return setResult(messageCard("還沒有任何紀錄", "AuditRegistry 已部署，但還沒有人登錄稽核紀錄。"));
    }
    const ids = [];
    for (let i = n; i >= 1 && ids.length < 5; i--) ids.push(i);
    const list = await recordList(ids, run);
    if (stale(run)) return;
    setResult(messageCard(`最近的紀錄（共 ${n} 筆）`, list,
      h("p", { class: "mute small" }, "點一筆看完整內容；也可以在上方輸入合約地址、紀錄編號或交易雜湊。")));
  }

  /** extra(record) -> text appended to an item; total: length of the whole list when ids is a page. */
  async function recordList(ids, run, { extra = null, total = ids.length } = {}) {
    const shown = ids.slice(0, 30);
    const recs = await Promise.all(shown.map((id) => getRecord(id).catch(() => null)));
    const ul = h("ul", { class: "reclist" });
    shown.forEach((id, i) => {
      const r = recs[i];
      if (!r) return ul.append(h("li", null, h("span", { class: "mute" }, `紀錄 #${id}：讀取失敗`)));
      const v = L.verdictInfo(r.input.verdict);
      const listed = S.dep && L.auditorName(r.auditor, S.dep.auditors);
      const ok = verified();
      ul.append(h("li", null, h("button", { type: "button", class: `recitem tone-${ok ? v.tone : "mute"}`, onclick: () => openRecord(id) },
        h("span", { class: "id" }, `#${id}`), h("span", { class: "v" }, ok ? v.label : `${v.short || v.label}（未驗證）`),
        h("span", { class: "go", "aria-hidden": "true" }, "查看 →"),
        h("span", { class: "sub" }, `${L.formatTime(r.timestamp)} · 稽核者 ${listed ? listed : L.shortHex(fmtAddr(r.auditor))}` +
          (r.input.parentId ? ` · 修補自 #${r.input.parentId}` : "") + (r.linkKind ? ` · 已部署（${L.linkInfo(r.linkKind).short}）` : "") +
          (extra ? extra(r) : "")))));
    });
    if (total > shown.length) ul.append(h("li", { class: "mute small" }, `另有 ${total - shown.length} 筆未列出。`));
    return ul;
  }

  // ------------------------------------------------------------------ record view
  async function showRecord(id, ctx = {}) {
    const run = begin(`讀取紀錄 #${id}…`);
    const count = await getCount();
    if (stale(run)) return;
    if (id > count) {
      return setResult(messageCard(`沒有紀錄 #${id}`, count ? `目前共有 ${count} 筆紀錄（編號 1～${count}）。` : "目前還沒有任何紀錄。"));
    }
    const rec = await getRecord(id);
    const inp = rec.input;
    const ancestors = [];
    for (let p = inp.parentId, guard = 0; p && guard < 12; guard++) {
      const pr = await getRecord(p);
      ancestors.unshift({ id: p, record: pr });
      p = pr.input.parentId;
    }
    const [childIds, deployments, linkCurrent, latest, sameInit, escrow] = await Promise.all([
      idList("childrenOf", id),
      tryRead(call(S.registry, "deploymentsOf", [id]).then(L.decodeAddressArray)),
      rec.linkKind ? tryRead(call(S.registry, "isLinkCurrent", [id]).then(L.decodeBool)) : null,
      tryRead(call(S.registry, "latestRecord", [rec.auditor, inp.sourceHash]).then(L.decodeNumber)),
      L.isZeroHex(inp.initcodeHash) ? null : tryRead(provenSameBytecode(id, inp.initcodeHash)),
      S.escrow ? escrowFor(id) : null,
    ]);
    const children = await Promise.all(childIds.slice(0, 8).map(async (c) => ({ id: c, record: await getRecord(c), child: true })));
    if (stale(run)) return;
    const view = renderRecord(id, rec, { ancestors, children, moreChildren: childIds.length - children.length,
                                         deployments, linkCurrent, latest, sameInit, escrow, ctx });
    setResult(view.el);
    document.title = `紀錄 #${id} · ARBITER Gate 紀錄驗證`;
    // slower checks fill in their placeholders afterwards
    fillTxs(id, rec, view, escrow);
    checkEvidence(rec, view.evidenceBox, ancestors.length ? ancestors[ancestors.length - 1] : null);
  }

  /** Other records for the same creation bytecode that say an exploit was proven. */
  async function provenSameBytecode(id, initcodeHash) {
    const { ids, total } = await idPage("recordsByInitcode", initcodeHash, MAX_SAME_INIT + 1);
    const others = ids.filter((x) => x !== id).slice(0, MAX_SAME_INIT);
    const recs = await Promise.all(others.map(async (x) => ({ id: x, record: await getRecord(x) })));
    return { proven: recs.filter((x) => x.record.input.verdict === 3), unchecked: Math.max(0, total - 1 - others.length) };
  }

  async function escrowFor(id) {
    try {
      const reqId = L.decodeNumber(await call(S.escrow, "settledBy", [id]));
      if (!reqId) return { reqId: 0 };
      return { reqId, q: L.decodeRequest(await call(S.escrow, "getRequest", [reqId])) };
    } catch (e) {
      return { error: e.message || String(e) };
    }
  }

  const openBtn = (rid, text = `紀錄 #${rid}`) =>
    h("button", { type: "button", class: "btn small", onclick: () => openRecord(rid) }, text);
  function auditorWho(addr) {
    const listed = S.dep && L.auditorName(addr, S.dep.auditors);
    return listed || L.shortHex(fmtAddr(addr), 8, 6);
  }

  function renderRecord(id, rec, { ancestors, children, moreChildren, deployments, linkCurrent, latest, sameInit, escrow, ctx }) {
    const inp = rec.input;
    const v = L.verdictInfo(inp.verdict);
    const pred = L.predicateInfo(inp.predicateClass);
    const tier = L.tierInfo(inp.evidenceTier);
    const listed = S.dep ? L.auditorName(rec.auditor, S.dep.auditors) : null;
    const commitUrl = L.commitLink(inp.toolCommit, S.dep && S.dep.publicToolCommits);
    const regSlot = pending("查詢登錄交易中…");
    const shareUrl = location.href;
    const proven = sameInit && sameInit.ok ? sameInit.v.proven : [];
    const selfProven = proven.find((x) => x.record.auditor === rec.auditor);
    // read through a node or from a contract the page cannot vouch for: no verdict colour, no badges
    const ok = verified();
    const tone = ok ? v.tone : "mute";

    // S.dep exists only for the official deployment (loadContracts)
    const auditorBadge = listed
      ? h("span", { class: "tag sys" }, `✓ ${listed}`)
      : S.dep ? h("span", { class: "tag amber" }, "不在部署紀錄的稽核者清單")
        : h("span", { class: "tag mute" }, S.trust && S.trust.official ? "沒有稽核者清單可比對" : "非官方來源：不比對稽核者清單");
    const meAddr = L.toMeAddress(rec.auditor);

    // what other records say about the same code
    const notices = [];
    if (inp.verdict !== 3) {
      for (const x of proven) {
        const same = x.record.auditor === rec.auditor;
        notices.push(h("div", { class: "notice red" },
          h("p", null, h("b", null, `同一份 bytecode 另有判定為已證實可攻擊的紀錄（#${x.id}，稽核者 ${auditorWho(x.record.auditor)}）`), " ",
            openBtn(x.id, `看紀錄 #${x.id}`)),
          h("p", { class: "small" }, same
            ? "登錄它的就是這筆紀錄的稽核者：AuditRegistry 不會經由閘門部署這份 bytecode（ContradictsProvenRecord）。"
            : "登錄它的是另一個地址。任何人都能登錄紀錄，請看稽核者是誰，並重跑那筆紀錄的證據；AuditRegistry 只擋同一位稽核者自相矛盾的部署。")));
      }
    }
    if (sameInit && sameInit.ok && sameInit.v.unchecked) {
      notices.push(h("p", { class: "mute small" }, `同一份 bytecode 另有 ${sameInit.v.unchecked} 筆紀錄沒有檢查。`));
    }
    if (sameInit && !sameInit.ok) notices.push(h("p", { class: "mute small" }, `讀不到同一份 bytecode 的其他紀錄：${sameInit.error}`));
    if (latest.ok && latest.v > id) {
      notices.push(h("p", { class: "notice" }, `同一位稽核者之後對同一份原始碼登錄了較新的紀錄 #${latest.v}。 `, openBtn(latest.v, `看紀錄 #${latest.v}`)));
    }

    const head = h("header", null,
      h("p", { class: "eyebrow" }, `紀錄 #${id} · ${S.net.name}`),
      sourceLine(),
      h("h2", { class: "verdict", id: "rec-title" }, h("span", { class: "dot", "aria-hidden": "true" }), v.label, ok ? null : unvTag()),
      h("p", { class: "verdict-desc" }, ok ? v.desc
        : "這筆紀錄讀自未經驗證的來源（見上方說明）：判定、稽核者和其他欄位都可能是捏造的。改用官方設定再查一次，才能當成官方紀錄看待。"),
      ctx.banner ? h("div", { class: "banner" }, h("p", null, ctx.banner), ctx.tx ? txRef(ctx.tx) : null) : null,
      notices,
      h("div", { class: "actions" },
        h("button", { type: "button", class: "btn small", onclick: (e) => copyText(shareUrl, e.currentTarget) }, "複製這筆紀錄的連結")));

    const content = kv([
      ["判定", h("span", null, `${v.label}（代碼 ${inp.verdict}）`)],
      ["謂詞等級", h("span", null, pred.label, h("span", { class: "desc" }, pred.desc))],
      ["證據等級", h("span", null, tier.label, h("span", { class: "desc" }, tier.desc))],
      ["稽核者", h("span", null, h("span", { class: "inline" }, hexValue(rec.auditor, { kind: "address" }), auditorBadge),
        meAddr ? h("span", { class: "desc mono" }, `ME 格式：${meAddr}`) : null,
        h("span", { class: "desc" }, "任何人都能登錄紀錄；看清楚是誰登錄的，比看結論更重要。"))],
      ["登錄時間", h("span", { title: L.isoUtc(rec.timestamp) }, L.formatTime(rec.timestamp), h("span", { class: "desc" }, "區塊時間，由鏈寫入，稽核者無法自己填。"))],
      ["登錄交易", regSlot],
      ["模型", inp.model ? h("span", null, inp.model) : h("span", { class: "mute" }, "（未填）")],
      ["工具版本", L.isZeroHex(inp.toolCommit) ? h("span", { class: "mute" }, "（未填）")
        : h("span", null, commitUrl ? extLink(commitUrl, h("span", { class: "mono" }, inp.toolCommit.slice(2)))
          : h("span", { class: "mono" }, inp.toolCommit.slice(2)),
          h("span", { class: "desc" }, commitUrl ? "ARBITER Gate 公開 repo 的這個 commit。"
            : S.dep ? "這個 commit 沒有列在部署紀錄的公開版本清單，所以不提供連結。" : "非官方來源：不比對部署紀錄的公開版本清單，所以不提供連結。"))],
      ["修補自", inp.parentId ? openBtn(inp.parentId) : h("span", { class: "mute" }, "無（不是從其他紀錄修補而來）")],
      ["同一稽核者的最新紀錄", !latest.ok ? h("span", { class: "mute" }, "（讀不到）")
        : latest.v > id ? h("span", null, openBtn(latest.v), h("span", { class: "desc" }, "這位稽核者之後又對同一份原始碼登錄了這筆。"))
          : h("span", null, "就是這筆", h("span", { class: "desc" }, "這位稽核者對這份原始碼沒有更新的紀錄（latestRecord）。"))],
      ["證據位址", inp.evidenceURI ? h("span", { class: "mono" }, inp.evidenceURI) : h("span", { class: "mute" }, "（未提供）")],
    ]);

    const zeroNote = { exploitHash: "只有已證實可攻擊的紀錄才有攻擊程式。", patchHash: "這筆紀錄沒有修補。", initcodeHash: "沒有登錄建立程式碼，所以不能經由 AuditRegistry 部署。" };
    const hashes = kv(["sourceHash", "initcodeHash", "gateJsonHash", "exploitHash", "patchHash"].map((f) => [
      `${L.FIELD_LABELS[f]}`,
      L.isZeroHex(inp[f]) ? h("span", { class: "mute" }, `無。${zeroNote[f] || ""}`)
        : h("span", null, hexValue(inp[f]), h("span", { class: "desc" }, f === "initcodeHash" ? "keccak256" : "sha256")),
    ]));

    // deployment: every gated address (deploymentsOf), then the auditor's own claim, if any
    const deploy = [];
    const depRows = [];
    let gated = deployments.ok ? deployments.v : [];
    if (!deployments.ok) {
      deploy.push(h("p", { class: "notice" }, `讀不到這筆紀錄的部署清單（deploymentsOf）：${deployments.error}`));
      if (rec.linkKind === 2) gated = [rec.deployed];
    }
    if (gated.length) {
      const l2 = L.linkInfo(2);
      const ul = h("ul", { class: "deplist" });
      for (const a of gated.slice(0, MAX_DEPLOYMENTS)) {
        const row = depRow(a, 2);
        depRows.push(row);
        ul.append(row.el);
      }
      deploy.push(h("p", null, ok ? h("span", { class: "tag sys" }, l2.label) : unvTag(`${l2.label}（未驗證）`), ` 共 ${gated.length} 個地址`),
        h("p", { class: "mute small" }, l2.desc), ul);
      if (gated.length > MAX_DEPLOYMENTS) deploy.push(h("p", { class: "mute small" }, `另有 ${gated.length - MAX_DEPLOYMENTS} 個地址未列出。`));
    }
    if (rec.linkKind === 1 && !L.isZeroHex(rec.deployed)) {
      const l1 = L.linkInfo(1);
      const row = depRow(rec.deployed, 1, rec.runtimeCodeHash);
      depRows.push(row);
      deploy.push(h("p", { class: gated.length ? "mt" : null }, h("span", { class: "tag amber" }, l1.label)),
        h("p", { class: "mute small" }, l1.desc), h("ul", { class: "deplist" }, row.el));
    }
    if (linkCurrent) {
      const first = L.shortHex(fmtAddr(rec.deployed), 8, 6);
      deploy.push(h("ul", { class: "checks mt" }, !linkCurrent.ok ? check("na", "讀不到 isLinkCurrent", linkCurrent.error)
        : linkCurrent.v ? check("ok", `AuditRegistry 回報：第一個連結的地址（${first}）仍是連結時的程式碼（isLinkCurrent）`,
          "這是合約自己在鏈上比對的結果，不需要瀏覽器的 keccak256 函式庫。")
          : check("bad", `AuditRegistry 回報：第一個連結的地址（${first}）程式碼已和連結時不同（isLinkCurrent = false）`,
            "合約可能已經自毀，或地址上的程式碼被換掉。")));
    }
    if (!depRows.length) {
      const why = inp.verdict === 3 ? "已證實可攻擊：AuditRegistry 的 deployAudited 會拒絕部署這份程式碼。"
        : inp.verdict === 0 ? "稽核沒有完成：AuditRegistry 不允許部署。"
        : L.isZeroHex(inp.initcodeHash) ? "尚未部署；這筆紀錄沒有登錄建立程式碼，只能由稽核者宣告連結。"
        : selfProven ? `尚未部署；同一位稽核者已把這份 bytecode 登錄為已證實可攻擊（紀錄 #${selfProven.id}），AuditRegistry 不會經由閘門部署它。`
        : "尚未部署。";
      deploy.push(h("p", null, why));
    }

    // provenance
    const nodes = [...ancestors, { id, record: rec, current: true, deployments: deployments.ok ? gated : null }, ...children];
    const timeline = renderTimeline(L.provenanceSteps(nodes), inp.verdict === 3 && !children.length);
    const prov = [timeline];
    if (moreChildren > 0) prov.push(h("p", { class: "mute small" }, `另有 ${moreChildren} 筆後續紀錄未列出。`));
    if (nodes.length === 1 && inp.verdict !== 3) prov.push(h("p", { class: "mute small" }, "這筆紀錄沒有修補前後的關聯紀錄。"));

    // escrow
    const esc = escrow ? renderEscrow(escrow, id) : null;

    const evidenceBox = h("div", null);
    const el = h("article", { class: `card record tone-${tone}`, "aria-labelledby": "rec-title" },
      head,
      h("h3", null, "來龍去脈"), prov,
      h("h3", null, "紀錄內容"), content,
      h("h3", null, "部署"), deploy,
      h("h3", null, "證據比對（追問）"), evidenceBox,
      esc ? [h("h3", null, "付費託管（AuditEscrow）", S.escrowVerified ? null : [" ", unvTag()]), esc.el] : null,
      h("h3", null, "雜湊（指紋）"),
      h("p", { class: "mute small" }, "雜湊是檔案的指紋：檔案改一個位元，雜湊就完全不同。鏈上只放指紋，檔案本身放在證據包。"),
      hashes);
    return { el, regSlot, depRows, settleSlot: esc && esc.settleSlot, evidenceBox };
  }

  /** One deployed address: its link transaction and a live code-hash check, filled in later. */
  function depRow(addr, kind, claimedHash) {
    const codeLi = check("wait", "比對地址上現在的程式碼…");
    const txSlot = pending(kind === 2 ? "查詢部署交易…" : "查詢宣告交易…");
    const el = h("li", { class: "dep" }, kv([
      ["地址", hexValue(addr, { kind: "address" })],
      [kind === 2 ? "部署交易" : "宣告交易", txSlot],
      claimedHash ? ["宣告時的程式碼雜湊", hexValue(claimedHash)] : null,
    ]), h("ul", { class: "checks mt" }, codeLi));
    return { addr: addr.toLowerCase(), kind, el, codeLi, txSlot };
  }

  function renderTimeline(steps, ghost) {
    const ol = h("ol", { class: "timeline", "aria-label": "紀錄的來龍去脈" });
    const ok = verified();
    for (const s of steps) {
      if (s.type === "record") {
        const v = L.verdictInfo(s.verdict);
        const main = s.current ? h("span", { class: "main" }, v.short || v.label)
          : h("button", { type: "button", class: "main", onclick: () => openRecord(s.id) }, v.short || v.label);
        ol.append(h("li", { class: `step tone-${ok ? v.tone : "mute"}${s.current ? " current" : ""}`, "aria-current": s.current ? "step" : null },
          h("span", { class: "st" }, s.child ? "後續：重新稽核" : s.stage), main,
          h("span", { class: "meta" }, `#${s.id} · ${L.formatTime(s.timestamp).slice(0, 10)}${s.current ? " · 這筆" : ""}`)));
      } else if (s.type === "patch") {
        ol.append(h("li", { class: "step patch" }, h("span", { class: "st" }, "修補"),
          h("span", { class: "main" }, L.isZeroHex(s.patchHash) ? "未登錄修補雜湊" : "修補內容"),
          h("span", { class: "meta mono" }, L.isZeroHex(s.patchHash) ? "" : L.shortHex(s.patchHash, 8, 6))));
      } else {
        ol.append(h("li", { class: `step deploy${ok ? "" : " unv"}` }, h("span", { class: "st" }, "部署"),
          h("span", { class: "main" }, L.linkInfo(s.linkKind).short + (ok ? "" : "（未驗證）")),
          h("span", { class: "meta mono" }, L.shortHex(fmtAddr(s.address), 8, 6) + (s.count > 1 ? ` 等 ${s.count} 個地址` : ""))));
      }
    }
    if (ghost) {
      ol.append(h("li", { class: "step ghost" }, h("span", { class: "st" }, "下一步"),
        h("span", { class: "main" }, "修補 → 重新稽核 → 部署"),
        h("span", { class: "meta" }, "還沒有修補後重新稽核的紀錄")));
    }
    return ol;
  }

  function renderEscrow(e, id) {
    if (e.error) return { el: h("p", { class: "mute" }, `讀取託管資料失敗：${e.error}`) };
    const why = h("p", { class: "mute small" }, "費用和結論無關：稽核完成（判定 1、2、3）就付給稽核者，稽核沒完成（判定 0）就退回申請人，稽核者不會因為給出比較好看的結論而多拿錢。" +
      "只有指定的稽核者能結算，而且只能用申請之後登錄的紀錄；期限加 1 小時寬限內沒有結算，任何人都能把費用退回申請人。");
    const unchecked = S.escrowVerified ? null
      : h("p", { class: "notice" }, "這個 AuditEscrow 沒有經過程式碼驗證（見上方說明）：下面的申請、費用和結算都可能是捏造的。");
    if (!e.reqId) return { el: h("div", null, unchecked, h("p", null, "沒有付費託管申請由這筆紀錄結算。"), why) };
    const q = e.q;
    const st = L.escrowStatusInfo(q.status);
    const settleSlot = pending("查詢結算交易…");
    return { settleSlot, el: h("div", null, unchecked, kv([
      ["申請編號", `#${e.reqId}（由紀錄 #${id} 結算）`],
      ["結果", h("span", { class: `tag ${st.tone}` }, st.label)],
      ["費用", `${L.formatUnits(q.fee)} ${S.net.symbol}`],
      ["申請人", hexValue(q.requester, { kind: "address" })],
      ["指定稽核者", hexValue(q.auditor, { kind: "address" })],
      ["申請時間", L.formatTime(q.createdAt)],
      ["期限", h("span", null, L.formatTime(q.deadline),
        h("span", { class: "desc" }, `紀錄要在期限前登錄；結算最晚到 ${L.formatTime(q.deadline + L.SETTLE_GRACE)}。`))],
      ["可結算的紀錄", `#${q.minRecordId} 以後（申請之後才登錄的紀錄）`],
      ["結算交易", settleSlot],
    ]), why) };
  }

  /** ref: {hash, own}: own = the hash recorded when this very address was linked. */
  async function checkCode(row, ref) {
    const li = row.codeLi;
    if (!S.ethers) {
      return replaceCheck(li, "na", "無法比對程式碼", "keccak256 函式庫（ethers，從 cdnjs 載入）沒有載入成功，這項略過。");
    }
    try {
      const code = await rpc("eth_getCode", [row.addr, "latest"]);
      if (!code || code === "0x") {
        return replaceCheck(li, "bad", "這個地址現在沒有程式碼", "合約可能已經自毀；連結時記下的程式碼已不在鏈上。");
      }
      const now = window.ethers.keccak256(code);
      if (ref.own) {
        return L.sameHash(now, ref.hash)
          ? replaceCheck(li, "ok", "地址上現在的程式碼，和連結時記下的雜湊相同",
            "代表部署後程式碼沒有被換掉。它不代表程式碼沒有漏洞，只代表這就是當初連結的那一份。")
          : replaceCheck(li, "bad", "地址上的程式碼和連結時不同", `連結時是 ${ref.hash}，現在是 ${now}。`);
      }
      return L.sameHash(now, ref.hash)
        ? replaceCheck(li, "ok", "地址上的程式碼，和這筆紀錄第一個部署地址連結時的雜湊相同", "沒有讀到這個地址自己的連結事件，改和第一個部署地址比對。")
        : replaceCheck(li, "warn", "地址上的程式碼和第一個部署地址連結時的雜湊不同",
          `沒有讀到這個地址自己的連結事件。同一份 bytecode 的建構子若寫入 immutable，部署後的程式碼也會不同。現在的雜湊是 ${now}。`);
    } catch (e) {
      replaceCheck(li, "na", "無法比對程式碼", e.message || String(e));
    }
  }

  const topic0 = (lg) => String((lg.topics || [])[0] || "").toLowerCase();
  /** Registration, link and settlement transactions of a record (eth_getLogs), then the live
   * code checks of every linked address against the hash its own Linked event recorded. */
  async function fillTxs(id, rec, view, escrow) {
    const where = { timestamp: rec.timestamp };
    const linkedOf = (logs) => {
      const m = new Map();
      for (const lg of logs) {
        const e = topic0(lg) === L.TOPICS.Linked ? L.decodeLog(lg) : null;
        if (e && !m.has(e.deployed)) m.set(e.deployed, { ...e, tx: lg.transactionHash });
      }
      return m;
    };
    const regP = recordLogs(where, { address: S.registry, topics: [[L.TOPICS.Registered, L.TOPICS.Linked], word(id)] },
      (got) => got.some((lg) => topic0(lg) === L.TOPICS.Registered) && linkedOf(got).size >= view.depRows.length)
      .catch(() => null);
    const settleP = view.settleSlot
      ? recordLogs(where, { address: S.escrow, topics: [L.TOPICS.Settled, word(escrow.reqId), word(id)] }, (got) => got.length > 0)
        .catch(() => null)
      : null;
    const noTx = (text) => h("span", { class: "mute small" }, text);

    const logs = await regP;
    const reg = logs && logs.find((lg) => topic0(lg) === L.TOPICS.Registered);
    view.regSlot.replaceWith(reg && L.isBytes32(reg.transactionHash) ? txRef(reg.transactionHash)
      : noTx("（節點沒有回傳這筆紀錄的登錄交易）"));
    const linked = logs ? linkedOf(logs) : new Map();
    for (const row of view.depRows) {
      const ev = linked.get(row.addr);
      row.txSlot.replaceWith(ev && L.isBytes32(ev.tx) ? txRef(ev.tx)
        : noTx(logs ? "（沒有找到這個地址的連結事件）" : "（節點沒有回傳事件）"));
      const own = ev ? ev.runtimeCodeHash : row.addr === rec.deployed ? rec.runtimeCodeHash : null;
      checkCode(row, own ? { hash: own, own: true } : { hash: rec.runtimeCodeHash, own: false });
    }
    if (settleP) {
      const s = await settleP;
      const lg = s && s[0];
      view.settleSlot.replaceWith(lg && L.isBytes32(lg.transactionHash) ? txRef(lg.transactionHash)
        : noTx("（節點沒有回傳結算交易）"));
    }
  }

  // ------------------------------------------------------------------ evidence
  /** parent: {id, record} of the record this one was patched from, or null. */
  async function checkEvidence(rec, box, parent) {
    const inp = rec.input;
    const intro = h("p", { class: "mute small" },
      "把證據檔重新計算 sha256，和鏈上的雜湊比對。相符代表你拿到的就是當初登錄的那一份檔案；判定對不對，要自己重跑攻擊程式才知道。");
    const out = h("div", { "aria-live": "polite" });
    const local = h("div", null);
    const drop = dropZone("拖入證據檔（可多選），或按這裡選檔：gate.json、原始碼、攻擊程式、修補。檔案只在瀏覽器裡計算，不會上傳。",
      true, (files) => compareLocal(files, inp, local));
    box.replaceChildren(intro, out, drop, local);

    const loc = L.evidenceLocation(inp.evidenceURI);
    if (!loc.ok) {
      out.append(h("ul", { class: "checks" }, check("na", "沒有自動比對", loc.message)));
      return;
    }
    out.append(loading(`從 ${loc.host} 讀取證據清單（manifest.json）…`));
    let manifest;
    try {
      const raw = await fetchBytes(loc.manifest, MAX_MANIFEST);
      manifest = JSON.parse(new TextDecoder("utf-8").decode(raw));
      if (!manifest || !Array.isArray(manifest.files)) throw new UserError("manifest.json 沒有 files 清單");
    } catch (e) {
      out.replaceChildren(h("ul", { class: "checks" }, check("warn", "讀不到證據清單", `${loc.manifest}：${e.message || e}`)));
      return;
    }
    const entries = manifest.files.slice(0, MAX_FILES);
    out.replaceChildren(loading(`下載並計算 ${entries.length} 個檔案的 sha256…`));
    const results = [];
    for (const f of entries) {
      const name = f && typeof f.name === "string" ? f.name : "";
      const item = { name: name || "（沒有檔名）", role: f && f.role,
                     manifestSha256: f && L.isBytes32(f.sha256) ? f.sha256.toLowerCase() : null };
      const url = L.bundleFileUrl(loc.base, name);
      if (!url) { results.push({ ...item, error: "檔名不合法（只接受證據資料夾裡的相對路徑）" }); continue; }
      try {
        item.sha256 = await L.sha256Hex(await fetchBytes(url, MAX_FILE));
      } catch (e) {
        item.error = e.message || String(e);
      }
      results.push(item);
    }
    const cmp = L.compareEvidence(inp, results, parent ? { id: parent.id, input: parent.record.input } : null);
    out.replaceChildren(renderEvidence(cmp, loc, manifest.files.length > MAX_FILES, L.manifestSchemaProblem(manifest)));
    announce(cmp.ok ? "證據比對完成：全部相符" : "證據比對完成：有不符或缺漏");
  }

  const ONCHAIN_TEXT = {
    match: ["ok", "和鏈上雜湊相符"], mismatch: ["bad", "和鏈上雜湊不符"], absent: ["na", "鏈上沒有登錄這種檔案的雜湊"],
    error: ["warn", "讀取失敗"],
  };
  // files with no hash of their own on chain are compared with the manifest only
  const MANIFEST_TEXT = {
    match: ["ok", "和 manifest 列的雜湊相同（鏈上沒有這個檔案的雜湊）"], mismatch: ["bad", "和 manifest 列的雜湊不同"],
    null: ["na", "只列出（鏈上和 manifest 都沒有它的雜湊）"],
  };
  const rowState = (r) => (r.onchain === "none" ? MANIFEST_TEXT[r.manifest] : ONCHAIN_TEXT[r.onchain]);
  const MARK = { ok: "✓", bad: "✗", na: "–", warn: "!" };

  function renderEvidence(cmp, loc, truncated, schemaProblem) {
    const top = [];
    if (cmp.ok) top.push(check("ok", "證據包和鏈上紀錄相符", "鏈上每一個檔案雜湊都在證據包裡找到相同的檔案。"));
    else {
      const bad = cmp.rows.filter((r) => r.onchain === "mismatch").map((r) => r.name);
      const missing = cmp.fields.filter((f) => f.status === "missing").map((f) => L.FIELD_LABELS[f.field]);
      const failed = cmp.rows.filter((r) => r.onchain === "error").map((r) => r.name);
      if (bad.length) top.push(check("bad", "有檔案和鏈上雜湊不符", `${bad.join("、")}：檔案在登錄之後被改過，或不是同一份。`));
      if (missing.length) top.push(check("warn", "證據包缺少檔案", `鏈上有「${missing.join("、")}」的雜湊，但證據包裡沒有對應的檔案。`));
      if (failed.length) top.push(check("warn", "有檔案讀取失敗", failed.join("、")));
      if (cmp.rows.some((r) => r.manifest === "mismatch")) top.push(check("warn", "manifest.json 列的雜湊和檔案不同", "清單本身不在鏈上，以鏈上雜湊為準。"));
    }
    if (schemaProblem) {
      top.push(check("warn", "manifest.json 的格式不是這個頁面認得的",
        `schema 是「${schemaProblem}」（認得的是 ${L.MANIFEST_SCHEMAS.join("、")}）；仍依檔名和雜湊比對。`));
    }
    const fieldChecks = cmp.fields.map((f) => {
      const st = { match: "ok", mismatch: "bad", missing: "warn" }[f.status];
      const word = { match: "相符", mismatch: "不符", missing: "證據包裡沒有" }[f.status];
      return check(st, `${L.FIELD_LABELS[f.field]}：${word}`, f.files.length ? f.files.join("、") : null);
    });
    const parentChecks = cmp.rows.filter((r) => r.from === "parent" && r.onchain !== "error").map((r) =>
      check(r.onchain === "match" ? "ok" : "bad", `${r.label}：${r.onchain === "match" ? "相符" : "不符"}`, r.name));
    const extras = cmp.rows.filter((r) => r.onchain === "none" && r.label);
    const extraChecks = extras.map((r) => {
      const [st, text] = { match: ["ok", "和 manifest 列的雜湊相同"], mismatch: ["bad", "和 manifest 列的雜湊不同"],
                           null: ["na", "manifest 沒有列它的雜湊"] }[r.manifest];
      return check(st, `${r.label}：${text}`, r.name);
    });
    const list = h("ul", { class: "evlist" }, cmp.rows.map((r) => {
      const [st, text] = rowState(r);
      const tag = { ok: "sys", bad: "red", na: "mute", warn: "amber" }[st];
      return h("li", { class: `evitem${st === "bad" ? " bad" : ""}` },
        h("div", { class: "head" }, h("span", { class: "name" }, r.name),
          r.label ? h("span", { class: "tag mute" }, r.label) : null,
          h("span", { class: `tag ${tag}` }, `${MARK[st]} ${text}`)),
        h("div", { class: "hashes" },
          r.sha256 ? h("div", null, h("span", null, "計算結果"), h("span", { class: "mono" }, r.sha256)) : null,
          r.onchain === "mismatch" ? h("div", null, h("span", null, "鏈上雜湊"), h("span", { class: "mono" }, r.expected)) : null,
          r.manifest === "mismatch" ? h("div", null, h("span", null, "manifest"), h("span", { class: "mono" }, r.manifestSha256)) : null,
          r.error ? h("div", null, h("span", null, "錯誤"), h("span", null, r.error)) : null));
    }));
    return h("div", null,
      h("p", { class: "small" }, "證據來源：", h("span", { class: "mono" }, loc.base)),
      h("ul", { class: "checks" }, top, fieldChecks, parentChecks),
      extras.length ? [h("p", { class: "small mt" }, "其他證據檔：鏈上沒有它們自己的雜湊，只和 manifest 比對（用來重跑攻擊或重新編譯）。"),
        h("ul", { class: "checks" }, extraChecks)] : null,
      h("details", { class: "evfiles", open: cmp.ok ? null : true },
        h("summary", null, `每個檔案的計算結果（${cmp.rows.length} 個）`), list),
      truncated ? h("p", { class: "mute small" }, `清單超過 ${MAX_FILES} 個檔案，只比對前 ${MAX_FILES} 個。`) : null,
      h("p", { class: "mute small" }, "manifest.json 本身沒有寫在鏈上，只用來列出檔名；判斷依據是每個檔案的 sha256 和鏈上雜湊。"));
  }

  async function compareLocal(files, inp, out) {
    const items = [];
    for (const f of [...files].slice(0, MAX_FILES)) {
      if (f.size > MAX_FILE) { items.push(check("warn", f.name, `檔案超過 ${MAX_FILE >> 20} MB，略過。`)); continue; }
      const sha = await L.sha256Hex(await f.arrayBuffer());
      const hit = L.matchFields(inp, sha);
      items.push(hit.length
        ? check("ok", `${f.name}：和鏈上的「${hit.map((x) => L.FIELD_LABELS[x]).join("、")}」雜湊相同`, sha)
        : check("bad", `${f.name}：和這筆紀錄的任何雜湊都不同`, sha));
    }
    out.replaceChildren(h("ul", { class: "checks mt" }, items));
    announce("本機檔案比對完成");
  }

  function dropZone(text, multiple, onFiles) {
    const input = h("input", { type: "file", class: "sr-only", tabindex: "-1", "aria-hidden": "true", multiple: multiple || null });
    const zone = h("div", { class: "drop", role: "button", tabindex: "0" }, text, input);
    const pick = () => input.click();
    zone.addEventListener("click", (e) => { if (e.target !== input) pick(); });
    zone.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
    zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
    zone.addEventListener("dragleave", () => zone.classList.remove("over"));
    zone.addEventListener("drop", (e) => {
      e.preventDefault();
      zone.classList.remove("over");
      if (e.dataTransfer && e.dataTransfer.files.length) onFiles(e.dataTransfer.files);
    });
    input.addEventListener("change", () => { if (input.files.length) onFiles(input.files); input.value = ""; });
    return zone;
  }

  // ------------------------------------------------------------------ static states
  function renderNotDeployed() {
    if (S.registryRefused) {
      const fromUrl = S.registryFrom === "url";
      return setResult(h("section", { class: "card", "aria-labelledby": "nd-h" },
        h("p", { class: "eyebrow" }, S.net.name),
        h("h2", { id: "nd-h" }, fromUrl ? "這個地址上的合約不是 AuditRegistry" : "部署紀錄檔裡的 AuditRegistry 沒有通過程式碼檢查"),
        kv([["合約地址", hexValue(S.registryRefused, { kind: "address" })],
            ["它的程式碼雜湊", S.registryCodehash ? hexValue(S.registryCodehash) : "—"],
            ["AuditRegistry 應有的雜湊", S.file && S.file.registryCodehash ? hexValue(S.file.registryCodehash) : "—"]]),
        h("p", { class: "mt" }, "程式碼雜湊不同，代表這個地址上跑的不是 AuditRegistry：它回傳的紀錄、稽核者和部署都可能是捏造的。" +
          (fromUrl ? "要查證，請改用官方設定。" : "")),
        fromUrl ? h("p", null, officialLink("改用官方設定查看", "btn primary")) : null));
    }
    if (!S.rpcOfficial && !S.registryMissing) {
      return setResult(messageCard("使用網址指定的節點時，要另外指定 AuditRegistry",
        `頁面不會把官方部署紀錄檔套用到網址指定的節點（${hostOf(S.net.rpc)}）：那個節點可以回傳任何內容。` +
        "要讀它，請在下方「網路與合約」或用網址參數 ?registry=0x… 指定合約；讀到的內容仍然只是那個節點的說法。"));
    }
    const onMe = S.net.key === "me-testnet" || S.chainId === 400;
    const title = S.registryMissing ? "這個地址上沒有 AuditRegistry" : onMe ? "合約尚未部署到 ME 測試網" : `${S.net.name} 上找不到 AuditRegistry`;
    const card = h("section", { class: "card", "aria-labelledby": "nd-h" },
      h("p", { class: "eyebrow" }, S.net.name),
      h("h2", { id: "nd-h" }, title),
      S.registryMissing ? h("p", { class: "notice" }, `地址 ${S.registryMissing} 上沒有合約程式碼。請確認網路和地址。`) : null,
      h("p", null, `已連線到 ${S.net.name}（chainId ${S.chainId}，目前區塊 #${S.block.toLocaleString("en-US")}），讀取正常；只是還沒有可以查詢的 AuditRegistry。部署之後，這個頁面會直接從鏈上讀出：`),
      h("ul", { class: "checks" },
        check("plan", "每筆稽核紀錄的判定", "四種之一：已證實可攻擊（擋部署）、靜態工具提示但未證實、未發現可證明攻擊（不等於安全）、無法判定（稽核未完成）。沒有「安全」這個選項。"),
        check("plan", "謂詞等級與證據等級", "攻擊是用嚴格還是寬鬆的條件判定、證據爬到第幾階。"),
        check("plan", "證據檔的指紋比對", "原始碼、gate.json、攻擊程式、修補的 sha256；頁面會下載證據包逐一重算比對。"),
        check("plan", "部署與程式碼現況", "經由 AuditRegistry 部署的每個合約地址（和稽核者自行宣告的地址分開標示），以及它們現在的程式碼是否和連結時相同。"),
        check("plan", "來龍去脈", "已證實可攻擊 → 修補 → 重新稽核 → 部署，每一步都是一筆鏈上紀錄。"),
        check("plan", "付費託管", "稽核費用由 AuditEscrow 依紀錄結算：完成就付款，沒完成就退回。"),
        check("plan", "區塊瀏覽器連結", "每筆交易附 0x 雜湊；向 ME Hub 查出瀏覽器索引的 Cosmos 交易後附上連結，查不到時給自己驗證的指令。")),
      h("p", { class: "mute small" }, "如果你知道合約地址，可以在下方「網路與合約」填入；或用網址參數 ?registry=0x…&escrow=0x…。"));
    setResult(card);
  }

  function renderNetInfo() {
    const t = S.trust;
    const desc = (text) => h("span", { class: "desc" }, text);
    const rows = [
      ["網路", `${S.net.name}（chainId ${S.chainId}）`],
      ["RPC", h("span", null, h("span", { class: "mono" }, S.net.rpc),
        desc(!S.rpcOfficial ? "網址指定的節點（非官方，回傳的內容可能是捏造的）"
          : S.net.key === "custom" ? "部署紀錄檔列出的節點" : "頁面內建的節點"))],
    ];
    const reg = S.registry || S.registryRefused;
    if (reg) {
      const code = { match: "✓ 程式碼雜湊和官方部署紀錄相同", mismatch: "✗ 程式碼雜湊和官方 AuditRegistry 不同" }[S.code]
        || (!S.rpcOfficial ? "沒有比對程式碼（網址指定的節點回傳的程式碼不能當成證據）"
          : !S.ethers ? "沒有比對程式碼（keccak256 函式庫沒有載入）" : "沒有比對程式碼（沒有部署紀錄可比對）");
      rows.push(["AuditRegistry", h("span", null, hexValue(reg, { kind: "address" }), desc(code))]);
      if (S.registry) rows.push(["紀錄筆數", String(S.count ?? "—")]);
    }
    if (S.escrow) {
      rows.push(["AuditEscrow", h("span", null, hexValue(S.escrow, { kind: "address" }),
        desc(S.escrowVerified ? `✓ 程式碼和官方 AuditEscrow 相同${S.escrowFrom === "url" ? "（網址指定）" : ""}`
          : `未驗證（${S.escrowFrom === "url" ? "網址指定" : "部署紀錄檔"}）`))]);
    }
    const ignored = (a, why) => rows.push(["AuditEscrow", h("span", { class: "warnline" }, `${a} ${why}，已忽略。`)]);
    if (S.escrowMismatch) ignored(S.escrowMismatch, "不是這個 AuditRegistry 的託管合約");
    if (S.escrowRejected) ignored(S.escrowRejected.address, "的程式碼沒有通過檢查");
    if (S.escrowIgnored) ignored(S.escrowIgnored, "由網址指定（官方部署只讀部署紀錄檔裡的 AuditEscrow）");
    const src = S.registryFrom === "url" ? "網址參數（不是官方部署紀錄檔）"
      : S.file ? h("span", { class: "mono" }, new URL(S.file.url).pathname) : "沒有";
    rows.push(["合約地址來源", src]);
    rows.push(["來源判定", S.registryRefused ? "不是 AuditRegistry（不讀取）"
      : !S.rpcOfficial ? "非官方來源（網址指定的節點）"
        : !t ? "—"
          : { official: "官方部署：部署紀錄檔裡的合約，鏈上程式碼雜湊相符", genuine: "非官方部署：網址指定的 AuditRegistry",
              unverified: "未驗證：無法比對程式碼雜湊" }[t.level]]);
    if (S.dep && S.dep.deployedAt) rows.push(["部署時間", S.dep.deployedAt]);
    if (S.dep) rows.push(["稽核者清單", S.dep.auditors.length ? `${S.dep.auditors.length} 個地址` : "沒有列出"]);
    $("net-info").replaceChildren(kv(rows));
    const off = !S.rpcOfficial || (t && !t.official) || S.registryRefused;
    $("net-summary").textContent = `${S.net.name}${S.registry ? ` · ${S.count} 筆紀錄` : " · 尚無 AuditRegistry"}` +
      (off ? " · 非官方來源" : "");
  }

  function fillNetForm() {
    $("net").value = S.net.key;
    $("rpc").value = S.net.rpc;
    $("rpc").disabled = S.net.key !== "custom";
    $("registry").value = S.params.registry || "";
    $("escrow").value = S.params.escrow || "";
    paramWarnings();
  }
  function paramWarnings() {
    const w = [...(S.params.warnings || [])];
    if (S.escrowIgnored) w.push(`escrow 參數 ${S.escrowIgnored}（官方部署只讀部署紀錄檔裡的 AuditEscrow）`);
    $("param-warn").textContent = w.length ? `網址參數有問題，已忽略：${w.join("；")}` : "";
  }

  // ------------------------------------------------------------------ theme and wiring
  function storedTheme() { try { return localStorage.getItem("vp-theme"); } catch (e) { return null; } }
  function applyTheme(t) {
    if (t === "dark" || t === "light") document.documentElement.setAttribute("data-theme", t);
    else document.documentElement.removeAttribute("data-theme");
  }
  function toggleTheme() {
    const cur = document.documentElement.getAttribute("data-theme") ||
      (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
    const next = cur === "light" ? "dark" : "light";
    applyTheme(next);
    try { localStorage.setItem("vp-theme", next); } catch (e) { /* private mode */ }
    announce(next === "light" ? "已切換為淺色" : "已切換為深色");
  }

  function wire() {
    $("theme-btn").addEventListener("click", toggleTheme);
    $("lookup-form").addEventListener("submit", (e) => { e.preventDefault(); lookup($("q").value); });
    $("sol-drop").replaceWith(dropZone("拖入 .sol 原始碼檔，或按這裡選檔：用 sha256 找出它的所有稽核紀錄（檔案只在瀏覽器裡計算，不會上傳）。",
      false, async (files) => {
        if (!S.registry) { $("q-err").textContent = noRegistryText(); return; }
        const f = files[0];
        if (f.size > MAX_FILE) { $("q-err").textContent = "檔案太大。"; return; }
        const hash = await L.sha256Hex(await f.arrayBuffer());
        setUrl({ source: hash });
        lookupSource(hash, f.name).catch(showError);
      }));
    $("net").addEventListener("change", () => {
      const custom = $("net").value === "custom";
      $("rpc").disabled = !custom;
      if (!custom) $("rpc").value = NETWORKS[$("net").value].rpc;
      else $("rpc").focus();
    });
    $("net-form").addEventListener("submit", (e) => {
      e.preventDefault();
      const next = new URLSearchParams();
      const net = $("net").value;
      if (net !== "me-testnet") next.set("net", net);
      if (net === "custom") next.set("rpc", $("rpc").value.trim());
      for (const k of ["registry", "escrow"]) if ($(k).value.trim()) next.set(k, $(k).value.trim());
      if (S.params.theme) next.set("theme", S.params.theme);
      history.pushState(null, "", location.pathname + (next.toString() ? `?${next}` : ""));
      S.params = L.parseParams(location.search);
      connect();
    });
    window.addEventListener("popstate", () => {
      const prev = S.params;
      S.params = L.parseParams(location.search);
      const same = KEEP_PARAMS.every((k) => (prev[k] || null) === (S.params[k] || null));
      if (same && S.registry) route(S.run); else connect();
    });
  }

  // The same page is served by the local ARBITER Gate web UI (at /verify/) and by GitHub Pages.
  // Locally "home" is the web UI's front page; Pages has no front page, so it links the project's
  // README on GitHub instead.
  function setHomeLink() {
    const a = $("home-link");
    if (!a) return;
    if (/^\/verify(\/|$)/.test(location.pathname)) {
      a.href = "/";
      a.textContent = "← 回首頁";
    } else {
      a.href = `${L.TOOL_REPO}/blob/me-hackathon/me/README.md`;
      a.textContent = "← 專案首頁";
      a.title = "ARBITER Gate 在 GitHub 上的專案說明";
      a.rel = "noopener";
    }
    a.hidden = false;
  }

  function start() {
    setHomeLink();
    S.params = L.parseParams(location.search);
    applyTheme(S.params.theme || storedTheme());
    S.ethers = !!(window.ethers && window.ethers.keccak256 && window.ethers.id);
    wire();
    if (S.ethers) {
      const bad = selfCheck();
      if (bad.length) {
        setPill("bad", "頁面內部檢查失敗");
        setResult(messageCard("頁面內部檢查失敗", `內建的 ABI 常數和 keccak256 重算結果不同：${bad.join("、")}。請回報這個問題。`));
        return;
      }
    } else {
      $("lib-warn").textContent = "keccak256 函式庫（ethers）沒有載入：仍可查詢紀錄與比對證據，但無法比對部署後的程式碼。";
    }
    connect();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
