// End-to-end check of the verify page in headless Chrome, over the DevTools protocol (node >= 22,
// no packages). Needs the anvil fixture (me/scripts/verify_page_fixture.py) served over HTTPS:
//
//   node me/scripts/verify_page_browser_check.js --fixture /tmp/vp_root/fixture.json \
//        --base https://127.0.0.1:8751/me/web/verify/ --cert /tmp/vp_cert.pem \
//        [--out shots/] [--chrome PATH] [--port 8758] [--proxy-port 8752] [--no-me]
//
// --cert is the fixture server's self-signed certificate; Chrome trusts only that key (by its
// SPKI hash), not certificate errors in general. A small proxy in front of anvil (--proxy-port)
// answers eth_getLogs like ME does (at most 10,000 blocks per query), so the page's windowed log
// search is exercised; a second one (the next port) reports chain id 400 and swaps in the hash of
// a real ME transaction, so the page's live Hub lookup and explorer links are exercised too.
// Two more (the ports after) are nodes a crafted link could name: one claims to be ME (chain id
// 400) and one is just another URL for the same anvil. With them and the fixture's "spoof"
// contracts, the spoof cases check that a node, registry or escrow from the URL is never shown as
// the official deployment (web-security-wording-2..4): a warning on the page and in the header,
// no "✓" auditor badge, and a registry whose code is not AuditRegistry's is not read at all.
// Each case loads a deep link, waits until nothing is loading, then checks the visible text,
// element counts, that the page did not log errors, and that nothing is wider than the viewport.
// The ME cases are live and read-only (--no-me skips them). Prints "N of M".
"use strict";
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");

function arg(name, dflt) {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : dflt;
}
const has = (name) => process.argv.includes(`--${name}`);
const CHROME = arg("chrome", process.env.CHROME || (process.platform === "win32"
  ? "C:/Program Files/Google/Chrome/Application/chrome.exe" : "google-chrome"));
const PORT = Number(arg("port", "8758"));
const PROXY_PORT = Number(arg("proxy-port", "8752"));
const BASE = arg("base", "https://127.0.0.1:8751/me/web/verify/");
const CERT = arg("cert", "");
const OUT = arg("out", "");
const FX = JSON.parse(fs.readFileSync(arg("fixture", "/tmp/vp_root/fixture.json"), "utf8"));
const ME_HUB = "https://beta-hub-26657.explorer-testnet.me";
const LOG_SPAN = 10000; // ME: "maximum [from, to] blocks distance: 10000"

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class Cdp {
  constructor(url) {
    this.ws = new WebSocket(url);
    this.id = 0;
    this.pending = new Map();
    this.listeners = [];
    this.ws.onmessage = (m) => {
      const msg = JSON.parse(m.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
      } else if (msg.method) {
        for (const fn of this.listeners) fn(msg);
      }
    };
  }
  open() { return new Promise((res, rej) => { this.ws.onopen = res; this.ws.onerror = rej; }); }
  send(method, params = {}) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }
  async eval(expr) {
    const r = await this.send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text + " " + ((r.exceptionDetails.exception || {}).description || ""));
    return r.result.value;
  }
}

/** sha256 of the certificate's public key (what --ignore-certificate-errors-spki-list takes). */
function spkiHash(certPath) {
  const der = new crypto.X509Certificate(fs.readFileSync(certPath)).publicKey.export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("base64");
}

async function launch() {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "vpcdp-"));
  const flags = ["--headless=new", `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`,
    "--no-first-run", "--no-default-browser-check", "--disable-gpu"];
  if (CERT) flags.push(`--ignore-certificate-errors-spki-list=${spkiHash(CERT)}`);
  const proc = spawn(CHROME, [...flags, "about:blank"], { stdio: "ignore" });
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}/json/version`);
      if (r.ok) break;
    } catch (e) { /* not up yet */ }
    await sleep(200);
  }
  const tab = await (await fetch(`http://127.0.0.1:${PORT}/json/new?about:blank`, { method: "PUT" })).json();
  const cdp = new Cdp(tab.webSocketDebuggerUrl);
  await cdp.open();
  return { proc, cdp, profile };
}

/**
 * JSON-RPC proxy to anvil. cap: refuse eth_getLogs over more than LOG_SPAN blocks, like ME.
 * asMe: {txHash}: report chain id 400 and give every log the transaction hash of a real ME
 * transaction, so the page (as on ME) looks it up on the live Hub and links the explorer.
 * chainId: report this chain id and pass everything else through (a node that lies about its chain).
 */
function rpcProxy(target, port, { cap = false, asMe = null, chainId = null } = {}) {
  const stats = { rejected: 0 };
  const cors = { "access-control-allow-origin": "*", "access-control-allow-headers": "content-type",
                 "access-control-allow-methods": "POST, OPTIONS" };
  const upstream = async (body) => (await fetch(target, { method: "POST", headers: { "content-type": "application/json" }, body })).text();
  const server = http.createServer(async (req, res) => {
    if (req.method === "OPTIONS") { res.writeHead(204, cors); return res.end(); }
    let body = "";
    for await (const chunk of req) body += chunk;
    try {
      const msg = JSON.parse(body);
      const reply = (result) => {
        res.writeHead(200, { ...cors, "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }));
      };
      if (asMe && msg.method === "eth_chainId") return reply("0x190");
      if (chainId && msg.method === "eth_chainId") return reply(chainId);
      if (asMe && msg.method === "eth_getLogs") {
        const logs = JSON.parse(await upstream(body)).result || [];
        return reply(logs.map((lg) => ({ ...lg, transactionHash: asMe.txHash })));
      }
      if (cap && msg && msg.method === "eth_getLogs") {
        const f = (msg.params || [])[0] || {};
        const latest = async () => parseInt(JSON.parse(await upstream(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }))).result, 16);
        const num = async (b) => (b == null || b === "latest" ? latest() : b === "earliest" ? 0 : parseInt(b, 16));
        if ((await num(f.toBlock)) - (await num(f.fromBlock)) > LOG_SPAN) {
          stats.rejected++;
          res.writeHead(200, { ...cors, "content-type": "application/json" });
          return res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id,
                                          error: { code: -32000, message: `maximum [from, to] blocks distance: ${LOG_SPAN}` } }));
        }
      }
      const text = await upstream(body);
      res.writeHead(200, { ...cors, "content-type": "application/json" });
      res.end(text);
    } catch (e) {
      res.writeHead(502, cors);
      res.end(String(e));
    }
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve({ server, stats, url: `http://127.0.0.1:${port}` })));
}

/** The newest EVM transaction the ME Hub has indexed: {evm, cosmos, height}. */
async function sampleMeTx() {
  const q = encodeURIComponent('"ethereum_tx.ethereumTxHash EXISTS"');
  const j = await (await fetch(`${ME_HUB}/tx_search?query=${q}&per_page=1&order_by=%22desc%22`)).json();
  const t = j.result.txs[0];
  const ev = t.tx_result.events.find((e) => e.type === "ethereum_tx" && e.attributes.some((a) => a.key === "ethereumTxHash"));
  return { evm: ev.attributes.find((a) => a.key === "ethereumTxHash").value, cosmos: t.hash, height: Number(t.height) };
}

// Wait until the result area has content, nothing shows a spinner, a pending check or a pending
// lookup, and the text has been stable for a moment.
const READY = `(() => {
  const r = document.getElementById("result");
  if (!r || !r.children.length || r.getAttribute("aria-busy")) return "";
  if (document.querySelector(".loading, .check.wait, .pending")) return "";
  return document.body.innerText.length + ":" + r.textContent.length;
})()`;
const OVERFLOW = `(() => {
  const w = document.documentElement.clientWidth;
  const bad = [];
  for (const el of document.querySelectorAll("body *")) {
    const r = el.getBoundingClientRect();
    if (r.width && r.right > w + 1 && getComputedStyle(el).position !== "fixed" && !el.closest(".sr-only")) {
      bad.push((el.id ? "#" + el.id : el.tagName.toLowerCase() + "." + el.className).slice(0, 60) + " right=" + Math.round(r.right));
    }
  }
  return { scrollWidth: document.documentElement.scrollWidth, width: w, bad: bad.slice(0, 8) };
})()`;

async function runCase(cdp, c, errors) {
  const width = c.width || 1280;
  await cdp.send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 600 });
  await cdp.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: c.scheme || "dark" }] });
  errors.length = 0;
  const before = c.before ? await c.before() : null;
  // noEthers: the CDN script is blocked, as on a network that cannot reach cdnjs
  await cdp.send("Network.setBlockedURLs", { urls: c.noEthers ? ["*cdnjs.cloudflare.com*"] : [] });
  await cdp.send("Network.setCacheDisabled", { cacheDisabled: !!c.noEthers });
  await cdp.send("Page.navigate", { url: c.url });
  let last = "", stable = 0;
  for (let i = 0; i < 160 && stable < 3; i++) {
    await sleep(250);
    let now = "";
    try { now = await cdp.eval(READY); } catch (e) { now = ""; }
    stable = now && now === last ? stable + 1 : 0;
    last = now;
  }
  const problems = [];
  if (stable < 3) problems.push("page did not settle within 40 s");
  const text = await cdp.eval("document.body.innerText");
  for (const want of c.expect || []) if (!text.includes(want)) problems.push(`missing text: ${want}`);
  for (const not of c.reject || []) if (text.includes(not)) problems.push(`unexpected text: ${not}`);
  for (const [sel, n] of Object.entries(c.selector || {})) {
    const got = await cdp.eval(`document.querySelectorAll(${JSON.stringify(sel)}).length`);
    if (got !== n) problems.push(`${sel}: ${got} element(s), expected ${n}`);
  }
  if (c.extra) problems.push(...(await c.extra(cdp, before)));
  const hasEthers = await cdp.eval("!!(window.ethers && window.ethers.keccak256)");
  if (!hasEthers && !c.noEthers) problems.push("ethers (cdnjs, SRI) did not load");
  if (hasEthers && c.noEthers) problems.push("ethers loaded although cdnjs was blocked");
  const ov = await cdp.eval(OVERFLOW);
  if (ov.scrollWidth > ov.width || ov.bad.length) problems.push(`horizontal overflow at ${width}px: ${JSON.stringify(ov)}`);
  const errs = errors.filter((e) => !/deployments\/[\w-]+\.json/.test(e) // missing deployment files are expected 404s
    && !(c.noEthers && /cdnjs|ERR_BLOCKED/.test(e)));
  if (errs.length) problems.push(`console errors: ${errs.slice(0, 3).join(" | ")}`);
  if (OUT && c.shot) {
    const h = Math.min(await cdp.eval("document.documentElement.scrollHeight"), 9000);
    await cdp.send("Emulation.setDeviceMetricsOverride", { width, height: h, deviceScaleFactor: 1, mobile: width < 600 });
    await sleep(300);
    const shot = await cdp.send("Page.captureScreenshot", { format: "png" });
    fs.mkdirSync(OUT, { recursive: true });
    fs.writeFileSync(path.join(OUT, c.shot), Buffer.from(shot.data, "base64"));
  }
  return problems;
}

async function main() {
  const proxy = await rpcProxy(FX.rpc, PROXY_PORT, { cap: true });
  const sample = has("no-me") ? null : await sampleMeTx();
  const meProxy = sample ? await rpcProxy(FX.rpc, PROXY_PORT + 1, { asMe: { txHash: sample.evm } }) : null;
  const fakeMe = await rpcProxy(FX.rpc, PROXY_PORT + 2, { chainId: "0x190" });
  const elsewhere = await rpcProxy(FX.rpc, PROXY_PORT + 3);
  const q = (o, rpc = FX.rpc) => BASE + "?" + new URLSearchParams({ rpc, ...o }).toString();
  const r = FX.records, tx = FX.tx, d = FX.deployed, sp = FX.spoof;
  // the same page served next to a deployment file that declares the fixture's contracts as ME testnet
  const SIM = new URL(sp.simBase, BASE).href;
  const sim = (o) => SIM + "?" + new URLSearchParams(o).toString();
  const ME_RPC = "https://beta-hub-8545.explorer-testnet.me";
  const official = { "#net-pill.ok": 1, ".trustcard": 0, "#trust:not([hidden])": 0 };
  const T = (hash) => `[data-tx="${hash.toLowerCase()}"]`;
  const github = 'a[href^="https://github.com/sam029031/arbiter-gate/commit/"]';
  const capped = { before: async () => proxy.stats.rejected,
                   extra: async (cdp, before) => (proxy.stats.rejected > before ? []
                     : ["the capped proxy refused no whole-range eth_getLogs, so the windowed search was not exercised"]) };
  if (!(FX.logGap > LOG_SPAN)) console.log(`note: fixture logGap ${FX.logGap} does not exceed ${LOG_SPAN}; the capped cases may not reach the fallback`);

  const cases = [
    { name: "proven record: evidence matches, escrow paid, newer record by the same auditor", url: q({ record: r.proven }),
      shot: "record1_desktop.png",
      expect: ["已證實可攻擊（擋部署）", "證據包和鏈上紀錄相符", "已付給稽核者", "示範稽核者", "嚴格", "第 3 階：本地真鏈",
               "後續：重新稽核", `同一位稽核者之後對同一份原始碼登錄了較新的紀錄 #${r.reaudit}`, "可結算的紀錄",
               `cast receipt ${tx.register1.toLowerCase()} --rpc-url ${FX.rpc}`],
      reject: ["和鏈上雜湊不符", "讀取失敗", "manifest.json 的格式不是"],
      selector: { ".timeline .step": 4, [T(tx.register1)]: 1, [T(tx.settle1)]: 1, ...official } },
    { name: "patched child: two gated deployments, record.py bundle, a dispute by another account", url: q({ record: r.patched }),
      shot: "record2_desktop.png",
      expect: ["未發現可證明攻擊（不等於安全）", "由 AuditRegistry 依稽核過的 bytecode 部署", "共 2 個地址",
               "地址上現在的程式碼，和連結時記下的雜湊相同", "證據包和鏈上紀錄相符", "上一版（#1）的原始碼：相符",
               "上一版（#1）的攻擊程式：相符", "回歸測試專案：和 manifest 列的雜湊相同", "編譯設定：和 manifest 列的雜湊相同",
               `同一份 bytecode 另有判定為已證實可攻擊的紀錄（#${r.dispute}，稽核者`, "登錄它的是另一個地址", "isLinkCurrent"],
      reject: ["和鏈上雜湊不符", "讀取失敗", "沒有找到這個地址的連結事件", "manifest.json 的格式不是"],
      selector: { ".timeline .step": 4, ".timeline .step.current": 1, ".dep": 2, ".dep .check.ok": 2,
                  [T(tx.register2)]: 1, [T(tx.deploy2a)]: 1, [T(tx.deploy2b)]: 1 } },
    { name: "unfinished audit: altered gate.json is caught, escrow refunded", url: q({ record: r.undetermined }),
      shot: "record3_light.png", scheme: "light",
      expect: ["無法判定（稽核未完成）", "有檔案和鏈上雜湊不符", "已退回申請人", "稽核沒有完成：AuditRegistry 不允許部署"],
      selector: { ".evitem.bad": 1, [T(tx.settle2)]: 1 } },
    { name: "static hint by another account: its own claim, public commit linked, no evidence URI", url: q({ record: r.hint_claimed }),
      shot: "record4_desktop.png",
      expect: ["靜態工具提示但未證實", "稽核者自行宣告（未經閘門部署，只能比對程式碼雜湊）", "這筆紀錄沒有提供證據位址",
               "ARBITER Gate 公開 repo 的這個 commit", "不在部署紀錄的稽核者清單", "宣告時的程式碼雜湊",
               "地址上現在的程式碼，和連結時記下的雜湊相同", "isLinkCurrent"],
      selector: { [github]: 1, ".dep": 1, [T(tx.link4)]: 1 } },
    { name: "a proven record carries no 'another proven record' warning", url: q({ record: r.dispute }),
      expect: ["已證實可攻擊（擋部署）", "已證實可攻擊：AuditRegistry 的 deployAudited 會拒絕部署這份程式碼"],
      reject: ["同一份 bytecode 另有判定為已證實可攻擊"] },
    { name: "re-audit of bytecode the same auditor proved exploitable", url: q({ record: r.reaudit }), shot: "record6_desktop.png",
      expect: [`同一份 bytecode 另有判定為已證實可攻擊的紀錄（#${r.proven}，稽核者 示範稽核者`, "登錄它的就是這筆紀錄的稽核者",
               `同一位稽核者已把這份 bytecode 登錄為已證實可攻擊（紀錄 #${r.proven}）`] },
    { name: "lookup: gated address deployed by the auditor", url: q({ address: d.gatedA }),
      expect: [`是 AuditRegistry 依紀錄 #${r.patched} 稽核過的 bytecode 部署的`, "共 2 個地址"] },
    { name: "lookup: gated address deployed by another caller", url: q({ address: d.gatedB }),
      expect: [`是 AuditRegistry 依紀錄 #${r.patched} 稽核過的 bytecode 部署的`] },
    { name: "lookup: claimed address lists the claim, labelled", url: q({ address: d.claimed }), shot: "claimed_lookup.png",
      expect: ["稽核者自行宣告（未經閘門部署，只能比對程式碼雜湊）", `#${r.hint_claimed}`, "宣告時的程式碼雜湊和地址上現在的相同"],
      reject: ["稽核過的 bytecode 部署的"], selector: { ".recitem": 1 } },
    { name: "lookup by deployAudited tx (another caller)", url: q({ tx: tx.deploy2b }),
      expect: ["這筆交易：把地址", `連結到紀錄 #${r.patched}`], selector: { [T(tx.deploy2b)]: 2 } },
    { name: "lookup by escrow settle tx", url: q({ tx: tx.settle2 }), expect: ["結算託管申請 #2", "退回申請人"],
      selector: { [T(tx.settle2)]: 1 } },
    { name: "lookup by source sha256 (one record)", url: q({ source: FX.sourceHashes["DemoToken.sol"] }),
      expect: [`只有一筆稽核紀錄：#${r.undetermined}`] },
    { name: "lookup by source sha256 (two records, latest by the listed auditor first)", url: q({ source: FX.sourceHashes["DemoVault.sol"] }),
      expect: ["這份原始碼有 2 筆稽核紀錄", "部署紀錄列出的稽核者對這份原始碼的最新紀錄"], selector: { ".recitem": 3 } },
    { name: "home lists latest records", url: q({}), expect: ["最近的紀錄（共 6 筆）"], selector: { ".recitem": 5 } },
    { name: "unknown record id", url: q({ record: 99 }), expect: ["沒有紀錄 #99", "目前共有 6 筆紀錄"] },
    { name: "malformed deep link is reported, not used", url: q({ address: "0x12", record: 1 }),
      expect: ["address 參數不是地址", "已證實可攻擊（擋部署）"] },
    // spoof cases (web-security-wording-2..4): a node, registry or escrow from the URL
    { name: "spoof: a node claiming to be ME does not get the official deployment file or auditor list",
      url: sim({ rpc: fakeMe.url, record: r.proven }), shot: "spoof_me_node.png",
      expect: ["使用網址指定的節點時，要另外指定 AuditRegistry", "不是頁面內建或部署紀錄檔列出的官方節點", "非官方來源"],
      reject: ["✓ 示範稽核者", "ME 測試網（自訂 RPC）", "已證實可攻擊（擋部署）"],
      selector: { "#net-pill.ok": 0, ".trustcard": 1, "#trust:not([hidden])": 1, ".record": 0 } },
    { name: "spoof: that node with the registry and escrow in the URL: unverified, no badge, cast asks the real ME node",
      url: sim({ rpc: fakeMe.url, registry: FX.registry, escrow: FX.escrow, record: r.proven }), shot: "spoof_me_node_record.png",
      expect: ["自訂 RPC（chainId 400）", "不是頁面內建或部署紀錄檔列出的官方節點", "非官方來源：不比對稽核者清單",
               `cast receipt ${tx.register1.toLowerCase()} --rpc-url ${ME_RPC}`],
      reject: ["✓ 示範稽核者", "ME 測試網（自訂 RPC）", `--rpc-url ${fakeMe.url}`],
      selector: { "#net-pill.ok": 0, ".trustcard": 1, ".record.tone-mute": 1, ".verdict .unv": 1 } },
    { name: "spoof: another URL for the same chain is not the deployment file's node",
      url: q({ record: r.proven }, elsewhere.url),
      expect: ["使用網址指定的節點時，要另外指定 AuditRegistry"], reject: ["✓ 示範稽核者", "已證實可攻擊（擋部署）"],
      selector: { "#net-pill.ok": 0, ".trustcard": 1 } },
    { name: "spoof: a registry in the URL whose code is not AuditRegistry's is not read at all",
      url: q({ registry: sp.fakeRegistry, record: sp.fakeRecord }), shot: "spoof_fake_registry.png",
      expect: ["這個地址上的合約不是 AuditRegistry", "頁面不讀取它的任何資料", "改用官方設定查看"],
      reject: ["未發現可證明攻擊（不等於安全）", "✓ 示範稽核者"],
      selector: { "#net-pill.bad": 1, ".trustcard": 1, ".record": 0, ".recitem": 0, ".verdict": 0 } },
    { name: "spoof: another genuine AuditRegistry in the URL is shown, but not as the official deployment",
      url: q({ registry: sp.otherRegistry, escrow: sp.otherEscrow, record: sp.otherRecord }),
      expect: ["未發現可證明攻擊（不等於安全）", "由網址指定，不是官方部署紀錄檔裡的合約", "程式碼和官方 AuditRegistry 相同",
               "非官方來源：不比對稽核者清單", "已付給稽核者"],
      reject: ["✓ 示範稽核者", "不在部署紀錄的稽核者清單", "ARBITER Gate 公開 repo 的這個 commit"],
      selector: { "#net-pill.ok": 0, ".trustcard": 1, ".verdict .unv": 0, "#trust:not([hidden])": 1 } },
    { name: "spoof: an escrow in the URL beside the official registry is ignored",
      url: q({ escrow: sp.fakeEscrow, record: r.patched }),
      expect: ["沒有付費託管申請由這筆紀錄結算", "官方部署只讀部署紀錄檔裡的 AuditEscrow"],
      reject: ["500 ETH", "bEEF"], selector: official },
    { name: "no keccak256 (cdnjs blocked): the code hash cannot be checked, so not shown as the official deployment",
      url: q({ record: r.proven }), noEthers: true,
      expect: ["瀏覽器沒有載入 keccak256 函式庫", "非官方來源：不比對稽核者清單", "已證實可攻擊（擋部署）"],
      reject: ["✓ 示範稽核者"], selector: { "#net-pill.ok": 0, ".trustcard": 1, ".verdict .unv": 1 } },
    { name: "spoof: a fake escrow beside another genuine registry is ignored",
      url: q({ registry: sp.otherRegistry, escrow: sp.fakeEscrowOther, record: sp.otherRecord }),
      expect: ["的程式碼和官方 AuditEscrow 不同，已忽略"], reject: ["500 ETH", "bEEF"],
      selector: { ".trustcard": 1 } },
    // the capping proxy is a node the deployment file does not name, so the contracts are given in the URL
    { name: "node capping eth_getLogs at 10,000 blocks: record 1 still finds its transactions",
      url: q({ record: r.proven, registry: FX.registry, escrow: FX.escrow }, proxy.url), ...capped,
      expect: ["已付給稽核者", "證據包和鏈上紀錄相符"], selector: { [T(tx.register1)]: 1, [T(tx.settle1)]: 1, ".trustcard": 1 } },
    { name: "node capping eth_getLogs at 10,000 blocks: record 2 finds both deployments",
      url: q({ record: r.patched, registry: FX.registry, escrow: FX.escrow }, proxy.url), ...capped,
      selector: { [T(tx.register2)]: 1, [T(tx.deploy2a)]: 1, [T(tx.deploy2b)]: 1, ".dep .check.ok": 2 } },
    { name: "mobile 390: proven record", url: q({ record: r.proven }), width: 390, shot: "record1_mobile.png",
      expect: ["證據包和鏈上紀錄相符"] },
    { name: "mobile 390: patched record (light)", url: q({ record: r.patched }), width: 390, scheme: "light",
      shot: "record2_mobile_light.png", expect: ["地址上現在的程式碼，和連結時記下的雜湊相同", "共 2 個地址"] },
    { name: "mobile 390: claimed address", url: q({ address: d.claimed }), width: 390, shot: "claimed_mobile.png",
      expect: ["稽核者自行宣告（未經閘門部署，只能比對程式碼雜湊）"] },
    { name: "mobile 375: home", url: q({}), width: 375, shot: "home_mobile.png", expect: ["最近的紀錄"] },
    { name: "mobile 390: a spoofed node's record keeps the warning in view (light)", width: 390, scheme: "light",
      url: sim({ rpc: fakeMe.url, registry: FX.registry, escrow: FX.escrow, record: r.patched }), shot: "spoof_mobile_light.png",
      expect: ["非官方來源", "AuditRegistry 部署（未驗證）"], selector: { "#trust:not([hidden])": 1, ".trustcard": 1, ".step.unv": 1 } },
  ];
  if (!has("no-me")) {
    cases.push(
      { name: "ME testnet (live, read-only): not deployed yet", url: BASE, shot: "me_testnet_desktop.png",
        expect: ["合約尚未部署到 ME 測試網", "chainId 400", "區塊瀏覽器連結"] },
      { name: "ME testnet mobile 390", url: BASE + "?record=1", width: 390, shot: "me_testnet_mobile.png",
        expect: ["合約尚未部署到 ME 測試網"] },
      { name: "ME explorer links (live Hub): transactions by Cosmos hash, accounts by me1 address",
        url: BASE + "?" + new URLSearchParams({ rpc: meProxy.url, registry: FX.registry, escrow: FX.escrow, record: r.proven }),
        shot: "record1_me_links.png",
        expect: ["自訂 RPC（chainId 400）", "非官方來源", "在區塊瀏覽器查看", `Cosmos 交易 ${sample.cosmos.slice(0, 6)}`],
        reject: ["區塊瀏覽器查不到", "這條鏈沒有區塊瀏覽器", "ME 測試網（自訂 RPC）"],
        selector: { [`a[href="https://www.explorer-testnet.me/zh-TW/transactions/${sample.cosmos.toUpperCase()}?netType=hub"]`]: 2,
                    [`a[href="https://www.explorer-testnet.me/zh-TW/blocks/${sample.height}?netType=hub"]`]: 2,
                    'button[aria-label^="複製 cast 驗證指令：cast receipt "]': 2,
                    // the self-check asks ME's own node, not the one the link named
                    [`button[aria-label$="--rpc-url ${ME_RPC}"]`]: 2 },
        extra: async (cdp) => {
          const hrefs = await cdp.eval(`[...document.querySelectorAll('#result a[href*="/accountDetails/"]')].map((a) => a.href)`);
          const ok = hrefs.length >= 3 && hrefs.every((u) => /^https:\/\/www\.explorer-testnet\.me\/zh-TW\/accountDetails\/me1[02-9ac-hj-np-z]{38}$/.test(u));
          return ok ? [] : [`account links: ${JSON.stringify(hrefs)}`];
        } },
      { name: "ME Hub (live): the page maps an EVM tx to the Cosmos tx the explorer indexes", url: BASE,
        extra: async (cdp) => {
          const s = sample;
          const got = await cdp.eval(`(async () => {
            const L = window.VerifyLib, evm = ${JSON.stringify(s.evm)};
            const res = await fetch(L.cosmosTxSearchUrl(${JSON.stringify(ME_HUB)}, evm), { credentials: "omit" });
            const c = L.parseTxSearch(await res.json(), evm);
            return { c, url: c && L.explorerUrl("https://www.explorer-testnet.me", "tx", c.hash) };
          })()`);
          const want = `https://www.explorer-testnet.me/zh-TW/transactions/${s.cosmos.toUpperCase()}?netType=hub`;
          return got.c && got.c.hash === s.cosmos.toUpperCase() && got.c.height === s.height && got.url === want ? []
            : [`hub lookup for ${s.evm}: got ${JSON.stringify(got)}, want ${s.cosmos} at ${s.height}`];
        } });
  }

  const { proc, cdp, profile } = await launch();
  const errors = [];
  cdp.listeners.push((m) => {
    if (m.method === "Runtime.exceptionThrown") errors.push(m.params.exceptionDetails.text + " " + (m.params.exceptionDetails.exception || {}).description);
    if (m.method === "Runtime.consoleAPICalled" && m.params.type === "error") errors.push(m.params.args.map((a) => a.value || a.description).join(" "));
    if (m.method === "Log.entryAdded" && m.params.entry.level === "error") errors.push(`${m.params.entry.text} ${m.params.entry.url || ""}`);
  });
  await cdp.send("Page.enable");
  await cdp.send("Runtime.enable");
  await cdp.send("Log.enable");
  await cdp.send("Network.enable");
  let passed = 0;
  for (const c of cases) {
    let problems;
    try { problems = await runCase(cdp, c, errors); } catch (e) { problems = [`exception: ${e.message}`]; }
    if (!problems.length) passed++;
    console.log(`${problems.length ? "FAIL" : "ok  "} ${c.name}${problems.length ? "\n       " + problems.join("\n       ") : ""}`);
  }
  console.log(`${passed} of ${cases.length} browser checks passed (capped proxy refused ${proxy.stats.rejected} whole-range queries)`);
  proc.kill();
  for (const p of [proxy, meProxy, fakeMe, elsewhere]) if (p) p.server.close();
  try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) { /* chrome may still hold it */ }
  process.exit(passed === cases.length ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(2); });
