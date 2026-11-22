// Static checks of the page files (no browser), and the wording of the hackathon docs under me/:
//   node --test me/web/verify/test/*.test.js
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const DIR = path.resolve(__dirname, "..");
const read = (f) => fs.readFileSync(path.join(DIR, f), "utf8");
const HTML = read("index.html");
const APP = read("app.js");
const LIB = read("verify-lib.js");

test("the CSP hash matches the inline trailing-slash script", () => {
  const inline = HTML.match(/<script>([\s\S]*?)<\/script>/)[1];
  const hash = crypto.createHash("sha256").update(inline).digest("base64");
  const csp = HTML.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)[1];
  assert.ok(csp.includes(`'sha256-${hash}'`), "update the CSP hash after editing the inline script");
  assert.match(csp, /default-src 'none'/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
});

test("only ethers comes from outside, pinned with SRI; everything else is local", () => {
  const srcs = [...HTML.matchAll(/<script[^>]*\ssrc="([^"]+)"[^>]*>/g)];
  const external = srcs.filter((m) => /^https?:/.test(m[1]));
  assert.equal(external.length, 1);
  const tag = external[0][0];
  assert.match(external[0][1], /^https:\/\/cdnjs\.cloudflare\.com\/ajax\/libs\/ethers\/6\.\d+\.\d+\/ethers\.umd\.min\.js$/);
  assert.match(tag, /integrity="sha(384|512)-[A-Za-z0-9+/=]+"/);
  assert.match(tag, /crossorigin="anonymous"/);
  const links = [...HTML.matchAll(/<link[^>]*href="([^"]+)"/g)].map((m) => m[1]);
  assert.ok(links.every((h) => !/^https?:/.test(h)), "no external stylesheets or fonts");
  assert.doesNotMatch(read("style.css"), /@import|url\(\s*["']?https?:/);
});

test("chain data never reaches innerHTML or eval", () => {
  for (const file of [APP, LIB]) {
    const src = file.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, ""); // comments may name them
    assert.doesNotMatch(src, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/);
  }
});

test("wording: no bare 安全, CLEAR or 首創 on the page", () => {
  const allowed = /不等於安全|沒有「安全」這個選項/g;
  for (const [name, src] of [["index.html", HTML], ["app.js", APP], ["verify-lib.js", LIB]]) {
    const stripped = src.replace(allowed, "");
    assert.equal(stripped.includes("安全"), false, `${name} says 安全 outside a negation`);
    assert.doesNotMatch(src, /CLEAR|首創/, name);
    assert.doesNotMatch(src, /\d+(\.\d+)?\s*%/, `${name}: write numbers as N 次中 M 次, not percentages`);
  }
});

// web-security-wording-5/7: the judges' README, the tool docs and this page's README follow the
// same wording rules as the page; and the escrow is 託管 everywhere under me/ (docs, CLI messages,
// the page), never the mainland form.
const ME = path.resolve(DIR, "../..");
test("wording: me/README.md, me/docs/*.md and the verify page README", () => {
  const docs = ["README.md", "web/verify/README.md",
                ...fs.readdirSync(path.join(ME, "docs")).filter((f) => f.endsWith(".md")).map((f) => `docs/${f}`)];
  const negations = /不等於安全|沒有「安全」/g; // e.g. 「合約裡沒有「安全」欄位」
  for (const rel of docs) {
    const src = fs.readFileSync(path.join(ME, rel), "utf8");
    assert.equal(src.replace(negations, "").includes("安全"), false, `me/${rel} uses 安全 outside a negation`);
    assert.doesNotMatch(src, /CLEAR|首創/, `me/${rel}`);
    assert.doesNotMatch(src, /\d+(\.\d+)?\s*%/, `me/${rel}: write numbers as N 次中 M 次, not percentages`);
  }
});

// web-security-wording-6: every measured count names its model. A count in the house format
// (「N 次…中 M 次」) must name the model on its own line, or in its section (heading to heading).
test("wording: measured counts in the docs name their model", () => {
  const MODELS = /arbiter-gpt/;
  const COUNT = /\d+\s*次[^|。\n]*?中\s*\d+\s*次/;
  const docs = ["README.md", "web/verify/README.md",
                ...fs.readdirSync(path.join(ME, "docs")).filter((f) => f.endsWith(".md")).map((f) => `docs/${f}`)];
  let counts = 0;
  for (const rel of docs) {
    const sections = fs.readFileSync(path.join(ME, rel), "utf8").split(/\n(?=#)/);
    for (const sec of sections) {
      if (MODELS.test(sec)) { counts += sec.split("\n").filter((l) => COUNT.test(l)).length; continue; }
      for (const line of sec.split("\n").filter((l) => COUNT.test(l))) {
        counts++;
        assert.match(line, MODELS, `me/${rel}: a measured count without its model: ${line.slice(0, 120)}`);
      }
    }
  }
  assert.ok(counts >= 2, `found ${counts} counts in the docs`); // the finals re-attacks, the strict re-proofs
});

test("zh-TW: 託管, not the mainland form, in every text file under me/", () => {
  const mainland = String.fromCharCode(0x6258, 0x7ba1); // built from code points so this file does not trip its own check
  const skip = new Set(["lib", "out", "cache", "node_modules", "broadcast"]);
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => {
    if (e.isDirectory()) return skip.has(e.name) ? [] : walk(path.join(d, e.name));
    return /\.(md|py|js|html|css|sh|json)$/.test(e.name) ? [path.join(d, e.name)] : [];
  });
  const files = walk(ME);
  assert.ok(files.length > 20, `walked ${files.length} files`);
  const bad = files.filter((f) => fs.readFileSync(f, "utf8").includes(mainland)).map((f) => path.relative(ME, f));
  assert.deepEqual(bad, []);
});

test("explorer links only on ME: the explorer and the Hub RPC are configured for me-testnet alone", () => {
  const net = (key) => APP.match(new RegExp(`(?:"${key}"|${key}): \\{([\\s\\S]*?)\\},\\n`))[1];
  assert.match(net("me-testnet"), /explorer: "https:\/\/www\.explorer-testnet\.me"/);
  assert.match(net("me-testnet"), /hubRpc: "https:\/\/beta-hub-26657\.explorer-testnet\.me"/);
  for (const key of ["anvil", "custom"]) {
    assert.match(net(key), /explorer: null/, key);
    assert.match(net(key), /hubRpc: null/, key);
  }
});

test("every element id the script looks up exists in the page", () => {
  const ids = new Set([...APP.matchAll(/\$\("([\w-]+)"\)/g)].map((m) => m[1]));
  for (const id of ids) assert.match(HTML, new RegExp(`id="${id}"`), `#${id}`);
});

// web-security-wording-2..4 (the browser check exercises the same rules end to end)
test("only the official deployment gets the deployment file's auditor list; ME self-checks name ME's own RPC", () => {
  const src = APP.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
  // S.dep (auditor list, public commits) is set in one place, from the trust level
  assert.deepEqual([...src.matchAll(/S\.dep\s*=(?!=)\s*([^;]+);/g)].map((m) => m[1].trim()), ["S.trust.official ? trusted : null"]);
  // a node named in the URL never gets the deployment file (unless the file names that node)
  assert.match(src, /const trusted = S\.rpcOfficial \? file : null;/);
  assert.match(src, /L\.sameRpc\(file\.rpc, S\.net\.rpc\)/);
  // cast receipt commands come from checkRpc(), which is ME's own RPC on chain 400
  assert.doesNotMatch(src, /selfCheckCommand\([^)]*S\.net\.rpc/);
  assert.match(src, /const checkRpc = \(\) => \(S\.chainId === NETWORKS\["me-testnet"\]\.chainId \? NETWORKS\["me-testnet"\]\.rpc : S\.net\.rpc\);/);
});
