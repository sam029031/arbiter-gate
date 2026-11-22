// Static checks of the page files (no browser):  node --test me/web/verify/test/
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
