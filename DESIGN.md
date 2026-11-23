# ARBITER Gate 設計系統（DESIGN.md）

一份規格，兩個介面：`me/web/verify/`（公開的鏈上紀錄驗證頁，GitHub Pages）與 `arbiter/arbiter/webui.py`（本機 ARBITER Gate 網頁）。兩邊共用同一組 token、同一套元件、同一組意義色，示範影片（`theme.ts`）也用同一組意義色。

視覺身分來自作者作品集：白底、粗體負字距標題、黑色主按鈕、細線卡片、night 深色、橘色 accent。資料密集元件的做法參考 VoltAgent/awesome-design-md 的 vercel 與 linear.app，只借做法、不借品牌：用細線環取代粗陰影；等寬字只用在技術層（雜湊、交易、指令、紀錄）；狀態用小號膠囊；深色模式靠表面階梯分層；焦點環只用一種顏色。

## 0. 先讀：不能動的東西

1. **字句不變**：既有的使用者可見句子、標籤全部保留（測試會比對用詞），CSS 產生的「展開／收合」也算。用詞規則照 `me/web/verify/test/page.test.js` 與 `arbiter/scripts/webui_probe.py`：zh-TW（託管）、不加肯定式宣稱字眼、可見文字不寫百分比。page.test.js 會掃描 `index.html`、`app.js`、`verify-lib.js` 的原始碼（含註解），三個檔案裡只要出現「數字＋%」就會失敗；`style.css` 不在掃描範圍。webui_probe.py 會先拿掉 `<style>`、`<script>` 再掃描，所以 CSS 字串裡寫百分比沒問題。
2. **驗證頁 CSP**：`default-src 'none'; style-src 'self'`。不能有行內 `style` 屬性或 `<style>`。`app.js` 的 `h()` 用 `setAttribute` 設屬性，所以 `h("div", { style: … })` 會被擋，一律改用 class。CSP 沒有 `font-src`，網頁字型會被擋（和第 3 節的決定一致）。favicon 是 `data:` URI（`img-src data:` 允許）。
3. **不加新的外部來源**：驗證頁唯一的外部檔案仍是 cdnjs 的 ethers（測試限定只能有一個）。不用 Google Fonts，不用 CDN 字型或圖示。
4. **webui_probe.py 會比對的標記**（照舊用單引號）：`<span class='tag…'>`、`class='banner…'`、`<ol class='mechain'>` 裡的 `<li class='…'><b>標題</b>`（class 值 `bad`／`info`／`ok` 和標題文字都會比對）、`class='hash'`。每一頁的 HTML 標籤都必須正確閉合。
5. **class 名稱不改**：app.js、webui.py 和頁內 JS 產生的 class（含 `tone-${tone}`、`check ${state}`、`lamp '+s`、`res '+code`）全部沿用；要新外觀就加新 class，不改舊名。webui 的行內樣式用到 `var(--line)` 和 `style='width:{w}%'`，所以 `--line` 這個 token 名稱必須保留。
6. **意義色固定**（2.3 節）：兩個介面、深淺兩種模式、示範影片全部一致。

## 1. 原則

- **證據先於裝飾**：判定、檢查結果、雜湊、交易是畫面上最清楚的東西。不用插圖、漸層背景、光暈、紋理、裝飾性動畫，也沒有整條的 night 色帶；night 只用在終端與 diff 區塊。
- **冷靜**：白底（深色模式用 night）、細線、少量陰影。品牌橘只拿來點出重點；紅色只留給「已證實可攻擊」和「不符」。
- **一個意思一個顏色，而且顏色從不單獨表意**：每個狀態都同時有文字和符號（✓ ✗ ! ? i … ○ –），色盲或灰階列印也看得懂。
- **狀態要誠實**：「稽核未完成」就要看得出未完成（灰色、虛線），不能做得像通過；「未發現可證明攻擊」是藍色，不是綠色。
- **好讀**：中文正文 16px、行高 1.7，段落寬度上限 `--measure`；雜湊用等寬字，可斷行、可複製。
- **手機一樣完整**：390px 寬不會出現橫向捲動，所有資料都看得到。

## 2. Token

### 2.1 中性色

| token | 淺色 | 深色（作品集 night） | 用途 |
|---|---|---|---|
| `--bg` | `#ffffff` | `#0e0e10` | 頁面底 |
| `--paper` | `#f5f4f2` | `#18181b` | 卡片底（第 1 層） |
| `--raised` | `#ffffff` | `#222226` | 卡片裡的列、步驟、輸入框（第 2 層） |
| `--paper-2` | `#eeece9` | `#2a2a2f` | 中性填色：中性膠囊、表頭、行內程式碼、hover |
| `--line` | `#e8e6e3` | `#2c2c31` | 細線、分隔線、卡片環 |
| `--line-2` | `#dad7d3` | `#3a3a40` | 次要按鈕框、步驟框 |
| `--line-strong` | `#85858d` | `#6e6e78` | 輸入框、拖放區的框（非文字對比 ≥ 3:1） |
| `--ink` | `#111113` | `#f4f4f5` | 正文、標題、主按鈕底 |
| `--ink-2` | `#45454c` | `#d4d4d8` | 次要正文、說明 |
| `--muted` | `#66666e` | `#a1a1aa` | 標籤、註解、meta |
| `--faint` | `#a4a4ab` | `#63636b` | 只做裝飾（箭頭、分隔符號），不放帶資訊的字 |
| `--on-ink` | `#ffffff` | `#0e0e10` | 主按鈕上的字 |
| `--focus` | `#111113` | `#f4f4f5` | 焦點環 |

`--muted` 比作品集的 `#74747c` 深一階，因為 `#74747c` 在 `--paper` 上只有約 4.2:1，小字達不到 AA。

### 2.2 品牌 accent

| token | 淺色 | 深色 | 用途 |
|---|---|---|---|
| `--accent` | `#ff5a1f` | `#ff5a1f` | 品牌標誌、眉標圓點、連結 hover 底線、拖放區 `.over`、「進行中」的環與脈動點、spinner |
| `--accent-ink` | `#c2410c` | `#ff8a5c` | 少數需要橘色文字的地方（白底 5.2:1） |
| `--accent-soft` | `#fff1ea` | `rgba(255,90,31,.14)` | 拖放區 `.over` 的底色 |

橘色與「已證實可攻擊」的紅色必須一眼就分得開：
- 橘色**不代表任何狀態或判定**：不做成膠囊、徽章、面板或整塊底色，也不出現在判定面板和檢查列裡。
- 白底小字不用 `#ff5a1f`（對白底只有 3.1:1）；需要橘色字時用 `--accent-ink`。
- 主按鈕照作品集用黑色，不用橘色。白字放在橘底上只有 3.1:1，而且橘色按鈕放在紅色判定旁邊容易混淆。
- 淺色模式的紅 `#c41c34` 是深胭脂紅，亮度大約只有橘色的一半；深色模式兩者亮度接近，所以在深色模式更要遵守上面的用法限制。

### 2.3 意義色（與示範影片一致）

深色值就是影片 `theme.ts` 的顏色；淺色值是同色相、在白底上達到 AA 的版本（沿用驗證頁現有的淺色值）。

| 意義 | token | 淺色 | 淺色 soft | 深色 | 深色 soft | 符號 |
|---|---|---|---|---|---|---|
| 已證實可攻擊（verdict 3，擋部署）、不符 ✗、拒絕部署 | `--red` | `#c41c34` | `#fdecee` | `#ff4d5e` | `rgba(255,77,94,.12)` | `!` `✗` |
| 未發現可證明攻擊（verdict 1） | `--blue` | `#1e5bd8` | `#e8f0fd` | `#4c8dff` | `rgba(76,141,255,.12)` | `i` |
| 只有靜態提示（verdict 2）、注意、錄好的紀錄 | `--amber` | `#8a5b00` | `#fff4db` | `#ffc24b` | `rgba(255,194,75,.12)` | `?` `!` |
| 稽核未完成（verdict 0）、略過、未驗證 | `--grey` | `#5f5f68` | `#efeff1` | `#a1a1aa` | `rgba(161,161,170,.12)` | `…` `–` |
| 修補 | `--purple` | `#5a48d8` | `#eeebfd` | `#8b7bff` | `rgba(139,123,255,.12)` | — |
| 部署、通過 ✓ | `--green` | `#0a7a4b` | `#e3f5ec` | `#2fd48a` | `rgba(47,212,138,.12)` | `✓` |

- soft token 的名稱是 `--red-soft`、`--blue-soft`……；實心意義色上的字和符號用 `--on-tone`（淺色 `#ffffff`、深色 `#0e0e10`）。
- 元件裡不直接寫意義色，而是透過 tone 範圍：`.tone-red { --tone: var(--red); --tone-soft: var(--red-soft); }`，元件只用 `var(--tone)` 和 `var(--tone-soft)`。
- 藍色只代表 verdict 1，一般連結、資訊框、「進行中」都不用藍色。紫色只代表修補，所以驗證頁的 `.check.plan` 改成灰色空心。綠色只代表部署和通過，所以「正在執行」改用 accent 脈動點。

### 2.4 可直接貼上的 token 區塊

```css
:root {
  color-scheme: light;
  --bg: #ffffff; --paper: #f5f4f2; --raised: #ffffff; --paper-2: #eeece9;
  --line: #e8e6e3; --line-2: #dad7d3; --line-strong: #85858d;
  --ink: #111113; --ink-2: #45454c; --muted: #66666e; --faint: #a4a4ab;
  --on-ink: #ffffff; --ink-hover: #2b2b30; --focus: #111113; --bar-bg: rgba(255,255,255,.86);
  --accent: #ff5a1f; --accent-ink: #c2410c; --accent-soft: #fff1ea;
  --red: #c41c34; --red-soft: #fdecee;         --blue: #1e5bd8; --blue-soft: #e8f0fd;
  --amber: #8a5b00; --amber-soft: #fff4db;     --grey: #5f5f68; --grey-soft: #efeff1;
  --purple: #5a48d8; --purple-soft: #eeebfd;   --green: #0a7a4b; --green-soft: #e3f5ec;
  --on-tone: #ffffff;
  /* night：終端、紀錄輸出、diff 區塊，兩種模式都用 */
  --night: #0e0e10; --night-2: #18181b; --night-line: #2c2c31; --on-night: #f4f4f5; --on-night-2: #a1a1aa;
  --diff-add: #2fd48a; --diff-del: #ff4d5e; --diff-hunk: #8b7bff;
  --shadow-1: 0 0 0 1px rgba(0,0,0,.06), 0 1px 2px rgba(0,0,0,.04);
  --shadow-2: 0 0 0 1px rgba(0,0,0,.06), 0 2px 5px -1px rgba(50,50,93,.25), 0 1px 3px -1px rgba(0,0,0,.3);
  --shadow-pop: 0 0 0 1px rgba(0,0,0,.08), 0 12px 32px -8px rgba(50,50,93,.3), 0 4px 8px -4px rgba(0,0,0,.2);
  --r-tile: 18px; --r-card: 14px; --r-btn: 10px; --r-sm: 8px; --r-xs: 6px; --r-pill: 999px;
  --s-1: 4px; --s-2: 8px; --s-3: 12px; --s-4: 16px; --s-5: 24px; --s-6: 32px; --s-7: 48px; --s-8: 64px;
  --wrap: 1200px; --measure: 44em; --pad: 24px;
  --font: "Geist", "Inter", "Noto Sans TC", "Noto Sans CJK TC", system-ui, -apple-system, "Segoe UI",
          "PingFang TC", "Microsoft JhengHei", "Heiti TC", sans-serif;
  --mono: "Geist Mono", ui-monospace, SFMono-Regular, "Cascadia Mono", Menlo, Consolas, "Liberation Mono",
          "Noto Sans Mono", "Noto Sans TC", "Noto Sans CJK TC", "PingFang TC", "Microsoft JhengHei", monospace;
  --fs-display: clamp(2rem, 1.35rem + 2.2vw, 2.625rem); --fs-h1: clamp(1.625rem, 1.3rem + 1.2vw, 2rem);
  --fs-verdict: clamp(1.375rem, 1.15rem + 1vw, 1.75rem); --fs-h2: 1.25rem; --fs-h3: 1rem; --fs-lead: 1.125rem;
  --fs-body: 1rem; --fs-sm: .875rem; --fs-xs: .8125rem; --fs-eyebrow: .75rem; --fs-code: .8125rem;
  --ease-out: cubic-bezier(.25,.8,.25,1); --ease-move: cubic-bezier(.45,0,.1,1);
  --ease-spring: cubic-bezier(.2,.9,.3,1.15); --ease-reveal: cubic-bezier(.2,.8,.2,1);
  --t-fast: .2s; --t-move: .45s; --t-reveal: .8s;
}
@media (max-width: 640px) { :root { --pad: 16px; } }
/* 深色：webui 只需要第一段；驗證頁兩段都要（第二段給切換鈕用）。兩段內容相同。 */
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { /* 同下 */ } }
:root[data-theme="dark"] {
  color-scheme: dark;
  --bg: #0e0e10; --paper: #18181b; --raised: #222226; --paper-2: #2a2a2f;
  --line: #2c2c31; --line-2: #3a3a40; --line-strong: #6e6e78;
  --ink: #f4f4f5; --ink-2: #d4d4d8; --muted: #a1a1aa; --faint: #63636b;
  --on-ink: #0e0e10; --ink-hover: #ffffff; --focus: #f4f4f5; --bar-bg: rgba(14,14,16,.82);
  --accent-ink: #ff8a5c; --accent-soft: rgba(255,90,31,.14);
  --red: #ff4d5e; --red-soft: rgba(255,77,94,.12);         --blue: #4c8dff; --blue-soft: rgba(76,141,255,.12);
  --amber: #ffc24b; --amber-soft: rgba(255,194,75,.12);    --grey: #a1a1aa; --grey-soft: rgba(161,161,170,.12);
  --purple: #8b7bff; --purple-soft: rgba(139,123,255,.12); --green: #2fd48a; --green-soft: rgba(47,212,138,.12);
  --on-tone: #0e0e10;
  --shadow-1: 0 0 0 1px #2c2c31, inset 0 1px 0 rgba(255,255,255,.03);
  --shadow-2: 0 0 0 1px #3a3a40, 0 8px 24px -8px rgba(0,0,0,.6);
  --shadow-pop: 0 0 0 1px #3a3a40, 0 16px 40px -8px rgba(0,0,0,.7);
}
```

舊的變數名稱（`--surface`、`--bg2`、`--ai`、`--sys`、`--vio`、`--field`、`--card`、`--redbg`、`--hl`、`--code`……）全部換成新名稱，不保留別名。預設是淺色；驗證頁原本預設深色，改版後跟著系統設定，沒有設定時用淺色。

### 2.5 已經算過的對比

- `--ink` 對 `--bg`：淺色 18.9:1、深色 17.6:1。`--muted` 對 `--paper`：5.2:1／6.9:1；對 `--paper-2`：4.8:1／5.6:1。
- `--tone` 對 `--tone-soft`：淺色都 ≥ 4.7:1（綠色最低）；深色疊在 `--paper` 上都 ≥ 4.6:1。`--on-tone` 對實心 `--tone`：淺色 ≥ 5.3:1、深色 ≥ 5.8:1。
- `--accent-ink` 對白底 5.2:1。`--accent` 對白底只有 3.1:1，只能用在圖形，不能用在文字。
- `--line-strong` 對 `--paper`：3.3:1／3.5:1（輸入框邊界）。`--faint` 對白底 2.4:1，所以只做裝飾。
- night 區塊：`--on-night` 對 `--night-2` ≥ 16:1、`--on-night-2` 6.9:1，三個 diff 顏色都 ≥ 5.3:1。

## 3. 字體與字級

- **字型堆疊**（見 2.4）：拉丁字母先用 Geist 或 Inter（使用者有安裝時），沒有就用系統字型（Segoe UI、SF）。中文先用 Noto Sans TC，接著依平台用 PingFang TC（Apple）、Microsoft JhengHei（Windows）、Noto Sans CJK TC（Linux、Android）。等寬堆疊最後接中文黑體，避免紀錄裡的中文退回細明體這類襯線字。
- **決定：只用系統字型，不自帶字型檔。** 本機有 fontTools 4.57，但沒有 brotli（也沒有 brotlicffi），無法輸出 woff2；規則不允許下載，所以這一輪不做子集。因此驗證頁的 CSP 不用加 `font-src`，`web.py` 的 `STATIC_TYPES` 也不用加 `.woff2`。日後要做的話：來源只用 Remotion 專案裡的 `NotoSansTC-VF.ttf`（OFL），子集只收 `app.js`、`index.html`、`verify-lib.js` 出現過的字，目標小於 400 KB；CSP 要加 `font-src 'self'`，`STATIC_TYPES` 要加 `.woff2 → font/woff2`（否則本機 `/verify` 會回 404），授權檔要放在字型檔旁邊。

| token | 大小 | 行高 | 字重 | 字距 | 用在 |
|---|---|---|---|---|---|
| `--fs-display` | 32→42px | 1.2 | 700 | -0.02em | 首頁大標（驗證頁 hero、webui 首頁） |
| `--fs-h1` | 26→32px | 1.25 | 700 | -0.02em | 內頁標題（稽核結果、工作名稱、選合約） |
| `--fs-verdict` | 22→28px | 1.3 | 700 | -0.015em | 判定標題 |
| `--fs-h2` | 20px | 1.4 | 600 | -0.01em | 卡片標題 |
| `--fs-h3` | 16px | 1.5 | 600 | 0 | 卡片內小節 |
| `--fs-lead` | 18px | 1.7 | 400 | 0 | hero 導言、`h1 + .sub` |
| `--fs-body` | 16px | 1.7 | 400 | 0 | 正文 |
| `--fs-sm` | 14px | 1.6 | 400／600 | 0 | 次要文字、表格、按鈕（14px/600） |
| `--fs-xs` | 13px | 1.5 | 400／600 | 0 | 註解、meta、膠囊、步驟說明 |
| `--fs-eyebrow` | 12px | 1.4 | 600 | 0.06em | 眉標、步驟標籤、表頭（不轉大寫） |
| `--fs-code` | 13px | 1.6 | 400 | 0 | `pre`、紀錄輸出、diff；行內雜湊用 `.875em` |

- 字重只用 400、600、700（webui 的 `.rung .n`、`.vcard .icon` 從 800 改成 700）。h1、h2 可加 `text-wrap: balance`。
- 數字（區塊高度、紀錄編號、金額、秒數、表格數字欄）一律 `font-variant-numeric: tabular-nums`。
- 正文 `overflow-wrap: break-word`；雜湊和 `.mono` 用 `overflow-wrap: anywhere`。
- **連結**：顏色 `--ink`，1px 底線 `--line-strong`、`text-underline-offset: 3px`；hover 時底線變成 2px `--accent`。不用藍色（藍色是 verdict 1），也不用紅色或橘色字。

## 4. 間距、圓角、陰影、版面

- **間距**：以 4px 為單位（`--s-1` 4px … `--s-8` 64px）。行內元素間距 6–8px；元件內距 12–16px；卡片內距 24px（≤640 為 16px）；卡片之間 16px；區段之間 48px（≤640 為 32px）。
- **圓角**：`--r-tile` 18px（webui 首頁三張卡）、`--r-card` 14px（卡片、判定面板、拖放區）、`--r-btn` 10px（按鈕、輸入框、內嵌列、提示框）、`--r-sm` 8px（小按鈕、`pre`、泡泡、表格外框）、`--r-xs` 6px（行內程式碼）、`--r-pill`（膠囊）。
- **陰影**：卡片預設用 `--shadow-1`（細線環）；可點的列 hover 時用 `--shadow-2`；泡泡用 `--shadow-pop`。深色模式不加投影，只靠表面階梯（`--bg` → `--paper` → `--raised`）和細線分層。標示用的色線一律用 inset shadow（例如 `box-shadow: inset 3px 0 0 var(--tone)`），在圓角裡才會乾淨，也不會影響排版。
- **寬度**：`--wrap` 1200px，左右留白 `--pad`（24px，≤640 為 16px）。頁首、信任帶、main、頁尾用同一個內容寬度，讓左緣對齊。段落（`.lead`、`.sub`、`.verdict-desc`、`.mean`、卡片內的 `p`）寬度上限是 `--measure`（44em）。
- **斷點**：≤640（手機，用 390×844 測試）、641–1023（平板）、≥1024（桌機）。webui 原本的 760 改用這兩個斷點。
- **驗證頁 ≥1024**：`main` 用 grid `minmax(0,7fr) minmax(0,5fr)`、欄距 32px；`.hero` 放左欄，查詢卡（`[aria-labelledby="lookup-h"]`）放右欄，`#result` 和其後的卡片 `grid-column: 1 / -1`。只用 CSS，不改 HTML 順序。<1024 時單欄。
- **webui**：`.cards` 在 ≥1024 時 3 欄，以下 1 欄；`.cols` 在 ≥641 時 2 欄；`.sbs`、`.story` 只在 ≥1024 時並排。
- **390px 不可橫向捲動**：grid 和 flex 的子元素都設 `min-width: 0`；長雜湊可以斷行；表格放在 `.tbl` 裡、`pre` 只在自己的框內捲動；`.pill` 設最大寬度並用省略號；不用固定寬度大於 358px 的元素。

## 5. 元件

### 5.1 頁首 brand bar（驗證頁 `.top`；webui 新增）
- 高 60px（≤640 為 56px），`position: sticky; top: 0`，底色 `--bar-bg` 加 `backdrop-filter: saturate(1.4) blur(10px)`，下緣 1px `--line`。
- `.brand`：`.mark` 是 28px 方塊（`--r-sm`、`--accent` 底、白色杯形線條，沿用現有的 `::after`）；`b` 15px/700/-0.01em `--ink`；`small` 12px `--muted`（≤640 隱藏）。右側放 `.pill`（5.7）和 `.icon-btn`（5.3）。
- 信任帶 `.trust`：頁首下方整條，13px／行高 1.5。`.warn` 用 `--amber-soft` 底加上緣 1px `--amber`，`span` 用 600 `--amber`；`.bad` 照同樣方式改用紅色。
- webui：`page()` 在 `<main>` 前面加同一條頁首，只放品牌並連到 `/`，不加新的導覽文字。兩邊用同一個 favicon data URI（`--accent` 底、白色杯形）；驗證頁把現在的 `%238B7BFF` 換成 `%23ff5a1f`（CSP 雜湊只涵蓋行內 script，不受影響）。

### 5.2 Hero 與頁標題
- 驗證頁 `.hero`：上下內距 56px／24px（≤640 為 32px／16px）。`.eyebrow` 12px/600、字距 .06em、`--muted`，前面加 6px `--accent` 圓點（`::before`）。`h1` 用 `--fs-display`；`.lead` 用 `--fs-lead` `--ink-2`。
- webui 首頁的 `h1`（ARBITER Gate）用 `--fs-display`，其他頁的 `h1` 用 `--fs-h1`；緊接在後的 `.sub` 當導言，選擇器寫 `h1 + .sub`。`.sub` 也出現在 `.mechain .sub`，兩者要分開寫。
- 數字列（作品集的 stat row）只在有真實數字時使用：數字 28px/700 tabular，說明 12px `--muted`。

### 5.3 按鈕

| 變體 | 底 | 字 | 框 | hover | 用在 |
|---|---|---|---|---|---|
| primary（`.btn.primary`） | `--ink` | `--on-ink` | 1px `--ink` | 底 `--ink-hover` | 每個畫面最主要的一個動作（查詢、開始稽核） |
| secondary（`.btn`） | `--raised` | `--ink` | 1px `--line-2` | 底 `--paper-2` | 其他動作、示範合約、檔案選擇鈕 |
| ghost | 透明 | `--ink-2` | 無 | 底 `--paper-2`、字 `--ink` | summary 的展開／收合、次要文字按鈕 |

- 尺寸：高 40px、左右內距 16px、14px/600、圓角 `--r-btn`、`gap: 8px`；≤640 時主按鈕和表單按鈕高 44px。`.btn.small`：高 28px、左右內距 10px、13px/500、圓角 `--r-sm`；複製鈕加 `min-width: 4.5em` 並置中，文字從「複製」變成「已複製」時才不會跳動。`.icon-btn`：36×36，secondary 樣式。
- 狀態：`:active` 時下移 1px；`:focus-visible` 用焦點環（7.2）；`:disabled` 透明度 .5、`cursor: not-allowed`，沒有 hover 效果。同一個畫面不要並排兩個 primary。
- webui `.btn.demo`：整列寬的 secondary，文字靠左、最小高度 44px，保留 `title` 提示。

### 5.4 輸入框與拖放區
- 文字、網址、select：高 40px（≤640 為 44px）、左右內距 12px、字 16px（避免 iOS 自動放大）、底 `--raised`、框 1px `--line-strong`、圓角 `--r-btn`。hover 時框變 `--ink-2`；focus 時框變 `--ink` 並加焦點環；`aria-invalid="true"` 時框變 `--red`，錯誤訊息放在 `.warnline`。placeholder 用 `--muted`；disabled 時底 `--paper-2`、字 `--muted`。
- `label` 14px/600 `--ink`、下距 6px；`.hint` 13px `--muted`；`.warnline` 13px `--amber`（沿用 `:empty` 時隱藏）。`.row` 讓輸入框和按鈕同列、間距 8px；≤640 時改成直排，按鈕占整列。`.netform` 在 ≤640 時改成單欄。
- 拖放區 `.drop`：最小高度 96px、1.5px 虛線 `--line-strong`、圓角 `--r-card`、底 `--raised`、14px `--muted` 置中。hover 時框變 `--ink-2`、字變 `--ink`。`.over`（拖曳中）框變 `--accent`、底變 `--accent-soft`、字變 `--ink`，這是橘色唯一可以成片出現的地方。拖放區要能用鍵盤操作（可以聚焦，按 Enter 或空白鍵會開檔案選擇）。
- webui `input[type=file]`：14px，`::file-selector-button` 套 secondary 按鈕樣式（右距 12px）。外層可以選擇性套用 `.drop` 的外觀；上傳表單的欄位名稱和按鈕文字不變。

### 5.5 卡片與內嵌列
- `.card`：底 `--paper`、`--shadow-1`、圓角 `--r-card`、內距 24px（≤640 為 16px）。`h2` 用 `--fs-h2`、下距 12px；`h3` 用 `--fs-h3`，上方加 1px `--line` 分隔線、上距 24px、上內距 16px。
- `.cards .card`（webui 首頁三張卡）：用 `--r-tile`；整張卡不能點，所以 hover 時不浮起。
- 內嵌列（卡片裡的一筆資料）：底 `--raised`、1px `--line` 框、圓角 `--r-btn`、內距 12px 14px。驗證頁的 `.recitem`、`.evitem`、`.dep`、`.step`；webui 的 `.mechain li`、`.tl details`、`.rung`、`.story .box`。
- 可點的內嵌列（`.recitem`、`.btn.demo`、`.pick`）：hover 時框變 `--line-2` 並加 `--shadow-2`。`.pick:has(input:checked)` 用 1.5px `--ink` 框、`--paper-2` 底。
- 折疊卡 `details > summary`：整列可點、間距 10px；保留 `::after` 的「展開／收合」文字，樣式改成 ghost 小字（13px `--ink-2`，hover 時加底線）。

### 5.6 判定（4 種）

| verdict | 意義 | tone | 符號 |
|---|---|---|---|
| 3 | 已證實可攻擊（擋部署） | red | `!` |
| 2 | 只有靜態提示，未證實 | amber | `?` |
| 1 | 未發現可證明攻擊（不等於安全） | blue | `i` |
| 0 | 稽核未完成，無法判定 | grey | `…` |

文字以 `verify-lib.js` 的 `label` 和 webui 的 `LABELS` 為準，不改。符號沿用 webui 的 `ICON`，兩個介面一致。
- **判定面板（大）**：底 `--tone-soft`、圓角 `--r-card`、內距 20px 24px（≤640 為 16px）、grid `44px 1fr`、欄距 16px。符號圓 44px（≤640 為 36px），實心 `--tone`，符號 `--on-tone` 22px/700。標題 `--fs-verdict`/700 `--tone`；說明 `--fs-body` `--ink`；下一步 `--fs-sm`/600 `--ink`。verdict 0 的面板外圍多一圈 1px 虛線 `--grey`，表示未完成。面板不加陰影、不做顏色動畫，也不放橘色。
- webui：`.vcard.v-proven/.v-hint/.v-none/.v-unrun` 就是判定面板（`.icon` 是符號圓，另有 `h2`、`.mean`、`.next`）。
- 驗證頁：`.record.tone-*` 卡片裡的 `.verdict`（標題列）加 `.verdict-desc`（soft 底的說明）。`.verdict .dot` 放大成 28px 符號圓，符號用 CSS 產生，不改 app.js 的文字，寫法是 `content: "!"; content: "!" / "";`（後一行讓螢幕報讀器跳過，不支援的瀏覽器會沿用前一行）。`.record` 原本的 4px 上緣改成 `box-shadow: inset 0 3px 0 var(--tone)`。
- **精簡判定**（用在列表和步驟裡）：tone 色文字，加左側 3px tone 色線（inset shadow），或改用 `.tag` 膠囊。用在驗證頁的 `.recitem .v`、`.step`，以及 webui 的執行紀錄表格。

### 5.7 膠囊（`.tag`）與狀態膠囊（`.pill`）
- `.tag`：高 22px、左右內距 8px、`--r-pill`、12px/600、不換行。有 tone 時底 `--tone-soft`、字 `--tone`；沒有 tone 時底 `--paper-2`、字 `--ink-2`。狀態用的膠囊前面可以加 6px `currentColor` 圓點。`.tag.lg`（webui）14px、高 26px、可以換行。`.tag.unv`（未驗證）：透明底、1px 虛線 `--amber` 框、字 `--amber`。
- 對應關係：驗證頁 `.tag.red/.amber/.blue/.mute/.sys` 依序是 red、amber、blue、grey、green；webui `.tag.bad/.warn/.ok` 依序是 red、amber、green，沒有修飾的 `.tag` 是中性樣式。
- `.pill`（頁首的網路狀態，就是作品集「● 接案中」那種）：高 28px、左右內距 10px、13px/500、`--r-pill`。預設底 `--raised`、1px `--line` 框、字 `--ink-2`、8px 圓點 `--faint`；`.ok/.warn/.bad` 的底分別換成 `--green-soft`、`--amber-soft`、`--red-soft`，圓點換成對應 tone，字維持 `--ink-2`。手機上照現在的做法：寬度上限約半個畫面，超出用省略號。

### 5.8 步驟：來源鏈、進度、攻防回合
共用的步驟卡：外觀同內嵌列，最小寬 160px、最大寬 240px（webui `.mechain li` 用 `flex: 1 1 160px`）；上緣 3px tone 色線用 `box-shadow: inset 0 3px 0 var(--tone)`，預設 tone 是 `--line-2`。內容：`.st` 眉標 12px/600 `--muted`、字距 .04em；標題 15px/600（有 tone 時用 `--tone`）；`.meta`／`.sub` 13px `--muted`，雜湊用 `--mono`。步驟之間用 `→`（16px `--faint`）連接；≤640 時改成直排，箭頭換成 `↓`。
- 狀態：`.current` 用 `--tone-soft` 底、1px `--tone` 框，並加 `aria-current="step"`（已有）。`.patch` 用紫色 tone 加虛線框；`.deploy` 用綠色 tone。`.ghost` 用虛線框、字 `--muted`，不要用整體透明度，否則對比會掉到 AA 以下。`.unv` 用灰色 tone、虛線框，加「未驗證」膠囊。驗證頁的 `.step .main` 是文字按鈕：沒有底色，hover 時加底線，要有焦點環。
- webui `.mechain li.bad/.warn/.info/.ok` 依序對應 red、amber、blue、green。有兩處要修正成正確的意義色：(a) verdict 0 現在是 `warn`（黃），應該是灰色：把 `ME_STEP_CLASS` 的 0 改成 `mute`，並新增 `.mechain li.mute`（probe 沒有比對 verdict 0，改完照樣要跑 probe）；(b)「修補」步驟現在輸出 `info`（藍），而且 probe 會比對這個值，所以 class 不改，改成在 `<b>` 裡包一層 `<span class='patch'>修補</span>`，CSS 用 `.mechain li:has(> b .patch)` 把它換成紫色（文字比對不受影響，改完要跑 probe）。
- webui 進度 `.steps .step`（7 格）：還沒到的步驟，底 `--paper-2`、字 `--muted`；`.done` 底 `--green-soft`、字 `--green`；`.skip` 透明底、1px 虛線 `--line-2`；`.now` 底 `--ink`、字 `--on-ink`，外圈加 `0 0 0 3px var(--accent-soft)`。注意：`.now` 同時是 `.step.now` 和獨立的「目前步驟」段落，現在的 CSS 會讓 `.step.now` 也變成 21px。新 CSS 要分開寫成 `.steps .step.now` 和 `.now:not(.step)`。
- webui 攻防回合 `.tl details`：`.att.proven` 用紅色；`.att.not_proven` 用藍色（這一輪沒有證實攻擊）；`.att.not_executed` 用灰色；`.def`（修補）一律用紫色 tone，summary 的字色 `.accepted` 用綠色、`.rejected` 用紅色。`details[open]` 展開時占整列。
- webui `.ladder .rung`：直排的步驟卡，1px 框；`.pass` 用綠色、`.fail` 用紅色，`.n` 20px/700 tone 色。`.story .box`：三格內嵌列加箭頭，≤1023 時改直排（箭頭轉 90°）。

### 5.9 檢查列（✓ ✗ 說明）
- 結構：grid `24px 1fr`、欄距 10px；符號圓 22px，底 `--tone-soft`，符號 13px/700 `--tone`；標題 15px/600 `--ink`（保留前面的 sr-only 狀態字）；說明 13–14px `--muted`。列與列之間間距 10px，不加分隔線。
- 狀態：`ok` 是綠色 ✓；`bad` 是紅色 ✗；`warn` 是琥珀色 !；`na` 是灰色 –；`wait` 是 …，外圈 2px `--accent` 環、慢速脈動；`plan` 是 ○，灰色空心虛線環（原本是紫色，但紫色只留給修補）。
- webui 燈號 `.lamp`（16px 圓）：`pass` 實心綠；`fail` 實心紅；`not_diverse` 實心琥珀；`skipped`、`not_reached` 實心 `--line-2`；`not_applicable`、`off` 空心虛線 `--line-strong`；`wait` 是 `--accent` 環加脈動。旁邊的 `.what` 已經用文字說明結果，所以燈號只放圓點也可以；要加符號的話用 `content: "✓" / ""`。`.light` 欄寬 `22px 150px 1fr`，≤640 時改成 `22px 1fr`。

### 5.10 雜湊列與複製
- 驗證頁 `hexValue()` 產生的 `.inline`：值用 `.mono`（`--mono`、`.875em`、`--ink`、`overflow-wrap: anywhere`），後面接複製鈕 `.btn.small`，有的話再接區塊瀏覽器連結；間距 `6px 8px`，可以換行。手機上值單獨占一行，按鈕和連結排到下一行。
- 欄位式雜湊（`.evitem .hashes div`、`.txref`）：grid `6.5em 1fr`，標籤 12px `--muted`，值 12.5–13px mono。`.evitem .name` 用 mono 14px/600；`.evitem.bad` 的框改成 `--red`。
- 複製後的回饋沿用「已複製」文字和 aria-live 播報，不另外變色。webui 的 `.hash` 是 13px mono、可以斷行；`.hash.short` 不斷行。webui 目前沒有複製鈕，不需要加。

### 5.11 鍵值與表格
- 鍵值 `.kv`（驗證頁）／`dl`（webui）：grid `11em minmax(0,1fr)`（webui 可以維持 `max-content`）、間距 10px 16px。`dt` 13px/500 `--muted`；`dd` 15px `--ink`、`min-width: 0`；`.desc` 13px `--muted`，另起一行顯示。≤640 時改成單欄，`dt` 上距 12px。`.dep .kv` 的第一欄寬 7em。
- 表格（webui）：14px。`th` 12px/600 `--muted`、字距 .04em、底 `--paper-2`、下緣 1px `--line`；`td` 內距 10px 12px、下緣 1px `--line`、靠上對齊；`td.num` 靠右並用 tabular 數字。外層 `.tbl` 設 `overflow-x: auto`、圓角 `--r-sm`、1px `--line` 環，表格只在自己的框內捲動。可點的格子（`.envt td.cell`）在 hover 和 focus 時底色變 `--paper-2`；`#envexplain` 用 info 提示框的外觀。

### 5.12 終端、執行紀錄與 diff
- `pre`（技術細節、原始輸出、diff）是 night 區塊，淺色模式也是深底：底 `--night-2`（深色模式改用 `--night` 加 1px `--night-line` 環）、字 `--on-night`、`--fs-code`／行高 1.6 mono、內距 14px 16px、圓角 `--r-sm`、`overflow-x: auto`。已經寫了 `white-space: pre-wrap` 的照舊。
- diff（webui `.add/.del/.hunk`）在 night 區塊裡固定使用 `--diff-add`（綠）、`--diff-del`（紅）、`--diff-hunk`（紫，代表修補）；整行底色用同一個顏色、透明度 .12。`.sbs`（修補前後並排）在 ≥1024 時兩欄、間距 12px；`.ln` 行號用 `--on-night-2`、`user-select: none`；`.chg`（改過的行）底色 `rgba(139,123,255,.18)`，左側加 2px `--diff-hunk`。
- 執行紀錄 `.log`／`.attempts`（webui 工作頁）不用 night，是一般列表：每列下緣 1px `--line`、上下內距 10px。`.res` 13px：`passed` 用綠色 600；`finding_accepted` 用紅色 600（代表系統接受了有實際執行成功的攻擊，也就是已證實可攻擊）；`refused`、`submission_rejected` 用琥珀色；其他用 `--muted`。
- 行內程式碼（`code`、驗證頁 `.selfcheck code`）：底 `--paper-2`、1px `--line` 框、圓角 `--r-xs`、內距 1px 6px、`.875em` mono，可以斷行。

### 5.13 提示框、橫幅、說明泡泡
- 提示框基本型：圓角 `--r-btn`、內距 12px 14px、14px／行高 1.6、左側 3px tone 色線（`box-shadow: inset 3px 0 0 var(--tone)`）、底 `--tone-soft`、內文 `--ink`；粗體字和標題用 `--tone`。info（中性）用 `--paper-2` 底、`--line-strong` 線，例如驗證頁的 `.banner`；warn 用琥珀色，例如驗證頁的 `.notice`、`.notice.claim`、`.trustcard`（`.srcline` 是只有琥珀色字的單行版）；danger 用紅色，例如 `.notice.red`、`.trustcard.bad`；ok 用綠色（備用）。
- `.trustcard` 是卡片加左側 4px tone 色線，`h2` 用 tone 色。
- webui 狀態橫幅 `.banner`：圓角 `--r-btn`、內距 10px 14px、15px/600，flex 排列，前面放 10px 的 `.dot`。`.live`（正在執行）：底 `--paper-2`、字 `--ink`，圓點用 `--accent` 並脈動。`.rec`（錄好的紀錄）：底 `--amber-soft`、字 `--amber`，圓點不動（影片也用琥珀色代表錄影）。
- `.note`（webui，用量很大）不是框，而是 14px `--muted` 的次要文字；裡面「技術細節」的 `details summary` 用 13px `--ink-2`。
- `.term`（名詞說明）：1px 點狀底線（`text-underline-offset: 3px`）、`cursor: help`。泡泡底 `--ink`、字 `--bg`、13px／行高 1.5、圓角 `--r-sm`、`--shadow-pop`、最大寬 `min(320px, 80vw)`，hover 和 `:focus-visible` 時都要顯示。現在的 `outline: none` 要拿掉，改用焦點環。
- `.loading`：16px 的圓環，底色 `--line`，轉動的那一段用 `--accent`，每圈 .9s；使用者要求減少動態時不轉。

### 5.14 頁尾
- 驗證頁 `.foot`：上緣 1px `--line`、上距 48px、內距 24px 0 40px、13px `--muted`（現在用的 `--faint` 不到 AA，要換掉），連結用 `--ink-2` 並加底線。webui 不需要加頁尾。

## 6. 動態

- token 照作品集原值：`--ease-out`、`--ease-move`、`--ease-spring`、`--ease-reveal`，`--t-fast` .2s、`--t-move` .45s、`--t-reveal` .8s。
- **載入時出現**：`.hero`、`.card`、`.vcard`、`.cards .card` 套用 `@keyframes rise { from { opacity: 0; transform: translateY(8px); } }`，寫成 `animation: rise var(--t-move) var(--ease-reveal) both`；hero 改用 `--t-reveal`。前 6 個元素依序延遲 60ms（用 `:nth-child`），之後的不延遲。判定面板不延遲、不位移，只用 `--t-fast` 淡入，讓證據最先出現。
- **捲動時出現（選用）**：JS 先在 `<html>` 加上 `reveal-on`，CSS 只在 `.reveal-on` 底下把第一個畫面以外的卡片設成透明；IntersectionObserver 偵測到卡片進入視窗時加上 `.is-in`，只觸發一次。沒有 JS 或 JS 出錯時，內容一律要看得到，不能預設隱藏。驗證頁寫在 app.js；webui 要做的話，寫成 `page()` 裡的一小段 script（本機頁沒有 CSP）。
- **互動**：顏色、底色、框、陰影的轉場用 `var(--t-fast) var(--ease-out)`；按鈕 `:active` 下移 1px；可點的列 hover 時只用陰影表現浮起；`.recitem .go` hover 時右移 2px（`--ease-spring`）。
- 持續播放的動畫只有三種：`.loading` 旋轉，以及 `.banner.live .dot` 和 `.lamp.wait`／`.check.wait` 的脈動（1.2s）。判定、紅色、警告永遠不閃爍、不脈動。
- `@media (prefers-reduced-motion: reduce)`：所有 animation 和 transition 的時間設成 .01ms、次數 1；捲動出現的內容直接顯示；spinner 改成靜止的圓環。截圖時至少等 1 秒，或模擬減少動態。

## 7. 無障礙

1. **對比 AA**：正文 ≥ 4.5:1、大字 ≥ 3:1、輸入框邊界和符號圓這類非文字元件 ≥ 3:1，深淺兩種模式都要達到（數值見 2.5）。`--faint` 和 `--accent` 不能拿來寫字。
2. **焦點**：`:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }`，按鈕、連結、summary、輸入框、拖放區、`.term`、`.step .main`、`.recitem` 全部一樣。不准用 `outline: none` 卻沒有替代樣式。輸入框聚焦時，框也要變成 `--ink`。
3. **點擊目標**至少 24×24px；手機上主要按鈕和輸入框高 44px；複製鈕高 28px，彼此間距至少 8px。
4. **狀態 = 文字＋符號＋顏色**。保留檢查列裡的 sr-only 狀態字，以及網路狀態、查詢結果、複製提示的 `role="status"`／`aria-live`。
5. 兩邊都用 `lang="zh-Hant"`。驗證頁的 `<meta name="color-scheme">` 改成 `light dark`（淺色優先）。
6. Windows 高對比模式（`forced-colors: active`）會拿掉 box-shadow，所以卡片、輸入框、按鈕、判定面板要保留真正的 1px `border`（平常可以設成 `transparent`）。

## 8. 對照表：既有 class → 元件

### 8.1 驗證頁（`style.css`、`index.html`、`app.js`）

| 既有 class／選擇器 | 元件（節） | 備註 |
|---|---|---|
| `.wrap` | 版面容器（4） | `max-width: var(--wrap)`、左右 `--pad` |
| `.skip`、`.sr-only`、`#sr-status` | 無障礙（7） | `.skip` 底 `--ink`、字 `--on-ink` |
| `.top`、`.top-in`、`.top-r` | 頁首（5.1） | sticky、`--bar-bg` |
| `.brand`、`.brand b`、`.brand small`、`.mark` | 品牌（5.1） | `.mark` 從漸層改成實心 `--accent` |
| `.pill`、`.pill.ok/.warn/.bad` | 狀態膠囊（5.7） | |
| `.icon-btn` | 圖示按鈕（5.3） | 切換深淺色，◐ 不變 |
| `.trust`、`.trust.warn/.bad`、`.trust-in` | 信任帶（5.1） | |
| `.hero`、`.eyebrow`、`h1`、`.lead` | Hero（5.2） | ≥1024 與查詢卡並排（4） |
| `.card`、`.card h2`、`.card h3`、`.explain` | 卡片（5.5） | `.explain li` 用 `--ink-2`，`b` 用 `--ink` |
| `details > summary`、`::after` | 折疊卡（5.5） | 「展開／收合」文字不改 |
| `label`、`input`、`select`、`.row`、`.netform`、`.full` | 輸入框（5.4） | |
| `.btn`、`.btn.primary`、`.btn.small`、`:disabled` | 按鈕（5.3） | `.small` 是複製鈕 |
| `.hint`、`.warnline`、`.srcline` | 欄位說明、單行警告（5.4、5.13） | |
| `.drop`、`.drop.over` | 拖放區（5.4） | `.over` 用 accent |
| `.kv`、`dt`、`dd`、`.desc` | 鍵值（5.11） | |
| `.inline`、`.mono`、`.txref`、`.selfcheck`、`.selfcheck code` | 雜湊列、行內程式碼（5.10、5.12） | |
| `.tag.sys/.amber/.red/.blue/.mute/.unv` | 膠囊（5.7） | sys 是綠、mute 是灰、unv 是虛線琥珀 |
| `.tone-red/.tone-amber/.tone-blue/.tone-mute` | tone 範圍（2.3） | `mute` 對應 `--grey` |
| `.record`、`.verdict`、`.verdict .dot`、`.verdict-desc` | 判定面板（5.6） | 符號用 CSS `content` |
| `.actions` | 按鈕列 | flex、間距 8px、可換行 |
| `.banner` | info 提示框（5.13） | |
| `.notice`、`.notice.red`、`.notice.claim`、`div.notice p` | warn／danger 提示框（5.13） | |
| `.trustcard`、`.trustcard.bad` | 提示卡（5.13） | |
| `.checks`、`.check.ok/.bad/.warn/.na/.wait/.plan`、`.ic` | 檢查列（5.9） | `.plan` 改灰色空心 |
| `.timeline`、`.step.current/.patch/.deploy/.ghost/.unv`、`.st`、`.main`、`.meta` | 來源鏈步驟（5.8） | |
| `.reclist`、`.recitem`、`.id`、`.v`、`.sub`、`.go` | 可點內嵌列、精簡判定（5.5、5.6） | `.id` 用 tabular 數字 |
| `.evlist`、`.evitem`、`.evitem.bad`、`.head`、`.name`、`.hashes`、`.evfiles` | 證據檔列（5.10） | |
| `.deplist`、`.dep` | 內嵌列加鍵值（5.5、5.11） | |
| `.loading` | 載入中（5.13） | |
| `.foot` | 頁尾（5.14） | 字改用 `--muted` |
| `.mt`、`.mute`、`.small`、`.pending` | 工具 class | `.mute` 用 `--muted` |

### 8.2 webui（`webui.py` 的 `CSS` 字串、`render_*`、頁內 JS）

| 既有 class／選擇器 | 元件（節） | 備註 |
|---|---|---|
| `main` | 版面容器（4） | `--wrap` |
| 新增 `header.top`、`.brand`、`.mark` | 頁首（5.1） | 在 `page()` 加，品牌連到 `/` |
| `h1`、`h1 + .sub` | Hero、頁標題（5.2） | 首頁用 `--fs-display`，其他頁用 `--fs-h1` |
| `h2`、`h3`、`.card>h2:first-child` | 字級（3） | |
| `.card`、`.cards`、`.cards .card`、`.cards h2`、`.big`、`.cols` | 卡片、卡片格（5.5、4） | `.big` 用 `--fs-lead` |
| `.btn`、`.btn.primary`、`.btn.small`、`.btn.demo`、`form.inline` | 按鈕（5.3） | |
| `input[type=file]` | 檔案輸入（5.4） | |
| `.pick` | 可選擇的內嵌列（5.5） | 用 `:has(input:checked)` |
| `table`、`th`、`td`、`td.num`、`.tbl` | 表格（5.11） | |
| `.envt`、`td.cell`、`#envexplain` | 互動表格、info 框（5.11、5.13） | |
| `dl`、`dt`、`dd` | 鍵值（5.11） | |
| `.note` | 次要文字（5.13） | |
| `.term` | 名詞說明泡泡（5.13） | 拿掉 `outline: none` |
| `.tag`、`.tag.ok/.warn/.bad/.lg` | 膠囊（5.7） | probe 會比對 `<span class='tag…'>` |
| `.hash`、`.hash.short` | 雜湊（5.10） | probe 會比對 `class='hash'` |
| `.vcard`、`.v-proven/.v-hint/.v-none/.v-unrun`、`.icon`、`.mean`、`.next` | 判定面板（5.6） | 符號字重 700 |
| `.banner.live/.rec`、`.dot` | 狀態橫幅（5.13） | probe 會比對 `class='banner…'` |
| `.steps`、`.step.done/.skip/.now` | 進度步驟（5.8） | `.now` 的衝突要拆開 |
| `.now`（段落） | 目前步驟標題 | `--fs-h2`、700 |
| `.log`、`.res.*`、`.attempts` | 執行紀錄（5.12） | `finding_accepted` 改成紅色 |
| `.lights`、`.light`、`.lamp.*`、`.what` | 檢查列（燈號）（5.9） | |
| `.mechain`、`li.ok/.bad/.warn/.info`、`.sub` | 來源鏈步驟（5.8） | probe 會比對；新增 `li.mute`；修補改用 span |
| `.tl`、`.att.*`、`.def.*`、`.r`、`.arrow` | 攻防回合（5.8） | `.r` 用 12px `--muted` |
| `.ladder`、`.rung.pass/.fail`、`.n` | 證據階梯（5.8） | |
| `.story`、`.box`、`.arrow` | 流程三格（5.8） | ≤1023 時直排 |
| `.bars`、`.bar`、`.track`、`.fill.a/.b/.g` | 長條圖 | 軌道 `--paper-2`；a 用 `--muted`、b 用 `--red`、g 用 `--ink`（舊的橘色 `#e07a5f` 拿掉） |
| `pre`、`.add`、`.del`、`.hunk` | night 區塊、diff（5.12） | |
| `.sbs`、`.ln`、`.chg` | 並排 diff（5.12） | `.chg` 用紫色 |
| `details`、`summary` | 折疊（5.5） | 技術細節 |
| `a`、`code` | 連結、行內程式碼（3、5.12） | |

## 9. 實作順序與驗收

1. 兩邊都先把 2.4 的 token 區塊貼在樣式最前面，刪掉舊變數，選擇器全部改用新 token；接著依 tone 範圍（2.3）把各狀態 class 掛上 `--tone`／`--tone-soft`。
2. 照第 8 節一個元件一個元件換樣式。markup 只在下列地方改：webui 的頁首、mechain 修補步驟的 span、`ME_STEP_CLASS` 的 0；驗證頁的 favicon 和 `color-scheme`。其他都只改 CSS。
3. 驗收：
   - 在 repo 根目錄執行 `node --test me/web/verify/test/*.test.js`，在 `arbiter/` 底下執行 `python3 scripts/webui_probe.py`，全部都要通過。
   - 截圖：驗證頁的首頁和紀錄頁（verdict 3 與 1 各一張），webui 的首頁、工作頁、結果頁（verdict 3）、鏈上頁；每一頁都要拍淺色和深色，各拍 1200px 和 390px 寬。
   - 390px 寬時 `document.documentElement.scrollWidth <= innerWidth`。
   - 驗證頁原始碼沒有新增 `style=`、`<style>` 或外部網址；webui 沒有新增外部網址。
   - 抽查：紅色判定旁邊沒有橘色元素；verdict 0 是灰色，修補是紫色，部署和通過是綠色，「未發現可證明攻擊」是藍色。
