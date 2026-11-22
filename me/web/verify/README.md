# ARBITER Gate 紀錄驗證頁（me/web/verify）

任何人用瀏覽器打開就能查 ME 鏈上的 ARBITER Gate 稽核紀錄：不用安裝、不用錢包、只讀不寫。
純靜態檔案，沒有建置步驟：`index.html`、`app.js`（畫面）、`verify-lib.js`（純函式）、`style.css`。
唯一的外部檔案是 cdnjs 上的 ethers 6.13.5（以 SRI 鎖定），只用來算 keccak256；載入失敗時頁面照常運作，只略過「部署後程式碼比對」（AuditRegistry 自己的 `isLinkCurrent` 仍會顯示）。
頁面讀的是 AuditRegistry／AuditEscrow **v2**（`me/contracts/src/`）。

## 放在哪裡都能用

- GitHub Pages／任何靜態主機：直接開 `…/me/web/verify/`。
- 本機網頁介面：以 `/verify/` 提供這個資料夾（`/verify` 會自動補成 `/verify/`），並提供 `/me/deployments/<network>.json`。
- 部署紀錄檔依序找 `../../deployments/<network>.json`（相對於頁面）→ `/me/deployments/<network>.json`，只讀和頁面同一個網站上的檔案。
  `<network>` 是 `me-testnet` 或 `anvil`；自訂 RPC 依它回報的 chainId（400、31337）對應。

## 官方部署，和網址參數指定的東西

頁面只替一件事背書，稱為**官方部署**，三個條件都要成立：

1. **節點是那個網路自己的**：頁面內建的 RPC（ME 測試網是 `https://beta-hub-8545.explorer-testnet.me`），或部署紀錄檔 `rpc` 欄位寫的那一個。
2. **AuditRegistry 是部署紀錄檔裡的那一個**（`?registry=` 寫的若就是它，也算）。
3. **鏈上程式碼雜湊相符**：`eth_getCode` 讀到的程式碼算 keccak256（ethers），等於部署紀錄檔的 `registry.codehash`。

只有官方部署才用部署紀錄檔的稽核者清單（「✓」）和公開版本清單（commit 連結）。其他情況：

| 情況 | 頁面怎麼做 |
|---|---|
| `?rpc=` 指定的節點不是上面第 1 條的節點 | 不套用部署紀錄檔（也不用它的 AuditRegistry 地址，要用 `?registry=` 自己指定），網路名稱寫「自訂 RPC（chainId N）」；頁首和每個畫面都標「非官方來源」，判定和部署標「未驗證」。chainId 400 時，`cast receipt` 自我驗證指令一律指向 ME 官方 RPC，不指向連結裡的節點。 |
| `?registry=` 指定另一個合約，程式碼雜湊和官方 AuditRegistry 相同 | 確實是 AuditRegistry（AuditRegistry 沒有 immutable，所有真的部署雜湊都一樣），照常顯示，但標「非官方部署」、不給「✓」：任何人都能自己部署一份。 |
| 程式碼雜湊不同 | 不是 AuditRegistry，可能是仿冒的合約：頁面完全不讀它的資料，只顯示兩個雜湊和「改用官方設定查看」。 |
| 無法比對（ethers 沒載入、沒有部署紀錄檔或沒有 `codehash`） | 不能當成官方部署：標「非官方來源」，判定和部署標「未驗證」。 |
| `?escrow=` | 官方部署只讀部署紀錄檔裡的 AuditEscrow，網址指定的其他地址列在「網址參數有問題，已忽略」。和 `?registry=` 一起用時才讀：先確認 `registry()` 是那個 AuditRegistry；它若是經過驗證的 AuditRegistry，AuditEscrow 的程式碼也要相符（唯一的 immutable 是 registry，把它換回官方地址後，雜湊要等於部署紀錄檔的 `escrow.codehash`），不符就忽略；來源本身沒驗證時照讀，標「未驗證」。 |

每個非官方畫面都有「改用官方設定查看」：同一個查詢，拿掉 `rpc`、`registry`、`escrow`。

## 網址參數

| 參數 | 用途 |
|---|---|
| `net=me-testnet\|anvil\|custom` | 網路（預設 ME 測試網，chainId 400） |
| `rpc=https://…` | 自訂 RPC（隱含 `net=custom`；不是官方節點時標「非官方來源」） |
| `registry=0x…`、`escrow=0x…` | 指定合約地址（見上一節：不是官方部署時一律標出來） |
| `record=ID`、`address=0x…`（或 me1…）、`tx=0x…`、`source=0x<sha256>` | 直接打開查詢結果 |
| `theme=dark\|light` | 指定配色（預設跟系統） |

## 查到什麼

- **地址**：先問 `deploymentOf`（AuditRegistry 依稽核過的 bytecode 部署的地址，閘門部署）→ 有就打開那筆紀錄；
  沒有再問 `claimsOf`，列出宣告這個地址的紀錄，標成「稽核者自行宣告（未經閘門部署，只能比對程式碼雜湊）」，並比對宣告時和現在的程式碼雜湊；
  都沒有才用程式碼雜湊（`recordsByCodehash`）給線索。
- **紀錄**：`deploymentsOf` 列出每一個閘門部署的地址，各自附部署交易，並把地址上現在的程式碼和它自己的 `Linked` 事件記下的雜湊比對；
  稽核者自行宣告的地址另列；`isLinkCurrent` 顯示合約自己的比對結果。
  `recordsByInitcode` 若有同一份 bytecode 的其他「已證實可攻擊」紀錄，會標出紀錄編號和稽核者（同一位稽核者時，AuditRegistry 不會經由閘門部署）。
  `latestRecord(稽核者, 原始碼)` 比這筆新時，提示有較新的紀錄。
- **原始碼 sha256**：用 `recordsBySourceCount/Page` 讀（別人灌入大量紀錄也讀得動），並先列出部署紀錄檔裡的稽核者各自的最新紀錄（`latestRecord`）。
- **付費託管**：結算這筆紀錄的申請、可結算的紀錄（`minRecordId` 以後）、結算截止（期限加 1 小時）和結算交易。

## 交易與區塊瀏覽器

ME 的區塊瀏覽器以 Cosmos 交易雜湊索引，不認 0x 雜湊。每筆交易都顯示 0x 雜湊（可複製），
再向 ME Hub 的 CometBFT RPC（`https://beta-hub-26657.explorer-testnet.me/tx_search?query="ethereum_tx.ethereumTxHash='0x<小寫雜湊>'"`，CORS `*`）
查出對應的 Cosmos 交易，連到 `https://www.explorer-testnet.me/zh-TW/transactions/<COSMOS_HASH>?netType=hub`（另附區塊連結）。
查不到時改給自己驗證的指令：`cast receipt <0x雜湊> --rpc-url https://beta-hub-8545.explorer-testnet.me`。
地址連到 `https://www.explorer-testnet.me/zh-TW/accountDetails/<me1…>`。本機 anvil 和自訂 RPC（chainId 不是 400）沒有瀏覽器連結。
回報 chainId 400 的自訂 RPC 也有瀏覽器連結：連結是向 ME 自己的 Hub 查出來的，只會連到 ME 上真的交易；
但那個節點說的「這筆交易屬於這筆紀錄」沒有經過驗證，所以畫面標「非官方來源」。

紀錄的登錄、部署與結算交易用 `eth_getLogs` 找。ME 的節點一次最多查 10,000 個區塊；整段查詢被拒時，
頁面依紀錄的區塊時間找出它所在的區塊，從那裡一段一段往後查（最多 8 段）。

## 部署紀錄檔的選用欄位

頁面用 `me/arbiter_me/contracts.py` 寫的 `me/deployments/<network>.json` 裡的 `chainId`、`rpc`、`registry`／`escrow` 的
`address`、`codehash`、`block`；另外讀兩個選用欄位：

```json
{"auditors": [{"address": "0x…", "name": "顯示名稱"}],
 "publicToolCommits": ["<40 位 commit sha>"]}
```

- `auditors`：只在官方部署上使用。列出的稽核者地址在紀錄上顯示「✓ 名稱」；沒列出的顯示「不在部署紀錄的稽核者清單」。
- `publicToolCommits`：紀錄的 toolCommit 在這個清單裡，才連到 `github.com/sam029031/arbiter-gate/commit/<sha>`；否則只顯示文字。

## 證據包（evidenceURI）

evidenceURI 是空的或一個 https 資料夾（合約 v2 只接受這兩種），也可以直接指向其中的 `manifest.json`。
頁面下載清單裡的每個檔案、算 sha256，和鏈上的雜湊比對。`me/arbiter_me/record.py` 寫的格式：

```json
{"schema": "arbiter-me-evidence/0.1",
 "files": [{"name": "compiler.json", "role": "compiler", "sha256": "0x…"},
           {"name": "exploit/Drain.t.sol", "role": "exploit", "sha256": "0x…"},
           {"name": "gate.json", "role": "gate_json", "sha256": "0x…"},
           {"name": "parent_src/Vault.sol", "role": "parent_source", "sha256": "0x…"},
           {"name": "patch.diff", "role": "patch", "sha256": "0x…"},
           {"name": "regression.zip", "role": "regression", "sha256": "0x…"},
           {"name": "src/Vault.sol", "role": "source", "sha256": "0x…"}]}
```

- 也接受最早的格式：`"schema": "arbiter-evidence/0.1"`、`"role": "gateJson"`。其他 schema 會顯示警告，仍依檔名和雜湊比對。
- `role` 對應鏈上欄位：`source`→sourceHash、`gate_json`／`gateJson`→gateJsonHash、`exploit`→exploitHash、`patch`→patchHash。
  修補後的紀錄：`parent_source` 和上一版紀錄的 sourceHash 比對；這筆沒有 exploitHash 時，攻擊程式和上一版的比對。
  `regression`（regression.zip）、`compiler`（compiler.json）鏈上沒有自己的雜湊，只和 manifest 比對，列為「其他證據檔」。
  沒寫 `role` 時依檔名推斷（`gate.json`、`compiler.json`、`regression.zip`、`parent_src/…`、`*.diff`／`*.patch`、`exploit/…`、`*.t.sol` 或含 exploit／poc／attack、其他 `*.sol`）。
- `name` 只接受資料夾內的相對路徑；manifest 本身不在鏈上，判斷以鏈上雜湊為準。
- 主機必須允許跨網域讀取（`Access-Control-Allow-Origin: *`；GitHub Pages、raw.githubusercontent.com 都可以）。
  只自動讀 https；http 只接受 127.0.0.1／localhost。單檔上限 20 MB、最多 50 個檔案。

## 測試

```bash
# 純函式與頁面靜態檢查（不連網路）
node --test me/web/verify/test/*.test.js
# ABI 測試向量（由 Foundry cast 編碼）
python3 me/scripts/verify_page_fixture.py --vectors me/web/verify/test/vectors.json
# 端對端：anvil + 測試紀錄 + 本機 https 伺服器（自簽憑證）+ headless Chrome（DevTools protocol）
anvil --port 8741 &
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=127.0.0.1 \
    -addext subjectAltName=IP:127.0.0.1 -keyout /tmp/vp_key.pem -out /tmp/vp_cert.pem
python3 me/scripts/verify_page_fixture.py --rpc http://127.0.0.1:8741 --root /tmp/vp_root \
    --evidence-url https://127.0.0.1:8751/evidence
python3 me/scripts/verify_page_fixture.py --serve 8751 --root /tmp/vp_root \
    --cert /tmp/vp_cert.pem --key /tmp/vp_key.pem &
node me/scripts/verify_page_browser_check.js --fixture /tmp/vp_root/fixture.json \
    --base https://127.0.0.1:8751/me/web/verify/ --cert /tmp/vp_cert.pem --out /tmp/vp_shots
```

瀏覽器檢查只信任那張自簽憑證的公鑰（SPKI 雜湊），並在 anvil 前面放一個像 ME 一樣限制 `eth_getLogs` 範圍的代理，
確認分段查詢找得到交易；另外兩個代理扮演連結可能指定的節點（自稱 chainId 400 的節點、同一條鏈的另一個網址），
配合 fixture 的仿冒合約（假 AuditRegistry、假 AuditEscrow、另一組真的 AuditRegistry／AuditEscrow、宣稱是 ME 測試網的部署紀錄檔），
確認這些都不會被顯示成官方部署。`--no-me` 略過 ME 測試網的唯讀檢查（未部署狀態、Hub 的 Cosmos 交易對應）。
