# ARBITER Gate × ME Network：AI 稽核結果的鏈上證據

> MetaEarth Hackathon 2026: BEACON 台灣站｜賽道 02「AI 與信任基礎設施」｜隊伍 nchumis

**AI 說合約「有漏洞」或「沒問題」，都只是一段文字。** ARBITER Gate 要求 AI 拿出能實際執行的攻擊程式，由系統用 AI 看不到也改不了的條件判定；這次我們把每一次稽核的判定、證據檔的指紋、模型與工具版本寫上 **ME Network**，把「先稽核、再部署」做成鏈上合約強制執行，並且讓任何人不用安裝就能從鏈上**追問**這個結論、自己重跑證據。

| | 位置 |
|---|---|
| 這次新增與改進（評審請看這裡） | [第 4 節](#4-11-月新增與改進評審請看這裡)；完整差異：[main...me-hackathon](https://github.com/sam029031/arbiter-gate/compare/main...me-hackathon)（公開 repo 的 `main` ＝ InnoServe 決賽版） |
| 線上驗證頁（不用錢包、不用安裝） | https://sam029031.github.io/arbiter-gate/me/web/verify/ （原始碼 `me/web/verify/`） |
| ME 測試網上的合約與交易 | [`me/EVIDENCE.md`](EVIDENCE.md)（每筆交易註明對應的功能） |
| 指令與工具細節 | [`me/docs/TOOLS.md`](docs/TOOLS.md) |
| 原有基礎（InnoServe 2026 決賽版） | `innoserve/README.md`；公開 repo 的 `main` 分支 |

---

## 1. 目標使用者與待解問題

- **要把合約部署到 ME Network 的開發團隊**：部署前想知道合約會不會被打穿，而且希望留下別人查得到、重跑得出來的證據，而不是一張「已稽核」的圖章。
- **使用合約的人與合作方**：想知道「這個位址上的程式碼有沒有被稽核過、結果是什麼、證據在哪」，不必相信任何人的一句話。

AI 稽核工具越來越多，但結論只是一段文字：用哪個模型、哪一版程式、根據什麼證據，部署後就查不到，也無法重跑。說「有漏洞」的可能是誤報，說「沒問題」的也可能只是沒找到。

## 2. 核心功能與 ME 使用方式

| 功能 | 在 ME 上怎麼用 | 程式 |
|---|---|---|
| **稽核紀錄上鏈** | 每次稽核的四級判定、gate.json／原始碼／攻擊程式／修補檔的 sha256、建立程式碼（initcode）的 keccak256、模型名稱、工具 commit、證據網址，登記到 ME 測試網 EVM 上的 `AuditRegistry`。紀錄只能新增，不能修改或刪除。**合約裡沒有「安全」欄位**：最好的結果只寫「未發現可證明的攻擊」。 | `contracts/src/AuditRegistry.sol` |
| **鏈上部署閘門** | `deployAudited` 只會用 CREATE2 部署**和稽核時完全相同的 bytecode**；判定 3（已證實可攻擊）、判定 0（稽核沒完成），以及同一稽核者已判定為可攻擊的 bytecode，一律拒絕。部署位址綁定「紀錄＋呼叫者＋salt」，別人搶不走、也不能把自己的紀錄掛上去。位址與紀錄由合約自己連結。 | 同上 |
| **來歷鏈** | 修補後的版本登記時指向「被證實可攻擊的原版」（`parentId`）並附修補檔雜湊，形成「已證實可攻擊的紀錄 → 修補 → 修補版的紀錄 → 部署」的鏈。 | 同上 |
| **任何人都能追問** | 純靜態驗證頁透過 ME 的 HTTPS RPC 直接讀鏈：貼上合約位址就看到來歷鏈、部署是否由閘門完成、程式碼雜湊是否還一致；證據檔自動下載並重算 sha256 比對。命令列 `me.py verify --replay` 會在你自己的電腦重跑攻擊：原版被打穿、修補版擋住。 | `web/verify/`、`arbiter_me/verify.py` |
| **MEC 結算** | `AuditEscrow`：委託人用 MEC 付稽核費，費用先鎖在合約裡；稽核完成（任何結論）才撥給指定的稽核者，稽核沒完成就退費，逾期可取回。**收費不看結論**，稽核者說「沒問題」也不會多拿錢。 | `contracts/src/AuditEscrow.sol` |
| **ME 相容性預檢** | 我們發現 ME 測試網拒絕 PUSH0（節點底層是 go-ethereum 1.10.26，雖然 chain_config 寫著 shanghai／cancun）。部署前先讓 ME 節點模擬部署，失敗時直接告訴開發者改用 `paris` 編譯。 | `arbiter_me/deploy.py preflight` |

ME 測試網連線資訊：EVM JSON-RPC `https://beta-hub-8545.explorer-testnet.me`（chainId 400，CORS 開放），區塊瀏覽器 `https://www.explorer-testnet.me`（以 Cosmos 交易雜湊索引；工具會自動換算）。MEC 在 EVM 上是 18 位小數，每筆交易約收 1 umec。

## 3. 架構

```
 開發者的合約 ──▶ ARBITER Gate（本機／GitHub Action）
                   │  AI（arbiter-gpt）寫攻擊程式 → 系統在離線沙箱裡用嚴格條件判定
                   │  證實 → 擋下＋附上通過 7 道檢查的修補（含「換手法再攻擊」）
                   ▼
              gate.json ＋ 證據資料夾（原始碼、攻擊程式、修補、回歸測試、manifest.json）
                   │  me.py deploy（簽章：你自己的 Foundry keystore，密碼自己輸入）
                   ▼
 ME Network 測試網（EVM, chainId 400）
   AuditRegistry ── register(紀錄) ── deployAudited(紀錄, bytecode, salt) ──▶ 部署出的合約
        ▲  │                                 （判定 3／0 → 合約直接拒絕）
        │  └── parentId：修補版 → 原版
   AuditEscrow ── request(MEC 費用) ── settle(紀錄) ──▶ 稽核者／退給委託人
        ▲
        └──── 驗證頁（瀏覽器直接讀鏈）／ me.py verify --evidence --rebuild --replay
```

## 4. 11 月新增與改進（評審請看這裡）

原有基礎是 InnoServe 2026 決賽版，也就是公開 repo 的 `main` 分支（`eb3af18`）。這次新增與改進全部在分支 `me-hackathon` 上，完整範圍是 `git diff main..me-hackathon`，也可以直接看比較頁 [main...me-hackathon](https://github.com/sam029031/arbiter-gate/compare/main...me-hackathon)（不含內附的 forge-std，約 26,700 行新增）。

### 4.1 新增：ME Network 鏈上層（`me/`）

- `AuditRegistry`、`AuditEscrow` 兩個合約，45 個 Foundry 測試（含 fuzz、重入、CREATE2 碰撞、搶先部署、搶占連結）。兩個合約都經過四個角度的對抗式審查，每個問題都先寫成會失敗的測試再修（v2）。
- `arbiter_me/`：從 gate.json 產生紀錄與可重現的證據資料夾、登記、經由閘門部署、驗證（`--evidence`、`--rebuild`、`--replay`）、託管、0x ↔ me1 位址換算、ME 區塊瀏覽器的 Cosmos 雜湊換算；只用 Python 標準函式庫＋Foundry。
- `web/verify/`：靜態驗證頁（桌機與手機），讀 ME 測試網或本機 anvil。
- 網頁結果頁新增「鏈上紀錄」卡片（判定 → 鏈上拒絕部署 → 修補 → 部署的時間軸）；本機網頁可直接開 `/verify`。
- `scripts/me_live_demo.sh`：一行指令在 ME 測試網完成整個示範，並寫出 `EVIDENCE.md`；`scripts/me_registry_probe.py`：在本機鏈上把同樣流程跑一遍的端到端檢查（79 項，含實鏈示範的排練）。
- 我們用 ARBITER Gate 稽核了自己的兩個合約（見 `EVIDENCE.md`）。

### 4.2 改進：修正 InnoServe 決賽時沒做好的地方

| 問題（決賽或這次審查時發現） | 改了什麼 | 檢查 |
|---|---|---|
| 「換手法再攻擊」只是在提示裡要求 AI 換，系統沒檢查；決賽（arbiter-gpt）5 次再攻擊中 3 次其實是同一招 | 系統用 forge 執行軌跡比對攻擊路徑（進入點、重入、回呼…）；同一招不算換手法（`not_diverse`），還會帶著修補內容與上一招的指紋再要求一次 | `technique_probe` 12/12 |
| AI 常用寬鬆條件（攻擊者獲利）證實，沒有損失表、修補與回歸測試 | 寬鬆條件證實後，自動要求 AI 改用嚴格條件（受害者損失＋守恆）再證明一次；成功就用嚴格的那一份做損失表與修補 | `strict_retry_probe` 13/13 |
| 工具說明只列舊的寬鬆條件、不檢查 AI 用了哪個條件、缺條件時默默當成寬鬆條件 | 說明、可用清單與實際檢查改成同一份清單，嚴格條件排第一；清單外或缺漏一律拒絕 | `predicate_surface_probe` 16/16 |
| **判定漏洞（這次發現）**：EOA 模式下，設定程式可以直接使用框架內部的受害者／攻擊者帳戶名稱，把擁有權交給攻擊者，沒有這個漏洞的合約（例如已修好的版本）也會被判「攻擊成立」 | 設定程式與受害者步驟不能使用框架帳戶；否定檢查（把攻擊拿掉後必須失敗）擴大到 EOA 模式 | `eoa_identity_probe` 16/16 |
| 嚴格條件只看一個一般使用者、只算 ETH：協議公庫被盜、ERC20 被盜都證實不了 | 加入「協議公庫當受害者」與 ERC20 版的受害者損失，仍要求守恆；捐款、搶先、擁有者正常提領等誤判情境都有反例 | `treasury_probe` 29/29 |
| 沙箱只有 solc 0.8.20／0.8.37，固定版本（如 `pragma solidity 0.8.24;`）的合約都變「無法判定」 | 新沙箱映像檔內含 0.6.12、0.7.6、0.8.0～0.8.37（逐一核對官方雜湊）；缺版本時用中文說明原因 | `sandbox_solc_probe` 7/7 |
| 結果頁：重現失敗顯示成「沒有受損」；沒有修補也寫「參考下方的修補」；「受害者受損」只看 B < A；英文內部訊息露出；回放結果頁沒有錄製日期 | 依實際狀態顯示「沒有量到」「重現失敗」與原因；建議文字依有沒有通過驗證的修補而定；標籤反映守恆規則；內部訊息翻成中文或收進技術細節 | `webui_probe` 25/25 |
| **這次審查發現**：驗證頁把網址參數指定的節點（`?rpc=`）或合約（`?registry=`、`?escrow=`）當成官方部署顯示，連「✓」稽核者都照給；結果頁把 AI 寫的代幣運算式當成金額單位、沒有跳脫就印出（可以插入程式碼） | 官方部署＝頁面內建（或部署紀錄檔列出）的節點＋部署紀錄檔裡的 AuditRegistry＋鏈上程式碼雜湊相符；其他來源在頁首和每個畫面標「非官方來源」、不給「✓」，程式碼不是 AuditRegistry 的合約完全不讀；單位只顯示代幣符號或地址，一律跳脫 | 驗證頁 node 測試 48/48、瀏覽器檢查 35/35；`webui_probe` 25/25 |

既有的合併檢查（8 個完整性 probe、patch、regression、mcp、repo_patch、reattack、project_upload、liveness_patch、live_drain、playback_date、diffscan、pr_gate、action_fork）全部照舊通過。改動的核心檔案（agent.py、tools.py、workspace.py、run.py、patch.py、gate.py）與原因，逐項寫在 commit 訊息裡；`innoserve/README.md` 裡「判定核心沒改」的雜湊表只適用於決賽版。

### 4.3 評測（同 40 份合約、同模型、同設定）

模型 arbiter-gpt（同一個 digest）、同一組 40 份自己寫的合約（有漏洞 20 份、修好 20 份）、同樣的參數與計分程式。新版跑 1 次（`me-strict-r1`，2026-11-22），決賽版跑過 3 次。比較方法與假設在跑之前就寫好並 commit：`arbiter/PREREGISTRATION_me_strict.md`。

| | 新版（1 次） | 決賽版（3 次） |
|---|---|---|
| 有漏洞的 20 份中，**嚴格標準**證實 | **4 份** | 2、3、3 份 |
| 修好的 20 份中，**嚴格標準**誤判 | **0 份** | 0、0、0 份 |
| 有漏洞的 20 份中，寬鬆＋嚴格合計證實 | 7 份 | 7、9、8 份 |
| 修好的 20 份中，寬鬆＋嚴格合計誤判 | 2 份 | 2、1、0 份 |

- 嚴格標準（受害者損失＋守恆、或功能被破壞）證實的數量，比決賽版每一次都多，而且修好的合約仍然 0 份誤判。預先登記的 3 個假設都成立。
- 寬鬆條件證實後的「嚴格重證」觸發 6 次，其中 1 次成功；修好的 2 份合約被寬鬆條件誤判，嚴格重證都沒有通過，代表嚴格標準擋住了這兩個誤報。
- 限制：只有 1 次對 3 次、20 份有漏洞的合約；5 項修改一起上線，無法把效果歸給單一項。原始資料、計分報告與檢查碼在 `me/eval/me-strict-r1/`。

## 5. 體驗方式

**線上（建議先看）**：驗證頁 https://sam029031.github.io/arbiter-gate/me/web/verify/ ，預設連 ME 測試網，資料直接從鏈上讀。例如修補後部署的 StakingVault：[紀錄 #4](https://sam029031.github.io/arbiter-gate/me/web/verify/?record=4)（來歷時間軸、部署檢查、證據自動下載重算）；也可以輸入 `EVIDENCE.md` 裡的任何合約位址、紀錄編號或交易雜湊。

**本機**（WSL／Linux，需要 Foundry 與 Python 3.11+，不需要任何金鑰）：

```bash
git clone --branch me-hackathon https://github.com/sam029031/arbiter-gate.git && cd arbiter-gate
export PATH=$HOME/.foundry/bin:$PATH
(cd me/contracts && forge test)                       # 合約測試 45 個
python3 me/scripts/me_registry_probe.py                # 本機鏈端到端：登記 → 拒絕部署 → 修補 → 部署 → 驗證 → 託管
python3 me/me.py verify <合約位址或紀錄編號> --network me-testnet --replay   # 直接驗證 ME 上的紀錄
cd arbiter && python3 -m arbiter.web --port 8765       # 網頁介面；開 http://127.0.0.1:8765/verify
```

**自己上鏈**（需要 ME 測試網 MEC，水龍頭每天 2 MEC）：`bash me/scripts/new_wallet.sh` 建錢包 → 水龍頭領 MEC → `bash me/scripts/me_live_demo.sh`。整個示範只需不到 0.0011 MEC。

## 6. ME 使用證據

2026-11-23 在 ME Hub 測試網（chain 400）用一行指令完成整個示範，共 11 筆交易：

- 合約：AuditRegistry `0xf619857eb017adc46d1dfeb8131979e1a97fb402`；AuditEscrow `0x8014653f1122833bc925b1b8741a1a202c7b955f`（由 AuditRegistry 依紀錄 #2 經閘門部署）。
- 紀錄 #1、#2：用 ARBITER Gate 稽核我們自己的兩個合約（判定 1）。
- 紀錄 #3：AI 證實 StakingVault 可被重入攻擊（判定 3）；對它呼叫 `deployAudited` 被合約拒絕（`NotDeployable(3)`）。
- 紀錄 #4：修補後的 StakingVault（判定 1，上一版 #3），經閘門部署到 `0x86e3e9e68b402537f76806e735167237873a2f3c`。
- 託管：委託 #1 鎖住 0.001 MEC，由紀錄 #3 結算付款（判定是 3 也照付）。

`EVIDENCE.md` 最後的 4 行 `me.py verify` 指令都已對 ME 鏈實跑通過（證據雜湊、重新編譯、重跑攻擊）。

見 [`EVIDENCE.md`](EVIDENCE.md)：每筆合約位址與交易都附 EVM 交易雜湊、Cosmos 交易雜湊、區塊、瀏覽器連結，以及對應的功能；瀏覽器打不開時可用 `cast receipt <交易> --rpc-url https://beta-hub-8545.explorer-testnet.me` 自己查。

## 7. 信任模型與限制（老實說）

- **紀錄是稽核者的主張，不是事實。** 合約保證的是：紀錄不會被改、內容自我一致、誰登記的、部署出去的就是稽核過的 bytecode。判定對不對，要靠證據重算與重跑；驗證頁和 `me.py verify` 就是為此而做。
- **判定 1 是「沒有找到可證明的攻擊」，不等於安全。** 通過修補檢查只代表擋住了這一次證實的攻擊。
- 任何人都能登記紀錄；讀者要自己決定信任哪些稽核者位址（`deployments/*.json` 的 `auditors` 名單只是部署者的背書）。`linkDeployment` 是稽核者自己的宣告，只能比對程式碼雜湊；`deployAudited` 才證明部署內容。
- 驗證頁只替一件事背書：經由頁面內建的 ME RPC（或部署紀錄檔列出的節點）讀到、部署紀錄檔裡的那一個 AuditRegistry，而且鏈上程式碼雜湊和紀錄相同。連結裡的 `?rpc=`、`?registry=`、`?escrow=` 都可能是別人的節點或仿冒的合約，頁面會標成「非官方來源」、不顯示「✓」。
- 已知缺口：`--replay` 只支援單檔、以受害者損失證實的攻擊；判定框架的帳戶身分仍是程式碼常數，目前用語法層檢查擋住 AI 讀取它們的管道；AuditEscrow 這類專案模式的稽核沒有 Slither 結果。
- 範圍：EVM、Solidity、Foundry；AI 寫的攻擊程式在不能上網、唯讀的容器裡執行；只有「已證實可攻擊」才擋部署。ME 上的示範是測試網。

## 8. 檔案地圖

| 路徑 | 內容 |
|---|---|
| `me/contracts/` | AuditRegistry、AuditEscrow、Foundry 測試（`evm_version = "paris"`） |
| `me/arbiter_me/` | 鏈上工具（Python 標準函式庫）；入口 `me/me.py`（`me_deploy.py`、`me_verify.py` 為別名） |
| `me/web/verify/` | 靜態驗證頁與其測試 |
| `me/scripts/` | 建錢包、實鏈示範、端到端檢查、驗證頁測試資料 |
| `me/docs/TOOLS.md` | 指令細節與 ME 測試網注意事項 |
| `arbiter/` | ARBITER Gate 本體（稽核、判定、修補閘門、網頁、GitHub Action） |
| `service/sandbox/` | 稽核沙箱（Docker，無網路、唯讀） |

## 9. 授權

Apache-2.0（見 `LICENSE`、`NOTICE`）。`me/contracts/lib/forge-std` 為 Foundry 的 forge-std（MIT／Apache-2.0）。
