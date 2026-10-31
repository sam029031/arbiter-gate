# ARBITER Gate：InnoServe 2026 決賽作品

ARBITER Gate 是放在智慧合約**部署前**的證據閘門。AI 寫攻擊，系統在不對外連線的沙箱裡、用模擬區塊鏈實際執行；只有真的跑成功、而且受害者真的少拿回錢（或一般使用者的操作被弄壞）的攻擊，才判定「已證實可攻擊」並擋下部署。其他結果分成另外三級，**都不代表合約沒有漏洞**。

這個資料夾（`innoserve/`）放決賽版的文件、預錄 demo 素材、評測資料和影片。程式碼在 repo 根目錄的 `arbiter/`。

## 從 AIS3 到 InnoServe

**來源**：AIS3 2026 專題 ARBITER（Team 011）。它的核心想法是：模型不能直接「回報」漏洞，必須寫出一個攻擊，由 harness 用 forge 編譯並執行；只有成功條件成立，才算數。而這個成功條件是模型看不到的。AIS3 時期的完整說明在 repo 根目錄的 `README.md` 與 `arbiter/README.md`、`arbiter/RESULTS.md`。

**起點**：公開 repo [yeee3642/arbiter-audit](https://github.com/yeee3642/arbiter-audit) 的 `arbiter-harness` 分支，commit `ead58aef4face495d47cce36fa08d78a9753321b`（2026-09-26）。本 repo 是決賽版的快照，沒有 git 歷史（見「歷史說明」）。

**InnoServe 期間的改善**：計算基準是 ead58ae。判定核心 `agent.py`、`tools.py` 一行都沒改；`workspace.py` 只新增 `run_poc()` 的兩個選用參數。可以自己比對，見「如何驗證判定核心沒有改」。

## 功能

| 功能 | 說明 | 主要檔案 |
|---|---|---|
| 四級判定 | 已證實可攻擊（擋部署）／靜態工具提示但未證實／未發現可證明攻擊（不等於安全）／無法判定（稽核未完成）；PR 改到函式外的另列「未涵蓋」。介面上不出現 CLEAR | `arbiter/arbiter/verdict.py` |
| A/B/G | 同一位受害者在 4 個環境下：A＝沒有攻擊時取回、B＝有攻擊時取回、G＝攻擊者獲利 | `arbiter/arbiter/patch.py`（`reproduce`） |
| 修補閘門 | AI 寫修補，系統依序檢查：0 重現原攻擊 → L 格式與行數 → 3 介面不變 → 1 同一攻擊在 4 個環境都失效 → 2 一般使用者取回不少於修補前 → 4 專案自己的測試（Foundry 專案才有）→ 5 修補後換手法再攻擊。支援 victim_loss 與 liveness_broken；寬鬆謂詞不產生修補 | `arbiter/arbiter/patch.py`、`arbiter/scripts/patch_probe.py`、`repo_patch_probe.py`、`reattack_probe.py`、`liveness_patch_probe.py` |
| 回歸測試下載 | 已證實的攻擊轉成 `TestArbiterRegression`（攻擊必須失敗＋4 個一般使用者路徑），放進 repo 後每次都會重跑 | `arbiter/arbiter/dump.py`、`arbiter/scripts/regression_probe.py` |
| SARIF 2.1.0 | 已證實＝error（漏洞函式的行號）、靜態提示＝warning；可上傳 GitHub code scanning | `arbiter/arbiter/sarif.py`、`arbiter/scripts/sarif_validate.py` |
| 靜態工具提示 | Slither 0.11.6 當第二級：沒證實時只顯示「靜態工具提示但未證實」，不當證據；餵給 AI 當提示的功能預設關閉 | `arbiter/arbiter/static_hints.py`、`arbiter/arbiter/proposals.py` |
| 沙箱 | 每份工作一個 Docker 容器：`--network none`、唯讀根目錄、只留 `PATH`、只掛工作目錄；網頁上傳一律在沙箱裡跑 | `arbiter/arbiter/sandbox.py`、`service/`（`service/tests/sandbox_assertions.py` 7 項斷言） |
| 網頁 | 只綁 127.0.0.1、只用標準函式庫、不連外：上傳 `.sol` 或 Foundry 專案 `.zip` → 工作頁看 AI 每一步 → 結果頁（判定卡、A/B/G、證據等級、修補燈號、攻防過程、下載區） | `arbiter/arbiter/web.py`、`webui.py`、`jobs.py`、`progress.py` |
| 證據等級 | 第 1 階合成環境 → 第 2 階抽成獨立 Foundry 專案重跑 → 第 3 階本地鏈（anvil）用真的交易重播 | `arbiter/arbiter/gate.py`、`live_replay.py`、`arbiter/scripts/live_drain_probe.py` |
| GitHub PR 閘門 | 只稽核 PR 改到的函式；已證實就擋合併，留言附 A/B/G、回歸測試與修補 suggestion；fork 的 PR 不執行 | `arbiter/arbiter/prgate.py`、`diffscan.py`、`arbiter/scripts/gate_pr.sh`、`.github/actions/arbiter-gate/action.yml` |
| MCP 工具 | `read_source`、`run_exploit` 等工具用 MCP 提供（不需要 mcp 套件） | `arbiter/scripts/arbiter_mcp.py`、`mcp_probe.py` |
| 本地鏈 demo | StakingVault 原合約被掏空（參考攻擊），套上 AI 修補後同一個攻擊失敗 | `arbiter/scripts/live_attack_stakingvault.py` |
| 決賽流程一鍵排練 | 計劃書 12.7 的 preflight（全部結束碼 0 才開場）＋ 12.4 的 6 分鐘腳本，逐段計時 | `arbiter/scripts/demo_gate.sh`、`innoserve/docs/DEMO_RUNBOOK.md` |

## 一定要講清楚的事

- **鏈上 demo 的攻擊是參考攻擊，不是 AI 寫的。** 它是 `arbiter/scripts/victim_probe.py` 的 DRAIN，在 2026-07-28 為了校正 victim_loss 判定而寫的已知攻擊。
- **修補是 arbiter-gpt 產生的**，並通過修補閘門（`innoserve/demo_runs/spark-test-{2,3,4}.patches.jsonl`）。修補只代表「針對此攻擊」通過驗證，不代表合約已經沒有漏洞；通過檢查的修補仍需要人工審查。
- 決賽 6 分鐘播的是**錄製紀錄**（畫面標日期），現場上傳放在背景、問答時揭曉。原因見 `innoserve/docs/reports/reliability_final_2026-10-30.md`：StakingVault 網頁上傳 10 次中 6 次證實（arbiter-gpt），達不到計劃書事先定的現場跑門檻。

## 數字分兩個時期，不要混用

| 時期 | 模型 | 數字從哪裡來 |
|---|---|---|
| AIS3（2026-07～09） | `ais3/nemotron-3-ultra-550b`（AIS3 課程 gateway） | 根目錄 README、`arbiter/RESULTS.md` |
| InnoServe（2026-10） | `arbiter-gpt:latest`（gpt-oss 120B，MXFP4，自架 Ollama） | 下面的「40 份評測結果」與 `innoserve/docs/reports/` |

兩個時期的模型、端點、判定條件和閘門都不同，不能互相比較。

## 40 份評測結果（arbiter-gpt，TUNE 集）

- **模型** `arbiter-gpt:latest`（gpt-oss 120B，MXFP4，自架 Ollama 伺服器）。**資料集** `arbiter/evalsets/v3_authored.json`：20 份故意留了漏洞的小型單檔合約，加上同一份合約把漏洞修好的 20 份，每份約 1,600 字元。這是 AIS3 時期調整系統時就用過的 **TUNE 集**，不是沒看過的測試集。
- **規則在跑之前就 commit**（`arbiter/PREREGISTRATION_arbitergpt_v3.md`）。同一個設定跑 3 次（r1、r2、r3）：每份最多 3 次嘗試、每次 16 回合、單檔（hermetic）模式、預設的嚴格謂詞。計分只用 `arbiter/arbiter/score.py`。
- **兩種計分並列，同樣重要**：
  - **as reported**：照系統畫面實際顯示的判定，包括用寬鬆謂詞（eth_profit、token_profit、state_change：「攻擊者手上的錢或代幣變多」「某個狀態值改變」）證實的。
  - **strict only**：只算用嚴格謂詞證實的：victim_loss（一般使用者因為攻擊而少拿回錢）、liveness_broken（一般使用者的操作被弄壞）。

| r1／r2／r3 | as reported | strict only |
|---|---|---|
| 有漏洞的 20 份：證實 | 20 份中 7 份／9 份／8 份 | 20 份中 2 份／3 份／3 份 |
| 修好的 20 份：被判成有漏洞 | 20 份中 2 份／1 份／0 份 | 20 份中 0 份／0 份／0 份 |
| MCC（-1～1，0＝和全部回答同一個答案一樣） | 0.299／0.462／0.500，平均 0.420 | 0.229／0.285／0.285，平均 0.266 |

- **和 AIS3 時期比較**：照預註冊的判讀規則，和 AIS3 時期 h2h-arbiter 那一次（nemotron、較舊的 harness 與判定條件）的 MCC 0.267 相比，兩種計分的結論都是**「差異在變動範圍內」**。而且 3 次之間的差距比和 AIS3 的差距還大，所以不說新模型比較好，也不說比較差。3 次都沒有 MCC ≤ 0。
- **as reported 的證實主要靠寬鬆謂詞**：每次證實的 7～9 份裡，有 5～6 份是寬鬆謂詞。修好的版本被判成有漏洞的 3 次也全部是寬鬆謂詞：2 次是攻擊程式鑽了判定條件的漏洞，1 次是修好的版本其實沒修乾淨、但那支攻擊程式是靠運氣贏的（逐筆檢查見完整報告第 3 節）。
- **修補**（3 次合計，嚴格謂詞證實的有漏洞列）：8 筆中 6 筆的修補通過修補閘門（victim_loss 6 筆中 6 筆；liveness_broken 2 筆中 0 筆，那支攻擊程式裡的「一般使用者操作」本身就靠漏洞才會成功，正確的修補也會被檢查 2 擋下）。修補通過後再請 AI 攻擊修補版 7 次：**用嚴格標準 7 次中 0 次攻破；另有 1 次用寬鬆標準（state_change）證實，系統照現行規則要求 AI 重修**。
- **對照**（同樣 40 份，不用 LLM）：永遠回答「有漏洞」或永遠回答「沒漏洞」MCC 都是 0。Slither 0.11.6（impact 與 confidence 都 ≥ Medium）：有漏洞的 20 份中標出 14 份、修好的 20 份中也標出 10 份，MCC 0.204；這個門檻本身是 AIS3 時期看著答案選的，所以偏樂觀，而且 Slither 只給偵測器名稱和行號，沒有可以重跑的攻擊。
- **限制**：40 份、每份約 1,600 字元的單檔合約，一個模型、一台伺服器，而且是 TUNE 集；信賴區間很寬（例如 as reported 的 MCC 95% 區間，3 次分別是 [0.000, 0.557]、[0.202, 0.681]、[0.317, 0.682]）。**這些數字不能推論到大型專案或一般程式碼。** r1 有 1 列（V_amm_spot_price_oracle）因為伺服器對外網路中斷沒跑完，照預註冊算「沒抓到」。
- 原始資料：`innoserve/eval/arbitergpt-v3/`（3 份 summary.json、3 份含逐列 trace 的 results.jsonl.gz、SHA256SUMS）。完整報告：`innoserve/docs/reports/eval_arbitergpt_v3_2026-10-30.md`。

### 參考：AIS3 時期 nemotron 的數字（不同模型、不同時間的 harness，只當參考）

這張表**不能**和上一張比較：模型不同；AIS3 時期可用的謂詞是 eth_profit、token_profit、state_change、liveness_broken（還沒有 victim_loss）；閘門較少；並行數 8。

| run（AIS3，nemotron-3-ultra-550b） | 資料 | 有漏洞的：證實 | 修好的：被判成有漏洞 | MCC |
|---|---|---|---|---|
| h2h-arbiter（07-26） | v3（同樣 40 份），16 回合，最多 3 次嘗試 | 20 份中 9 份 | 20 份中 4 份 | 0.267 |
| cascade-clean | v3，同上 | 20 份中 6 份 | 20 份中 1 份 | 0.329 |
| h2h-cascade | v3，同上 | 20 份中 7 份 | 20 份中 4 份 | 0.168 |
| fixed1／fixed2／casc2-strict | v4（70 份：有漏洞 35、修好 35），26 回合，最多 2 次嘗試 | 35 份中 7 份／13 份／10 份 | 35 份中 4 份／5 份／2 份 | 0.118／0.261／0.303 |

## 用在自己的 repo：GitHub Action

`.github/actions/arbiter-gate/action.yml` 是一個 composite action，跑在**裝好 ARBITER 的 self-hosted runner** 上（AI 稽核、forge、Slither 都在 runner 主機上執行，金鑰不放 GitHub）。

1. 在 runner 主機上準備 ARBITER（這個 repo）、Foundry、Docker，以及模型端點的 `.env`。
2. 建立 runner 主機的設定檔 `~/.config/arbiter/gate-runner.env`（權限 600，沒有秘密）：
   ```bash
   ARBITER_HOME=<ARBITER 的 arbiter/ 目錄>
   ARBITER_DOTENV=<模型端點的 .env>
   ```
3. 把 runner 註冊到你的 repo，加上 label `arbiter-gate`。
4. 在你的 repo 加 workflow（完整範例與說明在本 repo 的 `.github/workflows/arbiter-gate.yml`，那份的 `uses:` 指向示範 repo 裡內容相同的 action；用下面的 `@v1` 也可以）：
   ```yaml
   on:
     pull_request:
   permissions:
     contents: read
     pull-requests: write
     issues: write
     security-events: write
     actions: read
   jobs:
     gate:
       name: ARBITER Gate
       runs-on: [self-hosted, arbiter-gate]
       timeout-minutes: 45
       steps:
         - uses: sam029031/arbiter-gate/.github/actions/arbiter-gate@v1
   ```
5. 把「ARBITER Gate」設成預設分支的必要檢查，並在 Settings > Actions 設定「外部貢獻者的 PR 都要核准才執行」。

本 repo 自己沒有註冊 runner：`.github/workflows/arbiter-gate.yml` 在這裡只是範例，對本 repo 開的 PR 不會有機器執行它。

行為：PR 改到的 `.sol` 函式才送 AI 稽核；已證實可攻擊 → 結束碼 1（擋合併）；無法判定 → 結束碼 2（也不放行）；其他 → 0。SARIF 上傳到 code scanning，回歸測試放在執行紀錄的 Artifacts，PR 留言附判定、A/B/G 與修補 suggestion。fork 來的 PR 在 checkout 之前就拒絕（結束碼 2）。

**示範 repo**：[sam029031/arbiter-gate-demo](https://github.com/sam029031/arbiter-gate-demo)（只放自己寫的示範合約）。PR #1 是紅轉綠：第一個 commit 被擋下，套用 ARBITER 的修補 suggestion 後放行；PR #2～#5 示範只刪除、改函式外、加入回歸測試、回歸測試擋下再次引入的漏洞。

## 資料夾

| 路徑 | 內容 |
|---|---|
| `innoserve/docs/CLAUDE.md` | 交接文件。第 7 節是本機進度、使用者的決定（D1～D28）與已知陷阱 |
| `innoserve/docs/DEMO_RUNBOOK.md` | 決賽 demo 一頁說明：preflight、6 分鐘每段要說的話、備援、實測耗時 |
| `innoserve/docs/reports/` | 每一步的報告與原始輸出（截圖、gate.json、鏈上 transcript、Actions log） |
| `innoserve/demo_runs/` | 預錄 demo 素材：spark-test-1～5 的 results／ledger，加上 2～4 的 patches（arbiter-gpt，2026-10-28）；`spark-test-2.recorded.json` 是錄製回放橫幅的日期說明（紀錄本身沒有記時間，日期的出處寫在檔裡；D28） |
| `innoserve/eval/arbitergpt-v3/` | 40 份評測的原始資料（見上一節） |
| `innoserve/media/` | 程式地圖與評審 QA（PDF）、demo 動畫與操作教學影片（MP4＋SRT 字幕） |

文件和報告裡的本機路徑已經改成 `~`（家目錄）、`<本機備份位置>`，文字裡提到的家目錄名稱寫成 `/home/<使用者>`；預錄素材（`demo_runs/`）裡的路徑改成相對於 `arbiter/` 的路徑（例如 `examples/StakingVault.sol`），在別台電腦重播時證據等級才能爬到第 2 階（第 2 階會照紀錄裡的路徑讀原始碼）；DGX 主機位址與帳號改成 `<DGX 位址>`、`<user>`；個人與隊友的 email 改成 `<作者 email>`、`<隊友 email>`、`<學校 email>`；放完整歷史的私人 repo，名稱和網址一律寫成「私人 repo」。其他內容與本機原檔相同。描述公開前檢查與 repo 歷史的兩份報告（release_prep、release_push），以及 P9 報告資料夾裡的掃描輸出（`scan_*.txt`），沒有放進來。

## 還原 demo

需要 WSL2 或 Linux、Python 3.11 以上、Foundry（forge／anvil／cast，實測版本 1.8.6）。現場上傳另外需要 Docker（沙箱映像用 `service/sandbox/build.sh` 建，要連網）。

```bash
cd arbiter
mkdir -p runs && cp ../innoserve/demo_runs/* runs/      # 預錄素材放回 runs/（runs/ 在 .gitignore 裡）

# 只有現場上傳（--live）和 api_smoke 需要 LLM；錄製紀錄、本地鏈和 preflight 的其他項目都不需要
cat > ../.env <<'ENV'
AIS3_API_KEY=local
AIS3_BASE_URL=http://localhost:11434/v1
AIS3_MODEL=arbiter-gpt:latest
ENV

python3 scripts/victim_probe.py              # 判定閘門雙向自檢，不需要網路
python3 scripts/patch_probe.py               # 修補閘門 5 個固定案例，應該是 5/5 as expected
scripts/demo_gate.sh --auto --no-smoke       # 決賽流程：preflight → 6 分鐘各段（不送任何 LLM 請求）
```

- `demo_gate.sh` 會自己讀 `../.env`、啟動 `python3 -m arbiter.web`（http://127.0.0.1:8765/），在第 0 段跑完 12.7 的 preflight、把 spark-test-2 的錄製紀錄放完，再印出要開的分頁。
- 有 LLM 端點時拿掉 `--no-smoke`，preflight 會多一條 api_smoke；加 `--live` 會在 0:00 多一份現場上傳。
- `.env` 不在 repo 裡，也不要 commit。

## 歷史說明

- **這個 repo 只放快照，不含開發歷史。** 每個 commit 都是一份完整快照（e88e4d1 是 10/29 的版本；5ca3d98 是決賽版，tag `v1` 指向它，GitHub Action 引用它；之後的 commit 只修錄製回放橫幅的日期：`arbiter/arbiter/jobs.py`、一支測試 `arbiter/scripts/playback_date_probe.py` 和 `demo_runs/spark-test-2.recorded.json`，加上文件更新）。完整歷史（AIS3 時期到決賽版）放在私人 repo，評審需要時可以邀請檢視。
- 文件和報告裡引用的 commit hash（例如 d09b90f、2c26f68）都在那份完整歷史裡，本 repo 查不到。InnoServe 的起點 ead58ae 例外，它在公開的 yeee3642/arbiter-audit 上。
- **AIS3 gateway 金鑰**：AIS3 時期有幾個早期 commit 的訊息提到 AIS3 gateway 金鑰外洩。該金鑰已經輪替，歷史中所有的值都已遮蔽為 `REDACTED`。本快照不含那些 commit。
- **Bastet 提示原文**：AIS3 時期曾使用 Bastet 的 detector 提示原文，依 Apache-2.0 授權，出處見根目錄的 `NOTICE`。本快照不含那些提示檔：`arbiter/arbiter/bastet_arm.py` 在執行時，才從 repo 外的資料夾讀取提示。

## 貢獻者

依 git log 統計（完整歷史）：
- **ericchen913900**：AIS3 時期的判定核心、閘門與評測。到起點 ead58ae 為止共 **133 個 commit**，全部是這位作者，包括 `agent.py`、`tools.py`、`workspace.py`、`evalsets/`、`scripts/`。
- **sam029031**：InnoServe 延伸。ead58ae 之後到本版共 36 個 commit，內容是上面的「功能」。
- **AIS3 Team 011**：其他 AIS3 隊員以這個名義署名。

## 如何驗證判定核心沒有改

InnoServe 的起點是公開 repo `yeee3642/arbiter-audit` 的 `arbiter-harness` 分支，commit `ead58aef4face495d47cce36fa08d78a9753321b`。在本 repo 根目錄執行：

```bash
git clone -q https://github.com/yeee3642/arbiter-audit /tmp/arbiter-upstream
git -C /tmp/arbiter-upstream checkout -q ead58aef4face495d47cce36fa08d78a9753321b
(cd /tmp/arbiter-upstream && sha256sum arbiter/arbiter/*.py arbiter/cli.py) > /tmp/ead58ae.sha256
sha256sum -c /tmp/ead58ae.sha256
```

預期結果：16 個 `OK`，8 個 `FAILED`（下表中「有改」的 8 個），結束碼是 1。**`agent.py` 和 `tools.py` 一定是 `OK`**。想看改了什麼，可以執行：
`git diff --no-index /tmp/arbiter-upstream/arbiter/arbiter/workspace.py arbiter/arbiter/workspace.py`

| 檔案 | ead58ae 的 sha256 | 本版的 sha256 | |
|---|---|---|---|
| `arbiter/arbiter/agent.py` | `fb98375114a6bdb8aefa729ecc1eaf716f9ea4543f0763230d2b1218346aae7e` | 相同 | 沒改 |
| `arbiter/arbiter/tools.py` | `ea7b3e3bfe81a5897ffd5362edc016fd3da7803c4a0d170cb1e16ff2d1eb65f4` | 相同 | 沒改 |
| `arbiter/arbiter/__init__.py` | `7c5ce8015fae5876cc95899dd088d6025e2b7e90713846035cc28d18c610d48e` | 相同 | 沒改 |
| `arbiter/arbiter/bastet_arm.py` | `c21e00b798d3d7aa7d804aa450f65d236d31210b9da73e71d60134bafc8d4842` | 相同 | 沒改 |
| `arbiter/arbiter/benchmark.py` | `035acc31e054c9c9a76bd17f9baa74f9f2e9e5dcfee8af738d7b22ac5594c538` | 相同 | 沒改 |
| `arbiter/arbiter/broadside.py` | `bc867fcba11c5cd3243a178199622fb4ab086c203497a4b1fda4655f691fd23d` | 相同 | 沒改 |
| `arbiter/arbiter/cascade_lib.py` | `987b70e2ef897c9cacc53fde321f9e2e4ddb278d0c0a075078e60042ae88f478` | 相同 | 沒改 |
| `arbiter/arbiter/citation.py` | `b7b459b482cbe9349112d324b9424c22be8118634e4134f319c5660d54268b07` | 相同 | 沒改 |
| `arbiter/arbiter/evaluate.py` | `f2364e8e07a57b46516dab620ab6edd911adfee951e652ba4bf4b12335560465` | 相同 | 沒改 |
| `arbiter/arbiter/latebinding.py` | `a940a3902c0d1307bbf62debf8011a63d05b8f38a9467f35b8b4bc72d4d70818` | 相同 | 沒改 |
| `arbiter/arbiter/live.py` | `9cb3fdef6865192fdfe66a3684f773afe0283b69c63d597e232f4791393dff32` | 相同 | 沒改 |
| `arbiter/arbiter/onchain.py` | `2c18c66036e7edc31bf8eb5f0da0684d0c856e7398675ca2271cac804161797c` | 相同 | 沒改 |
| `arbiter/arbiter/prove.py` | `005dff0d16b2b0c8b58e915a4729b81ddf45f0174bc4423980f7568cf3bce1c4` | 相同 | 沒改 |
| `arbiter/arbiter/reconstruct.py` | `16c6b0546485833d23ee02e7ec1dd67a1a3a762c8992ff47513c267127b2f37c` | 相同 | 沒改 |
| `arbiter/arbiter/score.py` | `ea4b72a98617249c4e7d82b5eb359b2dac041074e443f5377571997370125b99` | 相同 | 沒改 |
| `arbiter/arbiter/triage.py` | `358e545aca90f0c7c5c023a4301b08cec5b21100793fcbde36d03320d9568250` | 相同 | 沒改 |
| `arbiter/arbiter/workspace.py` | `a374deb91b9463303431c49bdf161f4e436b5b6d39738bc39b38a35b4242127d` | `00042b364927122b40c991caf61e7f9fc9dc4c0b30087a87aaede2db3ff025d3` | **有改**（+17／−2） |
| `arbiter/arbiter/gateway.py` | `8c03db70e6088b2f1fe86c7e66a55b613b1febb8f6f4f26ad325d073b46b3a23` | `0a7cabcd35c5c59e37b44370170b28f8587551b0f779a6394b2151f9e47462c6` | **有改**（+16／−4） |
| `arbiter/arbiter/run.py` | `382d924a97d0511a78df5e4b0a1fe6e9e598cab929b31f7926c84f02761aab0d` | `406be8a1747c887470908cca660a45410f9dfd4244b42d51cb9477b02b66503f` | **有改**（+44／−2） |
| `arbiter/arbiter/dump.py` | `44de72404b3f66f67a4fcdaf2eb992aa837148a6f98fcbbc4f9d3ee2a8aa8918` | `f5fd173adb272290c0c7ca941fff10157af6a63e012b21ae76dd3a856a895890` | **有改**（+244／−25） |
| `arbiter/arbiter/proposals.py` | `cb00570446e80fe5bb115bf1657e3e980ac00a5d8e1f20fc1968583cce014293` | `6acf946f92494b357043646bdeb19f86b7606429cd049a90316e9e0adaae4701` | **有改**（+69／−0） |
| `arbiter/arbiter/repo.py` | `fbc386e929697ed6c4738bdaa8c5395c04f74830d488c2613086c4fda36e6cb4` | `bfa5a9bf9727da949a22dc022da9b1fbedecf8e4bf3906fcd9d9d5f49f396bdc` | **有改**（+38／−2） |
| `arbiter/arbiter/live_replay.py` | `6e83ea34cc59320afc0d991c813e73c91e26717ecd7990239f7232bfb491e69a` | `4c3469134051f0fab2e768a9f12532d98213c701a9e79319c9c4086d6ba2f708` | **有改**（+16／−2） |
| `arbiter/cli.py` | `55aeceb417035e0078900df63afd1407fd4a76a17626479026f62fc9f7c39215` | `005230bd01f3b206fc36a1ee66d26865ec59e7b1476f1573f9378b6433c27e48` | **有改**（+93／−9） |

改了什麼（行數是 `git diff --numstat` 的結果）：
- **`workspace.py`（+17／−2）**：只改 `run_poc()`，新增兩個選用參數 `match_contract`、`match_test`，有給值時才把 `--match-contract`／`--match-test` 加進 `forge test`。沒給時，指令和原本完全相同。修補閘門需要它，因為報告合約與 exploit 放在同一個測試檔，而 `_test_passed()` 只要看到任何一行 `[PASS]` 就算通過。
- **`gateway.py`（+16／−4）**：API 金鑰依序讀 `ARBITER_API_KEY` → `AIS3_API_KEY`；`base_url` 依序讀 `ARBITER_BASE_URL` → `AIS3_BASE_URL` → 原本的預設值；新增選用的 `on_request` 屬性（網頁顯示進度用，預設 None，掛上的函式出錯會被忽略，不影響送出什麼）。請求、重試、計費、限流的邏輯沒有改。
- **`run.py`（+44／−2）**：`run_arbiter()` 新增 4 個選用參數，預設都是 None、行為不變：`on_turn`、`on_row`、`on_request` 三個進度回呼（出錯會被忽略），以及 `proposal_renderer`（換掉提示文字的產生方式，只有 `gate --slither-proposals` 會用，預設關閉）。
- **`dump.py`（+244／−25）**：
  - 先用 `via_ir=false` 編譯，遇到 Stack too deep 才改 `via_ir=true`＋optimizer，讓 dump 出來的專案重現成功。
  - 搬進 dump 的檔案路徑改成相對於 repo，不再帶主機的目錄結構。
  - 新增回歸測試 `TestArbiterRegression` 的產生函式。
- **`proposals.py`（+69／−0）**：只新增 Slither 當提示來源的轉換與說明文字（預設關閉）；原本的 Bastet 路徑沒動。
- **`repo.py`（+38／−2）**：相依套件快取可以用 `ARBITER_DEP_CACHE` 指到工作目錄裡的副本（沙箱只掛工作目錄）；新增複製快取的函式。
- **`live_replay.py`（+16／−2）**：本地鏈（第 3 階）的「錢必須從被稽核合約流出」改成量**攻擊前後**的合約餘額，和合成層 forge 端的量法一致；舊的量法留成診斷欄位。其他三條判定和門檻沒改。這一階不影響評測計分。
- **`cli.py`（+93／−9）**：`--model` 預設改讀 `ARBITER_MODEL`／`AIS3_MODEL`；`audit` 的輸出改用 `verdict.py` 的四級判定，不再印 CLEAR，稽核未完成時結束碼是 2；新增 `fix` 子命令（修補閘門）。
- **InnoServe 新增的檔案**（ead58ae 沒有，所以不在上表）：`arbiter/arbiter/` 底下的 `verdict.py`、`patch.py`、`gate.py`、`web.py`、`webui.py`、`jobs.py`、`progress.py`、`sarif.py`、`static_hints.py`、`sandbox.py`、`prgate.py`、`diffscan.py`（取自 AIS3 時期 Team 011 自己寫的 Bastet-CC，出處在檔頭），以及 `arbiter/scripts/` 的 probe 與 demo 腳本、`service/`、`.github/actions/arbiter-gate/`。

## 授權

沿用 repo 根目錄的 `LICENSE`（Apache-2.0）與 `NOTICE`；Bastet 相關的出處說明見 `NOTICE`。
