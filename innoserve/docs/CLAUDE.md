# ARBITER Gate 交接包（雲端 → 本機）

產生日期：2026-10-28。這份說明讓本機的你（或本機的 Claude Code）不必看雲端對話紀錄，就能接著把系統做出來。

## 0. 這包裡有什麼

| 資料夾 | 內容 | 用途 |
|---|---|---|
| `plan/` | 計劃書 7 個章節的完整版（Markdown） | 實作的規格。**最重要的是 `06_patch_gate.md` 與 `08_implementation_steps.md`** |
| | 檔名對照：04_status_and_gaps＝現況與缺口、06_patch_gate＝修補閘門、07_code_changes＝程式修改範圍、08_implementation_steps＝實作步驟、09_evaluation＝評估、12_video_and_finals_demo＝影片與決賽展示、13_risks_and_QA＝風險與答辯 | |
| `prototype_patch_gate/` | 9/28 修補閘門原型：`probe*.py`、`variants.py`、5 種修補的測試工作區（只留 `.sol` 與 `foundry.toml`） | `patch.py` 的起點。五種修補的實測結果見 `plan/06_patch_gate.md` 6.1 |
| `reference_from_bastet/` | `diffscan.py`、`emit.py`、`solidity.py`（bastet 時期的舊程式） | `diffscan.py` 要整份借入（見 `plan/07` 7.3）；`emit.py` 可參考 SARIF 輸出 |
| `examples/` | `StakingVault.sol` | 決賽示範合約 |
| `deliverables/` | 兩份系統概述文件、架構圖 PDF／HTML、3 分鐘影片 MP4、demo reel HTML、旁白 SRT、配音稿 | 已交出或決賽要用的成品 |
| `tools/` | 產生上述成品的腳本：影片逐格輸出 `export_det.mjs`、Word 產生器、流程圖 | 之後要改影片或文件時用 |

**不在包裡、只在 claude.ai 上的東西：**
- 完整 15 章計劃書「ARBITER Gate 參賽計劃書」（Claude Docs，可匯出 Markdown／Word）。本包只有第 4、6、7、8、9、12、13 章。
- 影片的互動版：https://claude.ai/artifact/WKuwV4ttb2YS6RWTHqxotG
- 架構圖網頁：https://claude.ai/artifact/JL3vQVGvqR2gojw7JLVm2t

## 1. 程式碼從哪裡來

```bash
git clone https://github.com/yeee3642/arbiter-audit.git
cd arbiter-audit
git switch -c innoserve-gate origin/arbiter-harness   # = ead58ae
git tag innoserve-base ead58ae                        # 計算「明顯改善」的基準點
git config core.hooksPath .githooks                   # 啟用憑證掃描，避免金鑰被 commit
```

- **不要用 `sam029031/AIS3_CTF1`（fork）當起點。** fork 的現行版本和歷史都還留著去識別化前的評測資料（未完成廠商揭露的第三方漏洞程式碼、本機路徑、部署地址），而且是公開 repo。給評審看的 repo 一律從上游產生。fork 本身要不要轉私人或改寫歷史，還沒處理。
- 雲端沒有任何 commit 進 repo 的程式，唯一的新程式是 `prototype_patch_gate/`。
- `prototype_patch_gate/*.py` 裡寫死了雲端路徑（`/home/user/arbiter-audit/...`、`/tmp/claude-0/...`），本機要改成自己的路徑才能跑。

## 2. 本機環境

Windows 建議全部在 **WSL2（Ubuntu 24.04）** 裡做，Foundry、anvil、Docker 在 Linux 下最順。

| 工具 | 版本／說明 | 何時需要 |
|---|---|---|
| Python | 3.11。核心只用標準函式庫，不用裝 pip 套件 | 一定要 |
| Foundry（`forge`、`anvil`） | 原型實測用 1.5.1-stable。安裝：`curl -L https://foundry.paradigm.xyz \| bash && foundryup` | 一定要。找不到 `forge` 時 ARBITER 會拒絕啟動 |
| solc | 0.8.24（forge 會自動下載） | 一定要 |
| git、GitHub 帳號 | | 一定要 |
| Docker | 每個稽核工作一個容器、不對外連線、不放金鑰 | 做沙箱時（計劃 W3） |
| Slither | `pip install slither-analyzer`（另需 `solc-select`） | 選配，只當「靜態工具提示」 |
| Node 22、Playwright＋Chromium、ffmpeg（含 libx264） | 只有重新產生影片、Word、架構圖時才要 | 選配 |

驗收環境：
```bash
cd arbiter
python3 scripts/victim_probe.py            # 不用網路與金鑰，閘門雙向自檢
python3 scripts/live_attack.py             # 本地鏈上掏空重入漏洞
python3 scripts/live_attack.py --patched   # 修補後攻擊 revert
```

## 3. 金鑰與帳號（要自己準備，不在包裡）

- **LLM 端點**：`.env.example` 目前是 AIS3 課程 gateway：
  ```
  AIS3_API_KEY=...
  AIS3_BASE_URL=https://llm-api.zoolab.org/v1
  AIS3_MODEL=ais3/nemotron-3-ultra-550b
  ```
  課程結束後可能停用，先用 `python3 scripts/api_smoke.py` 測。要換供應商時，條件是 OpenAI 相容 API、支援 function calling，而且**不是陸資模型或 API**（競賽規定，細節以簡章為準）。計劃第 8 章 Step 0 要把變數改成優先讀 `ARBITER_BASE_URL`、`ARBITER_API_KEY`、`ARBITER_MODEL`，找不到再讀 `AIS3_*`；這個改動還沒做。
- 金鑰只放 `.env`，不要 commit。
- 選配：Azure Speech 金鑰（影片配音用；Clipchamp 免費版也可以直接配）。

## 4. 決賽（11/7）前建議只做這些

時間只剩約 10 天，照計劃書的「刪減順序」，主線不刪、外圍先砍：

1. **換模型（計劃 08 Step 0）**：端點可設定 → `api_smoke.py` 通過 → `cli.py audit examples/StakingVault.sol` 能印出 VULNERABLE 與 predicate satisfied。
2. **`patch.py`＋`scripts/patch_probe.py`（計劃 06）**：hermetic 模式、victim_loss、檢查 0 → L → 3 → 1 → 2。`patch_probe.py` 跑 5 個固定案例要 5/5 as expected。原型在 `prototype_patch_gate/`。
3. **`gate.py` 單檔版＋最小「上傳 → 結果頁」**：四級判定、A／B／G 三個數字（無攻擊取回、有攻擊取回、攻擊者獲利）、可下載修補 diff 與回歸測試。
4. **決賽 demo 備援（計劃 12、13）**：`scripts/demo.sh` 註解寫明現場即時稽核約 3 次成功 1 次，所以主線用**錄好的結果**加上可現場重跑的本地鏈重播。11/3 左右把 StakingVault 全流程連跑 10 次做可靠度測試；不行就退回 WithdrawalQueue 並在畫面註明。

時間夠才做：GitHub Action＋SARIF、diffscan、Docker 沙箱。
決賽前不做：預註冊評估重跑 3 次、Slither A/B、ME Network 整合。

**誠實原則**：系統概述文件描述的功能，決賽時評審會實際看。沒做完的部分在畫面和簡報上標「開發中」，不要用示意畫面冒充。影片第 11–13 幕是示意 UI，字幕「實際的系統」那句建議改掉。

## 5. 已知陷阱（實測或讀程式碼找到的）

- `tools._test_passed()` 只要輸出有任何一行 `[PASS]` 就算通過 → `Workspace.run_poc()` 要加 `match_contract` 與 `match_test` 兩個選用參數。
- `write_poc()` 會先刪掉 `test/` 下所有 `.t.sol` → exploit 和報告合約要寫在同一個檔案。
- `arbExit()` 在 `vm.startPrank` 之後 revert 時，prank 會殘留到下一個 trial → 報告合約每個 trial 用獨立的 test。
- `Workspace.neuter()` 對 victim_loss EOA 模式找不到攻擊（`_EOA_PRANK_RE` 只認 `vm.startPrank(eoa, eoa)`），否定測試會靜默放行 → 修補閘門不要用 `neuter()`。這是核心 harness 的既有問題，只記錄、不在這次修。
- 只做檢查 1 會放行「一律 revert」的假修補（失敗訊息和真修補一字不差）→ 一定要有檢查 2。
- 「只准外部帳戶呼叫」這種身分過擬合的修補會通過檢查 1、2、3，只有 L 擋得住。
- 對修補版重跑時 sample_id 要換（例如 `id + "__patched"`），因為 `_scaffold()` 會先刪掉同名目錄。
- `cli.py audit` 把所有非 vulnerable 的結果都印成 `CLEAR` → 輸出層改成四級判定，介面上不能出現「安全」或 CLEAR。
- 不要 import `onchain.py`（fork 模式），服務不接受鏈上地址、不對外廣播交易。

## 6. 給本機 Claude Code 的開場提示

把這個資料夾放在 repo 旁邊，第一句可以這樣貼：

> 讀 `README_handoff.md`、`plan/06_patch_gate.md`、`plan/07_code_changes.md`、`plan/08_implementation_steps.md`。repo 在 `./arbiter-audit`，已開 `innoserve-gate` 分支。照第 4 節的順序，從 Step 0（LLM 端點可設定）開始；`agent.py` 一行都不能改，`tools.py`、`workspace.py` 只能做計劃書列的純加法。每完成一步，先跑 `victim_probe.py` 和 `patch_probe.py` 再 commit。

## 7. 本機進度與已知陷阱（10/28 更新，以這節為準）

### 已完成
- 環境：WSL2 Ubuntu、Python 3.14.4（不是 3.11，目前相容）、Foundry 已裝。
  victim_probe.py 4/4 as expected；live_attack.py PROVEN；live_attack.py --patched NOT PROVEN。
- 模型：DGX Spark 上的 Ollama（0.40.11），透過 SSH 通道連線：
  `ssh -f -N -L 8080:localhost:8080 -L 11434:localhost:11434 <user>@<DGX 位址>`
  使用模型 `arbiter-gpt:latest`：底層是 gpt-oss 120B（MXFP4），有 tools 能力，num_ctx 65536，
  已移除原本 sec-gpt「只輸出繁體中文」的 SYSTEM 提示（可用 `ollama show arbiter-gpt:latest` 確認）。
  不要用 sec-daily、sec-coder（疑似 Qwen 底，競賽禁用陸資模型）。
- `.env`（在 arbiter-audit/ 根目錄，不 commit）：
  AIS3_API_KEY=local / AIS3_BASE_URL=http://localhost:11434/v1 / AIS3_MODEL=arbiter-gpt:latest
- commit ab8505b：gateway.py 的 base_url 改為依序讀 ARBITER_BASE_URL → AIS3_BASE_URL → 原預設值。
- 連線驗證通過（max_tokens=1024 時回 'AIS3_OK'，finish=stop）。

- commit 95a365a（Step 0 收尾）：
  - cli.py 的 --model 預設依序讀 ARBITER_MODEL → AIS3_MODEL → nemotron；source .env 後不必再加 --model。
  - gateway.py 金鑰依序讀 ARBITER_API_KEY → AIS3_API_KEY。
  - api_smoke.py 先讀 ARBITER_*，max_tokens 改 1024；對 arbiter-gpt 實測 PASS。
  - 新增 `arbiter/arbiter/verdict.py`：`classify(row)` 把結果列對應到四級判定，cli.py audit 改用它，不再印 CLEAR。
    proven → VULNERABLE 明細；conclude_safe／turn_budget_exhausted → 「未發現可證明攻擊（不等於安全）」；
    連線失敗、context_unbuildable、toolchain_unavailable、零回合 → 「無法判定（稽核未完成）」，audit 結束碼 2。
    gate.py 之後直接 import 這個模組（含 LABELS、EXIT_CODES、worst_exit）。
  - 實測：連線被拒 → 無法判定、rc=2（gateway 重試 7 次約 120 秒才放棄）；同 run-id 續跑會印 note 提示沿用舊結果。
  - commit 前檢查：8 個 probe 結束碼全 0；live_attack 正反兩向照舊；agent.py、tools.py、workspace.py 零差異。
- StakingVault 可靠度（arbiter-gpt，10/28，`--attempts 1 --max-turns 16`）：**證實 4/5**。
  | run-id | 結果 | 回合／請求 | 耗時 |
  |---|---|---|---|
  | spark-test-1 | 未證實（conclude_safe） | 4 | 184 秒 |
  | spark-test-2 | VULNERABLE（victim_loss） | 4 | 109 秒 |
  | spark-test-3 | VULNERABLE | 5 | 113 秒 |
  | spark-test-4 | VULNERABLE | 7 | 125 秒 |
  | spark-test-5 | VULNERABLE | 5 | 106 秒 |
  finish_reason=length 0 次（25 個請求，單次 completion ≤ 約 2,000 tokens）。reasoning_recoveries 偏高（gpt-oss 常把內容放在 reasoning 欄位，由 gateway 撈回），目前不影響結果。
  決賽建議：主線仍用預錄結果＋本地鏈重播，現場即時稽核當加分項，11/3 的 10 次測試再確認。
- spark-test-1 失敗原因：模型第 1 回合的 attacker_code 在建構子裡用 `vm.deal` 給自己生錢，
  被 harness 的 forgery 閘門拒絕（refusals: `forgery: attack forges authority`），沒進編譯所以沒有 PoC 紀錄。
  之後模型自己論述「無法實際利用」並呼叫 conclude_safe；因為已呼叫過 run_exploit，「攻擊前不得 conclude_safe」的擋法沒有觸發。
  判定本身沒錯（沒證據就不算證實），屬模型行為；tools.py 不能改，只記錄。

- commit 88aba8b（Step 1a 修補閘門）＋ e363530（Step 1b LLM 修補迴圈）：
  - workspace.py 唯一改動：`run_poc()` 加 `match_contract`、`match_test` 選用參數（純加法）。agent.py、tools.py 零差異。
  - `arbiter/arbiter/patch.py`：`reproduce()`（檢查 0＋A/B/G）、`verify_fix()`（0 → L → 3 → 1 → 2）、
    `TestArbiterReport`（8 個獨立 test，revert `ArbiterTrial`）、`exploit_from_row()`（把 repo 模式 exploit 改指向
    `../src/Target.sol`，只限沒有 import 的目標）、`repair()`（k=3 提案迴圈，回 PatchRecord）。
  - `scripts/patch_probe.py`：**5/5 as expected**，約 3 秒（human_fix、lock 接受；always_revert 被 2＋L 擋；
    deleted 被 3＋1 擋，removed=`StakingVault.unstake()`；eoa_only 只被 L 擋）。
  - `cli.py fix --results runs/<id>.results.jsonl [--rounds 3]` → `runs/<id>.patches.jsonl`。
  - .gitignore 補上 `**/runs/*.{results,ledger,patches}.jsonl`、`*.input.json`（原規則只擋檔名剛好叫 results.jsonl 的檔）。
  - 真實素材（arbiter-gpt）：spark-test-2～5 的 exploit 全部重現，A/B/G 每個環境為 2/2/1、2/2/1、2/2/1、**2/0/7**
    （模型的攻擊只重入一次，只有第 4 個環境〔8 輪〕受害者受損）。人工 CEI 修補 4/4 接受。
    LLM 修補：spark-test-2、3 第 1 輪接受（1 請求、11–17 秒）；spark-test-4 第 0 輪抄錯行被 L 擋，第 1 輪接受。

- LLM 修補交叉驗證（10/28，arbiter-gpt 產生修補，驗證不呼叫 LLM）：spark-test-2、3、4 的 3 個修補 ×
  spark-test-2～5 的 4 個 exploit，**12/12 攻擊失效**，12 格的閘門都是 0/L/3/1/2 全 pass；修補後 A＝2 ETH ×4，B＝2、G＝0。
  另加 victim_probe.py 的 DRAIN 攻擊（最多重入 8 次，規格一字未改直接打 StakingVault，LLM 沒看過）：
  原合約 A/B/G＝2/0/7 ×4（每個環境都受損）；3 個修補下 **3/3 失效**，修補後 2/2/0 ×4。
  **合計 15/15 失效，但只有 2 種手法**（spark-test-2～5 的 Attacker 一字不差，算 1 種；DRAIN 是第 2 種），
  兩種都是 unstake() 重入，沒有涵蓋其他漏洞類別。
  報告：`reports/xval_llm_patches_2026-10-28.md`（原始資料 .json、.drain.json）。

- Step 2a（gate.py 命令列版）：`python3 -m arbiter.gate --file X.sol | --from-results runs/<id>.results.jsonl [--patches runs/<id>.patches.jsonl] [--repair] --out gate.json`。
  - 判定與結束碼只用 verdict.py；A/B/G 用 `patch.reproduce()`；`--patches` 的修補會用 forge 重新驗證才顯示；`--from-results` 0 個 LLM 請求。
  - `--file` 的工作目錄在 `runs/gate/<run_id>/`（已 ignore）；run_arbiter 的進度列導到該目錄的 run.log。
  - 驗收：spark-test-2～5 rc=1、A/B/G 2/2/1 ×3、2/0/7（**計劃書的 2/0/7 ×4 是 DRAIN 攻擊的答案，照實不同**）；spark-test-1 rc=0；
    無 forge rc=2；輸出無 CLEAR／safe，「安全」只出現在「不等於安全」。報告：`reports/step2a_gate_2026-10-28.md`，原始輸出 `reports/step2a/`。
  - `runs/spark-test-{2,3,4}.patches.jsonl`：10/28 repair() 的輸出原樣（不 commit），demo 用 `--patches` 帶入。
  - **已決定（照實標示，不改判定規則）**：即時 hermetic 稽核 2/2 次用 **eth_profit** 證實（模型**明確傳入**；schema enum 只列 STRICT，
    但 `_run_exploit` 不檢查允許清單。Step 2a 曾誤寫成「沒帶參數、預設 eth_profit」，已更正）。repo 模式 spark-test 5/5 用 victim_loss。
    gate.json 加 `predicate_strict`（import tools.STRICT_PREDICATES），非 strict 顯示「以寬鬆謂詞 <名稱> 證實；A/B/G 與修補目前只支援 victim_loss」。
    tools.py、verdict.py 不動。**11/3 可靠度測試要分開統計 victim_loss 與非 strict 的證實次數。**

- Step 2b（最小上傳結果頁）：`python3 -m arbiter.web [--port 8765]` → http://127.0.0.1:8765/（只綁 127.0.0.1，不可改；沒有沙箱）。
  - 只用標準函式庫；網頁只呼叫 `python3 -m arbiter.gate`（一次一個 job）並渲染 gate.json，結果存 `runs/gate/web/`、上傳檔存 `runs/gate/uploads/`。
  - 預錄：列 `runs/*.results.jsonl` 與 `runs/gate/*/`，有 patches.jsonl 自動帶入；0 個 LLM 請求（ledger 前後 28 行不變）。
  - gate.py 新增 hermetic 編譯預檢：編不過 → 無法判定（context_unbuildable，附 solc 錯誤與行號），0 請求。
  - 驗收：spark-test-2 頁面有判定／A/B/G／diff、0 請求；spark-test-1「不等於安全」；Broken.sol 無法判定；
    即時上傳 68 秒、5 請求、已證實但 eth_profit。報告與截圖：`reports/step2b_web_2026-10-28.md`、`reports/step2b/`。
  - 截圖方法：Windows Edge headless 可直接連 WSL 的 127.0.0.1：
    `"/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe" --headless=new --screenshot="<wslpath -w 路徑>" --window-size=1100,1900 http://127.0.0.1:8765/`
  - 決賽前要清理預錄清單（runs/ 裡有早期的 `audit` 臨時 run）。

- eth_profit 成因調查（10/28，只查不修，報告 `reports/eth_profit_cause_2026-10-28.md`）：
  - hermetic 與 repo 的 system prompt、tool schema 完全相同；**唯一差異是 user 訊息**（location `src/Target.sol` vs `StakingVault.sol`，
    以及 repo 才有的 REPO_BRIEF；第一回合 prompt_tokens 4965 vs 5248）。temperature 0，第一回合推理文字逐字重複。
  - 第一次謂詞：**hermetic 5/5 eth_profit、repo 8/8 victim_loss**。NUDGE_TO_EXPLOIT 13 次都沒觸發（不是原因）。
    模型推理「Use eth_profit predicate: attacker ends with more ether」對應 `run_exploit` 說明文字（只列 eth_profit/token_profit/
    state_change/liveness_broken，沒提 victim_loss）；`_run_exploit` 不檢查 enum。REPO_BRIEF 與 location 哪個是關鍵：未知。
  - 新實驗 6 次證實率：hermetic 2/3（都 eth_profit），repo **1/3**（victim_loss）；repo 的 victim_loss 證實累計 **5/8**，波動大。
    repo-1 在第 14 回合也改用 eth_profit。
  - 修法待使用者決定：A. gate --file 單檔也走 repo 模式（只動 gate.py，唯一不動核心）；B/C 改 tools.py 說明或拒絕非 enum 謂詞；
    D 改 agent.py NUDGE（禁止）；E 維持照實標示（現況）。
- 結果頁用語小修（web.py）：「本金」→「受害者帳戶初始餘額」（endow＝`vm.deal(arbVictim, endow)`，進場前給的錢，不是存款）；
  A/B/G 表下加獲利來源說明，部署金額從結果檔 PoC 的 `arbSetup()` 讀（spark-test-2 顯示 5 ether）；首頁只列 spark-test-1～5，其他收進摺疊區。

- 修法 A 試跑與切換（10/28，報告 `reports/mode_repo_trial_2026-10-28.md`）：
  - gate.py 加 `--mode {hermetic,repo}`；repo 模式把單檔放進 `runs/gate/<run_id>/<原資料夾名>/`，user 訊息與 `cli.py audit` 逐字相同。
    編譯預檢兩種模式都做；A/B/G 與修補經 `exploit_from_row()` 轉 hermetic（限無 import）。
  - 事先寫好的條件（`reports/mode_repo_trial/PREREGISTERED_criterion.md`）：5 次第一次謂詞全 victim_loss 且無「無法判定」→ 切換。
    結果 5/5 victim_loss、0 次無法判定 → **`--mode` 預設已改為 repo，網頁上傳改走 `--mode repo --repair`**。
  - 5 次：證實 4/5（全 victim_loss，A/B/G 2/2/1 ×3、2/0/7），LLM 修補 4/4 通過閘門（1～2 輪）；耗時 125～174 秒；請求 4～6。
  - gate.json 請求數修正：`llm_requests_this_invocation`＝稽核＋修補，另有 `llm_requests_audit`、`llm_requests_repair`（試跑那 5 次是修正前產生的）。
  - 瀏覽器（Edge headless 自動送出表單）等了 367 秒沒有斷線；但那次 gate 本身 364.5 秒（conclude_safe），
    **超過網頁寫的「約 2～3 分鐘」**。repo 模式 9 次實測耗時 125～465 秒；建議改成「約 2～8 分鐘」，待使用者決定。
  - repo 模式 victim_loss 證實累計 **9/14**；決賽主線仍用預錄。

- 網頁上傳說明改為「約 2～8 分鐘（10/28 repo 模式實測 9 次：125～465 秒；找到攻擊時多半 2～3 分鐘，沒找到時較久）」。
  9 次＝predexp-repo 3（cli audit，無修補）＋modetrial 5＋網頁上傳 1；spark-test 5 次（106～184 秒）沒算進去。
- **live_replay 上鏈驗證（10/28，報告 `reports/live_replay_stakingvault_2026-10-28.md`）：不一致，已停下等使用者決定。**
  - 新增 `scripts/live_replay_one.py`（只呼叫現有函式，順序同 live_sweep；`--patches` 可打修補版）。anvil 1.8.6。
  - spark-test-2 的 exploit 轉譯成功（victim 模板），但鏈上 A/B/G＝7/7/0、`run()` revert「attack reverted」，NOT PROVEN；
    合成層 env0 是 2/2/1、env3 是 2/0/7。反向（修補版）沒有跑。0 個 LLM 請求（ledger 109→109）。
  - 原因：(1) 模型的 Attacker 建構子非 payable，鏈上用 `atk.call{value}` 注資會觸發它的 `receive()` 重入 → revert，攻擊者 0 ETH
    （合成層用 vm.deal 不觸發）；(2) 鏈上 setup 在受害者的 ArbWorld 建構子裡跑，部署時的 5 ETH 變成受害者的部位（A＝7）；
    (3) replay 只跑 1 輪，而模型攻擊要 8 輪才讓受害者受損。spark-test-3～5 片段一字不差，結果相同，沒重跑。
  - 選項：a. 改用 live_attack.py 的 WithdrawalQueue 並在畫面註明；b. 改 live_replay（規定不動，且修不了原因 3）；
    c. 用 DRAIN 上鏈（未測）；d. 鏈上重播維持「開發中」，只放合成層 A/B/G。

- **鏈上 demo 已決定：方案 e，成立（10/28，報告 `reports/live_attack_stakingvault_2026-10-28.md`）**，不需要退回 a。
  - `scripts/live_attack_stakingvault.py`（仿 live_attack.py，只用 arbiter.live 的現有函式＋patch.apply_diff）：
    目標＝examples/StakingVault.sol 原檔；deployer 部署帶 5 ETH（＝spark-test-2 PoC 的 arbSetup）、victim stake 2 ETH、
    attacker 部署 DRAIN Attacker 帶 1 ETH 並 attack()；對照鏈不送 attack()。判定規則＝live_attack.py 的
    `drained > 0 and attacker_net > 0 and victim_recovered < victim_paid_in`。
  - **鏈上攻擊是 victim_probe.py 的 DRAIN（2026-07-28、commit 69354be，為校正 victim_loss 判定而寫的已知攻擊），不是模型產生的；
    修補是 arbiter-gpt 產生的**（spark-test-2/3/4 的 patches.jsonl）。
  - 結果：原合約 PROVEN，A/B/G＝2/0/7（金庫 7→0）；3 個修補版 NOT PROVEN，2/2/0（attack() revert）。
    原合約與每個修補版各跑 3 次，數字、交易 hash、gas 完全相同（決定性）。0 個 LLM 請求（ledger 109→109）。
  - 用法：`python3 scripts/live_attack_stakingvault.py`（原合約）／`--patched spark-test-2`（修補版）。網頁尚未接這支腳本。
  - 細節：修補版的 attack() 在 cast 估 gas 時就 revert，沒有上鏈的 tx hash；部署交易的 gas 顯示 0（LiveChain.deploy 不讀 gas）。

- **決賽 demo 排練（10/28，報告 `reports/demo_rehearsal_2026-10-28.md`，給人看的一頁 `~/innoserve/DEMO_RUNBOOK.md`）**：
  - `scripts/demo_gate.sh [--auto] [--live [--live-upload]] [--timings F] [--pause N]`（scripts/demo.sh 是 AIS3 版，保留不動）。
    第 0 段前置（api_smoke 失敗只警告、forge/anvil/cast、web 沿用或啟動、**先產生 spark-test-2 結果頁**）→ 第 1 段即時上傳（--live）
    → 第 2 段預錄網址＋終端機印同一份 gate.json → 第 3 段 live_attack_stakingvault 原合約＋--patched spark-test-2 → 第 4 段收尾。
  - **網頁一次只跑一個 gate（_JOB_LOCK）**：即時上傳在跑時，任何「看結果」都會排隊 2～8 分鐘，所以預錄頁在第 0 段（上傳前）先產生。
  - 實測（不含暫停）：各段合計 17.1～28.6 秒（第 0 段 3.5～15.1、第 3 段 13.5～13.6、第 2/4 段 0）；`--auto` 含暫停 35～47 秒。
    腳本到第 4 段時即時稽核才跑 32 秒 → 第 2、3 段要講到瀏覽器跳轉為止。
  - `--live` 一次（arbiter-gpt）：247 秒、7 請求、**未發現可證明攻擊**（兩次 victim_loss PoC 都 no harm）→ repo 模式 victim_loss 證實累計 **9/15**。
  - 備案演練：通道斷 → api_smoke 約 2 秒失敗、第 1 段自動跳過；PATH 沒有 anvil → 第 3 段跳過；預錄照常。
  - 首頁摺疊區 16 筆裡有誤點風險的 run 已列在報告第 4 節（最嚴重：`audit` 會顯示 AIS3 401 錯誤）；**沒有刪，待使用者決定**。
  - 結果頁「0＝通過」與「本地鏈重播 開發中」兩處用語可能和 demo 內容讓人誤會（web.py 未動，runbook 有口頭說法）。→ 下一項已改。

- **demo 清理（10/28，報告 `reports/demo_cleanup_2026-10-28.md`）**：
  - 首頁摺疊區 16 個 run 搬到 `~/innoserve/runs_archive/2026-10-28/`（不刪）；首頁只剩 spark-test-1～5。
    已存的 12 個結果頁（runs/gate/web/）全部仍可開啟、判定不變（結果頁只讀 web/<id>.json）。
  - web.py 只改兩處文字：結束碼「0＝未擋部署（不代表沒有漏洞）」；開發中項目改為「網頁內的鏈上重播頁」＋「終端機版已完成（scripts/live_attack_stakingvault.py）」。
    13 頁用語檢查 CLEAR／safe／「不等於安全」以外的「安全」皆 0。
  - DEMO_RUNBOOK.md 刪掉三條已不需要的口頭補救；第 1 段加「即時上傳建議在報告開場就送出」。
  - demo_gate.sh --auto 照常（各段合計 28.1 秒；api_smoke 閒置後 13.3 秒）；0 個 LLM 請求（ledger 116→116）。

- **REV 行顯示＋第二次備份（10/28，commit d09b90f，報告 `reports/rev_display_backup_2026-10-28.md`）**：
  - `live_attack_stakingvault.py` 只改顯示：revert 的步驟印 `reverted: <Error("...") 的原因>`，取不到印「reverted（原因見 JSON transcript）」；
    沒有 tx hash 的 revert 另起一行註明「節點在估算 gas 時就拒絕，交易沒有送出上鏈」（已用 cast send 重現：訊息開頭是
    「Failed to estimate gas」、nonce 不變）。**原合約受害者的 unstake() 也沒有 tx hash，所以同樣會有這行註明**（不只修補版 attack()）。
  - 原合約與 --patched spark-test-2 的 JSON 和之前的執行逐欄相同（判定、A/B/G、交易 hash、transcript）；demo_gate.sh --auto 照常（29.9 秒）。
  - 第二次備份：`ARBITER_backup/` 底下新的時間戳資料夾（見「保留的素材」），tar 加入 runs_archive/；舊備份保留。

### 保留的素材（不要刪、不要 commit）
- `arbiter/runs/spark-test-2～5.{results,ledger}.jsonl`：已證實的 StakingVault exploit。
  `outcome.pocs[]` 裡 `passed && adjudicated` 那筆的 `solidity` 是完整測試檔，patch.py 的檢查 0／1／2 拿來當真實素材，也當預錄 demo 素材。
  runs/ 已在 .gitignore。spark-test-1 留著當「未發現可證明攻擊」的輸出範例。
- **本機備份（2026-10-28 22:24）**：`<本機備份位置>/20261028_222433/`
  （`arbiter-audit.bundle`＝git 全部 ref，innoserve-gate HEAD 9e676b1；`innoserve-materials.tar.gz`＝runs/、reports/、CLAUDE.md、DEMO_RUNBOOK.md；
  `RESTORE.md`＝sha256 與還原步驟）。**runs/ 不在 git 裡，預錄素材只能靠這份備份**；之後 runs/ 有新素材要重新備份。沒有推送到任何遠端。
- **第二次本機備份（2026-10-28 22:42，取代上一份作為最新）**：`…/ARBITER_backup/20261028_224246/`
  （bundle：innoserve-gate HEAD d09b90f；tar 另含 `~/innoserve/runs_archive/`；sha256 與還原位置見該資料夾的 RESTORE.md）。
  22:24 那份保留不刪。
- **runs_archive（2026-10-28 搬出）**：`~/innoserve/runs_archive/2026-10-28/runs/`（保持原相對路徑）放首頁摺疊區原本的 16 個 run
  （audit、predexp-repo-1～3、predexp-herm-1～3、modetrial-repo-1～5、4 個 gate-StakingVault-*；共 86 檔），沒有刪。
  不在 repo、不在 22:24 那份備份的 tar 路徑裡（tar 是搬移前打的，內容有），下次備份要把 runs_archive/ 加進去。
  之後網頁每次上傳會在 runs/gate/ 新增 gate-StakingVault-*，首頁摺疊區會再出現；demo 前把排練上傳也搬過去。

### 已知陷阱（實際踩過）
1. 程式「不會」自動讀 .env，每個新 shell 要先在 arbiter-audit/ 執行 `set -a; source .env; set +a`。
2. ~~--model 預設寫死 nemotron~~ → 95a365a 已修，改讀 ARBITER_MODEL → AIS3_MODEL。
3. ~~api_smoke.py max_tokens=32 必定 FAIL~~ → 95a365a 已修（1024）。
4. run.py 會依 runs/<run-id>.results.jsonl 跳過做過的樣本（續跑機制）。
   同一個 run-id 重跑會直接沿用舊結果（requests: 0），audit 現在會印 note 提醒。每次測試請用新的 --run-id。
5. ~~連線失敗或零請求時印 CLEAR~~ → 95a365a 已修，顯示「無法判定（稽核未完成）」、rc=2。
6. agent.py 每回合 max_tokens=4096。spark-test 實測沒有出現 length；若之後出現，agent.py 不能改，要從呼叫端或模型推理強度著手。
7. AIS3 時期的數字是用 nemotron-3-ultra-550b 量的。改用 arbiter-gpt 後量到的數字必須另外標明模型，不能混用。
8. 連線失敗時 gateway 會重試 7 次（約 120 秒）才放棄；demo 前先跑 api_smoke.py 確認通道，不要等 audit 卡兩分鐘。
9. `.githooks/pre-commit` 本機已 chmod +x（git 顯示 mode 變更，尚未 commit）。
10. 本機 forge 是 **1.8.6**（不是原型的 1.5.1）。`--match-test` 比對的是含括號的簽章，錨點要寫 `^name\(\)$`，寫 `name$` 會 0 個 test 符合。
11. gpt-oss 寫 diff 習慣 apply_patch 格式（`@@` 沒有行號、`*** Begin Patch`），`git apply` 不收；
    patch.py 失敗時改依內容套用 hunk，最後一律重新產生標準 diff。模型偶爾會改整段縮排（diff_line_count 不計空白，照樣通過，但畫面難看）。
12. spark-test-* 的結果檔在 `.git/info/exclude`（本機）與 .gitignore（e363530 起）都被忽略。

13. **tools.py 的 `run_exploit` 工具說明只列舊謂詞**（eth_profit、token_profit、state_change、liveness_broken，沒有 victim_loss），
    而 schema 的 enum 只有 STRICT、`_run_exploit` 又不檢查 enum。這是 AIS3 時期留下的缺陷：hermetic 單檔稽核下模型 5/5 選 eth_profit，推理用詞和這段說明一致（因果證據強度：中）。
    **決賽前不修**（tools.py 不動），答辯時主動說明：寬鬆謂詞證實的結果畫面上照實標示，A/B/G 與修補只對 victim_loss 提供。

### 下一步
- ~~待使用者決定：鏈上 demo 方案~~ → **已決定 e 並驗證成立**：`scripts/live_attack_stakingvault.py`（DRAIN 攻擊＋arbiter-gpt 修補）。
  網頁尚未接這支腳本；要接的話是下一個工作。
- ~~決賽 demo 排練腳本~~ → **已完成**：`scripts/demo_gate.sh`＋`DEMO_RUNBOOK.md`（10/28）。
- ~~待使用者決定：首頁摺疊區、結果頁兩處用語~~ → **已完成**（10/28，`reports/demo_cleanup_2026-10-28.md`；封存在 `~/innoserve/runs_archive/2026-10-28/`）。
- 決賽前：排練產生的網頁上傳（runs/gate/gate-StakingVault-*）上台前再搬到 runs_archive；之後 runs/ 或 runs_archive/ 有新素材時照第二次備份的做法重新備份（tar 含 runs_archive/）。
- 11/3 可靠度測試 10 次（決賽 demo 備援，計劃 12、13）：victim_loss 與非 strict、hermetic 與 repo 分開統計，並記錄耗時；
  可直接用 `scripts/demo_gate.sh --auto --live --live-upload --timings F` 連跑，順便量整套流程。上台前再完整排練一次（有人講話、計時）。
- Step 2c：SARIF、回歸測試下載（`TestArbiterRegression`）。
