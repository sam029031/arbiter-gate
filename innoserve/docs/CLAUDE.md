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

### 完整版守則（10/29 起，P0～P9 每一段都要遵守）
目標：初賽概述文件寫的每一項都要做到，分成 P0～P9 十段。
- **核心三檔**：agent.py 一行不改；tools.py 和 innoserve-base 零差異；workspace.py 不再新增改動（目前只有 run_poc 的 +17／−2）。
  功能非改這三檔不可時，**停下來回報**，不要自己改。
- 其他檔案照計劃書 7.4 的「小改／新增」：run.py、gateway.py 只加選用參數或回呼，預設行為不變；verdict.py 只能新增，不改既有對應。
- 計劃書和現況不同時以現況為準，並在報告寫明（例：計劃書寫 FastAPI，web.py 只用標準函式庫；solc 實際是 0.8.37 不是 0.8.24）。
- **每段結束**：
  · 合併前檢查：8 個 probe、patch_probe 5/5、**regression_probe 6/6**（P1 起）、live_attack 正反兩向、`arbiter/scripts/demo_gate.sh --auto` rc 0、agent.py 和 tools.py 與 innoserve-base 零差異；
    有 SARIF 輸出時再加 `~/innoserve/venv-tools/bin/python scripts/sarif_validate.py <sarif> <gate.json>`。
    **評測在跑時用 `demo_gate.sh --auto --no-smoke`（P2 起，完全不連 DGX）並在報告註明；評測沒在跑時跑完整版**；
    `scripts/mcp_probe.py` 3/3（P2 起，順便跑，約 1 秒）；
    **`python3 service/tests/sandbox_assertions.py` 7/7（P3 起，約 60 秒；需要 Docker Desktop 開著；評測在跑時第 7 條自動 SKIP，算通過但報告註明）**；
    `scripts/repo_patch_probe.py` 5/5、`scripts/reattack_probe.py` 5/5、`scripts/project_upload_probe.py` 10/10（P6 起）、`scripts/liveness_patch_probe.py` 10/10（10/30 起，讀 eval-worktree 的 r2 結果檔）、`scripts/live_drain_probe.py` 7/7（10/30 起，讀 runs/ 的 P8 dump，需要 anvil）；都不送 LLM 請求；
  · 報告存 `~/innoserve/reports/<段落>_<日期>.md`；更新第 7 節；commit（runs/ 不 commit）。
- 舊功能不能壞：預錄 spark-test-1～5、真鏈 demo、demo_gate.sh 每段結束後都要照常。
- 用語：不說「安全」「CLEAR」「首創」；數字標明模型（nemotron 或 arbiter-gpt）；畫面、報告、截圖不出現 DGX 位址、金鑰、個人路徑。
- 需要密碼、token，或要在 GitHub、Docker 設定頁操作的步驟，一律停下來請使用者自己做。
- 用到 DGX 之前先跑 api_smoke.py。
- **DGX 共用規則**：40 份評測（run-id `gptoss-v3-r*`）在跑時，開發工作不准對 DGX 送任何請求（api_smoke、網頁上傳、repair、live 測試都算；demo_gate.sh 第 0 段也會跑 api_smoke）。
  需要 LLM 的驗收等評測跑完再做，先做不需要 LLM 的部分。開始前先 `pgrep -af gptoss-v3` 確認沒有評測在跑。

### 使用者 10/29 的決定（D1～D9）
- **D1 Docker**：Docker Desktop 已開 Ubuntu 的 WSL integration。（P0 實測：Docker Desktop 沒開時 WSL 裡沒有 docker，開了才有。）
- **D2 PR 檢查**：本機 WSL 註冊成 self-hosted runner；不把金鑰或 Tailscale 設定放上 GitHub。
- **D3 PR 示範 repo**：公開的 `sam029031/arbiter-gate-demo`，只放自己寫的示範合約；外部人的 PR 不自動執行。
- **D4 評測**：arbiter-gpt 在 v3_authored.json（40 份）跑 3 次，設定和 AIS3 的 h2h-arbiter 相同。不跑同模型的 Bastet 對照；第九章的 70 份 A/B 留到賽後。
- **D5**：agent.py、tools.py 一行不改；寬鬆謂詞（eth_profit 等）證實的結果照實分開統計。
- **D6 決賽現場**：開場當評審的面上傳一份合約（評審從 3～5 份事先準備的漏洞合約挑一份）；6 分鐘講解用錄製回放，畫面標「錄製回放：<日期> 的實際紀錄」；
  問答時切回現場那份揭曉，沒證實就照實顯示並說明「未發現可證明攻擊不等於安全」。
  P8 照計劃書 12.4 門檻測 10 次，另測兩種加速：gpt-oss 推理強度 low、展示用較少回合數。達門檻才把現場跑升為主線。
- **D7 決賽形式**：現場說明與展示約 6 分鐘、問答約 7 分鐘；不做海報；概述文件不重交。大會不提供投影機和電腦（自備筆電）；
  競賽區有線＋無線、作品展示區只有無線；建議兩區各準備一台電腦。
- **D8 時程**：11/5 22:00 程式凍結；11/6 完整排練兩次並錄 6 分鐘備援影片。
  落後時的刪減順序：(1) 檢查 5 改選用、預設關 →(2) PR suggestion 改成留言附 diff →(3) 函式級 diffscan 改檔案級 →(4) 不做 zip 專案上傳 →(5) 評測 3 次改 2 或 1 次 →(6) 攻擊成功細節頁。
  **絕對不刪**：沙箱、回歸測試下載、Action＋SARIF＋PR 留言、看得懂的網頁、舊 demo 能跑。
- **D9 PR 擋合併**：改到的合約只要有「已證實可攻擊」就擋；漏洞在這次沒改到的函式也擋，並在留言註明。

### 使用者 10/30 的決定（D10～D22）
- **D10 舊的公開 Actions log 保留不刪**：demo repo 在 PR #6 合併前的 6 份公開 log 含一行 `~/.gitconfig`，保留。
  理由：log 是公開、可核對的證據，這一行沒有秘密。run id：40991523483、40992745484、40993168563、40993341264、40993511867、40993928603。
  **PR #6 之後的新 log 不能再有 `/home/`**。
- **D11 runner 的 `Machine name` 保留**，不處理（電腦名稱不是秘密）。
- **D12 PR 模式的再攻擊（檢查 5）維持預設開**。
- **D13 P7b 第 4 步原文**（使用者 10/29 決定加入）：修補統計（會用 LLM，三次評測都結束、DGX 空閒時跑）。
  · 程式用 innoserve-gate 最新版（含 P6 檢查 5），不用 eval-worktree 的凍結版；輸入讀 eval-worktree 的 gptoss-v3-r1～r3 結果檔，輸出寫 arbiter-audit 的 runs/，eval-worktree 任何檔案都不能改。
  · 對三次評測每一筆已證實的列跑修補閘門，修補通過的再跑檢查 5；S_ 列分開統計，不混進主數字。
  · 報告要寫：N 筆中幾筆修補通過；每道檢查（0、L、3、1、2、5，現在多 4）各擋下幾次；用了幾輪；每筆耗時；**依漏洞類型分列**；再攻擊 N 次中被攻破 M 次（攻破的列出新攻擊手法）。
    一律「N 次中 M 次」，不寫百分比，標明 arbiter-gpt。分母是 STRICT（victim_loss／liveness_broken）證實的列，skipped 另列原因，不說成修補失敗。
- **D14 更正**：計劃書 6.2 第 1 條是「只修 STRICT_PREDICATES（victim_loss、liveness_broken）」，所以 liveness_broken 的修補屬於計劃書範圍、還沒做的功能 → **10/30 補上**。eth_profit 等寬鬆謂詞維持 skipped，不放寬。
- **D15 liveness_broken 檢查 2 的發現：選 a＋b，不做 c**（c 決賽後再考慮）。
  · a：規則不改；這類 finding 照實記「未能產生通過驗證的修補」。
  · b：liveness_broken 的修補被檢查 2 拒收時，結果頁、PR 留言、gate.json（`patch.check2_note`）加一句白話說明：「檢查 2 以攻擊程式裡的『一般使用者操作』為基準；如果這個操作本身就依賴漏洞（例如沒付代幣也能拿到錢），正確的修補也會讓它失敗而被擋下，請人工確認修補。」→ **a63ccd5 已做**。
  · P7b 報告寫到 r2 V_unchecked_call_return_buyback 時註明：這筆的「誠實操作」依賴漏洞，「可用性被破壞」的證據較弱；**評測計分照預註冊不變**。
- **D16 修補統計的重跑規則**（r3 之前生效）：每一列只算「**第一次完整跑完**」的結果；只有沒跑完（not_executed，例如 HTTP 500、連線失敗）才可以重跑，每列最多 2 次。
  r2 V_unchecked_call_return_buyback 的 3 次全部列在報告，**計入的是第 1 次（13:49，rejected）**，和第 3 次結果相同。
  `patch_stats.py` 的主檔放的是最新紀錄、被取代的在 `patchstats.superseded.jsonl`；P7b 彙整時照這條規則挑，不改舊紀錄。
- **D17 檢查 5 的寬鬆謂詞證明**（P7b，10/30 晚）：
  · 報告和所有對外說法**一律兩個數字並列**，不單獨講一個：「修補後再攻擊 7 次，用嚴格標準 0 次攻破；另有 1 次用寬鬆標準（state_change）證實，系統照現行規則要求 AI 重修」。
  · **程式行為不改**：決賽前維持「再攻擊不論謂詞，只要證實就拒收修補」（較保守）；決賽後再評估。
  · r3 V_delegatecall 第 2 版修補加的 `totalDeposits = address(this).balance;` 改變了 totalDeposits 的意義，是為了應付 state_change 證明而加，人工判斷不是必要的修改。這是「AI 修補通過檢查後仍需要人工審查」的實例（報告已註明）。
- **D18 r3 V_unchecked_call_return_buyback 比照 D15 註明**：攻擊程式部署 `GovToken(0)`，「一般使用者」沒有代幣也能 sell，這筆的「誠實操作」依賴漏洞，「可用性被破壞」的證據較弱。評測計分照預註冊不變。
- **D19 P8 跳過 gpt-oss 推理強度 low**（10/30 晚）：主設定卡在證實次數（10 次中 6 次），不是速度；降低推理強度解決不了證實次數；程式凍結前不為它改 gateway.py。
  · 中途加的 gateway.py 6 行（`ARBITER_REASONING_EFFORT`）沒有 commit，已 `git checkout` 改回，和 a461776 相同。
  · `runs/p8/lowcheck`（21:55，1 個請求）是主設定判定後、收到 D19 前開始的確認請求，已中止、不計入任何設定，資料保留。
- **D20 修正第 3 階（live_replay）的流出量法**（10/30 晚，**commit 2c26f68**）：
  · 改成和 forge 端一致：在有攻擊的那條鏈上，量**攻擊前後**被稽核合約的餘額（對應 workspace.py:1835-1842 的 tgtPre／tgtPost），不再用兩條鏈「到最後（含受害者提款）」的總流出相減。
  · 「錢必須從被稽核合約流出」保留，ec5ad6a 要擋的場景攻擊照擋。舊值留成診斷欄位 `drained_vs_clean`。門檻「流出 > 0」沒改（forge 端寬鬆謂詞要求 ≥ 攻擊者獲利，這個差別保留）。
  · 第 3 階不影響評測計分：run.py、score.py、verdict.py、patch.py 和 P7b 腳本都不 import live_replay／prove。
  · 新 probe `scripts/live_drain_probe.py` 7/7（P8 素材，需要 runs/）。P8 數字不改；主設定第 3、6 次事後重判為成立，不改變 P8 判定，也不改變展示選擇；快取包不更新。
- **D21 2:30～3:20 用方案 e（`live_attack_stakingvault.py`）**，不改播 WithdrawalQueue。
  · 方案 e 是 10/28、P8 之前就決定的。
  · 畫面和旁白必須說「這段鏈上攻擊是事先寫好的參考攻擊（victim_probe 的 DRAIN），不是 AI 這次產生的」：runbook 第 3 段、網頁 `/chain` 橫幅、demo_gate.sh 第 3 段都已統一成這句。
  · WithdrawalQueue 的 `live_attack.py` 是 runbook 的第二備案（3b，先 echo 一行註明換了合約）。
- **D22 備份 runs/**：照 10/28 的做法，放本機私人位置；不放公開 repo、不放 GitHub、不上傳任何雲端公開位置；不刪任何東西，備份後驗 sha256。
  · **10/30 23:37 已做**：`ARBITER_backup/20261030_233732/`（和 10/28 兩份同一層）；bundle sha256 49f79c97…0712、tar 41baae6a…10b2，`sha256sum -c` OK。tar 另含 eval-worktree 的評測結果檔和 release_staging/。

### 使用者 10/31 的決定（D23～D27，看過 P9 階段 A 報告後）
- **D23 0:00 快取用 (a) spark-test-2 錄製回放**，demo_gate.sh 維持預設；不另開 (b)（P8 主設定第 3／6 次）的結果頁。
  檢查 5 口頭照實說（這份錄製紀錄沒有檢查 5），靠問答時揭曉的現場上傳補。
- **D24 首頁剩下的 15 筆不再搬**：P8 第 4、5、8、9 次是 `live_drain_probe.py` 要讀的；其他（P8 第 3、6 次、p6-*、測試上傳、fixture）留在折疊區。
- **D25 公開 repo 用 (甲)**：快轉推送，不 force push、不改寫歷史；p9-single 不推。
  e88e4d1 裡的 `/home/<使用者>`（68 檔 131 處，只有使用者名稱，沒有金鑰或 DGX 位址）照實記在報告裡，不另外處理。
- **D26 私人 repo 推 main，另推 tag eval-freeze**；demo-v1 這次不推。
- **D27 公開快照的 `innoserve/docs/CLAUDE.md` 換成最新版（含 P9）**，私人 repo 的名稱和網址一律遮成「私人 repo」：**整個公開快照不能出現私人 repo 的名稱**。
  P9 報告遮蔽後放進 docs/reports；`fullplan_p9/` 裡的 scan_*.txt 不放。
- B3（關公開 repo 的 Actions）和在示範 repo 的允許清單加 `sam029031/arbiter-gate/*` 由使用者自己在 GitHub 設定做；B5、B6 等使用者說「設定好了」再下指示。

### 段落表（預定日期）
| 段 | 內容 | 預定 | 狀態 |
|---|---|---|---|
| P0 | 環境 | 10/29 | **完成**（`reports/fullplan_p0_2026-10-29.md`） |
| P7a | 評測預註冊＋第 1 次夜跑 | 10/29 | 預註冊**完成**（`reports/eval_prereg_2026-10-29.md`）；**r1 主體 10/29 16:49～22:29 跑完**（40 列、585 請求、無 VOID）；22:30～23:09 補跑 3 筆 infra 全部正常跑完（infra 0、other_error 1）；r2 10/29 23:48～10/30 05:06 跑完（40 列全 ok）；**r3 10/30 14:19～19:57 跑完**（提前啟動；40 列全 ok、632 請求） |
| P1 | 回歸測試下載＋SARIF | 10/29～30 | **完成** f69fb39（`reports/fullplan_p1_2026-10-29.md`） |
| P2 | Slither＋MCP | 10/30 | **完成** d3ac2d1（10/29，`reports/fullplan_p2_2026-10-29.md`） |
| P3 | Docker 沙箱 | 10/31 | **完成** d020eaa（10/29，`reports/fullplan_p3_2026-10-29.md`） |
| P4 | 網頁改版 | 11/1～2 | **完成** b62ce80（10/29，`reports/fullplan_p4_2026-10-29.md`） |
| P7b | 彙整評測（3 次跑完後） | 11/1 之後 | **彙整完成**（10/30 晚，`reports/eval_arbitergpt_v3_2026-10-30.md`；修補統計 27 筆全做完）；待決定 2 項已由 **D17、D18** 決定；資料公開只準備、未推送 |
| P5 | GitHub PR 整合 | 11/3 | **完成** b318c16（10/30，`reports/fullplan_p5_2026-10-30.md`；demo repo PR #6 已於 10/30 合併） |
| P6 | Foundry 專案修補＋檢查 4、5 | 11/4 | **完成** 3d318b9（10/30，`reports/fullplan_p6_2026-10-30.md`） |
| P8 | 可靠度測試 | 11/4 晚 | **10/30 晚做完**（`reports/reliability_final_2026-10-30.md`）：主設定與較少回合數各 10 次，12.4 的 5 個條件都 0 個成立 → **從 0:00 用快取**；low 跳過（D19） |
| P9 | 收尾 | 11/5 | **階段 A 完成**（10/31 01:0x，commit 6af51f2，`reports/fullplan_p9_2026-10-31.md`）：demo_gate.sh／runbook 完整版流程、首頁清理 15 筆、公開快照與私人 main 在本機組好、第四次備份；**沒有推送**。階段 B（推送）待使用者看報告後指示；0:00 快取、首頁剩餘 15 筆、公開 repo 歷史處理待決定 |
評測夜跑：10/29 r1、**10/29 夜 r2（改排，N=2）、10/30 14:19 r3（提前，原訂 20:30）**（最初原訂 10/30 r2、10/31 r3）。

### P0 環境（10/29，報告 `~/innoserve/reports/fullplan_p0_2026-10-29.md`）
- tag **`demo-v1`＝d09b90f**（本機，未 push）：「已知可以 demo 的版本」，任何時候都能 `git switch --detach demo-v1` 回來。
- Docker：Docker Desktop 4.82.0／Engine 29.6.1；`docker run --rm --network none hello-world` rc 0。第一次失敗是因為 Docker Desktop 沒開（docker-desktop distro Stopped），**每次開機要先開 Docker Desktop**。
- Slither **0.11.6**（與 AIS3 同版）在 `~/innoserve/venv-tools/bin/slither`。系統沒有 python3.14-venv（要 sudo），改用 `venv --without-pip`＋PyPA get-pip.py。venv 裡的 solc-select 沒裝 solc，要加 `--solc ~/.svm/0.8.37/solc-0.8.37`。
- pragma：StakingVault、v3_authored 40、test_pairs_v2 70 全是 `^0.8.20`。`~/.svm` 有 0.8.20、0.8.37；**forge auto-detect 實際用 0.8.37**。P3 映像兩版都要放，否則結果可能不同。
- 資源：8 執行緒、7.6 GiB 記憶體（Docker 共用）、swap 2 GiB；**VHD 在 C:，C: 只剩 72 GB**。
- 背景程式：systemd=true、沒有 .wslconfig。SSH 通道掛在 Claude Code 那個終端機的 session 下。
  **夜跑時保持一個 Ubuntu 終端機開著（評測和 SSH 通道都放進同一個 tmux），Windows 不能睡眠**，不要 `wsl --shutdown`。
- 合併前檢查全過；demo_gate.sh --auto 33.1 秒，0 個 LLM 請求。P0 沒有 repo 內的改動，所以**沒有 commit**。
- ~~待修：demo_gate.sh 終端機輸出會印個人路徑~~ → **已解決**（P4 起輸出已無個人路徑；P5、P6 的 demo_gate.sh --auto 實測主機路徑 0 個）。

### P7a 評測預註冊（10/29，報告 `~/innoserve/reports/eval_prereg_2026-10-29.md`）
- `arbiter/PREREGISTRATION_arbitergpt_v3.md`＝commit **1c7f896**＝tag **`eval-freeze`**（本機）。腳本 commit：0bb2b9d、17d4930、cf7432f。
  第一次的 tag 打在 7ef4334，空跑發現 pgrep 未錨定而重做（當時 0 列，7ef4334 沒推送）。
- **worktree `~/innoserve/eval-worktree`**（detached＝eval-freeze，.env 已複製）。評測只在這裡跑，runs/ 也在這裡；主目錄繼續開發不影響它。
- 設定：attempts 3、max_turns 16、max_tokens 4096、rpm 45、repeats 1、hermetic、預設 STRICT、**concurrency 1**。
  模型 digest e914c3a9…50a3；v3 sha256 0ab903b9…3d33f。
- 吞吐量（arbiter-gpt，2 份）：c=1 中位數 22.3 秒、c=2 中位數 33.5 秒，兩者每請求都佔 26.7 秒牆鐘（伺服器不會因並行而變快）。
  **每次 40 份預估 3～5 小時，最壞約 11.5 小時**。
- **和指示不同的現況**：h2h-arbiter（07-26）早於 STRICT 謂詞（07-28）與後來的閘門，用的是舊謂詞；0.118～0.303 是 v4（70 份、26 回合、attempts 2），v3 上 AIS3 每種設定只有 1 次（h2h-arbiter 0.267）。
  已寫成已知差異；「變異範圍內」規則兩種讀法都納入。AIS3 的 forge／solc 無紀錄。
- 腳本：
  - `scripts/eval_launch.sh <run-id> [--resume]`：tmux session `eval`，視窗 tunnel／run／watch。
    前置檢查：run-id 只能是 r1～r3、HEAD＝eval-freeze、.env、無其他 gptoss-v3、C: >20 GB、ssh 金鑰登入可用。
  - `--dry-run`（run-id `dryrun`）：通道開在 11435、評測換成空殼，約 14 秒，0 請求。
  - `scripts/eval_watch.sh`：每 10 分鐘記列數、錯誤列、請求數、ledger 最後寫入時間；每分鐘探測 11434，連不上就 respawn tunnel 視窗。
  - `scripts/eval_requeue.py <run-id> [--check]`：預註冊 §7 的補跑規則（`GatewayError: gave up after` 的列移到 .requeued.jsonl，先備份，每份最多 2 次）；`--check` 驗 model_served／ModelMismatch。
  - 通道目標在 `~/.config/arbiter/tunnel.conf`（600，不在 repo），腳本不印位址。
- **run.py 已確認**：連線錯誤的列會寫進 results.jsonl，續跑時會被當成已完成而跳過 → 一定要先跑 eval_requeue.py 再 `--resume`。
  另外 summary 的 `usage` 在續跑時會歸零，所以有效性和成本要以 ledger 為準。
- 夜跑指令與睡前檢查表：報告 §7、§8。r1 跑完後 `eval` session 會留著（tunnel 繼續可用）；下一晚先 `tmux kill-session -t eval` 再啟動 r2。

- **r1 啟動（10/29 16:49:25，紀錄在 `reports/eval_prereg_2026-10-29.md` 末尾「第 1 次啟動紀錄」）**：eval-worktree HEAD＝eval-freeze 1c7f896、無改動；api_smoke PASS；
  `bash scripts/eval_launch.sh gptoss-v3-r1` 前置 7 項 ok，舊的 `ssh -f` 通道（pid 486）已關，**通道現在在 tmux `eval:tunnel`**。
  5 分鐘時 1/40 列（V_reentrancy_unstake proven 78 秒）、10 請求。跑完先看 `runs/gptoss-v3-r1.log` 結尾的 `--check`，有 infra 列照報告 §7 requeue＋--resume。
  **r1 跑完前主目錄不准送 DGX 請求**（`pgrep -af gptoss-v3` 有輸出就不行）。沒有 repo 內改動，所以沒有 commit。

- **r1 補跑（10/29 22:30，紀錄在同一份報告末尾「第 1 次補跑紀錄」）**：`--check` 為 infra 3（V_tx_origin_auth_router、V_slippage_check_skipped_branch 是 HTTP 500 error parsing tool call；S_amm_spot_price_oracle 是 Connection refused）、other_error 1。
  兩筆 HTTP 500 在溫度 0 下每次重試輸出長度相同（2755、3666 tokens），很可能再失敗；照規則最多補跑 2 次，之後記 not_executed。
  **V_amm_spot_price_oracle（RemoteDisconnected，18:44～18:51 DGX 對外網路中斷）不補跑、算 not_executed**：錯誤沒被包成 GatewayError，不符合補跑條件；這是規則的已知缺口，r2、r3 照同一套規則不改。
  **P7b 要人工檢查**：S_unchecked_call_return_buyback、S_missing_deadline_signed_order（修好的版本被證實可攻擊）。
- **r1 補跑結果（23:09 結束）**：3 筆都 3 次嘗試正常跑完（conclude_safe；646／573／1130 秒），HTTP 500 沒有重現（之前「很可能再失敗」是預測，報告已更正）。
  最終 `--check`：40 列、ok 39、other_error 1（V_amm_spot_price_oracle，not_executed）、646 請求、單一模型。指標留給 P7b。
- **r2 啟動（10/29 23:48:39，紀錄在報告末尾「第 2 次啟動紀錄」）**：HEAD＝eval-freeze 無改動、api_smoke PASS、前置 8 項 ok；5 分鐘時 1/40 列、10 請求。
  **r2 跑完前主目錄不准送 DGX 請求、P5 不繼續**；跑完後照 §7 看 `--check`，再做 P5 第 6 步。r3 排 10/30 晚上（先 `tmux kill-session -t eval`）。
- **r3 提前啟動（10/30 14:19:00，紀錄在報告末尾「第 3 次啟動紀錄」）**：
  - 原因：DGX 已閒置、使用者在場可以監看；設定與 r1、r2 完全相同。
  - 啟動前確認：HEAD＝eval-freeze，只有 r1、r2 的 summary.json 未追蹤；r2 `--check` 40 ok；api_smoke PASS；前置 8 項 ok。
  - 5 分鐘時 1/40 列、14 請求。
  - **r3 跑完前主目錄不准送 DGX 請求**；跑完照 §7 看 `--check`，再做 r3 的修補統計（D13、D16）。
- **r3 結束（10/30 19:57:15 rc 0）**：40 列全 ok、632 請求、單一模型、無 ModelMismatch、沒有要補跑的列。`eval` tmux session 已在 20:07 收掉。
  - 之後要用 DGX 時自己開通道：`tmux new-session -d -s dgx -n tunnel && tmux send-keys -t dgx:tunnel "exec bash ~/.config/arbiter/dgx_tunnel.sh" Enter`。
  - 這個腳本形狀同 eval_launch.sh，讀 tunnel.conf，位址不顯示；10/30 晚上開著的就是它（session `dgx`）。
  - 評測要重跑時，eval_launch.sh 會自己關掉別的 11434 通道。

### P1 回歸測試下載＋SARIF＋下載區（10/29，commit f69fb39，報告 `~/innoserve/reports/fullplan_p1_2026-10-29.md`）
- **TestArbiterRegression**（dump.py `write_regression`／`regression_solidity`）：已存的 victim_loss 攻擊＋`testExploitBlocked`（expectRevert 包 arbiterRun）＋`testHonestPath0..3`（取回＋10 wei ≥ 原合約 A）。
  交付檔把 `testArbiterVictimLoss` 改名成 `arbiterVictimLossProof`（不再是 test），所以直接 `forge test` 只跑 5 個回歸測試（和計劃書 6.6「用 match 參數」不同）。
  A 取自 gate.json，產生時不跑 forge。只有 victim_loss＋A/B/G measured 才產生；其他用 `regression_unavailable_reason()` 的白話說明。
- `scripts/regression_probe.py`：原合約／真修補／一律 revert × 兩組素材（V_reentrancy_unstake＋DRAIN；spark-test-2），**6/6**；沒有 runs/ 時用 `--evalset-only`（3/3）。
- `arbiter/sarif.py`：proven→error（漏洞函式定義的行號）、static hint→warning（P2 用 `static_hints`）、未發現→無 result（列在 coverage）、無法判定→executionSuccessful=false。
  官方 schema 在 `arbiter/tests/data/sarif-schema-2.1.0.json`（OASIS errata01，sha256 c3b4bb2d…）；驗證用 `scripts/sarif_validate.py`，要用 venv-tools 的 python（jsonschema 4.26.0）。
- gate.py：`--sarif`、`--regression-out`；gate.json 新增 `artifact{uri,sha256}`、finding 的 `region`、`regression`；**寫出的 gate.json 一律走 `public_report()`，沒有主機路徑**（input.results 變成 `runs/…` 相對路徑）。
- web.py：結果頁「下載區」（.patch／回歸測試 .zip／gate.json／report.sarif，每個附一句用途）。zip 是點下去時即時產生，舊結果頁也能下載。
  `.patch` 的檔頭改成 `src/<原檔名>.sol`，可以在 zip 解開的專案裡 `patch -p1` 套用。「尚未完成」拿掉 SARIF、回歸測試下載兩項。
- 驗收：spark-test-2～5 rc=1、A/B/G 不變；spark-test-1 rc=0；拿掉 forge／Broken.sol rc=2；8 份 SARIF 通過 schema、error 數＝proven 數；82 個下載檔 0 個主機路徑；舊結果頁 19＋5 頁照常。
- 網頁 server 已用新程式碼重新啟動（127.0.0.1:8765）。**改了 web.py 之後要重啟 server**，demo_gate.sh 會沿用已經在跑的舊程序。
- 已知問題（未修）：`dump_run` 的 `reproduces=0`（P1 之前就是如此）：dump 的 foundry.toml `via_ir=true`＋`optimizer=false` 會 stack too deep。影響 `cli.py dump`／`prove`，不影響回歸測試。

### P2 Slither 第二級＋MCP＋dump 修正（10/29，commit d3ac2d1，報告 `~/innoserve/reports/fullplan_p2_2026-10-29.md`）
- `arbiter/arbiter/static_hints.py`（新）：`run_slither(code, filename, work_dir)`，solc 從 ~/.svm 依 pragma（或 context.solc）挑；找 Slither：`$ARBITER_SLITHER`（設了但無效＝沒裝）→ PATH → `<checkout>/../venv-tools/bin/slither`。
  scripts/slither_arm.py 改用它；重跑 v3 和 AIS3 `runs/slither.json` 逐 check 相同（298 筆、Medium/Medium MCC 0.204）。
- gate.py：`--slither auto|off`（預設 auto）。沒證實＋Medium/Medium 提示 → **static_hint_unproven**（rc 0，畫面「這是自動掃描工具的提示，系統沒有證實它真的能被攻擊。」）；
  已證實時提示只當參考；Slither 不能跑時判定不變，寫「靜態分析未執行」。verdict.py 只新增 `with_static_hints()`。SARIF：warning＋`slither/<check>`。
- **spark-test-1 現在是「靜態工具提示但未證實」**（StakingVault 的 reentrancy-eth High/Medium），不再是「未發現可證明攻擊」。即時上傳 StakingVault 沒證實時也一樣；DEMO_RUNBOOK 第 4 段口頭說法已改。
  要示範「未發現」用 Slither 沒提示的合約，或加 `--slither off`。
- proposals.py：Slither 轉換器、專用前言、40 份參考語料的罕見度；run.py 加選用參數 `proposal_renderer`（預設不變）；gate `--slither-proposals` 才打開，**預設關閉**（A/B 沒跑）。
- dump.py：先 `via_ir=false`，Stack too deep 才 `via_ir=true`＋`optimizer=true` → spark-test-2～5、V＋DRAIN dump 都重現 1/1；`cli.py prove` standalone 變 yes。live_replay 沒動。
- demo_gate.sh `--no-smoke`：不連 DGX，和 `--live` 互斥。
- MCP：`scripts/arbiter_mcp.py` 不需要 mcp 套件（手寫 JSON-RPC）；`scripts/mcp_probe.py` 3/3（tools/list、read_source、run_exploit DRAIN 在 V 通過／S 不通過），0 個 LLM 請求。說明 `~/innoserve/docs/mcp_setup.md`（不在 repo）。
- 驗收用的 S_ 合成列在 `runs/gate/fixture-slither-display/`（每列有 fixture_note，畫面標「測試用合成資料」）；r1 跑完後用真實列重驗。
- 陷阱：`pkill -f "<字串>"` 會比對到自己的 shell 指令而把它殺掉；重啟 web 用 `kill $(pgrep -f '^python3 -m arbiter.web')`。

### P3 沙箱（10/29，commit d020eaa，報告 `~/innoserve/reports/fullplan_p3_2026-10-29.md`）
- 映像 **`arbiter-sandbox:p3`**（`service/sandbox/build.sh` 建；本機 forge／anvil／cast 1.8.6＋solc 0.8.20／0.8.37 複製進去並驗 sha256、Slither 0.11.6、/opt/soldeps）。225 MB 壓縮／870 MB 展開。
  **重建映像要連網**，執行時一律 `--network none`。~~chainlink 不在快取~~ → **P6 已解決**（tag 改 `0.8.0`，映像重建，13 個相依都在）。
- `arbiter/arbiter/sandbox.py`：`JobSandbox`（每 job 一容器，唯讀根、tmpfs、host uid、2 GiB／2 CPU／512 pids、只掛 job 目錄、`sleep <job_max>`＋`--rm`、flock 一次一個）。
  `python3 -m arbiter.sandbox exec -- <指令>` 讓我們自己的腳本整支走沙箱。
- `service/bin/{forge,anvil,cast,slither}` → `_sandbox_exec`：`docker exec … env -i PATH=… timeout …`；沒有容器就 rc 126 拒絕，**絕不退回主機**。
- 開關：**網頁上傳一律開（無法關）**；`gate --sandbox on|off`，預設看 `ARBITER_SANDBOX`，再沒有就關；預錄重播、demo_gate、probes 預設關（理由見報告 §3）。
  沙箱不能用：`--file` → not_executed（sandbox_unavailable，0 請求）；重播 → A/B/G「無法重現（沙箱無法使用）」。網頁 job 逾時 → 移除容器、判 not_executed。
- `service/tests/sandbox_assertions.py` **7/7**；開沙箱多 1.5～2.5 秒、記憶體最高約 33～35 MiB（memory.peak）。
- 沙箱即時上傳 1 次（arbiter-gpt）：336 秒、8 請求、未證實 → 靜態提示；**repo 模式 victim_loss 證實累計 9/16**。
- **Docker Desktop 必須開著網頁上傳才能用**；沒開時上傳判「無法判定」。待使用者確認 Docker Desktop 的 Resource Saver 已關閉。
- ~~P6 要處理：repo 模式的相依快取~~ → **P6 已解決**：沙箱 job 把快取的 .sol 複製進 job 目錄（`repo.localize_dep_cache`），見 P6 一節。
- 陷阱：pre-commit 會擋像 `sk-...` 的字串（測試的假金鑰改用 PLACEHOLDER_*，不要 `--no-verify`）。

### P4 網頁改版（10/29，commit b62ce80，報告 `~/innoserve/reports/fullplan_p4_2026-10-29.md`）
- 新檔：`arbiter/arbiter/webui.py`（所有 HTML／CSS／JS，行內、不連外）、`jobs.py`（單一 worker、`runs/gate/jobs/<id>/` 的 job.json＋events.jsonl、快取播放重建）、`progress.py`（事件、白話對照）。web.py 只剩路由／下載／job runner。
- 進度 hooks（純加法）：run.py `on_turn`／`on_row`／`on_request`；gateway.py `on_request` 屬性；patch.py `on_check`／`on_propose`；gate.py `--events FILE`、`--evidence-ladder auto|off`。
- 頁面：`/job/<id>`（7 格、現在在做什麼、活動紀錄、5 燈號；`?stay=1` 不自動跳轉）、`/api/job/<id>?since=N`、`/result/<rid>`（四級判定卡、故事圖、4 情境表、修補前後、證據梯子）、`/result/<rid>/chainreplay/<i>-<j>`、`/chain`（參考攻擊真鏈示範，job 種類 chain）。
  POST：`/upload`、`/demo`（4 份自製示範合約）、`/playback`（spark-test-2，speed 1／4）、`/chain`；`/replay` 仍是同步（demo_gate.sh 用）。
- **上傳後是跳到工作頁，不是結果頁**；改了 web.py／webui.py 後要重啟 server（`kill $(pgrep -f '^python3 -m arbiter.web')`）。
- 證據梯子：gate 背景跑 dump＋prove（多約 4 秒）。spark-test-2 爬到第 2 階；第 3 階不成立（run() revert、只在 8 輪環境造成損失）。
- 快取播放：spark-test-2 原速 123 秒、4 倍速 42 秒；執行耗時沒錄（用平均值、頁面註明）；損失與修補檢查當場用 forge 重跑。
- 實測範圍由 `jobs.timing_history()` 從紀錄算（runs/、runs/gate/、../../runs_archive 的 repo 模式 arbiter-gpt）：目前 16 次，106～465 秒。
- 即時上傳 1 次（示範「存款金庫」、沙箱）：271 秒、7 回合、未證實 → 靜態提示。**repo 模式 victim_loss 證實累計 9/17**。
- demo_gate.sh 輸出已無個人路徑；`--live-upload` 改輪詢工作頁 API。DEMO_RUNBOOK 已更新（第 1 段按「存款金庫」、備援 L1＝首頁快取播放）。
- 用語：畫面 0；例外是技術細節裡 AI 原文節錄與工具名 `conclude_safe`（標「不是系統的判定」）。
- Edge headless 最小視窗 492px：手機截圖用 390px iframe 外框拍。

### P5 GitHub PR 整合（10/29～30，**commit b318c16**（取代 WIP cef8999，沒有 push），報告 `~/innoserve/reports/fullplan_p5_2026-10-30.md`）
- commit **013d06f**（diffscan.py 照抄 7b957d0）、**2d414d5**（只改說明文字；AST 比對程式碼相同）。授權：Team 011 自己寫的 Bastet-CC 程式，受 repo 的 Apache-2.0 涵蓋，不在 NOTICE 的 OneSavie 衍生清單；出處寫在 docstring。
- **WIP commit cef8999**（10/29，合併前檢查尚未跑，沒有 push；P5 完成後再正常 commit）包含：`arbiter/prgate.py`（AST 索引、範圍、未涵蓋、留言、suggestion、回歸測試重跑、fork 拒絕）、gate.py `--repo/--base/--head/--pr-comment/--run-url`、
  `scripts/{diffscan_probe.py 13/13, pr_gate_probe.py 6/6（含 --sandbox）, gate_pr.sh, gate_pr_publish.py}`、`.github/actions/arbiter-gate/action.yml`、`.github/workflows/arbiter-gate.yml`、.gitignore `**/runs/gate-pr/`。
- runner 主機設定 `~/.config/arbiter/gate-runner.env`（600，無秘密）：ARBITER_HOME、ARBITER_DOTENV、**ARBITER_GATE_BLOCK_PATTERN（評測在跑時 PR 檢查一律「無法判定」、0 請求）**。
- **公開 repo https://github.com/sam029031/arbiter-gate-demo**（main 87d1b22：S_reentrancy_unstake、誠實使用者測試 3 個、workflow＋action）。
  設定：fork PR 核准＝all_external_contributors；main 保護（必須通過 check「ARBITER Gate」，app 15368，enforce_admins）；allowed actions＝GitHub 官方＋本 repo。
- runner 套件 `~/innoserve/runner-dl/actions-runner-linux-x64-2.338.2.tar.gz`（sha256 已驗）；預定裝在 `/opt/arbiter-gate-runner`（log 裡不會出現 /home 路徑）；WSL 沒有 libicu，要跑 installdependencies.sh。
  **10/29 17:14 使用者已註冊**（runner `arbiter-gate-wsl`，labels self-hosted/Linux/X64/arbiter-gate，只在這個 repo）；**17:15 起在 tmux session `arbiter-runner` 跑 run.sh（online）**。
  重開機後要重新開：`tmux new-session -d -s arbiter-runner -c /opt/arbiter-gate-runner ./run.sh`（Docker Desktop 也要開）。
- gate.py 加 `--llm-blocked REASON`：gate_pr.sh 偵測到評測在跑時加上它 → 範圍、未涵蓋、回歸測試照跑，需要 AI 的檔案判「無法判定」、0 請求。
  實測（r1 在跑時）：改函式的 PR rc 2、0 請求；只刪除的 PR rc 0、未涵蓋 1；印出的 log 無路徑；r1 ledger 不受影響。pr_gate_probe **7/7**。
- **PR 實測（10/30，r2 跑完後，arbiter-gpt）**：
  - PR #1：引入 V_ 的 commit 71f7ca6 跑 2 次、證實 1 次（第 1 次靜態提示 rc 0，第 2 次 rc 1、error alert、A/B/G 2/2/1 ×3＋2/0/7、2 個 suggestion）；本機照「Commit suggestion」規則套用 → 32077c5 rc 0、alert fixed、CLEAN。
  - PR #2（只刪除）、#3（函式外常數）：rc 0、「未涵蓋」、0 請求。
  - PR #4（加入回歸測試）：重跑 5/5、rc 0。
  - PR #5（有回歸測試時再引入 V_）：回歸測試失敗＋AI 證實 → rc 1。
  - **引入 V_ 共 3 次、證實 2 次**；repo 模式 victim_loss 累計 **11/20**。
  - fork：沒實測，`scripts/action_fork_probe.py` 22/22。
  - DGX 請求 30（PR 27、api_smoke 3）。
  - PR 都沒合併，**PR #1 是決賽的紅轉綠那組，不要合併**。
- **公開 log 發現個人路徑**：actions/checkout 印出 runner 使用者 `.gitconfig` 的路徑 → action.yml 的 checkout 步驟改用空的 `HOME`。demo repo 的修正是 **PR #6（使用者已於 10/30 合併）**；重跑 PR #3 確認新 log 沒有 `/home/`。runner 會印 `Machine name`（主機名稱）：使用者決定保留（見 D10～D12）。
- code scanning 會建一個同名的 check「ARBITER Gate」（紅燈時也是 success，因為 alert 在定義行、不在 diff 行）。main 的必要檢查綁 app 15368（Actions），所以擋得住；**不要改成不綁 app**。
- 網頁：首頁 ③ 連到 `/github`（7 張本機截圖 `arbiter/webassets/github/`，不用網路）和 GitHub PR #1。Security 分頁要登入才看得到，沒有截圖。
- 陷阱：`service/tests/sandbox_assertions.py` 在 **repo 根目錄**跑（不是 arbiter/ 底下）；它的第 7 條會送 1 次 api_smoke。

### P6 Foundry 專案修補＋檢查 4、5（10/30，**commit 3d318b9**，報告 `~/innoserve/reports/fullplan_p6_2026-10-30.md`）
- **相依快取**：沙箱 job 把 `~/soldeps` 的 .sol（14 個套件、2,405 檔、約 2 秒）**複製**進 `<job>/soldeps`，`ARBITER_DEP_CACHE` 指過去（repo.py `default_dep_cache()`）。
  不用硬連結（容器可寫 job 目錄）；不指向 /opt/soldeps（容器只掛 job 目錄的規則不破例）。主機的 `~/soldeps` 是從映像 `docker cp` 匯出的，`service/sandbox/build.sh` 建完會自動匯出。
- **映像重建**：chainlink tag `v0.8.0` 不存在 → `0.8.0`；`build_dep_cache.sh` 任一套件失敗就 exit 1（以前會默默缺）。`arbiter-sandbox:p3` 現在是 `220a1abd…`，13 個相依加 hardhat-shim 全部都在。
- PR #6 已合併；重跑 PR #3 的 log 沒有 `/home/`。
- **patch.py**：
  - repo 模式（`repo={root, rel, solidity}`）：每次建置都 `copy_project()` 到 work 目錄，修補只寫進副本，再對副本跑 `plan_for()` 和 `prepare_context()`。
  - **檢查 4**：在副本跑 `forge test --json --offline`，修補前通過、修補後失敗必須 0；跑不起來記 skipped（不算通過）；單一檔案 not_applicable。
  - **檢查 5**（`repair(reattack_turns=…)`／`patch.reattack()`）：對修補版呼叫 `agent.audit(ruled_out=…)`。證實新攻擊 → 拒收，新攻擊（victim_loss）成為檢查 1 的額外證據；最多 2 次防守，再被打穿就是 `rejected_reattack`「修補未通過再攻擊」。
- **gate**：
  - `--project DIR [--target REL]`、`--reattack on|off`（預設 on）。
  - PR 模式也走 repo 模式修補，所以 PR 檢查現在也會跑檢查 4、5，會變久。
  - gate.json 新增 `patch.timeline`／`patch.reattack`／`gate_checks["4"/"5"]`／`repo_tests`。
  - 開了再攻擊時，沙箱壽命改 3600 秒、網頁 job 時限 3300 秒（只放寬時限）。
- **網頁**：
  - 上傳接受 .zip（20 MB／解壓 100 MB／5,000 檔；擋 zip-slip、符號連結；外層資料夾一律變 `project`）。多份候選時出現選擇合約頁。
  - 結果頁有「攻防過程」時間軸；燈號 7 個；工作頁顯示再攻擊。
- **實測（arbiter-gpt）**：
  - zip 上傳示範 repo 專案（71f7ca6）：證實 → 修補 → **檢查 4 通過（3/3）** → 再攻擊 4 回合未成功；337 秒、12 請求。
  - StakingVault 攻防 3 次：2 次證實並走完（225、154 秒），1 次沒證實。
  - **兩扇門合約 TwoDoorVault**：只修 withdrawAll 的人工修補過了 0～2，**再攻擊從 withdraw(uint256) 打穿**（7 回合、104 秒）。
  - 再攻擊 49～153 秒／次，<10 分鐘，不需縮短。
  - repo 模式 victim_loss 證實（StakingVault 系列）累計 **14/24**。
  - P6 的 DGX 請求共 69 次。
- 新 probe（不需要 LLM）：
  - `repo_patch_probe.py` 5/5（`--sandbox` 6/6，含「修好漏洞但弄壞誠實測試 → 只被檢查 4 擋」）
  - `reattack_probe.py` 5/5（攻守 5 格、額外證據、上限、沒跑完）
  - `project_upload_probe.py` 10/10
  - `reattack_trial.py` 是 LLM 試驗腳本，不是 probe。
- 還沒做：真實流程還沒走到第 2 次防守（AI 都一次修好，只有離線 probe）；有 import 的合約沒有回歸測試下載；要不要在 PR 模式關掉再攻擊待決定。

### P6 後續＋P7b 修補統計前半（10/30 下午，報告 `~/innoserve/reports/p6_followup_p7b_part1_2026-10-30.md`）
- **PR 模式實測**：demo repo **PR #7**（測試，內容同 PR #1 第一個 commit，已關閉、未合併、分支保留）。
  - 4 次檢查、證實 2 次（2 分 22 秒～5 分 25 秒；請求 9／11／4／11）。
  - 證實的那 2 次，留言都有 7 個燈號＋攻防回合表；第 4 次另有「檢查 4：修補前 3 個、修補後 3 個專案測試通過」。
  - 4 份 log 逐行檢查，沒有 `/home/`、DGX 位址、金鑰、email。
  - 發現留言沒寫檢查 4 的測試數 → commit **1ddd0b6** 補上（留言、公開 log 摘要、CLI）。
- **修補統計**：`arbiter/scripts/patch_stats.py`（可續跑，`--stop-at`，偵測到評測就停）。
  - 輸入 eval-worktree r1、r2 結果檔（只讀），輸出 `arbiter/runs/patchstats/patchstats.jsonl`（不 commit）。
  - 沙箱開、再攻擊開、16 回合、3 個提案。
  - **目前做了 19 筆**（r1 9、r2 10＝全部已證實列）。其中 victim_loss 4 筆（兩次 V_reentrancy_unstake、兩次 V_ecrecover_zero_address_session）進了修補閘門，eth_profit／token_profit 照計劃書 6.2 記 skipped。r2 的 liveness_broken 那 1 筆在 10/30 下午補做（見 liveness_broken 修補一節）。
  - S_ 3 筆分開列。結論數字等 r3 做完再寫（「N 次中 M 次」）。
  - 明天補 r3：同一個指令加 `--results …gptoss-v3-r3.results.jsonl`，已做的 19 筆會跳過。
- ~~「計畫書 P7b 第 4 步」原文沒有找到~~ → 使用者已提供原文，見 D13；今天的做法和原文一致，P7b 報告要補「依漏洞類型分列」。
- commit 1ddd0b6、fceb355（沒有 push）。DGX 請求 63 次，最後一個在 13:34。

### liveness_broken 修補（10/30 下午，**commit f365b74**，報告 `~/innoserve/reports/liveness_patch_2026-10-30.md`）
- patch.py：
  - `predicate_of()` 從模板判斷謂詞；`STRICT_PATCHED=(victim_loss, liveness_broken)`。
  - liveness_broken 跑 `TestArbiterExploit`，沒有報告合約和 A/B/G。
  - 檢查 1：exploit 不再成立（編不過算拒收）。
  - **檢查 2：exploit 的失敗訊息含「already fails before the attack」就不合格**。
  - 檢查 5 的 liveness_broken 新攻擊也成為額外證據。
  - liveness_broken 有自己的修補提示。
- gate：liveness_broken 的 finding 進修補閘門，A/B/G 維持「不支援」並附原本的說明；回歸測試用白話寫原因。
- 顯示：沒有 A/B/G 時不顯示「修補後再量一次」；修補說明依謂詞切換。
- `scripts/liveness_patch_probe.py` 9/9（素材是 r2 V_unchecked_call_return_buyback，結果檔只讀）。victim_loss 的 probe 全部照舊。
- **重要發現（待使用者決定 a／b／c，見報告）**：
  - 這支 exploit 的「誠實操作」是無代幣的帳戶 `sell(1 ether)`，在漏洞版能成功正是靠漏洞。
  - 所以 v3 的 S_ 修補和 AI 的正確修補（轉帳失敗就 revert）都被檢查 2 擋下，s_fix 和 always_fail 一樣被擋。
  - 只有「轉帳失敗就 return」能通過，也就是計劃書 6.10 的盲點形狀；規則沒有改。
- LLM：r2 V_unchecked_call_return_buyback 跑了 **3 次**（原本的 skipped 紀錄已另存）：
  - 第 1 次 rejected（L／2／L，提案內容沒存）。
  - 第 2 次 not_executed（HTTP 500 error parsing tool call ×7）。
  - **第 3 次 rejected**（2／L／2；第 0、2 輪是正確修補但被檢查 2 擋，第 1 輪 diff 寫成相對於自己上一版）。
  - 沒有進到檢查 5；DGX 請求 16。
- patch_stats.py 現在會把每個提案（diff、AI 的說明、第一個失敗的檢查、回饋訊息）存進 `rounds`。

### P7b 評測彙整（10/30 晚，**commit a461776**，報告 `~/innoserve/reports/eval_arbitergpt_v3_2026-10-30.md`）
- 新腳本（不用 LLM）：
  - `arbiter/scripts/p7b_report.py`：預註冊第 5、8、9 節，只呼叫 score.py、report_arm.winning_predicate、analyst_cost 的函式；`--slither` 跑第 9 節的 S 臂。輸出 `runs/p7b/metrics.json`。
  - `arbiter/scripts/patch_stats_report.py`：照 D16 挑紀錄。輸出 `runs/patchstats/summary.json`。
  - .gitignore 加 `**/runs/p7b/`。
- 完整性：r1 40 列（ok 39、other_error 1＝V_amm not_executed）、r2／r3 40 列全 ok；三次都只有一個模型、無 ModelMismatch、無 VOID；r3 不用補跑。
- **指標（arbiter-gpt，TUNE）**：
  - as reported：MCC 0.299／0.462／0.500（平均 0.420）；TP 7／9／8、FP 2／1／0。
  - strict only：MCC 0.229／0.285／0.285（平均 0.266）；TP 2／3／3、FP 0。
  - 第 8 節判讀：兩種計分都是「差異在變動範圍內」；沒有一次 ≤ 0；三次全距大於和 AIS3 的差距，所以差距不寫成差異；as reported 的 recall 主要靠寬鬆謂詞（TP 中佔 5／6／5）。
  - 第 9 節：F0 兩種常數基準 MCC 0；Slither 0.11.6 Medium/Medium 是 TP 14、FP 10、MCC 0.204（和 AIS3 存檔相同，solc 0.8.37）。
  - finish_reason=length 18／25／19 次。
- 3 個 FP 人工檢查（forge 重跑，0 LLM）：
  - r1 S_unchecked：攻擊程式自己用假代幣，屬判定條件被鑽。
  - r1 S_missing_deadline：token_profit 不扣付出的 ETH，屬判定條件被鑽。
  - r2 S_weak_randomness：修好版還有「挑時機結算」的真弱點（等 seedOf() 會贏才結算，10 次中 10 次贏），但那支攻擊程式是靠運氣（換時間 10 次中 1 次贏）。
- **修補統計**：
  - 主數字：嚴格謂詞的 V_ 列 8 筆中 6 筆通過；victim_loss 6 筆中 6 筆，liveness_broken 2 筆中 0 筆。
  - 13 個提案，L 擋 3、檢查 2 擋 3、檢查 5 擋 1。
  - 再攻擊 7 次，用嚴格謂詞證實 0 次。
  - r3 V_delegatecall 的第 1 次再攻擊用 **state_change** 證實，程式當成攻破；第 2 版修補多了 `totalDeposits = address(this).balance;`，之後通過。
  - r3 的 8 筆在 20:09～20:24 跑完，21 個請求。
- ~~待使用者決定 2 項~~ → **已決定（10/30 晚）**：檢查 5 的寬鬆謂詞證明見 **D17**（兩個數字並列、程式不改）；r3 V_unchecked 比照 D15 見 **D18**。報告末尾有「使用者決定（10/30 晚）」一節。
- 資料公開：`~/innoserve/release_staging/eval-arbitergpt-v3/`（3 份 summary.json、3 份 results.jsonl.gz、SHA256SUMS、README）。
  - 掃描路徑、DGX、金鑰、email、v1_paired14 扣留的 7 份，全部 0 命中。
  - **沒有推送**，P9 再推（計劃書 9.2：比賽分支，不放 fork）。

### P8 決賽展示可靠度測試（10/30 晚，報告 `~/innoserve/reports/reliability_final_2026-10-30.md`）
- 預先登記 `arbiter/PREREGISTRATION_reliability_p8.md`：commit 4cdca1a（21:16:29，執行前）。加速的使用者決定在結果出來前補記：9ad959c（21:20:31）。
- 驅動腳本 `arbiter/scripts/reliability_p8.py`：
  - 網頁上傳，一次一份；`--direct` 跑同一條 gate 指令。
  - `--summary` 算 12.4 的 5 個條件。
  - 逐次紀錄在 `runs/p8/runs.jsonl`（不 commit）。
- **主設定**（網頁上傳、沙箱、max_turns 16、再攻擊開；arbiter-gpt）：
  - 證實 10 次中 6 次（victim_loss 4、eth_profit 2），最快 80.3 秒。
  - 成功上鏈 10 次中 0 次。
  - 修補通過 10 次中 4 次，含再攻擊 234.8～302.6 秒。
  - 再攻擊 4 次中 0 次證實；94 個請求。
- **較少回合數**（`gate --max-turns 10` 直接跑）：
  - 證實 10 次中 6 次（victim_loss 3、eth_profit 3）。
  - 成功上鏈 0 次。
  - 修補通過 3 次（249.4～343.5 秒）。
  - 第 7 次 Ollama HTTP 500 ×7，1,062 秒後判「無法判定」。
  - 再攻擊也只有 10 回合，比主設定弱，不能說「修補後攻不破」。
- **判定**：兩組都 5 個條件 0 個成立 → 決賽**從 0:00 用快取**。即時上傳照 D6 可在開場背景送出當加分。
- **快取包沒有更新**（0 次成功上鏈）。2:30～3:20 照 12.4 第 5 條改播 WithdrawalQueue 的 `live_attack.py`：23:02 正向 PROVEN、`--patched` NOT PROVEN。DEMO_RUNBOOK 仍寫方案 e（live_attack_stakingvault.py），沒改，待使用者決定。
- **第 3 階（本地鏈）調查，待使用者決定要不要修**：
  - 12 次證實中，無法轉譯 5 次、攻擊交易 revert 5 次。
  - 主設定第 3、6 次是錢被抽走（shortfall 6／7 ETH、attacker_gain 6／7 ETH）卻判不成立。原因是 `live_replay.py:413,448,472-476` 的流出條件，拿兩條鏈「到最後」的總流出相減；受害者在沒攻擊那條鏈的正常提款也算流出，所以剛好抵消。
  - 這個條件來自 AIS3 的 ec5ad6a（刻意保守），但量法和 forge 端不一致：victim_loss 沒有流出條件（`workspace.py:1192-1198`），寬鬆謂詞的 `ArbiterNotDrained` 只量攻擊前後（`:1835-1842`、`:2193-2206`）。
  - 判定程式沒改。這兩次的 job 保留在 `runs/gate/jobs/20261030-212309-109f0d/`、`…-213656-54de09/`，runs/ 還沒備份（上次 10/28）。
- DGX 請求：成功 189 次，另有 10 次 HTTP 錯誤（稽核階段）。
- **P8 之後（D20～D22，commit 2c26f68）**：
  - 第 3 階量法已修，`live_drain_probe.py` 7/7；主設定第 3、6 次事後重判為成立，P8 判定不變。
  - runbook 第 3 段旁白、網頁 `/chain` 橫幅、demo_gate.sh 第 3 段統一成「這段鏈上攻擊是事先寫好的參考攻擊（victim_probe 的 DRAIN），不是 AI 這次產生的」；runbook 加備案 3b（WithdrawalQueue）。
  - 網頁 server 23:31:12 重開（pid 542405）。
  - 完整檢查全過；DGX 請求 2 次（api_smoke）。

### P9 階段 A（10/30 23:5x～10/31 01:0x，**commit 6af51f2**，報告 `~/innoserve/reports/fullplan_p9_2026-10-31.md`）——**沒有任何 push／gh／GitHub 設定／demo repo 改動**
- **demo_gate.sh 改成 12.4 的 6 分鐘腳本**：第 0 段＝12.7 preflight（全部 rc 0 才往下，否則印 `PREFLIGHT FAILED: 不開場，改走 L1`、rc 1）＋網頁＋埠檢查＋方案 e 暖機＋**spark-test-2 錄製回放先放完**（網頁一次一個工作，現場上傳會占住）；
  第 1～6 段＝0:00–1:45 上傳／快取播放、1:45–2:30 結果與 A/B/G、2:30–3:20 證據等級＋方案 e（**鏈上兩向從第 2 段開始背景跑**，前景跑曾 72 秒超過 50 秒預算）、3:20–4:20 修補燈號、4:20–5:10 PR 分頁＋SARIF、5:10–6:00 判定用語；問答揭曉現場上傳。
  新選項 `--preflight-only`、`--talk-pace`、`--cache-result RID`、`--speed`。D7 不做海報 → 「指海報」兩拍改口頭／結果頁頁底。
- 正式計時 `--auto --talk-pace`：preflight 全 rc 0；第 1～6 段程式時間 0.3／1.0／12.6（背景兩向共 57.5）／0.2／0.6／0.1 秒，合計 14.8／預算 360；6 分鐘實跑 360.3 秒。第 0 段 63～485 秒（**這台晚上效能起伏很大**），runbook 寫提前 15 分鐘。`--live` 沒跑（不送稽核請求）。
- DEMO_RUNBOOK.md 全部改寫（上台前清單、第 0 段、6 分鐘逐段、切換點、L0～L3、個別狀況、實測耗時）。
- webui.py 只改顯示文字：示範合約提示原本寫「P8 會測」（P8 只測 StakingVault）→ 改成實際紀錄。web server 00:56:25 重開（pid 657499）。
- **0:00 快取待使用者決定**：(a) spark-test-2 回放（畫面已標「錄製回放：2026-10-28」，缺檢查 5／攻防過程，A/B/G 只在 8 輪環境受損）；(b) P8 主設定第 3／6 次（有沙箱、檢查 5、1/0/6×4，但畫面標「即時稽核結果」、第 3 階是 D20 前的「沒過」）；(c) 新錄（要先預先登記、用 DGX，畫面標示同 b）。**建議 (a)**；腳本預設 (a)，(b) 用 `--cache-result 76f5896b7db0`／`81c3a7a659ea`。
- **首頁清理**：P8 的 15 個資料夾（主設定第 1、2、7、10 次、較少回合數 10 次、p8-lowcheck；141 檔）搬到 `~/innoserve/runs_archive/2026-10-31/runs/gate/`，逐檔 sha256 相同；折疊區 30 → 15。jobs/、web/*.json、uploads/ 沒搬（連結照常）。
  **待決定**：P8 第 4、5、8、9 次（`live_drain_probe.py` 讀它們的 dump，搬了 probe 會壞）、p6-*、P3／P4／P6 測試上傳、fixture-slither-display 沒搬。
- **公開快照（本機）** `~/innoserve/release/arbiter-gate-public/`：main **929c043**（接在 e88e4d1 後）、替代分支 **p9-single 695ec5e**（同一棵樹、無歷史）。`git archive 6af51f2`＋innoserve/（README 改寫含評測段落與 Action 用法、docs 與到 P8 的報告、demo_runs、eval/arbitergpt-v3、media）。
  - 遮蔽：docs／reports 的家目錄 → `~`、DGX → `<DGX 位址>`／`<user>`、email → 佔位字；**demo_runs 的路徑改成相對於 arbiter/**（證據第 2 階照紀錄的絕對路徑讀原始碼，絕對路徑在別台電腦一定停在第 1 階；相對路徑在乾淨 clone 爬到第 2 階）。release_prep／release_push 報告不放。
  - 掃描（`~/innoserve/release/tools/pubscan.py`，DGX 從 tunnel.conf 讀）：DGX 0、金鑰 0、`/home/<使用者>` 0、隊友／作者／學校 email 0、扣留 7 份 sha256 137,084 變體 0。
  - **e88e4d1（已公開）含 `/home/<使用者>` 68 檔 131 處**（demo_runs、報告原始輸出）→ 階段 B 要決定 (甲) 加 commit 或 (乙) 用 p9-single 取代歷史。
  - sha256：ead58ae → 現在 16 相同、**8 有改**（多了 run.py、dump.py、proposals.py、repo.py、live_replay.py；gateway.py 變 +16／−4）；agent.py、tools.py 相同。乾淨 clone 照 README：16 OK／8 FAILED、patch_probe 5/5、`demo_gate.sh --auto --no-smoke` rc 0。
  - `.github/workflows/arbiter-gate.yml` 留在原位（action_fork_probe 讀它）；公開 repo 沒有 runner，可請使用者關 Actions。
- **私人 repo（本機）** `~/innoserve/release/arbiter-gate/` main **0e235cb**＝3b1442c → merge 53456b2（innoserve-gate d09b90f..6af51f2，hash 不變）→ innoserve/ 更新；**快轉，不用 force push**。新歷史掃描乾淨。
- 評測資料公開：公開 repo main 的 `innoserve/eval/arbitergpt-v3/`＋私人 repo main（都已放進本機 commit）。
- demo repo workflow 改 `uses: sam029031/arbiter-gate/.github/actions/arbiter-gate@v1`：**只有 diff**（`reports/fullplan_p9/demo_repo_workflow.diff`）。要先 B1、B2、允許清單加 `sam029031/arbiter-gate/*`（使用者做）；用 PR 改（PR 本身是第一個測試）；再開一個比照 PR #7 的測試 PR；demo 的 action.yml 保留（舊 run 重跑用）。PR #1 不受影響（不對它做新事件就好）。
- **第四次備份** `…/ARBITER_backup/20261031_005648/`：arbiter-audit.bundle `bb177a0b…dfbce0`、innoserve-materials.tar.gz `3981c550…95bf4a`（含 eval-worktree runs、runs_archive 兩個日期）、另加 release 私人／公開兩個 bundle；`sha256sum -c` 4 個 OK、bundle verify okay、clone patch_probe 5/5。
- 完整檢查全過（8 probe、patch 5/5、regression 6/6、mcp 3/3、diffscan 13/13、pr_gate 7/7＋sandbox 7/7、action_fork 22/22、repo_patch 5/5＋sandbox 6/6、reattack 5/5、project_upload 10/10、liveness 10/10、live_drain 7/7、live_attack 兩向、sandbox_assertions 7/7、SARIF、demo_gate --auto rc 0）。
- DGX 請求 4 次（全是 api_smoke）。收尾時誤下一次 `git ls-remote`（唯讀，沒推送），報告第 9 節照實記。
- **階段 B 清單**：報告第 7 節 B1～B6（公開 main＋tag v1、公開 repo Actions、私人 main、demo workflow PR、測試 PR）。

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

- **新 GitHub repo 第一階段：檢查＋本機組裝（10/28，報告 `reports/release_prep_2026-10-28.md`）**——**沒有建 repo、沒有 push**：
  - 組裝在 `~/innoserve/release/arbiter-gate/`（--no-hardlinks clone；**沒有 remote**）：main＝innoserve-gate d09b90f＋commit cb68ece（`innoserve/`：
    README、docs〔CLAUDE.md／DEMO_RUNBOOK.md 的 DGX 位址與帳號改成 `<DGX 位址>`／`<user>`〕、reports 全部、demo_runs〔spark-test-1～5〕、media〔2 PDF＋2 MP4＋SRT，22 MB〕）；
    `ais3/{main,project-grade-upgrade,upgrade_by_sam,rescue/bastet-plus,arbiter-harness}` 分支；6 個 tag 全保留。arbiter-audit 本身沒動。
  - 檢查結果：v1_paired14 只有 blob 3078b2ea（20,063 B），addb6b3a 不存在；7 筆 withheld 在歷史中沒有程式碼（字詞＋sha256 比對 974 blob）；
    秘密掃描沒有真金鑰（測試假值、Solidity 變數、`os.environ`）；AIS3 runs 檔無 withheld 樣本；release 裡 8 probe、patch_probe 5/5、live_attack、demo_gate.sh --auto 照 README 還原後都照常。
  - **待使用者決定**（報告開頭 6 項）：AIS3 runs 14 檔其實在 git 裡（main 也有）；tag `archive/main-pre-consolidation` 與 commit 4212381 寫「含明文金鑰」但已被取代為
    `***REDACTED-ROTATED-AIS3-KEY***`；ais3/main、ais3/upgrade_by_sam（及其 archive tag）有 Bastet 提示原文但無 LICENSE／NOTICE；歷史中有 `/home/<隊友>/`、`/home/ubuntu/`；
    docs 有 `/mnt/c/Users/<user>/…`；commit 作者 4 個身分（含隊友個人 email）要徵得同意。

### 保留的素材（不要刪、不要 commit）
- **第四次本機備份（2026-10-31 00:56，P9 階段 A，最新）**：`…/ARBITER_backup/20261031_005648/`（arbiter-audit.bundle：innoserve-gate 6af51f2；tar 含 runs/、eval-worktree runs、runs_archive/（2026-10-28＋2026-10-31）、reports/、release_staging/、CLAUDE.md（P9 之前）、DEMO_RUNBOOK.md；另含 release 私人／公開兩個 bundle；見 RESTORE.md）。
- **runs_archive（2026-10-31 搬出）**：`~/innoserve/runs_archive/2026-10-31/runs/gate/` 放 P8 的 15 個資料夾（主設定第 1、2、7、10 次、較少回合數 10 次、p8-lowcheck），沒有刪。
- **release/tools**：`~/innoserve/release/tools/pubscan.py`（公開前掃描）、`sanitize.py`（遮蔽；本身含要遮蔽的字串，不要放進任何 repo 或 reports）。
- **第三次本機備份（2026-10-30 23:37，D22）**：`…/ARBITER_backup/20261030_233732/`（bundle：innoserve-gate HEAD 2c26f68；tar 含 runs/、eval-worktree 評測結果、runs_archive/、reports/、release_staging/、CLAUDE.md、DEMO_RUNBOOK.md；sha256 與還原步驟見該資料夾的 RESTORE.md）。10/28 兩份保留。
- `arbiter/runs/spark-test-2～5.{results,ledger}.jsonl`：已證實的 StakingVault exploit。
  `outcome.pocs[]` 裡 `passed && adjudicated` 那筆的 `solidity` 是完整測試檔，patch.py 的檢查 0／1／2 拿來當真實素材，也當預錄 demo 素材。
  runs/ 已在 .gitignore。spark-test-1 留著當「未發現可證明攻擊」的輸出範例。
- **本機備份（2026-10-28 22:24）**：`<本機備份位置>/ARBITER_backup/20261028_222433/`
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
- **新 GitHub repo 第二階段（10/29，報告 `reports/release_push_2026-10-29.md`）：在推送前的檢查停下，沒有建 repo、沒有 push。**
  - 目標 `sam029031/arbiter-gate`（私人），只推 main＋tag innoserve-base。release main 已加 bc9f810（備份路徑改 `<本機備份位置>`、README「歷史說明」；secret_scan 新增 0）。
  - **停止原因**：main 可到達的 059b188、e218add、1ee723a、071c269（07-25）含 Bastet 提示原文 56 個、Tag Definitions.md、bastet-cc/runs（Kaggle 衍生），
    樹中完全沒有 LICENSE／NOTICE（4212381 起才有）。作者信箱只有 ericchen913900 noreply 與 <作者 email>，沒有 <隊友>。
  - gh 已登入 sam029031（scopes 含 repo）。cb68ece 仍含舊備份路徑（推送前可併入 bc9f810）。
  - **待使用者決定**：A 照推私人／B 改寫歷史補 LICENSE（hash 全變）／C 截斷歷史／D 無歷史快照。建議 A，改公開前再處理。
  - repo 建立後要記：網址、目前是私人、改公開前要再確認。→ 見下一項。

- **GitHub repo 已建立並推送（10/29，報告 `reports/release_push_2026-10-29.md`「推送」一節）**：
  - **私人 repo**：main＝3b1442c（bc9f810 併入 cb68ece，parent d09b90f）＋tag innoserve-base（ead58ae）。只推這兩個 ref。
    **這個 repo 不能改成公開**：main 歷史含 059b188、e218add、1ee723a、071c269（07-25）4 個 commit，有 Bastet 提示原文、Tag Definitions.md、
    bastet-cc/runs（Kaggle 衍生資料），樹中沒有 LICENSE／NOTICE。另外它的 innoserve/README.md 第 11 行寫「保留在 ais3/* 分支與 tag 裡」，與實際推送不符（未修）。
  - **公開** https://github.com/sam029031/arbiter-gate ：main＝e88e4d1，**只有 1 個 commit、沒有歷史**（git archive 3b1442c 的檔案樹，只改 innoserve/README.md：
    快照說明、貢獻者、對 yeee3642/arbiter-audit ead58ae 的 sha256 對照表與比對指令）。公開前檢查全過；/tmp clone 驗證 patch_probe 5/5、demo_gate.sh --auto rc 0、
    sha256sum -c 21 OK／3 FAILED（gateway.py、workspace.py、cli.py，與 README 預期相同）。
  - 本機：`~/innoserve/release/arbiter-gate/`（完整，remote＝私人 repo；ais3/* 分支與其他 tag 只在本機）、`~/innoserve/release/arbiter-gate-public/`（remote＝公開 repo）。
  - arbiter-audit 沒動（remote 仍是 yeee3642）。之後 arbiter-audit 有新 commit 時，兩個 repo 都不會自動更新。
- 決賽前：排練產生的網頁上傳（runs/gate/gate-StakingVault-*）上台前再搬到 runs_archive；之後 runs/ 或 runs_archive/ 有新素材時照第二次備份的做法重新備份（tar 含 runs_archive/）。
- 11/3 可靠度測試 10 次（決賽 demo 備援，計劃 12、13）：victim_loss 與非 strict、hermetic 與 repo 分開統計，並記錄耗時；
  可直接用 `scripts/demo_gate.sh --auto --live --live-upload --timings F` 連跑，順便量整套流程。上台前再完整排練一次（有人講話、計時）。
- Step 2c：SARIF、回歸測試下載（`TestArbiterRegression`）。
