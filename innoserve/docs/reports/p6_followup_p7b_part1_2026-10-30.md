# P6 後續＋P7b 第 4 步前半（修補統計 r1、r2）（2026-10-30）

數字的模型一律是 **arbiter-gpt**（gpt-oss 120B，DGX）。
- 開始時 HEAD＝3d318b9；這次新增 commit 1ddd0b6（PR 留言補上檢查 4 的測試數）和 fceb355（patch_stats.py 與 .gitignore 的 `runs/patchstats/`）；都沒有 push。
- eval-worktree 沒有任何改動，r1、r2 結果檔只讀。agent.py、tools.py 與 innoserve-base 零差異，workspace.py 仍是 +17／−2。
- 佐證在 `reports/p6_followup/`（PR #7 四次的 Actions log 與留言、修補統計的終端機輸出）。

**DGX 請求：63 次**（api_smoke 1、PR #7 實測 35、修補統計 27）。最後一個請求在 13:34，**遠早於 20:15**；之後沒有再送。

## 0. 使用者決定（已寫進第 7 節 D10～D12）與過時行的更正

- D10：demo repo 在 PR #6 合併前的 6 份公開 Actions log（run 40991523483、40992745484、40993168563、40993341264、40993511867、40993928603，各含一行 `~/.gitconfig`）保留不刪，因為它們是公開、可核對的證據，這一行沒有秘密。**PR #6 之後的新 log 不能再有 `/home/`**；本次 PR #7 的 4 份 log 都沒有（§1.4）。
- D11：runner 印出的 `Machine name` 保留。
- D12：PR 模式的再攻擊（檢查 5）維持預設開。
- 第 7 節過時的行改成現況：
  - P5 列：「待使用者合併 PR #6」→ 已合併。
  - P3 一節：「chainlink 不在快取」→ P6 已解決。
  - P0 一節：「demo_gate.sh 會印個人路徑」→ 已解決（P5、P6 的 `demo_gate.sh --auto` 實測都是 0 個主機路徑）。
  - P5 一節：「PR #6 等使用者合併」→ 已合併。

## 1. PR 模式用新程式實測（demo repo PR #7，已關閉）

### 1.1 前置確認

- runner 的設定 `ARBITER_HOME` 指向本機 arbiter-audit 的 `arbiter/`，HEAD＝**3d318b9**，工作樹乾淨。
- runner `arbiter-gate-wsl` 在線、閒置；demo repo main＝12c7c17（含 PR #6）。
- 第 3、4 次檢查前，加了 commit **1ddd0b6**（§1.5）。

### 1.2 測試 PR

- **PR #7**「測試：P6 之後的 PR 檢查（內容同 PR #1 的第一個 commit）」，分支 `test/p6-pr-mode`。
- 從 main 開分支，`src/StakingVault.sol` 換成 71f7ca6 的內容；diff 和 PR #1 第一個 commit 完全相同（已比對）。專案自己的 `forge test` 3/3。
- PR #1～#6 沒有動。跑完後關閉 PR #7（**不合併**），分支保留，沒有刪任何東西。

### 1.3 四次檢查（同一個 commit bea2d41，run 41006113509 的 attempt 1～4）

| 次 | 程式 | 結果 | PR 檢查耗時 | 請求 |
|---|---|---|---|---|
| 1 | 3d318b9 | **沒證實**：靜態工具提示但未證實，放行 | 5 分 25 秒 | 9 |
| 2 | 3d318b9 | **證實並擋下**（exit 1）；修補第 1 個提案通過；再攻擊 5 回合未成功（54.3 秒）；2 個 suggestion | 5 分 01 秒 | 11（稽核 5、修補＋再攻擊 6） |
| 3 | 1ddd0b6 | **沒證實**：靜態工具提示但未證實，放行 | 2 分 22 秒 | 4 |
| 4 | 1ddd0b6 | **證實並擋下**；修補閘門 7 項全部通過；**檢查 4：修補前 3 個專案測試通過，修補後 3 個通過**；再攻擊 6 回合未成功（106.1 秒） | 3 分 57 秒 | 11 |

- 跑了 4 次，證實 2 次；4 次都列出，沒有只報成功的。
- 第 3、4 次是為了在真實 PR 上看到修正後的「檢查 4 測試數」而重跑的。

### 1.4 PR 留言與公開 log

- 第 2、4 次的留言都有：
  - **7 個燈號那一行**：「修補閘門：重現 通過、改得乾淨 通過、介面不變 通過、同一招失效 通過、一般使用者不受影響 通過、專案自己的測試 通過、換手法再攻擊 通過」。
  - **攻防回合表**（回合／誰／結果／細節）：1 攻擊成功 → 1 修補通過（1 個提案）→ 2 換手法攻擊未成功。
  - 結論句：「修補後再攻擊 1 次（N 回合）未成功。『未成功』只代表這一次換手法沒有找到能成功的攻擊，不代表合約安全。」
- 第 4 次的留言另外有「專案自己的測試（檢查 4）：修補前 3 個通過，修補後 3 個通過。」。
- 第 4 次的公開 log 摘要有 `patch gate: 0:pass … 5:pass`、`project tests (check 4): 3 passed before the patch, 3 after`、`re-attack (check 5): pass, 1 attack(s), 6 request(s), 106.1 s`。
- 留言原文：`reports/p6_followup/pr7_attempt{1..4}_comment.md`。
- 4 份 Actions log（319～356 行）存在 `reports/p6_followup/pr7_attempt{1..4}_actions.log`，逐行比對以下樣式，**實際命中 0**：
  - 比對樣式：`/home/`、`/mnt/`、`/Users/`、DGX 位址、11434、8080、localhost、127.0.0.1、`AIS3_*=`、`ARBITER_*=` 的值、api key、Bearer、`gh*_` token、password、secret、tailscale、`<user>@`、email、`Copying`。
  - 唯一的比對結果是時間戳 `05:12:29.9580803Z` 裡的「8080」，是誤判。
  - `$HOME`、`$ARBITER_HOME` 只是 action 原始碼的變數名稱。

### 1.5 發現並修正的 PR 模式問題（commit 1ddd0b6）

- 第 2 次的留言只寫「專案自己的測試 通過」，**沒寫跑了幾個測試**。有這個數字的 gate.json 會在 job 結束時刪掉。
- 修正後，三處都會寫出測試數：
  - PR 留言加一行「專案自己的測試（檢查 4）：修補前 N 個通過，修補後 M 個通過」（有新失敗就列出；沒跑就寫原因）。
  - 公開 log 摘要和 CLI 報告印出修補閘門各項、檢查 4 的數字、檢查 5 的結果，只有數字和標籤。
- 重跑的 probe：diffscan_probe 13/13、pr_gate_probe 7/7（`--sandbox` 7/7）、action_fork_probe 22/22。摘要的 Python 片段也用 P6 的 zip 上傳 gate.json 離線測過。
- 第 4 次檢查（真實 PR）用的就是這版。沒有改任何攻防設定。

## 2. P7b 第 4 步前半：修補統計（r1、r2）

### 2.1 依據與設定

- **「計畫書 P7b 第 4 步」的原文在交接包、預註冊文件、reports/ 和先前的對話紀錄裡都找不到**（段落表只有「P7b 彙整評測」一行）。這次照使用者 10/30 指示的內容做；如果另有原文，明天補 r3 前請提供，對照後再補。
- 程式：arbiter-audit 1ddd0b6 加上新腳本 `arbiter/scripts/patch_stats.py`（含檢查 4、5）。
- 輸入：eval-worktree 的 `gptoss-v3-r1`、`gptoss-v3-r2` 結果檔（只讀）。
- 輸出：arbiter-audit 的 `runs/patchstats/patchstats.jsonl`（每列一行、append＋fsync），每列一個 job 目錄 `runs/patchstats/jobs/`。
- 設定和 P6 驗收相同：
  - 每列一個沙箱容器（開）。
  - `patch.repair` 最多 3 個提案過檢查 0、L、3、1、2、4。
  - 再攻擊開（`reattack_turns=16`，最多 2 次防守）。
  - 模型 arbiter-gpt:latest。
- **續跑**：已寫進輸出的列，以 `run_id::repeat::sample_id` 為鍵，跳過。`--stop-at HH:MM` 之後不開始新的列；偵測到 `gptoss-v3-` 評測程序就停，不送請求。這次用 `--stop-at 19:50`。
- 在 tmux session `p7b` 執行（不是 `eval`），13:21:50 開始、13:34:45 結束，`EXIT=0`。
- 處理範圍：每一筆 `outcome.proven` 的列。**S_ 開頭的列照樣記錄，分開列，不混進主數字**。
- 修補閘門這一版只支援 victim_loss（計劃書 6.2：其他謂詞記 skipped）。liveness_broken 雖然屬於 STRICT，但它的修補檢查一直沒有實作，照實記 skipped，寫明原因。
- v3 的評測樣本沒有 `path`（hermetic），所以：
  - 再攻擊也用 hermetic 版面，和評測當時的稽核相同。
  - 檢查 4 一律「不適用（單一檔案）」。

### 2.2 進度：**目前做了 19 筆**（r1 9 筆、r2 10 筆，等於兩個結果檔已證實列的全部）

明天補 r3。結論數字等 r3 做完，在 P7b 報告寫成「N 次中 M 次」，這裡不寫。

**V_ 列（主數字的來源）**

| run | 樣本 | 證實謂詞 | 狀態 | 0 | L | 3 | 1 | 2 | 4 | 5 | 提案 | 再攻擊 | 被打穿 | 耗時 | 請求（提案＋再攻擊） |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| r1 | V_reentrancy_unstake | victim_loss | 修補通過 | pass | pass | pass | pass | pass | 不適用 | pass | 1 | 4 回合，109.3 秒，未成功 | 否 | 132.1 秒 | 5（1＋4） |
| r1 | V_missing_access_control_disburse | eth_profit | skipped（謂詞不是 victim_loss） | | | | | | | | | | | 0 | 0 |
| r1 | V_unchecked_call_return_buyback | eth_profit | skipped（同上） | | | | | | | | | | | 0 | 0 |
| r1 | V_delegatecall_unchecked_module | eth_profit | skipped（同上） | | | | | | | | | | | 0 | 0 |
| r1 | V_signature_replay_voucher | eth_profit | skipped（同上） | | | | | | | | | | | 0 | 0 |
| r1 | V_ecrecover_zero_address_session | victim_loss | 修補通過 | pass | pass | pass | pass | pass | 不適用 | pass | 1 | 10 回合，304.6 秒，未成功 | 否 | 331.8 秒 | 11（1＋10） |
| r1 | V_weak_randomness_flip_payout | eth_profit | skipped（同上） | | | | | | | | | | | 0 | 0 |
| r2 | V_reentrancy_unstake | victim_loss | 修補通過 | pass | pass | pass | pass | pass | 不適用 | pass | 1 | 4 回合，97.0 秒，未成功 | 否 | 123.2 秒 | 5（1＋4） |
| r2 | V_missing_access_control_disburse | eth_profit | skipped（同上） | | | | | | | | | | | 0 | 0 |
| r2 | V_unchecked_call_return_buyback | **liveness_broken** | skipped（liveness_broken 的修補檢查沒有實作） | | | | | | | | | | | 0 | 0 |
| r2 | V_delegatecall_unchecked_module | eth_profit | skipped（同上） | | | | | | | | | | | 0 | 0 |
| r2 | V_amm_spot_price_oracle | token_profit | skipped（同上） | | | | | | | | | | | 0 | 0 |
| r2 | V_signature_replay_voucher | eth_profit | skipped（同上） | | | | | | | | | | | 0 | 0 |
| r2 | V_ecrecover_zero_address_session | victim_loss | 修補通過 | pass | pass | pass | pass | pass | 不適用 | pass | 1 | 5 回合，164.9 秒，未成功 | 否 | 180.7 秒 | 6（1＋5） |
| r2 | V_commit_reveal_frontrun | eth_profit | skipped（同上） | | | | | | | | | | | 0 | 0 |
| r2 | V_weak_randomness_flip_payout | eth_profit | skipped（同上） | | | | | | | | | | | 0 | 0 |

**S_ 列（修好的版本卻被證實；分開記，不混進主數字）**

| run | 樣本 | 證實謂詞 | 狀態 |
|---|---|---|---|
| r1 | S_unchecked_call_return_buyback | eth_profit | skipped（謂詞不是 victim_loss） |
| r1 | S_missing_deadline_signed_order | token_profit | skipped（同上） |
| r2 | S_weak_randomness_flip_payout | eth_profit | skipped（同上） |

這 3 筆 S_ 列原本就在 P7b 的人工檢查清單上。它們都沒有進修補閘門，人工檢查照原計畫做。

- 每筆的完整紀錄在 `runs/patchstats/patchstats.jsonl`：時間軸、diff、每道檢查、提案的第一個失敗、再攻擊的回合／秒數／請求／沒成功的原因或新攻擊手法。
- 這次沒有任何一筆被打穿，所以「新攻擊手法」欄是空的。
- 單次再攻擊最長是 r1 V_ecrecover_zero_address_session 的 304.6 秒（10 回合），仍在 10 分鐘內。

### 2.3 要先讓使用者知道的事（不是結論數字）

- 19 筆裡只有 4 筆能進修補閘門，原因是評測的稽核是 hermetic 模式。10/28 已經量過，模型在這個模式下多半選 eth_profit，而 eth_profit 證實的結果沒有修補（計劃書 6.2，第 7 節已知陷阱 13）。
- P7b 報告裡，修補統計的分母要寫清楚是「victim_loss 證實的列」，skipped 的列另外列出原因，不能說成「修補失敗」。
- 腳本的停止與續跑機制這次沒有被觸發（19 筆在 13:34 就做完了）。明天 r3 跑完後，用同一個指令加上 r3 結果檔，就會跳過這 19 筆、只做 r3：
  ```bash
  cd ~/innoserve/arbiter-audit/arbiter && set -a && . ../.env && set +a
  python3 scripts/patch_stats.py --results ~/innoserve/eval-worktree/arbiter/runs/gptoss-v3-r1.results.jsonl \
    --results ~/innoserve/eval-worktree/arbiter/runs/gptoss-v3-r2.results.jsonl \
    --results ~/innoserve/eval-worktree/arbiter/runs/gptoss-v3-r3.results.jsonl \
    --out runs/patchstats/patchstats.jsonl --stop-at HH:MM
  ```

## 3. 時限

- 最後一個 DGX 請求在 **13:34**（修補統計第 16 筆，r2 V_ecrecover_zero_address_session），之後只做文字和 commit，**沒有再送 DGX 請求**。
- r3 由使用者在 20:30 啟動，這份報告與 commit 都在那之前完成。
- 沒有殘留的沙箱容器。tmux 的 `p7b` session 跑完後已關掉；`eval` session 沒有動。

## 4. 還沒做

1. r3 的修補統計（明天，r3 跑完後）。
2. P7b 報告的結論數字（r3 做完才寫）。
3. 「P7b 第 4 步」原文沒找到，見 §2.1。
4. liveness_broken 的修補檢查沒有實作（r2 有 1 筆）。要不要在 P7b 前補，待使用者決定。
