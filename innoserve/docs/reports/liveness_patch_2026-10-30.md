# liveness_broken 的修補閘門（2026-10-30）

數字的模型一律是 **arbiter-gpt**（gpt-oss 120B，DGX）。
- 開始時 HEAD＝fceb355；本次 commit **f365b74**（沒有 push）。
- eval-worktree 沒有任何改動，結果檔只讀；13:48 之後 eval-worktree 沒有任何檔案被寫入（`find -newer` 確認）。
- agent.py、tools.py 與 innoserve-base 零差異，workspace.py 仍是 +17／−2。
- 佐證在 `reports/liveness_patch/checks.log`。

**DGX 請求：16 次**，全部在 13:48～13:59，**遠早於 20:15**：
- api_smoke 1
- 第 1 次 3
- 第 2 次 2，加上第 3 個請求回 HTTP 500 的 7 次重試
- 第 3 次 3

## A. 使用者的回答（寫進第 7 節）

1. 「計畫書 P7b 第 4 步」原文已記入第 7 節。今天 r1、r2 的做法和原文一致（多了檢查 4）；P7b 報告要補「依漏洞類型分列」。分母寫法照 §2.3：victim_loss／STRICT 證實的列為分母，skipped 另列原因，不說成修補失敗。
2. 更正：計劃書 6.2 第 1 條是「只修 proven 且謂詞屬於 STRICT_PREDICATES（victim_loss、liveness_broken）的 finding；其他謂詞記 skipped」。所以 liveness_broken 的修補是計劃書範圍內、還沒做的功能，**今天補上**。eth_profit 等寬鬆謂詞維持 skipped，不放寬。

## B. 實作（只動 patch.py 與顯示／probe；核心三檔不動）

- `patch.predicate_of(solidity)`：從 harness 固定的模板判斷謂詞。
  - `contract TestArbiterVictim` → victim_loss。
  - `contract TestArbiterExploit` 且含「already fails before the attack」 → liveness_broken。
- `exploit_from_row`：接受 `STRICT_PATCHED = (victim_loss, liveness_broken)`，其他謂詞照舊 skipped，訊息寫「plan 6.2: strict predicates only」。
- `_Run`：
  - liveness_broken 不附報告合約（沒有 A/B/G）。
  - 攻擊測試跑 `TestArbiterExploit::testArbiterExploit()`。
  - 失敗訊息含「already fails before the attack」時一併記下。
- 檢查 0：在原合約重現，必須成立；`abg` 為 None。
- 檢查 1：已存的 solidity 寫進修補版，編不過就算沒失效、拒收；攻擊測試必須不成立。只有一個環境。
- **檢查 2（計劃書 6.3）**：檢查 1 的失敗訊息是「already fails before the attack」（修補讓這個操作連沒被攻擊時都失敗）就不合格。拒收訊息：「with your patch the ordinary user's operation fails even before any attack. Disabling the operation is not a fix.」
- 檢查 L、3、4、5 和 victim_loss 相同。檢查 5 證實的新攻擊若是 liveness_broken，也會成為檢查 1 的額外證據；在新的修補版上「攻擊前就失敗」也算不合格。
- 修補提示：liveness_broken 用另一份 system prompt（「操作在攻擊前成功、攻擊後失敗」；「讓操作永遠失敗不算修好」），使用者提示列出被弄壞的那個誠實操作。不給攻擊程式碼，和 victim_loss 一樣。
- gate.py：
  - liveness_broken 的 finding 現在會進修補閘門。
  - A/B/G 維持 `not_supported`，附原本的說明「liveness_broken 沒有取回金額；證據是可用性被破壞」，加註 `reproduced: true`。
  - 回歸測試沿用 `regression_unavailable_reason` 的白話說明（「這個漏洞的證據是『功能被弄壞』……」），不顯示成錯誤。
  - 「修補後再量一次」表在沒有 A/B/G 時不顯示（以前會出現 4 列空白）。
- 依謂詞切換的說明文字：
  - 結果頁的「通過驗證只代表…」、PR 留言的修補說明、suggestion 的說明，liveness_broken 都改成「沒有攻擊時一般使用者的操作照常成功」。
- `patch_stats.py`：
  - 每個提案都存下來（diff、AI 的說明、第一個失敗的檢查、回饋訊息）。
  - 過時的「liveness_broken 沒有實作」說明已移除。

victim_loss 路徑沒變：patch_probe 5/5、regression_probe 6/6、repo_patch_probe 5/5（`--sandbox` 6/6）、reattack_probe 5/5。

## 驗收

### 離線 probe：`scripts/liveness_patch_probe.py` **9/9**

- 不需要 LLM。
- 素材：r2 V_unchecked_call_return_buyback 的 exploit `BuybackPoolDrainLiveness2ExploitPoc`，結果檔只讀。
- 誠實操作：`sell(1 ether)`。

| 案例 | 預期 | 實際 |
|---|---|---|
| check0 | 原合約上重現、沒有 A/B/G | pass，abg None |
| **s_fix**（v3 的 S_ 版本，1 行：`require(ok && …)`） | 使用者原本預期「應接受」 | **被檢查 2 單獨擋下**（0／L／3／1 pass，2 fail）——見下面「重要發現」 |
| min_fix（人工最小修補 1 行：轉帳失敗就 `return`，不付錢） | 應接受 | **接受**（0／L／3／1／2 pass，4 不適用） |
| always_revert（sell 第一行 `revert`） | 2 和 L 擋下 | L fail、2 fail |
| always_fail（`require(amount == 0)`，lint 抓不到） | 2 擋下 | 只有 2 fail（L／3／1 pass）：證明真正擋住它的是檢查 2 |
| deleted（刪掉 sell） | 3 擋下 | 3 fail（removed `BuybackPool.sell(uint256)`），另外 L、1、2 也 fail |
| unchanged（漏洞版當修補） | 1 擋下 | 1 fail，L 也 fail（沒改任何東西） |
| extra（同一支 exploit 當作檢查 5 的新證據） | 對 min_fix 失效、對 always_fail 不合格 | pass／fail（「the honest operation already fails before the attack」） |
| repair_loop（劇本：被 liveness_broken 再攻擊打穿一次） | 新攻擊保留成下一輪的證據 | predicate=liveness_broken、accepted、保留 1 筆額外證據；時間軸 A1:proven → D1:accepted → A2:proven → D2:accepted → A3:not_proven |

### 重要發現（待使用者決定）：這支 exploit 的「誠實操作」本身就依賴漏洞

- exploit 用一個**手上沒有代幣**的帳戶（`arbiter.liveness`）呼叫 `sell(1 ether)` 當「誠實操作」。
- 在漏洞版（V_）上它會成功，正是因為漏洞：`sell` 不檢查代幣轉帳的結果，沒拿到代幣也照付 ETH。
- 所以任何「轉帳失敗就 revert」的正確修補（包括 v3 的 S_、AI 提的修補），都會讓這個操作在攻擊前就失敗。照計劃書 6.3 的檢查 2，這就是「讓操作永遠失敗」，於是被拒收。
- 檢查 2 在這裡分不出「正確修補」和「停用功能」（s_fix 和 always_fail 的結果相同）。
- 能通過的只有「轉帳失敗就 return、不付錢」這種寫法，正好是計劃書 6.10 寫的 liveness_broken 盲點形狀（不做事就返回）。在這份合約裡，它同時也是正確的修補。
- 這也表示這筆 liveness_broken 的證明本身比較弱：
  - 「攻擊後誠實操作失敗」成立，但「攻擊前成功」靠的是漏洞。
  - V_ 本來就是漏洞版，判定沒錯，但「可用性被破壞」這個說法有疑問。
  - P7b 報告寫到這筆時要註明。
- **規則沒有改**（「不要為了讓數字好看改任何攻防設定」）。可能的處理方式，請使用者決定：
  - a. 維持現狀：這類 finding 的修補照實記「未能產生通過驗證的修補」，報告註明原因。
  - b. 在 gate／P7b 對 liveness_broken 加一句說明：「檢查 2 以 exploit 自己的誠實操作為基準；若該操作依賴漏洞，正確修補也會被擋」。
  - c. 另外設計 liveness_broken 的檢查 2（例如要求誠實操作在修補版上、由持有資產的帳戶執行時成功）。這要改 exploit 組裝或另寫基準，屬於新功能，決賽前不建議。

### LLM：patch_stats.py 只重跑 r2 V_unchecked_call_return_buyback

- 原本的 skipped 紀錄先另存：
  - `runs/patchstats/patchstats.20261030-before-liveness.bak.jsonl`：整份備份。
  - `runs/patchstats/patchstats.superseded.jsonl`：被取代的紀錄，加註取代原因。
- 其他 18 筆沒有重跑：腳本跳過，主檔仍是那 18 筆加這一筆的最新結果。
- 前置：`pgrep -af gptoss-v3` 沒有輸出；api_smoke PASS（13:48）。
- 設定和 P6 驗收相同：每列一個沙箱、3 個提案、再攻擊開、16 回合。

**這一筆跑了 3 次（照實）：**

| 次 | 時間 | 結果 | 提案的第一個失敗檢查 | 請求 | 耗時 | 紀錄 |
|---|---|---|---|---|---|---|
| 1 | 13:49 | 修補未通過（rejected） | L、2、L | 3 | 81.2 秒 | superseded（當時腳本沒有存提案內容，無法說明 L 為何失敗） |
| 2 | 13:51 | **沒有完成**（not_executed）：第 3 個提案請求，Ollama 回 HTTP 500「error parsing tool call」（模型寫的 tool call JSON 格式壞掉），溫度 0 下 7 次重試都一樣 | — | 2 個成功，加上 7 次 500 | 327.3 秒 | superseded（job 目錄 `…buyback.run2`） |
| 3 | 13:57 | **修補未通過（rejected）** | 2、L、2 | 3 | 96.1 秒 | **現行紀錄**（主檔） |

第 3 次的三個提案（diff 全文在主檔的 `rounds`）：
- 第 0 輪：在 low-level call 後面加 `require(ok, …)`，並在有回傳值時 `require(abi.decode(ret, (bool)), …)`。**這是正確的修補**；0／L／3／1 pass，**2 fail**（原因見「重要發現」）。
- 第 1 輪：改成直接呼叫 `token.transferFrom` 並 require 回傳值，但 diff 寫成相對於自己上一版修補，而不是原始檔。套用不上，**L fail**（第 7 節陷阱 11 那類行為）。
- 第 2 輪：同樣的直接呼叫寫法，這次相對於原始檔；0／L／3／1 pass，**2 fail**。
- 沒有修補通過，所以**沒有進到檢查 5**；檢查 4 不適用（單一檔案）。

## 合併前檢查（評測沒在跑，完整版；`reports/liveness_patch/checks.log`）

| 檢查 | 結果 |
|---|---|
| agent.py、tools.py 對 innoserve-base | 零差異 |
| workspace.py | +17／−2 |
| 8 個 probe | 8/8 rc 0 |
| patch_probe／regression_probe／mcp_probe | 5/5、6/6、3/3 |
| diffscan_probe／pr_gate_probe（--sandbox）／action_fork_probe | 13/13、7/7（7/7）、22/22 |
| repo_patch_probe（--sandbox）／reattack_probe／project_upload_probe | 5/5（6/6）、5/5、10/10 |
| **新**：liveness_patch_probe | 9/9 |
| live_attack／--patched | PROVEN／NOT PROVEN |
| sandbox_assertions | 7/7，0 skipped，沒有殘留容器 |
| sarif_validate | spark-test-2 通過；r2 重播（含這筆 liveness_broken）通過，error 數 10＝proven 10 |
| demo_gate.sh --auto（完整版，含 api_smoke） | rc 0，主機路徑 0 |
| 結果頁 | r2 重播的結果頁（`984fbffa6541`）顯示「liveness_broken 沒有取回金額；證據是可用性被破壞」和回歸測試的白話原因；沒有 CLEAR、主機路徑 |

## 時間

- 13:59 之後沒有再送 DGX 請求，14:05 收尾。
- 沒有殘留的沙箱容器；tmux `p7b` 已關，`eval` 沒有動。

## 還沒做／待使用者決定

1. 上面「重要發現」的 a／b／c。
2. 明天補 r3：用同一個指令加 r3 結果檔，已做的 19 筆會跳過；r3 裡的 liveness_broken 列會直接進修補閘門。
3. 目前做了 19 筆（r1 9、r2 10）；結論數字和「依漏洞類型分列」等 r3 做完寫進 P7b 報告。
