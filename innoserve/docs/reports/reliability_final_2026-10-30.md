# 決賽展示可靠度測試（P8）：StakingVault，arbiter-gpt

- 2026-10-30 21:16～22:51 實測，報告 23:0x 完成。模型一律是 **arbiter-gpt**（gpt-oss 120B，本機 Ollama 伺服器）。
- 預先登記在任何一次執行前 commit：4cdca1a（21:16:29）。加速兩種的使用者決定在主設定還沒有結果時補記：9ad959c（21:20:31）。兩份的原文在下面「預先登記」一節，沒有改。
- **這是 StakingVault 單一合約的展示可靠度，不代表 ARBITER 的一般準確率。**

## 結論（照預先登記第 3 節判定）

**兩組都是 12.4 的 5 個條件 0 個成立，照 12.4 第 4 條：決賽「從 0:00 用快取」**，開場直接說明這是哪一天的實際紀錄。照 D6，即時上傳仍可以在開場送出、在背景當加分，但主線用快取。

| 條件（12.4 第 3 條） | 主設定（網頁上傳、決賽版預設） | 較少回合數（10 回合） |
|---|---|---|
| 10 次中至少 9 次證實 | **不成立**：10 次中 6 次 | **不成立**：10 次中 6 次 |
| 第 9 快的證實時間 ≤ 95 秒 | **不成立**：只有 6 次證實，沒有第 9 快；最快 80.3 秒 | **不成立**：同上；最快 114.9 秒 |
| 至少 9 次上鏈 | **不成立**：10 次中 0 次 | **不成立**：10 次中 0 次 |
| 第 9 快的重播完成時間 ≤ 140 秒 | **不成立**：沒有成功上鏈的 | **不成立**：同左 |
| 第 9 快的修補驗證完成時間 ≤ 190 秒 | **不成立**：修補通過 10 次中 4 次；最快 234.8 秒 | **不成立**：修補通過 10 次中 3 次；最快 249.4 秒 |
| **判定** | **從 0:00 用快取** | **從 0:00 用快取** |

- **gpt-oss 推理強度 low：沒有測**。使用者決定 D19 跳過，理由是主設定卡在證實次數（10 次中 6 次），不是速度。詳見第 9 節，包括中途送出的 1 次確認請求。
- **主設定卡在三件事，不是速度而已**：
  - 證實不到 9 次。
  - 修補加上再攻擊（檢查 5）要 234～303 秒。
  - 本地鏈重播一次都沒成立。
- **上鏈 0 次的原因**（第 7 節）：
  - 12 次證實裡，5 次是寬鬆謂詞，攻擊沒辦法轉成鏈上交易。
  - 5 次是攻擊交易在鏈上 revert。
  - 2 次是錢真的被抽走、受害者領不回來，卻被第 3 階的「流出比較」判不成立。這個判準和 forge 端 victim_loss 的定義不一致，要不要修等使用者決定；P8 數字照現行定義計。
- **2:30～3:20 的後備**：照 12.4 第 5 條，10 次都沒上鏈，改播 WithdrawalQueue 的 `live_attack.py`。23:02 重跑：正向 PROVEN、`--patched` NOT PROVEN（第 8 節）。

## 預先登記（執行前寫好，照抄計劃書 12.4）

寫於 2026-10-30 晚上，**在任何一次 P8 執行之前** commit。門檻照計劃書 12.4（9/28 寫下）原文，結果出來後不改。這裡只把「怎麼量」寫清楚，量法也在執行前定下。

### 1. 計劃書 12.4 原文（照抄）

> 現場跑或全用快取，由預先登記的規則決定（9/28 寫下並 commit，結果出來後不改門檻）：
>
> 1. 11/3（二）在展示筆電上用選定模型，以 `--attempts 1 --max-turns 16`（與 `demo.sh --live` 相同）把 StakingVault 全流程連跑 10 次。
> 2. 每次記錄五項：是否證實；從上傳到證實的秒數；已證實的 exploit 能否經 `live_replay` 上本地鏈（三種翻譯都丟 `Untranslatable` 就上不了鏈）與重播完成秒數；修補是否通過修補閘門；從上傳到修補驗證完成的秒數。
> 3. 同時滿足四項才現場跑：10 次中至少 9 次證實，且第 9 快的證實時間在 95 秒內（1:45 減 10 秒）；至少 9 次上鏈，第 9 快的重播完成時間在 140 秒內（2:30 減 10 秒）；第 9 快的修補驗證完成時間在 190 秒內（3:20 減 10 秒）。
> 4. 未達門檻就從 0:00 開始用快取，開場直接說明這是哪一天的實際紀錄。
> 5. 只要有 1 次成功上鏈，就把那次的重播存進快取包。10 次都無法上鏈，2:30–3:20 改播 WithdrawalQueue 的 `live_attack.py`，畫面註明換了合約。

同節的切換點（原文）：「1:45 時間軸還沒結束：按『載入快取執行』……」「3:20 重播或修補還沒完成：同樣切到快取結果。」

使用者決定 D6：P8 照 12.4 門檻測 10 次，另測兩種加速（gpt-oss 推理強度 low、展示用較少回合數），達門檻才把現場跑升為主線。即時上傳仍可以在開場送出、在背景當加分，但主線照規則判定。

### 2. 這次的對應

| 12.4 | 這次 |
|---|---|
| 11/3、展示筆電 | 10/30 晚起，開發用的這台筆電（WSL2）。決賽是否用同一台，報告裡註明 |
| 選定模型 | arbiter-gpt:latest（gpt-oss 120B，本機 Ollama 伺服器，SSH 通道） |
| `--attempts 1 --max-turns 16` | **主設定＝網頁上傳的現行預設**：`gate --file --mode repo --repair`，attempts 1、max_turns 16、修補最多 3 個提案、檢查 5（再攻擊）開、沙箱開、Slither auto、證據階梯 auto |
| StakingVault 全流程 | `arbiter/examples/StakingVault.sol`（sha256 77c8b55471f4790d…），用瀏覽器同樣的 multipart 上傳 |
| 程式版本 | arbiter-audit a461776 之後的這個 commit（arbiter/arbiter/ 和 a63ccd5 相同；網頁 server 14:22 用這份程式啟動） |

加速兩種（D6）另外各跑 10 次，用同一套量法、同一套門檻。條件見報告；需要改程式才能做到的，先停下來請使用者決定，不自己改。

### 3. 量法（`arbiter/scripts/reliability_p8.py`）

- 一次只跑一份：網頁沒有任何 job 在跑時才上傳，所以時間裡沒有排隊。
- **t0**：網頁收下上傳的時刻（job.json 的 `created`）。所有秒數都是 t0 到下列事件（job 自己的 events.jsonl）。
- **是否證實／證實秒數**：稽核那一列 `proven=true` 的 `row` 事件。這就是判定「已證實可攻擊」的時刻。
  - 照產品實際顯示的判定計數，謂詞是 victim_loss 或寬鬆謂詞都算證實。
  - victim_loss 和寬鬆謂詞的次數分開列。
  - 寬鬆謂詞沒有 A/B/G 和修補，會在修補那一項自然不通過。
- **上鏈／重播秒數**：證據階梯第 3 階（`prove_dump` → `live_replay`，三種翻譯）的 `ladder rung=3` 事件。
  - **「成功上鏈」＝第 3 階通過**，也就是本地鏈上的重播顯示了損失。
  - 另外記「有重播」：至少一種翻譯成功、鏈有跑，但不一定顯示損失。12.4 的括號只寫了「三種翻譯都失敗＝上不了鏈」。2:30 那一拍要顯示「合約餘額被抽走」，所以門檻用較嚴的「成功上鏈」，兩種次數都報。
- **修補是否通過／修補秒數**：`repair_result accepted=true` 事件，也就是修補的最終判定。現行預設有檢查 5，所以這個時間包含再攻擊。
  - 另記第一個通過檢查 0～4 的時間（patch04），只當參考，不用來判門檻。
  - 修補被拒或 `rejected_reattack` 算不通過，沒有修補秒數。
- **結果頁出現**：`done` 事件，另外記錄。
- **第 9 快**：10 次的秒數由小到大排，沒有發生該事件的那次當作無限大，取第 9 個。
  - 「第 9 快的修補驗證完成時間」只計修補通過的次數，所以修補通過不到 9 次就不成立。
- **判定**：下列全部成立才「現場跑」，否則「從 0:00 用快取」。12.4 原文寫「四項」，但列出的是這 5 個條件，全部都要成立：
  - 證實 ≥ 9 次
  - 第 9 快證實 ≤ 95 秒
  - 成功上鏈 ≥ 9 次
  - 第 9 快重播 ≤ 140 秒
  - 第 9 快修補 ≤ 190 秒
- **每一次都算**：上傳失敗、逾時、中斷、DGX 連線問題都照實記成那一次的結果，不補、不換。
- **快取包**：只要有 1 次成功上鏈，就照第 7 節「保留的素材」的做法保存那次的 job 與結果（不刪、重新備份）。
- 也記錄：謂詞、A/B/G、再攻擊結果、請求數（gate.json 的 `llm_requests_this_invocation`）。
- 用語：一律寫「N 次中 M 次」、標明 arbiter-gpt。這是 StakingVault 單一合約的展示可靠度，**不代表一般準確率**。
### 4. 補充：加速兩種的使用者決定（10/30 21:2x）

這時主設定的第 1 次已經跑完，第 2 次正在跑。主設定的結果還沒有出來，使用者這時決定：

- **較少回合數**：
  - 回合上限定為 **10**，現在就定下來，不看主設定的結果再改。
  - 跑法：直接跑網頁 job 完全相同的 gate 指令，只多加 `--max-turns 10`（`reliability_p8.py --direct --max-turns 10`），不改任何程式。
  - 差別是不經過網頁的上傳按鈕，t0 是 gate 啟動前一刻，網頁收下上傳的處理時間（約 1 秒）沒量到。
  - `--max-turns` 同時套用在稽核和再攻擊（檢查 5），所以這個設定的再攻擊比主設定弱。它的再攻擊結果和主設定分開列，**不能拿來說「修補後攻不破」**。
  - 10 次都計入，量法和門檻同第 3 節。
- **gpt-oss 推理強度 low**：
  - 現行 gateway.py 送出的欄位是寫死的，不改程式做不到。
  - 主設定照 12.4 **達門檻**：就不測 low，報告註明「主設定已達門檻，未測」。
  - **沒達門檻**：才在 gateway.py 加一個選用環境變數，沒設就完全不送、預設行為不變。不改 DGX 上的任何設定、不建新模型。
  - 改完先只送 1 次請求，確認 Ollama 真的吃這個參數（completion tokens 或耗時明顯下降）。有效才跑 10 次，量法和門檻同第 3 節；無效就停下來回報。


## 5. 結果：主設定（網頁上傳 StakingVault，沙箱開，max_turns 16，再攻擊開）

21:16:35～21:54:14，一次一份。秒數都從網頁收下上傳的時刻算起。

| # | 開始 | 結果 | 謂詞 | 證實 | 第 3 階（秒、結果） | 修補過 0～4（參考） | 修補最終 | 結果頁 | 再攻擊 | 請求 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 21:16:35 | 未證實（AI 判斷找不到攻擊，conclude_safe） | — | — | — | — | — | 138.2 | — | 3 |
| 2 | 21:18:55 | 未證實（conclude_safe） | — | — | — | — | — | 253.0 | — | 11 |
| 3 | 21:23:09 | 證實 | victim_loss | 80.3 | 92.4，**錢被抽走但判不成立**（見第 7 節） | 109.3 | 通過，269.6 | 270.2 | 5 回合未成功 | 11 |
| 4 | 21:27:42 | 證實 | victim_loss | 190.9 | 202.6，攻擊交易 `run()` revert | 215.0 | 通過，302.6 | 303.1 | 3 回合未成功 | 14 |
| 5 | 21:32:46 | 證實 | eth_profit | 244.8 | 245.5，無法轉成鏈上交易 | — | 不產生（寬鬆謂詞） | 249.1 | — | 8 |
| 6 | 21:36:56 | 證實 | victim_loss | 114.8 | 132.3，**錢被抽走但判不成立** | 143.7 | 通過，244.5 | 244.9 | 4 回合未成功 | 12 |
| 7 | 21:41:03 | 未證實（conclude_safe） | — | — | — | — | — | 247.2 | — | 6 |
| 8 | 21:45:13 | 證實 | victim_loss | 139.1 | 153.1，攻擊交易 `run()` revert | 163.3 | 通過，234.8 | 235.4 | 6 回合未成功 | 11 |
| 9 | 21:49:09 | 證實 | eth_profit | 109.6 | 110.0，無法轉成鏈上交易 | — | 不產生 | 111.8 | — | 8 |
| 10 | 21:51:02 | 未證實（conclude_safe） | — | — | — | — | — | 184.6 | — | 10 |

五項統計（主設定）：

1. **是否證實**：10 次中 6 次（victim_loss 4 次、eth_profit 2 次）。未證實 4 次都是 AI 自己結束（conclude_safe），畫面會顯示「靜態工具提示但未證實」。
2. **證實秒數**：80.3、109.6、114.8、139.1、190.9、244.8。95 秒內只有 1 次。
3. **上鏈**：
   - 成功上鏈（第 3 階成立）10 次中 0 次。
   - 有重播（翻譯成功、鏈有跑）10 次中 4 次，都是 victim_loss。
   - 第 3 階完成秒數 92.4～245.5。
4. **修補是否通過**：10 次中 4 次。victim_loss 4 次中 4 次；eth_profit 照計劃書 6.2 不產生修補。
5. **修補驗證完成秒數**（含再攻擊）：234.8、244.5、269.6、302.6。只算到檢查 0～4 通過的話是 109.3、143.7、163.3、215.0（參考，不用來判門檻）。

- 再攻擊：4 次中 0 次證實（3～6 回合）。
- 請求：94 次成功；稽核階段另有 2 次 HTTP 錯誤，重試後成功。

## 6. 結果：較少回合數（直接跑 gate，`--max-turns 10`）

21:56:35～22:51，指令和網頁 job 相同，只多 `--max-turns 10`。10 次都在 tmux 裡先 `unset ARBITER_REASONING_EFFORT` 才啟動；顧問另從 /proc 確認過，10 次都沒有設這個變數。

| # | 開始 | 結果 | 謂詞 | 證實 | 第 3 階（秒、結果） | 修補過 0～4（參考） | 修補最終 | 結束 | 再攻擊 | 請求 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 21:56:35 | 證實 | victim_loss | 149.5 | 170.1，攻擊交易 revert | 173.2 | 通過，343.5 | 344.2 | 6 回合未成功 | 13 |
| 2 | 22:02:19 | 未證實（10 回合用完，turn_budget_exhausted） | — | — | — | — | — | 201.1 | — | 10 |
| 3 | 22:05:41 | 未證實（conclude_safe） | — | — | — | — | — | 252.0 | — | 9 |
| 4 | 22:09:53 | 證實 | eth_profit | 186.0 | 186.6，無法轉成鏈上交易 | — | 不產生 | 189.9 | — | 9 |
| 5 | 22:13:03 | 證實 | eth_profit | 244.8 | 245.5，無法轉成鏈上交易 | — | 不產生 | 249.4 | — | 9 |
| 6 | 22:17:12 | 證實 | eth_profit | 153.1 | 153.6，無法轉成鏈上交易 | — | 不產生 | 156.9 | — | 8 |
| 7 | 22:19:49 | **無法判定（稽核未完成）** | — | — | — | — | — | **1062.0** | — | 4（另 7 次 HTTP 500） |
| 8 | 22:37:31 | 證實 | victim_loss | 140.4 | 158.1，攻擊交易 revert | 162.0 | 通過，276.8 | 277.5 | 6 回合未成功 | 11 |
| 9 | 22:42:09 | 證實 | victim_loss | 114.9 | 131.5，攻擊交易 revert | 136.3 | 通過，249.4 | 250.2 | 3 回合未成功 | 8 |
| 10 | 22:46:19 | 未證實（conclude_safe） | — | — | — | — | — | 331.9 | — | 10 |

五項統計（較少回合數）：

1. **是否證實**：10 次中 6 次（victim_loss 3 次、eth_profit 3 次）。
2. **證實秒數**：114.9、140.4、149.5、153.1、186.0、244.8。95 秒內 0 次。
3. **上鏈**：
   - 成功上鏈 10 次中 0 次。
   - 有重播 10 次中 3 次。
   - 第 3 階完成秒數 131.5～245.5。
4. **修補是否通過**：10 次中 3 次（victim_loss 3 次中 3 次）。
5. **修補驗證完成秒數**（含再攻擊）：249.4、276.8、343.5。只算到檢查 0～4：136.3、162.0、173.2。

- **再攻擊 3 次中 0 次證實，但這一組的再攻擊上限也是 10 回合，比主設定弱，不能拿來說「修補後攻不破」**（使用者決定）。
- 回合數沒有讓整體變快：證實和修補的秒數都沒有比主設定少。
- **第 7 次為什麼要 1062 秒**（`gateway.py:222-255`，只讀）：
  - 第 4 回合的請求在 168.8 秒送出。
  - Ollama 連續 7 次回 HTTP 500「error parsing tool call」，也就是模型寫的工具呼叫格式它解析不了，gateway 依規則重試 7 次後放棄（GatewayError）。
  - 5xx 重試之間的等待是 2、4、8、16、30、30、30 秒，合計 120 秒。其餘約 770 秒是 7 次生成，每次約 110 秒。溫度 0 下每次輸出相同，所以每次都失敗；r1 評測有過同樣的現象。
  - 這一次照預先登記算進 10 次，判「無法判定」，不補、不換。
- 第 5 次和主設定第 5 次的證實、重播秒數剛好幾乎相同（244.8／245.5）。核對過是兩個不同的 job，開始時間不同，稽核耗時分別是 241.5 和 240.9 秒，照實記錄。
- 請求：91 次成功；稽核階段另有 8 次 HTTP 錯誤（第 7 次的 7 次，加上第 1 次重試成功的 1 次）。

## 7. 本地鏈重播（第 3 階）調查：只讀、不用 LLM、不改程式

### 7.1 12 次證實的分類（核對顧問的分類：相符）

| 類別 | 次數 | 哪幾次 | 說明 |
|---|---|---|---|
| 無法轉成鏈上交易 | 5 | 主設定 5、9；較少回合 4、5、6 | 都是 eth_profit。三種翻譯都不支援，沒有重播 |
| 攻擊交易 revert | 5 | 主設定 4、8；較少回合 1、8、9 | 都是 victim_loss。鏈上的 `run()` revert，受害者領回金額兩條鏈相同、攻擊者獲利 0。較少回合第 8 次另有原因：合成層只有在攻擊重複 8 輪的環境才造成損失，鏈上只跑一輪 |
| 錢被抽走、受害者 exit() revert，仍判不成立 | 2 | 主設定 3、6 | 有攻擊的那條鏈：攻擊成功（`run()`、`sweep()` 都成功），受害者的 `exit()` revert。受害者沒攻擊時領回 6／7 ETH、有攻擊時 0；攻擊者獲利 6／7 ETH；shortfall 6／7 ETH |

### 7.2 主設定第 3、6 次為什麼判不成立

- 判定在 `arbiter/arbiter/live_replay.py:472-476`，4 個條件要全部成立：
  ```
  clean["recovered"] > 0
  and shortfall > 0
  and attacked["attacker_gain"] >= shortfall
  and (max(0, drained) > 0 or target_held_rose)
  ```
- 前三個條件，第 3、6 次都成立（6>0、6>0、6≥6）。**不成立的是第 4 個「流出比較」**。
  - `drained = attacked["target_drained"] - clean["target_drained"]`（`:448`）
  - `target_drained = tgt_pre - 合約在這條鏈最後的餘額`（`:413`）。「最後」是在受害者 `exit()` 之後，所以沒攻擊那條鏈也把受害者自己的提款算成「流出」。
  - 結果：沒攻擊時受害者提走 6 ETH（流出 6），有攻擊時攻擊者抽走 6 ETH（流出 6），相減是 0，就被判「沒有東西離開合約」。
- 所以直接原因**不是「exit() revert 就判 fail」**。受害者 exit() revert 本身是照 forge 端的規則算成「領回 0」（見下）。真正的原因是：**攻擊者剛好抽走受害者原本會領回的全部金額時，兩條鏈的總流出相等，互相抵消**。

### 7.3 是設計還是和 forge 端不一致？

- **計劃書與 CLAUDE.md 第 7 節都沒有規定這個判準**。
  - 計劃書只把它當成既有事實提到：04 章第 14、52 行，07 章第 185 行，08 章第 217 行，09 章第 237 行，內容都是「`ec5ad6a`（2026-07-30）本地鏈判準加入 drain invariant」之後上鏈比例從 12 筆中 8 筆降到 7 筆中 1 筆，要求用現行 harness 重測。
  - CLAUDE.md 第 7 節沒有提到。
- 來源是 AIS3 時期的 commit `ec5ad6a`（2026-07-30，在 innoserve-base 之內；live_replay.py 從 innoserve-base 到現在沒改過）。
  - 用意是擋一個上鏈的誤報：shortfall 10、attacker_gain 10，但合約一毛都沒流出，錢來自攻擊者自己搭的場景。
  - commit 說明原文：「The synthetic harness has always required that value leave the contract being audited; the live path measured it, recorded it as a diagnostic, and never used it」。程式註解在 `live_replay.py:456-470`。
  - 所以「要求錢真的從被稽核的合約流出」是**刻意的保守設計**。
- **但量法和 forge 端不一致**：
  - forge 端的 victim_loss 判定沒有流出條件，只有三條：受害者有攻擊時領回較少、攻擊者有獲利、攻擊者獲利 ≥ 受害者短少（`workspace.py:1192-1198`）。
  - forge 端還明寫「受害者完全領不出來＝領回 0，這是損害，不是錯誤」（`workspace.py:1695-1698`）。主設定第 3、6 次在 forge 端就是這樣證實的（A/B/G 1/0/6、2/0/7）。
  - forge 端確實有流出條件 `ArbiterNotDrained`，但只用在寬鬆謂詞的範本（`workspace.py:2193-2206`），而且只量**攻擊前後**、同一條鏈的合約餘額（`tgtPre`／`tgtPost`，`workspace.py:1835-1842`）。照那個量法，第 3、6 次的攻擊讓合約從 6／7 ETH 變成 0，會成立。
  - 本地鏈則是量**整條鏈到最後（含受害者提款）**再拿兩條鏈相減，所以 commit 說明的「和合成層一樣」在這種情況並不成立。
- **結論**：「要求錢從合約流出」是刻意的保守設計，但第 3 階的量法和 forge 端的定義不一致，會把「攻擊者剛好抽走受害者全部存款」這種最典型的金庫掏空判成不成立。這比較像量法的缺陷，不是計劃書規定的結果。
- 判定程式沒有改。P8 的數字照現行定義計（成功上鏈 0 次）。要不要修、修了之後怎麼處理這兩次，**等使用者決定**。

### 7.4 保留的檔案（不刪）

| 次 | job | 稽核與證據 | 結果頁 |
|---|---|---|---|
| 主設定第 3 次 | `arbiter/runs/gate/jobs/20261030-212309-109f0d/` | `arbiter/runs/gate/web-20261030-212309-109f0d/`（含 dump） | `arbiter/runs/gate/web/76f5896b7db0.json` |
| 主設定第 6 次 | `arbiter/runs/gate/jobs/20261030-213656-54de09/` | `arbiter/runs/gate/web-20261030-213656-54de09/` | `arbiter/runs/gate/web/81c3a7a659ea.json` |

runs/ 不在 git 裡。上一次本機備份是 10/28，這兩次還沒有進任何備份。

- **→ D22（10/30 23:37）已備份**。位置是本機私人資料夾 `<本機備份位置>/ARBITER_backup/20261030_233732/`，和 10/28 的兩份放在同一層，沒有放 repo、GitHub 或任何雲端。
  - 照 10/28 的做法：`arbiter-audit.bundle`（`git bundle --all`，innoserve-gate＝2c26f68）＋`innoserve-materials.tar.gz`＋`RESTORE.md`＋`SHA256SUMS`。
  - tar 包含 arbiter-audit 的 runs/、runs_archive/、reports/、CLAUDE.md、DEMO_RUNBOOK.md，**另外加了** eval-worktree 的評測結果檔（r1～r3，只讀取）和 release_staging/。
  - **上表兩次的 job、dump、結果頁都在 tar 裡**（逐一確認過）。
  - sha256：

| 檔案 | sha256 |
|---|---|
| `arbiter-audit.bundle` | `49f79c978aa2c02fe401a266702f0ba60d8166cd28bcd87494f4f62725ae0712` |
| `innoserve-materials.tar.gz` | `41baae6a2bf322dfcd8f986b10f73221e3e146fb956d0b0ee4f4feff103110b2` |

  - 驗證：
    - 重新讀檔 `sha256sum -c` 兩個都 OK。
    - `git bundle verify` okay；從 bundle clone 的 HEAD＝2c26f68，clone 裡 patch_probe 5/5。
    - tar 解開後抽兩個檔（第 3 次的 gate.json、r3 的 results.jsonl）和原檔 sha256 相同。
    - tar 裡沒有 .env、ssh 設定、私鑰檔。
  - 沒有刪除任何東西；10/28 的兩份備份保留。

### 7.5 D20：修正第 3 階的流出量法，以及事後重判

> **事後重判，不改變 P8 判定，也不改變展示選擇。** P8 的成功上鏈照舊是 20 次中 0 次（第 5～8 節不改），快取包也不因此更新。

- **先確認：第 3 階完全不影響評測計分**。
  - 評測（`cli.py run` → `run.py`）、計分（`score.py`）、判定對應（`verdict.py`）、修補閘門（`patch.py`），以及 P7b 的 `p7b_report.py`、`patch_stats.py`、`patch_stats_report.py`、`eval_requeue.py`，都沒有 import `live_replay` 或 `prove`。
  - 只有 `cli.py` 的 `prove` 子命令、`gate.py` 的證據階梯和幾支示範腳本會用到。
  - eval-worktree（凍結版）也一樣，而且這次沒有動它。所以 r1～r3 的分數和 P7b 的數字都不受影響。
- **改了什麼**（只改 `arbiter/arbiter/live_replay.py`）：
  - `run_world()`：攻擊結束後、受害者 `exit()` 之前，多量一次被稽核合約的餘額（`tgt_post_attack`），記成 `target_held_after_attack` 和 `attack_drained`。這和 forge 端 `workspace.py:1835-1842` 的 tgtPre／tgtPost 一樣，夾住攻擊本身。
  - `replay()`：「錢必須從被稽核合約流出」改用 `attack_drained`；「合約餘額反而增加」的例外也改成攻擊前後比。舊的兩條鏈相減留成診斷欄位 `drained_vs_clean`，不再用來判定。
  - 判定的其他三條（沒攻擊時領得到、受害者短少、攻擊者獲利 ≥ 短少）和門檻「流出 > 0」都沒改。forge 端寬鬆謂詞的 `ArbiterNotDrained` 要求流出 ≥ 攻擊者獲利；這個差別保留，沒有一起改。
- **新的離線 probe** `arbiter/scripts/live_drain_probe.py`（本機 anvil，0 個 LLM 請求；P8 素材先複製到暫存目錄再跑，原檔不動）：**7/7 as expected**

| 案例 | 素材 | 結果 |
|---|---|---|
| (a) 主設定第 3 次 | P8 dump | **成立**：shortfall 6、攻擊者獲利 6、攻擊抽走 6 ETH（舊量法是 0） |
| (a) 主設定第 6 次 | P8 dump | **成立**：shortfall 7、攻擊者獲利 7、攻擊抽走 7 ETH（舊量法是 0） |
| (b) ec5ad6a 要擋的情況 | probe 自己組的：受害者的錢放在 setup 搭的場景合約，攻擊者拿走它，被稽核合約沒被碰 | **不成立**：shortfall 5、攻擊者獲利 5、被稽核合約流出 0。如果拿掉流出條件，這個案例就會被判成立，所以它確實守著這條 |
| (c) 攻擊交易 revert | 主設定第 4、8 次 | **不成立**：鏈上 `run()` revert，shortfall 0、獲利 0 |
| (d) 無法轉譯 | 主設定第 5、9 次 | 三種翻譯都丟 `Untranslatable`，沒有重播 |

- 改之前先用現行程式跑過同樣的 6 份素材：第 3、6 次判不成立（`extracted_from_contract` 0），其他和 P8 相同。確認改動只影響第 3、6 次這一類。
- **其他結果不變**：
  - `live_attack_stakingvault.py` 原合約和 `--patched spark-test-2`，和 10/28 存的 JSON 逐欄相同（含交易 hash）；它和 `live_attack.py` 都不 import `live_replay`。
  - `live_attack.py` 兩個方向和 23:02 相同。
  - regression_probe 6/6，demo_gate.sh `--auto` rc 0。
- **事後重判**：主設定第 3、6 次在新量法下第 3 階成立。照預先登記的定義，若當時就用新量法，主設定的成功上鏈是 10 次中 2 次，仍然遠低於 9 次，5 個條件的判定不變。

## 8. 快取包與 2:30～3:20 的後備

- **快取包：沒有更新**。照預先登記的定義（第 3 階成立），兩組 20 次中成功上鏈 0 次，12.4 第 5 條「有 1 次成功上鏈就存進快取包」沒有觸發。
- 照 12.4 第 5 條「10 次都無法上鏈」：2:30～3:20 改播 WithdrawalQueue 的 `live_attack.py`，畫面註明換了合約。
- 23:02 重跑（紀錄 `reports/reliability_final/live_attack_withdrawalqueue.log`，本機 anvil，0 個 DGX 請求）：

| 指令 | 結果 | 數字 |
|---|---|---|
| `python3 scripts/live_attack.py` | **PROVEN**，rc 0 | 佇列有 6 ETH（5 是受害者的）；佇列被提走 6.0000 ETH，攻擊者淨得 5.9999 ETH（投入 1、gas 231,081），受害者短少 5.0000 ETH，受害者的 claim 失敗 |
| `python3 scripts/live_attack.py --patched` | **NOT PROVEN**，rc 0 | 受害者的 claim 成功；提走 5.0000 ETH（受害者自己的），攻擊者淨得 −0.0000，受害者短少 0 |

- 注意：DEMO_RUNBOOK 目前第 3 段用的是 10/28 決定的方案 e（`live_attack_stakingvault.py`，StakingVault＋DRAIN 參考攻擊）。這次照 12.4 第 5 條確認了 WithdrawalQueue 的後備可用，runbook 沒有改。決賽用哪一個，由使用者決定。

- **使用者決定 D21（10/30 晚）**：2:30～3:20 照用**方案 e**（`live_attack_stakingvault.py`），不改播 WithdrawalQueue。
  - **和 12.4 第 5 條的關係**：方案 e 是 10/28 使用者在 P8 之前就決定的（見 CLAUDE.md 第 7 節「鏈上 demo 已決定：方案 e」），不是看了 P8 結果才選的。
    - 12.4 第 5 條寫於 9/28。當時 StakingVault 還沒有上鏈紀錄，所以寫的後備是 WithdrawalQueue。
    - 10/28 已經改用 StakingVault 加事先寫好的參考攻擊（DRAIN），在本地鏈上成立。
  - **畫面和旁白必須註明**：「這段鏈上攻擊是事先寫好的參考攻擊（victim_probe 的 DRAIN），不是 AI 這次產生的」。逐處確認，原本只有意思相近的句子，這次統一改成這句，只改顯示文字：
    - DEMO_RUNBOOK 第 3 段的旁白
    - 網頁「參考攻擊的真鏈示範」頁的橫幅（`webui.py`）
    - `demo_gate.sh` 第 3 段的終端機說明
  - 網頁 server 為了顯示新文字，在 23:31:12 重開（P8 已經結束）。
  - WithdrawalQueue 的 `live_attack.py` 寫進 runbook 當**第二備案**（備案 3b）：方案 e 在決賽筆電上跑不起來時使用。`live_attack.py` 的輸出沒有合約名稱，所以備案指令先 `echo` 一行「換了合約：WithdrawalQueue……參考攻擊，不是 AI 這次產生的」，讓畫面註明換了合約。

## 9. 推理強度 low：跳過（D19），以及中途送出的 1 次確認請求

- 使用者先前的條件式決定（見預先登記第 4 節）：主設定沒達門檻，才在 gateway.py 加選用環境變數，先送 1 次請求確認有效再跑 10 次。
- 主設定 21:54 判定沒達門檻後，我照這個條件做了：
  - 在 gateway.py 加了 6 行（沒有 commit），並離線確認：沒設變數時送出的欄位和原本完全相同。
  - 21:55:52 送了 1 次確認請求（`runs/p8/lowcheck/`）。用的是和網頁相同的 gate 指令加 `--max-turns 1 --slither off --evidence-ladder off`，不修補、`ARBITER_REASONING_EFFORT=low`。
  - 結果：1 個請求，turn_budget_exhausted（1 回合用完），判「未發現可證明攻擊」。completion 409 tokens、12.9 秒、prompt 5,366 tokens。
  - 主設定 10 次的第 1 回合是 completion 452～4,096 tokens、12.3～103 秒、prompt 5,253～5,255 tokens。
  - 我事先定的「明顯下降」是 tokens 和耗時都低於主設定 10 次的最小值。耗時沒有低於（12.9 對 12.3），所以沒有確認有效，10 次沒有跑。
- **之後使用者決定 D19：跳過 low**。
  - 理由：主設定卡在證實次數（10 次中 6 次），不是速度；降低推理強度解決不了證實次數；程式凍結前不為它改 gateway.py。
  - gateway.py 的 6 行已經用 `git checkout` 改回去，和 a461776 相同，從來沒有 commit。
- `runs/p8/lowcheck`：主設定判定後、收到使用者決定前開始，已中止，**不計入任何設定**。資料保留不刪。
- 較少回合數那 10 次（21:56～22:51）執行時，工作目錄裡的 gateway.py 是加了這 6 行的版本，但變數沒有設，所以送出的請求欄位和原本相同（離線確認過）。網頁 server 是 14:22:02 啟動的同一個程序（pid 沒變），沒有重開，它的環境裡沒有這個變數；主設定那 10 次走的是它。

## 10. 每一次嘗試與 DGX 請求

- 兩組各 10 次全部計入，沒有補跑、沒有替換。失敗與中斷：
  - 主設定未證實 4 次。
  - 較少回合數未證實 3 次，另有無法判定 1 次（第 7 次，HTTP 500×7）。
- `tee` 第一次寫 log 失敗（`runs/p8/` 還不存在），不影響 `runs/p8/runs.jsonl` 的逐次紀錄。
- **DGX 請求（成功的）共 189 次**：

| 項目 | 次數 |
|---|---|
| api_smoke（21:14:50） | 1 |
| 主設定 10 次 | 94 |
| low 確認請求 | 1 |
| 較少回合數 10 次 | 91 |
| 收尾檢查（demo_gate.sh 第 0 段 api_smoke 1、sandbox_assertions 第 7 條 1） | 2 |

- 另外有 **10 次送到 DGX 但回 HTTP 錯誤**，都在稽核階段（主設定 2、較少回合數 8），所以送出的總數是 199。
- 修補與再攻擊階段的 gateway 沒有記錄錯誤重試次數，如果有，不在上面的數字裡。

## 11. 限制

- 這是 StakingVault 單一合約、單一模型、單一伺服器的展示可靠度，**不代表一般準確率**。
- 12.4 寫的是 11/3、展示筆電。這次是 10/30 在開發用的這台筆電上跑；決賽要不要換電腦未定，換的話時間可能不同。
- DGX 是共用的，跑的時候有沒有其他人用沒辦法確認，秒數會受影響。
- 較少回合數是直接跑 gate，不經網頁上傳按鈕；網頁收下上傳的約 1 秒沒量到。

## 12. 檢查與 commit

完整紀錄在 `reports/reliability_final/checks.log`，IP 和家目錄已遮掉。

- **第一輪（22:52～22:59，完整版，評測沒在跑）**：
  - 8 個 probe 8/8。
  - patch_probe 5/5、regression_probe 6/6、mcp_probe 3/3、diffscan_probe 13/13、pr_gate_probe 7/7（`--sandbox` 7/7）、action_fork_probe 22/22。
  - repo_patch_probe 5/5（`--sandbox` 6/6）、reattack_probe 5/5、project_upload_probe 10/10、liveness_patch_probe 10/10。
  - live_attack 正向 PROVEN、`--patched` NOT PROVEN。
  - sandbox_assertions **7/7**，沒有殘留容器。
  - gate spark-test-2 rc 1，SARIF 的 error 數等於 proven 數。
  - demo_gate.sh --auto rc 0，主機路徑 0 個。
  - 其中 sandbox_assertions、gate、demo_gate 這 3 項是腳本的 sandbox_assertions 那行出錯（我改壞了指令），修正後補跑的。log 裡兩次都留著。
  - 這一輪跑的時候，工作目錄裡還有 gateway.py 那 6 行（變數沒有設）。
- **改回 gateway.py 之後補跑一小輪（23:04～23:06，不送 DGX 請求）**：
  - gateway.py 和 a461776 差 0 行；agent.py、tools.py 和 innoserve-base 差 0 行；workspace.py +17／−2。
  - 8 個 probe 8/8、patch_probe 5/5、regression_probe 6/6、reattack_probe 5/5、liveness_patch_probe 10/10。
  - demo_gate.sh --auto --no-smoke rc 0，主機路徑 0 個。
- commit（arbiter-audit，沒有 push）：
  - 4cdca1a：預先登記和驅動腳本，執行前。
  - 9ad959c：加速的使用者決定和 `--direct`，結果出來前。
  - **102764e**：`--summary`。
  - runs/p8/ 不 commit。demo repo 的 PR #1 沒有動。

**D20～D22 之後的完整檢查（23:31～23:35，`reports/live_drain_d20/checks.log`，評測沒在跑）**：

- 8 個 probe 8/8。
- patch_probe 5/5、regression_probe 6/6、mcp_probe 3/3、diffscan_probe 13/13、pr_gate_probe 7/7（`--sandbox` 7/7）、action_fork_probe 22/22。
- repo_patch_probe 5/5（`--sandbox` 6/6）、reattack_probe 5/5、project_upload_probe 10/10、liveness_patch_probe 10/10、**live_drain_probe 7/7**。
- live_attack 正向 PROVEN、`--patched` NOT PROVEN。
- sandbox_assertions 7/7，沒有殘留容器。
- gate spark-test-2 rc 1，SARIF 的 error 數等於 proven 數。
- demo_gate.sh --auto rc 0，主機路徑 0 個。另跑一次 `--no-smoke`：第 3 段印出新句子，原合約 PROVEN、修補後 NOT PROVEN。
- agent.py、tools.py 和 innoserve-base 差 0 行；workspace.py +17／−2；gateway.py 和 a461776 相同。
- **commit 2c26f68**（沒有 push），改動：
  - live_replay.py +16／−2
  - 新增 live_drain_probe.py
  - webui.py、demo_gate.sh 各改 1 行顯示文字
- DEMO_RUNBOOK.md 不在 repo 裡，直接改。
- 這一步的 DGX 請求共 2 次，都是 api_smoke（demo_gate.sh 第 0 段、sandbox_assertions 第 7 條）。probe、事後重判、live_attack 都是本機 anvil，0 次。
