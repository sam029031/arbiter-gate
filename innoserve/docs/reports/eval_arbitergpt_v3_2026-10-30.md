# 評測彙整（P7b）：ARBITER＋arbiter-gpt 在 v3_authored（40 份）跑 3 次

- 日期：2026-10-30。模型一律是 **arbiter-gpt**（gpt-oss 120B，MXFP4，本機 Ollama 伺服器）。資料集是調整系統時用過的 **TUNE** 集。
- 規則：`arbiter/PREREGISTRATION_arbitergpt_v3.md`（tag `eval-freeze`＝1c7f896，跑之前就 commit）。計分沒有加、沒有改。
- 三次評測：gptoss-v3-r1、r2、r3，設定完全相同（attempts 3、max_turns 16、max_tokens 4096、concurrency 1、rpm 45、repeats 1、hermetic、預設 STRICT 謂詞）。

## 結論（白話）

我們準備了 40 份小型智慧合約：20 份故意留了漏洞，另外 20 份是同一份合約把漏洞修好的版本。ARBITER 的做法是讓 AI 實際寫出攻擊程式，在模擬鏈上跑成功才算「證實有漏洞」。同樣的 40 份跑了 3 次：

- **有漏洞的 20 份，每次證實 7～9 份（3 次分別是 7、9、8），其他 11～13 份沒抓到。** 20 組裡有 11 組 3 次都沒抓到。
- **修好的 20 份，被誤判成有漏洞的：第 1 次 2 份、第 2 次 1 份、第 3 次 0 份。** 這 3 份逐一檢查過：2 份是攻擊程式鑽了判定條件的漏洞（攻擊程式自己放了一個假代幣；或「多花 5 倍的錢、買到比較多代幣」被當成獲利），1 份是修好的版本其實沒修乾淨，但那支攻擊程式是靠運氣贏的。
- **證實的大多數，靠的是比較寬鬆的判定標準。** 系統主要的判定標準只有兩種：「一般使用者因為攻擊而少拿回錢」或「一般使用者的操作被弄壞」。但每次證實的 7～9 份裡，只有 2～3 份符合這兩種，其他 5～6 份用的是「攻擊者手上的錢或代幣變多」這種寬鬆標準。**只算嚴格標準的話，有漏洞的 20 份每次只證實 2～3 份**；修好的 20 份則 3 次都沒有被誤判。
- 主要指標是 MCC：-1 到 1，0 代表和「全部回答同一個答案」一樣沒有資訊。
  - 照系統畫面實際顯示的計分：3 次是 0.299、0.462、0.500，平均 0.420。
  - 只算嚴格標準：3 次是 0.229、0.285、0.285，平均 0.266。
  - 沒有任何一次 ≤ 0，所以不寫「換模型後退步」。
  - 和舊模型（AIS3 課程的 nemotron，另一套較舊的 harness）那一次的 0.267 比：依預註冊規則寫成**「差異在變動範圍內」**。而且 3 次之間的差距（0.201）比和舊模型的差距（0.154）還大，所以**不能說新模型比較好，也不能說比較差**。
- **修補：嚴格標準證實的漏洞版共 8 筆（3 次評測合計），8 筆中 6 筆的修補通過系統的檢查**。
  - 通過的 6 筆都是「一般使用者少拿回錢」這一型。
  - 沒通過的 2 筆是同一組合約（買回池沒檢查代幣轉帳結果），提案被「一般使用者操作不受影響」或格式檢查擋下。原因是那支攻擊程式裡的「一般使用者操作」本身就靠漏洞才會成功。→ 見 D18
  - 修補通過後再請 AI 攻擊修補版共 7 次。用嚴格標準，7 次都沒有攻破。有 1 次用寬鬆標準（某個狀態值有改變）證實，程式把它當成攻破、要 AI 再修一次。**這 1 次要不要算「攻破」，規則沒寫，等使用者決定**（第 4.4 節）。→ 見 D17
- 這 40 份都是約 1,600 字元的單檔合約，又是 TUNE 集，**這些數字不能推論到大型專案或一般程式碼**。

## 1. 開工前與完整性（第 0、1 步，不用 LLM）

| 項目 | 結果 |
|---|---|
| 評測程序 | `pgrep -af gptoss-v3` 沒有；GitHub runner 只有 `Runner.Listener` |
| r3 結束 | sessions.log `2026-10-30 19:57:15 end gptoss-v3-r3 rc=0`；watch 最後一筆 40/40、error_rows 0、632 請求 |
| `eval` tmux session | 確認 r3 結束後於 20:07 收掉；改開 tmux `dgx`（tunnel 視窗，形狀同 eval_launch.sh，位址不顯示） |
| api_smoke | 20:07:33 PASS（arbiter-gpt:latest，1 請求） |
| eval-worktree | HEAD＝1c7f896（eval-freeze）；只有 3 個未追蹤的 summary.json；**沒有改任何檔案** |

`scripts/eval_requeue.py <run-id> --check`（20:07:45）：

| | 列數 | 分類 | ledger 請求 | ledger model_served | summary models_seen | ModelMismatch | VOID |
|---|---|---|---|---|---|---|---|
| r1 | 40 | ok 39、other_error 1 | 646 | 只有 arbiter-gpt:latest | 只有 arbiter-gpt:latest | 0 | 否 |
| r2 | 40 | ok 40 | 609 | 只有 arbiter-gpt:latest | 只有 arbiter-gpt:latest | 0 | 否 |
| r3 | 40 | ok 40 | 632 | 只有 arbiter-gpt:latest | 只有 arbiter-gpt:latest | 0 | 否 |

**基礎設施錯誤（預註冊第 7 節），全部列出：**

| run | 列 | 原因 | 處理 | 最後結果 |
|---|---|---|---|---|
| r1 | V_tx_origin_auth_router | GatewayError（HTTP 500 error parsing tool call） | 補跑 1 次（10/29 22:30） | 3 次嘗試都 conclude_safe，判 safe（FN） |
| r1 | V_slippage_check_skipped_branch | GatewayError（HTTP 500 error parsing tool call） | 補跑 1 次 | conclude_safe，判 safe（FN） |
| r1 | S_amm_spot_price_oracle | GatewayError（Connection refused） | 補跑 1 次 | conclude_safe，判 safe（TN） |
| r1 | **V_amm_spot_price_oracle** | `error: RemoteDisconnected`（第 3 次嘗試；前 2 次已 conclude_safe） | **不補跑，算 not_executed**（第 7 節第 2 條：不是 GatewayError） | 計分照 harness 記 safe（FN）。見第 6 節「限制」 |
| r2、r3 | — | 沒有 | — | — |

- r3 沒有需要補跑的列，所以沒有停下來。
- gateway 自己重試後成功的 HTTP 錯誤（不影響結果，只記錄）：r2 4 次、r3 6 次。r1 的 summary 只涵蓋補跑那段，第一段的重試次數沒有紀錄。

## 2. 指標（第 2 步，不用 LLM）

- 程式：`arbiter/scripts/p7b_report.py`（新增）。矩陣用 `score.score()`，mean／min／max 用 `score.summarise_runs()`，as reported 的預測直接取 summary 的 `predictions_by_repeat`（和 results.jsonl 逐列核對一致）。
- 謂詞：`report_arm.winning_predicate()`；strict only 只把 victim_loss、liveness_broken 證實的算 vuln。
- 95% 區間：bootstrap 10,000 次、seed 20260726。MCC 用 `score.bootstrap_delta(a=constant_no, b=run, metric="mcc")`；其他指標用同一個產生器、同樣的抽樣，每次抽樣呼叫 `score.score()`。程式裡檢查過兩種算法的 MCC 區間完全相同。
- 輸出：`arbiter/runs/p7b/metrics.json`（不 commit）。
- 下面每一格的 precision 旁邊都有 recall。

### 2.1 as reported（系統畫面實際顯示的判定）

| run | TP | TN | FP | FN | precision | recall | specificity | F1 | accuracy | **MCC** |
|---|---|---|---|---|---|---|---|---|---|---|
| r1 | 7 | 18 | 2 | 13 | 0.778 [0.455, 1.000] | 0.350 [0.143, 0.562] | 0.900 [0.750, 1.000] | 0.483 [0.231, 0.688] | 0.625 [0.475, 0.775] | **0.299** [0.000, 0.557] |
| r2 | 9 | 19 | 1 | 11 | 0.900 [0.667, 1.000] | 0.450 [0.235, 0.667] | 0.950 [0.833, 1.000] | 0.600 [0.357, 0.783] | 0.700 [0.550, 0.825] | **0.462** [0.202, 0.681] |
| r3 | 8 | 20 | 0 | 12 | 1.000 [1.000, 1.000] | 0.400 [0.188, 0.619] | 1.000 [1.000, 1.000] | 0.571 [0.316, 0.765] | 0.700 [0.550, 0.825] | **0.500** [0.317, 0.682] |
| mean | 8.0 | 19.0 | 1.0 | 12.0 | 0.893 | 0.400 | 0.950 | 0.551 | 0.675 | **0.420** |
| min | 7 | 18 | 0 | 11 | 0.778 | 0.350 | 0.900 | 0.483 | 0.625 | **0.299** |
| max | 9 | 20 | 2 | 13 | 1.000 | 0.450 | 1.000 | 0.600 | 0.700 | **0.500** |

### 2.2 strict only（只算 victim_loss／liveness_broken 證實的）

| run | TP | TN | FP | FN | precision | recall | specificity | F1 | accuracy | **MCC** |
|---|---|---|---|---|---|---|---|---|---|---|
| r1 | 2 | 20 | 0 | 18 | 1.000 [0.000, 1.000] | 0.100 [0.000, 0.250] | 1.000 [1.000, 1.000] | 0.182 [0.000, 0.400] | 0.550 [0.400, 0.700] | **0.229** [0.000, 0.388] |
| r2 | 3 | 20 | 0 | 17 | 1.000 [0.000, 1.000] | 0.150 [0.000, 0.318] | 1.000 [1.000, 1.000] | 0.261 [0.000, 0.483] | 0.575 [0.425, 0.725] | **0.285** [0.000, 0.442] |
| r3 | 3 | 20 | 0 | 17 | 1.000 [0.000, 1.000] | 0.150 [0.000, 0.318] | 1.000 [1.000, 1.000] | 0.261 [0.000, 0.483] | 0.575 [0.425, 0.725] | **0.285** [0.000, 0.454] |
| mean | 2.67 | 20.0 | 0.0 | 17.33 | 1.000 | 0.133 | 1.000 | 0.235 | 0.567 | **0.266** |
| min | 2 | 20 | 0 | 17 | 1.000 | 0.100 | 1.000 | 0.182 | 0.550 | **0.229** |
| max | 3 | 20 | 0 | 18 | 1.000 | 0.150 | 1.000 | 0.261 | 0.575 | **0.285** |

- precision 的下限是 0.000：重抽樣裡如果一份 vuln 都沒預測到，`score.py` 把 precision 記成 0（不是「無法計算」）。這是 score.py 本來的規則，照用。

### 2.3 寬鬆謂詞的證實次數（依謂詞、依 V_／S_）

| run | eth_profit V_ | eth_profit S_ | token_profit V_ | token_profit S_ | state_change V_ | 合計（V_／S_） | 嚴格謂詞證實（V_） |
|---|---|---|---|---|---|---|---|
| r1 | 5 | 1 | 0 | 1 | 0 | 5／2 | 2（victim_loss 2） |
| r2 | 5 | 1 | 1 | 0 | 0 | 6／1 | 3（victim_loss 2、liveness_broken 1） |
| r3 | 4 | 0 | 0 | 0 | 1 | 5／0 | 3（victim_loss 2、liveness_broken 1） |

- **as reported 的 recall 主要由寬鬆謂詞撐起**（第 8 節最後一條）：TP 7／9／8 裡，寬鬆謂詞佔 5／6／5。
- **3 個 FP 全部是寬鬆謂詞證實的**（eth_profit 2、token_profit 1），所以 strict only 的 FP 3 次都是 0。

### 2.4 not_executed（列在矩陣旁，仍在分母、算 safe）

| run | 列 | truth | 原因 |
|---|---|---|---|
| r1 | V_amm_spot_price_oracle | vuln（計為 FN） | `error: RemoteDisconnected: Remote end closed connection without response`（第 3 次嘗試；第 1、2 次 conclude_safe） |
| r2 | — | | |
| r3 | — | | |

context_unbuildable、toolchain_unavailable：3 次都是 0（40/40 可編譯）。

### 2.5 每一組 3 次的結果

`-`＝沒證實；NE＝not_executed；其他＝證實用的謂詞（r1／r2／r3）。S_ 欄只有 3 格不是 `-`（即 3 個 FP）。

| 組 | V_（r1／r2／r3） | S_（r1／r2／r3） |
|---|---|---|
| ecrecover_zero_address_session | victim_loss／victim_loss／victim_loss | -／-／- |
| reentrancy_unstake | victim_loss／victim_loss／eth_profit | -／-／- |
| delegatecall_unchecked_module | eth_profit／eth_profit／victim_loss | -／-／- |
| unchecked_call_return_buyback | eth_profit／liveness_broken／liveness_broken | **eth_profit**／-／- |
| missing_access_control_disburse | eth_profit／eth_profit／eth_profit | -／-／- |
| signature_replay_voucher | eth_profit／eth_profit／eth_profit | -／-／- |
| weak_randomness_flip_payout | eth_profit／eth_profit／state_change | -／**eth_profit**／- |
| commit_reveal_frontrun | -／eth_profit／eth_profit | -／-／- |
| amm_spot_price_oracle | NE／token_profit／- | -／-／- |
| missing_deadline_signed_order | -／-／- | **token_profit**／-／- |
| 其餘 10 組 | -／-／- | -／-／- |

其餘 10 組：approval_double_spend、fee_on_transfer_credit、first_depositor_share_inflation、forced_ether_refund、slippage_check_skipped_branch、stale_cached_price_liquidation、tx_origin_auth_router、uint128_downcast_reward_debt、unbounded_queue_dos、withdraw_rounding_favours_user。加上 missing_deadline_signed_order，V_ 3 次都沒證實的共 11 組。

### 2.6 第 8 節判讀規則（逐條套用）

參考值：h2h-arbiter MCC 0.267（0.2669）；v4 範圍 0.118～0.303，寬度 0.185。

| 規則 | as reported | strict only |
|---|---|---|
| 平均 MCC | 0.420 | 0.266 |
| 和 0.267 的差距 ≤ 0.185？ | 0.154 → **是** | 0.001 → **是** |
| 落在 0.118～0.303？ | 否 | 是 |
| → 寫法 | **「差異在變動範圍內」** | **「差異在變動範圍內」** |
| 任一次 MCC ≤ 0？（→「換模型後退步」） | 否（0.299／0.462／0.500） | 否（0.229／0.285／0.285） |
| 3 次 MCC 全距 vs 和 AIS3 的差距 | 0.201 ＞ 0.154 → **差距不寫成差異** | 0.055 ＞ 0.001 → **差距不寫成差異** |
| precision 旁邊放 recall | 2.1、2.2、2.7、2.10 每張表都有 | 同左 |
| 寬鬆謂詞撐起 recall？ | **是**（TP 7／9／8 中寬鬆 5／6／5），strict only 和它並列在 2.1、2.2 | — |

- 預註冊沒有寫第 8 節要套在哪一種計分上，所以兩種都套；兩種的結論相同，不需要選。
- 第 4 節：謂詞集合和閘門都和 AIS3 不同，就算差距更大也不能只歸因於模型。

### 2.7 第 9 節對照組（0 個 LLM 請求）

| 臂 | TP | TN | FP | FN | precision | recall | specificity | F1 | accuracy | MCC |
|---|---|---|---|---|---|---|---|---|---|---|
| F0 永遠回答「有漏洞」 | 20 | 0 | 20 | 0 | 0.500 | 1.000 | 0.000 | 0.667 | 0.500 | 0.000 |
| F0 永遠回答「沒漏洞」 | 0 | 20 | 0 | 20 | 0.000 | 0.000 | 1.000 | 0.000 | 0.500 | 0.000 |
| S：Slither 0.11.6，impact ≥ Medium 且 confidence ≥ Medium（10/30 重跑） | 14 | 10 | 10 | 6 | 0.583 | 0.700 | 0.500 | 0.636 | 0.600 | 0.204 |
| 參考：AIS3 存的 `runs/slither.json`，同一門檻 | 14 | 10 | 10 | 6 | 0.583 | 0.700 | 0.500 | 0.636 | — | 0.204 |

- Slither：每份跑 1 次，40 份都成功、0 個錯誤，共 298 個 finding（和 AIS3 存檔相同）。solc **0.8.37**（40 份都是；`static_hints.pick_solc` 依 pragma `^0.8.20` 取已安裝的最新版）。門檻照預註冊固定，沒有讀 `best`。
- 預註冊已寫明：Medium/Medium 這個門檻本身是 AIS3 時期看著答案在 v3 上選的，所以 S 是偏樂觀的基準。
- Slither 只給偵測器名稱和行號，沒有可以重跑的攻擊程式。

### 2.8 分析師時間（`analyst_cost.py` 的函式，AIS3 假設不變：未證實 15 分鐘、證實 2 分鐘、誤報一律 15 分鐘）

| run | 回報數 | 真的漏洞 | 分鐘 | 每個真漏洞分鐘 | recall@60 分鐘 |
|---|---|---|---|---|---|
| r1 | 9 | 7 | 44 | 6.3 | 7.0 |
| r2 | 10 | 9 | 33 | 3.7 | 9.0 |
| r3 | 8 | 8 | 16 | 2.0 | 8.0 |

用的是 as reported 的 TP、FP。120～600 分鐘的 recall@budget 和 60 分鐘相同（都在 60 分鐘內看完）。

### 2.9 成本（ledger 為準）

| | r1 | r2 | r3 |
|---|---|---|---|
| 請求數 | 646（含補跑前被移走的 3 列） | 609 | 632 |
| prompt tokens | 6,802,193 | 6,350,295 | 6,936,595 |
| completion tokens | 754,098 | 712,728 | 751,450 |
| 牆鐘時間（sessions.log 加總） | 22,727 秒（6 時 18 分 47 秒；主體 5:39:38＋補跑 0:39:09） | 19,071 秒（5:17:51） | 20,295 秒（5:38:15） |
| 平均回合數（最後結果） | 6.00 | 5.92 | 6.40 |
| 每份平均請求數（各次嘗試回合加總） | 15.88 | 15.22 | 15.80 |
| no_verdict_rate | 0.025（1 列，即 V_amm） | 0.000 | 0.000 |
| finish_reason=length 次數 | **18** | **25** | **19** |
| finish_reason：tool_calls／stop | 544／84 | 511／73 | 538／75 |
| 美元成本 | 0（本機伺服器，沒有計價） | 0 | 0 |

- length 是回應寫到 4096 tokens 上限被截斷。10/28 的 spark-test 是 0 次，這次每次評測都有 18～25 次。max_tokens 照預註冊不改。
- 平均回合數、每份請求數、no_verdict_rate 由 results.jsonl 重算，和 summary 的值相同。

### 2.10 參考：AIS3 時期 nemotron 的數字（**不同模型、不同時間的 harness，只當參考**）

| run（AIS3，nemotron-3-ultra-550b） | 資料 | TP | TN | FP | FN | precision | recall | MCC |
|---|---|---|---|---|---|---|---|---|
| h2h-arbiter（07-26） | v3，16 回合，attempts 3 | 9 | 16 | 4 | 11 | 0.692 | 0.450 | 0.267 |
| cascade-clean | v3，同上 | 6 | 19 | 1 | 14 | 0.857 | 0.300 | 0.329 |
| h2h-cascade | v3，同上 | 7 | 16 | 4 | 13 | 0.636 | 0.350 | 0.168 |
| fixed1／fixed2／casc2-strict（TALK.md） | v4（70 份），26 回合，attempts 2 | 7／13／10 | 31／30／33 | 4／5／2 | 28／22／25 | 0.636／0.722／0.833 | 0.200／0.371／0.286 | 0.118／0.261／0.303 |

- 差異（預註冊第 4 節）：AIS3 可用的謂詞是 eth_profit、token_profit、state_change、liveness_broken（還沒有 STRICT）；閘門較少；concurrency 8；forge／solc 沒有紀錄。
- h2h-arbiter 用同一套分析師時間假設是 78 分鐘（9 個真漏洞、4 個誤報）。

## 3. 人工檢查：修好的版本卻被證實可攻擊的 3 筆（第 3 步，不用 LLM）

**A、B、G 是什麼**（`patch.py` 的 `report_contract`／`parse_trials`）：A＝沒有攻擊時，一般使用者（受害者）最後取回的金額；B＝先發生攻擊後，同一位使用者取回的金額；G＝攻擊者在那次攻擊中淨賺的金額。每份合約在 4 個測試環境各量一次，只有 victim_loss 證實的攻擊才量。

這 3 筆都是寬鬆謂詞證實的，系統沒有量 A/B/G。所以我改讀攻擊程式自己量的兩個數：
- honestGain：一個普通帳戶做一般操作賺到多少。
- attackGain：攻擊者賺到多少。

判定規則是 attackGain 大於 honestGain、而且錢真的是從被測合約流出。下面的數字都用 forge 實際重跑取得（只讀結果檔、0 個 LLM 請求）。另外也跑了幾個變體來確認原因。

| run／列（謂詞） | 結論 | 證據（forge 重跑） |
|---|---|---|
| r1 S_unchecked_call_return_buyback（eth_profit） | **判定條件被鑽了漏洞**：攻擊程式自己決定池子用哪個代幣，用的是「轉帳一律回報成功」的假代幣，所以修補加的那行檢查沒有東西可擋 | 部署寫的是 `new BuybackPool{value: 10 ether}(address(new DummyToken()))`，DummyToken.transferFrom 永遠 return true。honestGain 0.01 ETH、attackGain 9.99 ETH，池子 9.99→0 ETH；同一支程式打漏洞版數字完全相同（修補那行根本沒被用到）。改成合約自己的 GovToken 後：修好版 **FAIL「token transfer failed」**，漏洞版 PASS |
| r1 S_missing_deadline_signed_order（token_profit） | **判定條件被鑽了漏洞**：token_profit 只比代幣數量、不扣掉付出的 ETH；「攻擊」只是多花 5 倍的錢買代幣，而且打的是 SwapPool，不是修補所在的 fill() | 誠實帳戶 1 ETH 換到 453.3 顆；攻擊者 5 次×1 ETH 換到 1,417.5 顆（每 ETH 283.5 顆，比誠實帳戶還差）。拿掉程式裡「強塞 100 ETH 進池子」那行，數字完全相同（池子用自己記的 reserve，強塞的錢沒影響）。攻擊者只換 1 次 1 ETH 時：**ArbiterNoGain**（換到的比誠實帳戶少） |
| r2 S_weak_randomness_flip_payout（eth_profit） | **修好的版本還有同一類的真弱點（沒修乾淨）**，但這支攻擊程式沒有用到它，**是靠運氣押中** | 程式：押 1 ETH、`vm.roll` 往後 300 個區塊、結算；honestGain 0（誠實帳戶什麼都沒做）、attackGain 1 ETH、賭場 10→9 ETH。同一支程式把結算時間往後移 12～120 秒重跑 10 次，**只贏 1 次**（其他 9 次 ArbiterNoGain(0, 0)）。但修好版的 `seedOf()` 是公開函式、結果在結算當下就算得出來，而且誰在什麼時候結算由下注者決定：改成「每個區塊先讀 seedOf()，算出會贏才結算」：先等 300 個區塊再開始讀，**10 次中 10 次贏**；不等 256 個區塊、從下一個區塊就開始讀，也 **5 次中 5 次贏**。這個做法不依賴 blockhash 的值是多少，只要在結算的同一筆交易裡先讀 seedOf() |

- 計分照預註冊不變：3 筆都照 harness 的判定算 FP。
- v3 對這組 S_ 的說明寫「等一個區塊後 blockhash 未知，所以預先計算沒用」；它沒有考慮下注者可以挑結算時機。這是資料集標註的問題，記錄下來，不改標籤。
- 重跑腳本只在 scratchpad，沒有放進 repo，也沒有寫進 eval-worktree。

## 4. 修補統計（第 4 步，用 LLM）

### 4.1 怎麼跑的

- 程式是 arbiter-audit 的最新版（a63ccd5，含 P6 的檢查 4、5 和 liveness_broken 修補）。輸入只讀 eval-worktree 的 r1～r3 結果檔，輸出寫 `arbiter/runs/patchstats/`。
- 設定：沙箱開、再攻擊開（16 回合，最多 2 次防守）、每筆最多 3 個提案。
- r3 在 20:09:12～20:24:02 補做，指令和 r1、r2 相同，只多加 r3 的結果檔。前 19 筆自動跳過，r3 的 8 筆全部跑完，沒有 not_executed，也沒有重跑。開始前把主檔備份成 `patchstats.20261030-before-r3.bak.jsonl`。
- 彙整：`arbiter/scripts/patch_stats_report.py`（新增，不用 LLM）照 D16 挑紀錄，輸出 `runs/patchstats/summary.json`。
- 這一步的 DGX 請求：21 次（r3 V_unchecked 3、V_delegatecall 13、V_ecrecover 5）。另外開工時跑 api_smoke 1 次。

### 4.2 主數字：嚴格謂詞證實的 V_ 列（arbiter-gpt）

分母是 victim_loss／liveness_broken 證實的 V_ 列，3 次評測合計 8 筆。

- **8 筆中 6 筆修補通過**（victim_loss 6 筆中 6 筆；liveness_broken 2 筆中 0 筆）。
- 共 13 個修補提案。每道檢查擋下的次數，以每個提案第一個沒過的檢查計：

| 檢查 | 0 重現 | L 格式 | 3 介面 | 1 同一攻擊失效 | 2 一般使用者不受影響 | 4 專案測試 | 5 再攻擊 |
|---|---|---|---|---|---|---|---|
| 擋下次數 | 0 | 3 | 0 | 0 | 3 | 0 | 1（見 4.4，待決定） |

- 檢查 0：8 筆的攻擊在原合約都重現成功。
- 檢查 4：評測是單檔，8 筆都是「不適用」，沒有實際執行。
- 檢查 L、2 擋下的 6 次都發生在 unchecked_call_return_buyback 的 2 筆。

| 列 | 謂詞 | 結果 | 提案數 | 防守次數 | 每個提案第一個沒過的檢查 | 再攻擊（結果、回合、秒） | 耗時 | 請求 |
|---|---|---|---|---|---|---|---|---|
| r1 V_reentrancy_unstake | victim_loss | 通過 | 1 | 1 | — | 未成功，4 回合，109 秒 | 132 秒 | 5 |
| r1 V_ecrecover_zero_address_session | victim_loss | 通過 | 1 | 1 | — | 未成功，10 回合，305 秒 | 332 秒 | 11 |
| r2 V_reentrancy_unstake | victim_loss | 通過 | 1 | 1 | — | 未成功，4 回合，97 秒 | 123 秒 | 5 |
| r2 V_ecrecover_zero_address_session | victim_loss | 通過 | 1 | 1 | — | 未成功，5 回合，165 秒 | 181 秒 | 6 |
| r2 V_unchecked_call_return_buyback | liveness_broken | 未通過 | 3 | 1 | L、2、L | 沒有進到再攻擊 | 81 秒 | 3 |
| r3 V_delegatecall_unchecked_module | victim_loss | 通過（第 2 個提案） | 2 | 2 | 都通過 0～4 | 第 1 次：**以 state_change 證實**，5 回合，172 秒；第 2 次：未成功，6 回合，325 秒 | 596 秒 | 13 |
| r3 V_ecrecover_zero_address_session | victim_loss | 通過 | 1 | 1 | — | 未成功，4 回合，167 秒 | 193 秒 | 5 |
| r3 V_unchecked_call_return_buyback | liveness_broken | 未通過 | 3 | 1 | 2、L、2 | 沒有進到再攻擊 | 101 秒 | 3 |

- 每筆耗時 81～596 秒（中位數 156 秒）。

### 4.3 依漏洞類型分列

| 類型（組） | v3 的漏洞說明 | 筆數 | 修補通過 | 再攻擊 |
|---|---|---|---|---|
| ecrecover_zero_address_session | ecrecover 對壞簽章回傳 address(0)，剛好等於沒設定 session key 的帳戶預設值 | 3（r1、r2、r3） | 3 筆中 3 筆 | 3 次中 0 次證實 |
| reentrancy_unstake | 提領 ETH 時違反「先記帳再轉帳」造成重入 | 2（r1、r2；r3 用 eth_profit 證實，不在分母） | 2 筆中 2 筆 | 2 次中 0 次證實 |
| delegatecall_unchecked_module | delegatecall 到使用者可控制的位址 | 1（r3；r1、r2 用 eth_profit 證實） | 1 筆中 1 筆（第 2 個提案） | 2 次中 1 次證實（state_change） |
| unchecked_call_return_buyback | 沒檢查低階 call 的回傳值，帳目和實際不符 | 2（r2、r3，都是 liveness_broken） | 2 筆中 0 筆 | 沒有進到再攻擊 |

### 4.4 再攻擊（檢查 5）：7 次，**規則沒寫到的情況，待使用者決定怎麼算** → 見 D17

- 修補通過檢查 0～4 之後，再請 AI 攻擊修補版，共 7 次。用嚴格謂詞（victim_loss／liveness_broken）證實的是 7 次中 0 次。
- 有 1 次（r3 V_delegatecall 的第 1 次再攻擊）是用寬鬆謂詞 **state_change** 證實的。
  - 新攻擊手法：用 selfdestruct 把 ETH 強塞進合約，讓 `idleBalance()`（合約餘額減掉 totalDeposits）變動。AI 的假設原文：「Self-destructed ether becomes idle balance that cannot be withdrawn…」，函式標為 execute／withdraw。這不會讓任何使用者少拿錢。
  - 現在的程式（`patch.repair()`）只要再攻擊證實，**不論謂詞**都會拒收修補、要求再修一次。寬鬆謂詞的攻擊不會加進檢查 1 的額外證據，也不量 A/B/G。
  - 所以 AI 交了第 2 版修補：保留第 1 版的「只准白名單模組」，另外在 withdraw() 加了一行 `totalDeposits = address(this).balance;`。這行改變了 totalDeposits 的意思，從「使用者存款總額」變成「合約目前餘額」，而加它只是為了應付那次 state_change 證明。第 2 版通過 0～4 和第 2 次再攻擊，記為「通過」。→ 見 D17
- **兩種算法，兩個數字都列出，我沒有選**：→ 見 D17
  - 照程式現在的行為：再攻擊 7 次中被攻破 1 次。
  - 只算嚴格謂詞：再攻擊 7 次中被攻破 0 次，另有 1 次以 state_change 證實。
- 預註冊和 D13 都沒有說檢查 5 的寬鬆謂詞證明要不要算攻破，所以停下來請使用者決定。另一個待決定的是產品行為：檢查 5 要不要忽略寬鬆謂詞的證明。程式沒有改。→ 見 D17

### 4.5 S_ 列（分開統計，不進主數字）

| 列 | 謂詞 | 結果 |
|---|---|---|
| r1 S_unchecked_call_return_buyback | eth_profit | skipped（寬鬆謂詞，計劃書 6.2 不修） |
| r1 S_missing_deadline_signed_order | token_profit | skipped（同上） |
| r2 S_weak_randomness_flip_payout | eth_profit | skipped（同上） |

這 3 筆就是第 3 節人工檢查的那 3 筆誤報。

### 4.6 寬鬆謂詞的 V_ 列：skipped，不是修補失敗

計劃書 6.2 只修 STRICT 謂詞，所以下面 16 筆都記 skipped，理由是 `predicate_not_patched`。它們不算修補失敗，也不在分母裡。

| 謂詞 | 筆數 | 列 |
|---|---|---|
| eth_profit | 14 | r1：delegatecall、missing_access_control、signature_replay、unchecked_call_return、weak_randomness；r2：commit_reveal、delegatecall、missing_access_control、signature_replay、weak_randomness；r3：commit_reveal、missing_access_control、reentrancy_unstake、signature_replay |
| token_profit | 1 | r2 amm_spot_price_oracle |
| state_change | 1 | r3 weak_randomness_flip_payout |

### 4.7 每一次嘗試（D16）

- r2 V_unchecked_call_return_buyback 共 4 筆紀錄，**計入第 1 次完整跑完的那筆**：

| 開始 | 結果 | 每個提案第一個沒過的檢查 | 是否計入 | 原因 |
|---|---|---|---|---|
| 13:31:37 | skipped | — | 否 | 當時修補閘門還沒支援 liveness_broken，不算一次閘門執行 |
| **13:49:08** | **rejected** | L、2、L | **是** | 第一次完整跑完 |
| 13:51:21 | not_executed | — | 否 | 第 3 個提案請求 HTTP 500（error parsing tool call）7 次 |
| 13:57:20 | rejected | 2、L、2 | 否 | 不是第一次跑完的（結果和計入的那次相同） |

- **D15 註明**：這筆的「誠實操作」本身依賴漏洞，是一個沒有代幣的帳戶賣代幣、在漏洞版拿到錢。所以「可用性被破壞」的證據比較弱，正確的修補（轉帳失敗就 revert）也會被檢查 2 擋下。評測計分照預註冊不變。
- **r3 V_unchecked_call_return_buyback 是同樣的情況**（事實）：攻擊程式部署 `GovToken(0)`（總供給 0），「一般使用者」同樣沒有代幣卻 `sell(1 ether)`。這筆的修補也被檢查 2 擋下 2 次，gate 的紀錄裡有 check2_note。D15 只點名 r2，r3 要不要比照註明，**待使用者決定**。→ 見 D18
- 其他 r1～r3 的列都只跑了 1 次。

## 5. 限制

- **r1 V_amm_spot_price_oracle 是規則缺口**：第 3 次嘗試因為 DGX 對外網路中斷（10/29 18:44～18:51）以 `RemoteDisconnected` 結束，這個錯誤沒有被包成 GatewayError，所以照第 7 節第 2 條不補跑、算 not_executed（計為 FN）。它的前 2 次嘗試已經 conclude_safe，所以就算補跑也不一定會證實。r2 用 token_profit 證實了這份，r3 沒證實。r2、r3 照同一套規則，沒有改。
- r1 的 summary.json 是補跑那段寫的，`usage`、`wall_clock_s` 只涵蓋補跑；請求數和 tokens 以 ledger 為準（預註冊第 5 節）。r1 第一段的重試次數因此沒有紀錄。
- 評測是 hermetic 單檔模式。10/28 已經量過，這個模式下模型多半選 eth_profit（第 7 節已知陷阱 13：tools.py 的 run_exploit 說明只列舊謂詞，且不檢查 enum）。所以 as reported 和 strict only 差很多。tools.py 不改，兩種並列。
- liveness_broken 的證據較弱：r2、r3 的 V_unchecked_call_return_buyback 都是用 liveness_broken 證實的。攻擊程式裡的「一般使用者操作」是一個沒有代幣的帳戶賣代幣，這在漏洞版能成功本來就是靠漏洞（r3 用的是 `GovToken(0)`，總供給 0）。D15 規定 r2 那筆要註明這點，評測計分照預註冊不變。r3 那筆是同樣的情況，見第 4 節。
- 40 份、單檔、每份約 1,600 字元、一個模型、一台伺服器、一個計分器，而且是 TUNE 集（預註冊第 10 節）。區間都很寬（例如 as reported 的 MCC 區間從 0.000～0.557 到 0.317～0.682）。
- r1、r2 在夜間跑，r3 在下午跑（提前啟動），設定相同。Ollama 在溫度 0 下也不保證每次相同。
- AIS3 數字的模型、harness、謂詞、閘門、並行數都不同，只能當參考，不能配對比較。

## 6. 資料公開（只準備，沒有推送）

- 準備在 `~/innoserve/release_staging/eval-arbitergpt-v3/`（不在任何 git repo 裡）：3 份 summary.json（原樣）、3 份 results.jsonl.gz（`gzip -n -9`，含逐列 trace）、SHA256SUMS、README。解壓後的 sha256 和原檔相同。
- 照計劃書 9.2：P9 再 commit 到從上游 arbiter-harness 開的比賽分支，不放進使用者的 fork。
- 準備前的掃描（6 個原始檔）：

| 項目 | 結果 |
|---|---|
| `/home/`、`/mnt/c/Users/`、`/Users/`、Windows 路徑 | 0 |
| 主機名稱、使用者名稱、email | 0 |
| DGX 位址與帳號（從 tunnel.conf 讀出比對，不顯示）、`100.x.x.x`、`localhost:8080／11434` | 0 |
| 金鑰樣式（sk-、ghp_、github_pat_、私鑰、AKIA、xox、AIS3_API_KEY=、api_key、Bearer） | 0 |
| v1_paired14 扣留的 7 份：id 和可辨識詞（stakecredit、rwavault、slippage_branch 等、sample-A～D） | 0 |
| v1_paired14 扣留的 7 份：所有 JSON 字串（原樣、去空白、加換行）的 sha256 對 7 個 code_sha256 | 0（共比對 89,828 個變體） |
| 唯一出現的路徑 | harness 自己的 `/tmp/arbiter-ws/<run-id>/...` 工作目錄（沒有使用者名稱） |

## 7. 檢查與 commit

完整紀錄在 `reports/eval_arbitergpt_v3/checks.log`。評測已經結束，所以跑的是完整版，不是 `--no-smoke`。時間 20:24:51～20:27。

| 檢查 | 結果 |
|---|---|
| agent.py、tools.py 和 innoserve-base 比 | 0 行差異 |
| workspace.py | +17／−2（不變） |
| 8 個 probe | 8/8 rc 0 |
| patch_probe | 5/5 |
| regression_probe | 6/6 |
| mcp_probe | 3/3 |
| diffscan_probe | 13/13 |
| pr_gate_probe | 7/7；`--sandbox` 也是 7/7 |
| action_fork_probe | 22/22 |
| repo_patch_probe | 5/5；`--sandbox` 6/6 |
| reattack_probe | 5/5 |
| project_upload_probe | 10/10 |
| liveness_patch_probe | 10/10 |
| live_attack | 原合約 PROVEN，`--patched` NOT PROVEN |
| gate spark-test-2 | rc 1；SARIF 的 error 數等於 proven 數 |
| demo_gate.sh --auto（完整版） | rc 0；各段合計 17.5 秒；輸出裡主機路徑 0 個 |
| sandbox_assertions | **7/7**，0 skipped，沒有殘留容器。第 7 條這次實際送了 1 次 api_smoke |

- sandbox_assertions 第一次用錯路徑（在 arbiter/ 底下找），rc 2、沒有執行。它要在 repo 根目錄跑（第 7 節已知陷阱），改正後重跑得到上面的 7/7。兩次都記在 log 裡。
- log 裡的 IP 位址已遮成 `<host>`，家目錄已改成 `~`。
- 這次的 DGX 請求共 24 次：api_smoke 1 次（20:07）、修補統計 21 次、demo_gate.sh 第 0 段 1 次、sandbox_assertions 第 7 條 1 次。
- **commit a461776**（arbiter-audit，接在 a63ccd5 之後）內容：`arbiter/scripts/p7b_report.py`、`arbiter/scripts/patch_stats_report.py`、`.gitignore` 加 `**/runs/p7b/`。runs/ 不 commit。沒有 push，demo repo 的 PR #1 沒有動。
- eval-worktree：HEAD 仍是 1c7f896，tracked 檔案沒有改動，只有 3 個本來就未追蹤的 summary.json。

## 使用者決定（10/30 晚）

第 4.4、4.7 節和結論裡標「待決定」的兩件事，使用者在 10/30 晚上決定如下。第 7 節的 D17、D18 記的是同樣內容。這一步沒有用 LLM，也沒有送 DGX 請求。

### D17 檢查 5 的寬鬆謂詞證明

- **報告和所有對外說法一律兩個數字並列，不單獨只講一個**：「修補後再攻擊 7 次，用嚴格標準 0 次攻破；另有 1 次用寬鬆標準（state_change）證實，系統照現行規則要求 AI 重修」。
- **程式行為不改**：決賽前維持「再攻擊不論謂詞，只要證實就拒收修補」，這是比較保守的一邊；決賽後再評估。
- **r3 V_delegatecall_unchecked_module 的第 2 版修補**：
  - 它在 withdraw() 加了 `totalDeposits = address(this).balance;`，把 totalDeposits 的意思從「使用者存款總額」改成「合約目前餘額」。
  - 這行是為了應付那次 state_change 證明才加的，人工判斷**不是必要的修改**。真正擋住原攻擊的是第 1 版就有的「只准白名單模組」。
  - 這是「AI 修補通過檢查後，仍然需要人工審查」的實例：修補閘門檢查的是格式、介面不變、這個攻擊失效、一般使用者取回金額不變，不會判斷每一行修改有沒有必要。

### D18 r3 V_unchecked_call_return_buyback 比照 D15 註明

- 攻擊程式部署 `GovToken(0)`，「一般使用者」沒有代幣也能 `sell`。所以這筆的「誠實操作」依賴漏洞，「可用性被破壞」的證據較弱。
- 和 r2 的同一組（D15）一樣：評測計分照預註冊不變，這筆仍算 TP（strict only 也算）。修補「未通過」照實記錄。
