# P7a 評測預註冊（2026-10-29）

這一段只做準備，**沒有啟動正式評測**（gptoss-v3-r1～r3 都還沒有任何一列）。第 1 次由使用者睡前另外貼的「夜跑」prompt 啟動。

## 結論

| 項目 | 結果 |
|---|---|
| 預註冊 | `arbiter/PREREGISTRATION_arbitergpt_v3.md`，commit **1c7f896**，tag **`eval-freeze`**（本機，未 push） |
| worktree | `~/innoserve/eval-worktree`（detached，HEAD＝eval-freeze），`.env` 已複製（權限 600、被 ignore），runs/ 和主目錄分開 |
| concurrency | **1**。實測 c=2 沒有增加吞吐量（§3） |
| 每次 40 份預估 | **約 3～5 小時**（最壞約 11～12 小時，§3） |
| 腳本 | `scripts/eval_launch.sh`、`scripts/eval_watch.sh`，另加 `scripts/eval_requeue.py`（把預註冊的補跑規則寫成程式）。空跑 14 秒通過，0 個 LLM 請求 |
| commit | 0bb2b9d、17d4930、cf7432f（腳本）、1c7f896（預註冊）。runs/ 沒有 commit |
| 合併前檢查 | 全部通過（§6） |

## 1. 預註冊重點

- **模型**：`arbiter-gpt:latest`，Ollama 0.40.11。digest `e914c3a9517b9824cb35fd945b7c5148baca5442819d19e44c549f1ff6cd50a3`（`/api/tags`）。
  上游是 gpt-oss:120b（116.8B、MXFP4）。Modelfile 只有 `num_ctx 65536`、`temperature 1`，沒有 SYSTEM 提示。文件裡沒有寫 DGX 位址。
- **資料集**：`evalsets/v3_authored.json` sha256 `0ab903b9dbc9a8218a958a595106c82ac855995a641e8c2b49dda832d653d33f`，40 份（20 對）。標成 **TUNE**。
- **設定**：照 `runs/h2h-arbiter.summary.json` 和當時的指令（RESULTS.md L108–109）：attempts 3、max_turns 16、max_tokens 4096、repeats 1、rpm 45、hermetic，不帶 predicates（＝STRICT 預設）。
  現在 `cli.py run` 的 `--max-turns` 預設是 26，所以每個值都明寫在指令裡。
- **run-id**：gptoss-v3-r1、r2、r3，一次只跑一個。
- **指標**：
  - score.py 的混淆矩陣和 6 項指標，三次各算，再算平均、最小、最大。以 MCC 為主。
  - bootstrap 10,000 次（seed 20260726，用 score.py 的 `_Lcg`）。
  - 兩套計分：「照系統判定」和「只算 strict」。寬鬆謂詞證實的陽性，在 strict 那套裡算成 safe，並分謂詞列數量。
  - not_executed 另列數量和原因。
  - analyst_cost 用 AIS3 的假設：15／2 分鐘，誤報一律 15 分鐘。
  - 成本：請求數、token 數、牆鐘時間，從 ledger 和 sessions.log 算，續跑後也完整。
- **有效性**：ledger 的 `model_served` 和 summary 的 `models_seen` 都只能有一個值，而且不能有 ModelMismatch。不符合就整次作廢重跑。每次跑完會自動檢查。
- **什麼不算贏**：見 §5 的對照。任何一次 MCC ≤ 0，就寫成「換模型後退化」。三次之間的範圍比和 AIS3 的差距還大時，不報成差異。精確率一定和召回率一起出現。
- **附加對照臂**（P7b 算，0 個 LLM 請求）：F0（全有、全無）；S＝Slither 0.11.6，Medium/Medium 固定，不讀 `best`。

## 2. 和指示不同、以現況為準的地方

1. **AIS3 的 h2h-arbiter 不是 STRICT 謂詞。** 它是 2026-07-26（abf7077）跑的，STRICT_PREDICATES 到 07-28（0538719）才出現。當時 agent 能用的是 eth_profit／token_profit／state_change／liveness_broken，也還沒有 cheatcode 禁令、negation、halt、drain、forgery 這些閘門。
   這次照指示用現在的預設 STRICT，所以「設定完全相同」只對 attempts、turns、tokens、rpm、hermetic 成立。謂詞和閘門的差異列為已知設定差異（預註冊 §4），差距不能只歸因於模型。
2. **0.118～0.303 是 v4 的數字，不是 v3 的。** 它來自 fixed1、fixed2、casc2-strict，都是 70 份、26 回合、attempts 2（TALK.md L11–13）。
   v3 上 AIS3 每種設定只跑過 1 次：h2h-arbiter MCC 0.267；同回合數的 cascade 是 0.329 和 0.168。
   預註冊的規則寫成：新的平均 MCC 落在 0.118～0.303 之內，**或**和 0.267 相差不超過 0.185，就寫「差異在變異範圍內」。兩種讀法都納入，比較保守。
3. **concurrency**：AIS3 當時是 8（舊預設），這次實測後用 1（§3），列為已知差異。
4. **順序**：指示是先寫預註冊、再打 tag、最後測吞吐量。但 concurrency 要寫進預註冊，所以我先在主目錄（程式碼＝d09b90f，和 eval-freeze 的 arbiter/ 套件完全相同）測吞吐量，再 commit 預註冊、打 tag。
5. **eval-freeze 重打過一次**：第一次打在 7ef4334。之後空跑時發現啟動腳本找舊通道的 `pgrep` 沒有錨定開頭，會比對到「指令文字含這串字」的 bash 程序並把它殺掉。
   當時正式評測還沒有任何一列，所以我刪掉 tag、撤回預註冊 commit、先 commit 修正（cf7432f），再重新 commit 預註冊（1c7f896）並打 tag。7ef4334 沒有推送到任何地方。
6. **補跑規則多寫了一支腳本** `eval_requeue.py`：預註冊要求「事先寫明補跑的具體做法」，寫成程式比較不會在半夜手動做錯。

## 3. 吞吐量實測（arbiter-gpt，2 份樣本，不算進正式評測）

樣本是 `V_reentrancy_unstake`、`S_reentrancy_unstake`，設定同正式評測（attempts 3、turns 16、tokens 4096、rpm 45）。run-id 是 tput-c1、tput-c2，輸出在 scratch 目錄。

| | c=1 | c=2 |
|---|---|---|
| 牆鐘總時間 | 427 秒 | 481 秒 |
| 請求數 | 16 | 18 |
| 每請求延遲：中位數／p90／最大 | 22.3／44.9／58.6 秒 | 33.5／58.6／116.5 秒 |
| completion tokens/s（每請求） | 38.2 | 23.9 |
| 每請求平均佔用牆鐘 | 26.7 秒 | 26.7 秒 |
| V_reentrancy_unstake | 證實（1 次嘗試、3 回合、81 秒） | 證實（257 秒） |
| S_reentrancy_unstake | conclude_safe（3 次嘗試、346 秒） | conclude_safe（480 秒） |

- 中位數變成 1.5 倍，沒到「超過 2 倍」的門檻。但伺服器是把同一份吞吐量分給並行的請求（每個請求的 tokens/s 減半），牆鐘時間完全沒省，所以用 **1**。
- DGX 的 Ollama 沒有設任何 `OLLAMA_*` 環境變數（唯讀查 systemd，沒有送 LLM 請求）。finish_reason 沒有出現 length。

**每次 40 份的預估**：
- 估法：每請求約 26.7 秒；第 1 次嘗試就證實的樣本約 3～7 個請求，沒證實要用完 3 次嘗試的樣本約 13 個請求（實測），沒證實的估約 30 份。
  合計約 450～600 個請求 → **約 3.3～4.5 小時**。
- 最壞情況：模型像 AIS3 的 nemotron 那樣每份用約 39 個請求（h2h-arbiter 1555 個請求），會到 **約 11.5 小時**。
- 23:00 開跑的話，多半清晨前會跑完；最壞的情況會跑到隔天中午。跑的時候照 DGX 共用規則，開發工作不能對 DGX 送請求。

## 4. 工具鏈對照

| | AIS3 h2h-arbiter（nemotron，2026-07-26） | 這次（arbiter-gpt） |
|---|---|---|
| forge | 無紀錄 | 1.8.6 |
| solc | 無紀錄（test_pairs_v2 裡的 `solc 0.8.24` 是出題時用 ethereumjs 驗證的說明，不是這次 run） | 0.8.37（auto-detect）；0.8.20 也已安裝。v3 全部是 `^0.8.20` |
| 伺服器 | vLLM 0.24.0 tp8（system_fingerprints） | Ollama 0.40.11（`fp_ollama`） |
| Slither | 0.11.6 | 0.11.6（`~/innoserve/venv-tools`） |

沒有為了對齊去改 solc 設定。

## 5. AIS3 參考數字（只並列，不配對、不合併）

| 來源 | 資料集 | 設定 | MCC |
|---|---|---|---|
| h2h-arbiter | v3 40 份 | attempts 3、turns 16、舊謂詞 | 0.267（TP 9 / TN 16 / FP 4 / FN 11） |
| cascade-clean／h2h-cascade | v3 40 份 | 同上＋Bastet proposals | 0.329／0.168 |
| fixed1／fixed2／casc2-strict | v4 70 份 | attempts 2、turns 26、STRICT | 0.118／0.261／0.303 |

全部是 nemotron 的數字。

## 6. 合併前檢查（P7a 結束時）

| 檢查 | 結果 |
|---|---|
| agent.py、tools.py 對 innoserve-base | 零差異 |
| workspace.py | +17／−2（只有 run_poc，不變） |
| d09b90f→HEAD 的改動 | 5 個檔、+590：.gitignore、3 支 eval 腳本、預註冊。沒有動到功能程式碼 |
| 8 個 probe | 全部 rc 0 |
| patch_probe | 5/5 as expected |
| live_attack／--patched | PROVEN／NOT PROVEN |
| demo_gate.sh --auto | rc 0。api_smoke PASS（2.1 秒）；各段合計 46.4 秒（第 0 段 8.0、第 3 段 38.3。P0 時第 3 段是 15.7 秒，這次可能是機器忙，判定不受影響）；0 個 LLM 請求 |

另外：
- 啟動腳本空跑 14 秒：前置檢查 8 項都 ok，tmux 的三個視窗都起來；監看腳本看到空殼結束後自己退出，session 也移除了。
- 不存在的 run-id `gptoss-v3-r9` 在前置檢查第一項就被擋下（rc 1，0.006 秒）。
- eval_requeue.py 用假資料測過：只移出 infra 列，同一份最多補跑 2 次，ledger 出現第二個模型時判作廢。

## 7. 夜跑：啟動指令（照抄）

在一個**會一直開著的 Ubuntu 視窗**裡執行：

```bash
cd ~/innoserve/eval-worktree/arbiter
pgrep -af gptoss-v3          # 應該沒有輸出
bash scripts/eval_launch.sh gptoss-v3-r1
```

- 前置檢查全部 ok 之後，會關掉原本從 Claude Code 終端機開的 `ssh -f` 通道，改由 tmux 的 `tunnel` 視窗接手（同時開 11434 和 8080）。
- 看進度：`tmux attach -t eval`（離開但不停止：Ctrl-b 再按 d）。
  也可以看 `runs/gptoss-v3-r1.watch.log`（每 10 分鐘一行）和 `runs/gptoss-v3-r1.log`。
- **跑完之後**：
  - `runs/gptoss-v3-r1.log` 結尾會有 `eval_requeue.py --check` 的輸出。
  - 如果有 `infra` 列：
    ```bash
    python3 scripts/eval_requeue.py gptoss-v3-r1
    tmux kill-session -t eval
    bash scripts/eval_launch.sh gptoss-v3-r1 --resume
    ```
  - 如果出現 `VOID`：不要自己處理，留給下一段判斷。
- 跑完後 `eval` session 會留著（tunnel 視窗繼續提供 11434，白天開發可以用）。下一晚開 r2 之前先 `tmux kill-session -t eval`，再 `bash scripts/eval_launch.sh gptoss-v3-r2`。

## 8. 使用者睡前要確認的事

- [ ] Windows 接上電源，睡眠設成「永不」，闔上螢幕設成「不執行任何動作」
- [ ] Docker Desktop 開著（評測本身不用，但 P0 發現它沒開時 WSL 裡沒有 docker，之後的段落要用）
- [ ] 保持一個 Ubuntu 視窗開著；不要執行 `wsl --shutdown`；關掉 Windows Update 的自動重新啟動
- [ ] DGX 開著（`curl -s http://localhost:11434/api/version` 有回應）
- [ ] `pgrep -af gptoss-v3` 沒有輸出，`tmux ls` 沒有 `eval` session

## 第 1 次啟動紀錄（gptoss-v3-r1，2026-10-29）

N=1，沒有上一次可檢查（跳過）。預註冊文件沒有任何改動。

| 時間 | 動作 | 結果 |
|---|---|---|
| 16:49 前 | `git -C ~/innoserve/eval-worktree rev-parse HEAD eval-freeze^{commit}`；`git status --porcelain` | 兩者都是 1c7f896；沒有改動（只有 ignore 的 `.env`、`__pycache__/`；runs/ 尚無 r1 檔） |
| 16:49 前 | `pgrep -af gptoss-v3`、`tmux ls`、程序清單、網頁 job 狀態 | 沒有評測程序、沒有 tmux server；`arbiter.web`（127.0.0.1:8765）開著但 4 個 job 全是 done，沒有 gate／cli 程序在跑 |
| 16:49 前 | `set -a; . ./.env; set +a; python3 scripts/api_smoke.py`（eval-worktree） | PASS（arbiter-gpt:latest 回 AIS3_OK，1 請求，completion 70 tokens）。C: 剩 68 GB；Docker 可用 |
| 16:49:25 | `cd ~/innoserve/eval-worktree/arbiter && bash scripts/eval_launch.sh gptoss-v3-r1` | 前置檢查 7 項全 ok；關掉 Claude Code 終端機的 `ssh -f` 通道（pid 486），改由 tmux `eval:tunnel` 接手；rc 0 |
| 16:49:28 | sessions.log：`start gptoss-v3-r1 concurrency=1 resume=0 head=1c7f896` | tmux session `eval`（視窗 tunnel／run／watch） |
| 16:54:52 | 5 分鐘檢查：`runs/gptoss-v3-r1.{watch.log,ledger.jsonl,results.jsonl,log}` | 1/40 列完成（`r0 V_reentrancy_unstake -> vuln (proven, 1x3t, 77.89s)`），ledger 10 個請求；watch.log 第一筆 10 分鐘報告會在 16:59 出現 |

- 預估結束：第 1 列 78 秒偏快（第一次就證實）。照預註冊 §3 的吞吐量（每請求約 26.7 秒牆鐘）與預估「每次 40 份 3～5 小時」，**約 20:00～22:00 跑完；最壞約 04:20（11.5 小時）**。
- 跑完後照 §7 的步驟：看 `runs/gptoss-v3-r1.log` 結尾的 `eval_requeue.py --check`；有 infra 列就 requeue＋`--resume`；出現 VOID 不自己處理。
- 評測在跑時的 DGX 規則：主目錄的開發工作不送任何 LLM 請求（P5 的 PR 實測等 `pgrep -af gptoss-v3` 沒有輸出才做）。
- 這次啟動沒有 repo 內的改動（腳本與預註冊都在 eval-freeze），所以沒有對應的 commit。

## 第 1 次補跑紀錄（gptoss-v3-r1，2026-10-29）

主體 16:49:28 開始、22:29:06 結束（rc 0，40 列，585 請求，model_served 只有 `arbiter-gpt:latest`，沒有 VOID）。預註冊文件和評測設定都沒有改動。

| 時間 | 動作 | 結果 |
|---|---|---|
| 22:30:13 | `python3 scripts/eval_requeue.py gptoss-v3-r1 --check` | `40 rows infra=3 ok=36 other_error=1`；和使用者事先看的一致（見下表） |
| 22:30:34 | `python3 scripts/eval_requeue.py gptoss-v3-r1` | 3 列移到 `gptoss-v3-r1.requeued.jsonl`（第 1 次補跑）；備份 `gptoss-v3-r1.results.20261029-223034.bak.jsonl` |
| 22:30:3x | `tmux kill-session -t eval`；`bash scripts/eval_launch.sh gptoss-v3-r1 --resume` | 前置檢查 8 項全 ok（含 tunnel 回應 11434）；rc 0 |
| 22:30:38 | sessions.log：`start gptoss-v3-r1 concurrency=1 resume=1 head=1c7f896` | 22:32:34 ledger 585 → 587，補跑在前進 |

| 樣本 | 分類 | 錯誤 | 處理 |
|---|---|---|---|
| V_tx_origin_auth_router | infra | `GatewayError: gave up after 7 attempts; last error: HTTP 500 … error parsing tool call` | 補跑（第 1 次） |
| V_slippage_check_skipped_branch | infra | 同上（HTTP 500，error parsing tool call） | 補跑（第 1 次） |
| S_amm_spot_price_oracle | infra | `GatewayError: gave up after 7 attempts; last error: URLError … Connection refused` | 補跑（第 1 次） |
| V_amm_spot_price_oracle | other_error | `RemoteDisconnected: Remote end closed connection without response` | **不補跑，算 not_executed** |

- **兩筆 HTTP 500 很可能再失敗**（使用者查 DGX 的 Ollama 紀錄）：同一列每次重試的輸出長度都一樣（V_tx_origin_auth_router 2755 tokens、V_slippage_check_skipped_branch 3666 tokens），溫度 0 下是**可重現的模型輸出格式錯誤**（Ollama 解析不了模型寫的 tool call），不是暫時的連線問題。
  照預註冊規則仍然補跑，**每份最多補跑 2 次**（`MAX_REQUEUES = 2`）；第 2 次補跑後還是 infra，就保留最後一列，記為 not_executed（`--check` 會標「cap reached」）。報告要寫明這個觀察，不能只寫「補跑後失敗」。
- **V_amm_spot_price_oracle 不補跑**：它是 **18:44～18:51 通道中斷**造成的（DGX 端對外網路中斷，tailscaled 回報 UDP blocked；Ollama 沒有重啟，DGX 沒有重開機；以上由使用者查 DGX 端確認）。
  但這個錯誤（`RemoteDisconnected`）沒有被 gateway 包成 `GatewayError: gave up after …`，所以**不符合預註冊 §7 的補跑條件**，照規則以 harness 的計分（判為未證實）計入，並列為 not_executed。
  這是**規則的已知缺口**：同樣是基礎設施中斷，錯誤型別不同就分到不同類。**r2、r3 照同一套規則，中途不修改**；彙整（P7b）時把這列單獨列出並說明。
- **留到 P7b 人工檢查（這一步不處理）**：S_unchecked_call_return_buyback、S_missing_deadline_signed_order 這兩份是「修好的版本」（S_），卻被證實可攻擊。要人工看證據是真的攻擊（樣本本身仍有漏洞）還是判定誤判。
- 補跑的預估：被移走的 3 列原本分別耗時 1357 秒、1187 秒（兩筆 HTTP 500，各自重試到放棄）和 360 秒；正常列中位數 483 秒、最長 858 秒。預估 **23:20～23:40 跑完，最壞約 00:15**。
- 補跑期間主目錄不送任何 DGX 請求。補跑結束後再看 `runs/gptoss-v3-r1.log` 結尾的 `--check`：還有 infra 列就照規則做第 2 次補跑；第 2 次後仍失敗的記 not_executed。

### 第 1 次補跑結果（gptoss-v3-r1，2026-10-29 23:09 結束）

- sessions.log：`23:09:47 end gptoss-v3-r1 rc=0`。補跑 61 請求；gateway 的 retries 0、http_errors 0。
- 23:47:50 `python3 scripts/eval_requeue.py gptoss-v3-r1 --check`：`40 rows ok=39 other_error=1`，infra 0；ledger 646 請求，model_served 只有 `arbiter-gpt:latest`；models_seen 只有 `arbiter-gpt:latest`；沒有 ModelMismatch，沒有 VOID。**不需要第 2 次補跑。**

| 樣本 | 補跑結果 | 耗時 |
|---|---|---|
| V_tx_origin_auth_router | 3 次嘗試都正常跑完（conclude_safe） | 646 秒 |
| V_slippage_check_skipped_branch | 3 次嘗試都正常跑完（conclude_safe） | 573 秒 |
| S_amm_spot_price_oracle | 3 次嘗試都正常跑完（conclude_safe） | 1130 秒 |

- other_error 1 列仍是 V_amm_spot_price_oracle（RemoteDisconnected），照上面的處理算 not_executed。
- **更正**：上面「兩筆 HTTP 500 很可能再失敗」是使用者端依 Ollama 紀錄做的預測；實際補跑時兩筆都沒有重現格式錯誤（HTTP 500 0 次），照實記錄。
- r1 的指標這裡不算，留給 P7b。

## 第 2 次啟動紀錄（gptoss-v3-r2，2026-10-29 夜，N=2）

使用者決定：今晚先收尾 r1，接著啟動 r2；P5 第 6 步的 PR 實測延到 r2 跑完之後；r3 改排在 10/30 晚上。預註冊文件與評測設定都沒有改動。

| 時間 | 動作 | 結果 |
|---|---|---|
| 23:47:50 | 檢查上一次：`python3 scripts/eval_requeue.py gptoss-v3-r1 --check` | 40 列，ok 39，other_error 1，infra 0；只有一個模型；沒有 ModelMismatch／VOID（見上方「第 1 次補跑結果」） |
| 23:48 前 | `git -C ~/innoserve/eval-worktree rev-parse HEAD eval-freeze^{commit}`；`git status --porcelain` | 兩者都是 1c7f896；追蹤的檔案沒有改動，runs/ 以外沒有未追蹤檔（只有 ignore 的 `.env`、`__pycache__/`） |
| 23:48 前 | `pgrep -af gptoss-v3`、程序清單、網頁 job 狀態、runner | 沒有評測程序；`arbiter.web` 開著但 job 全是 done；GitHub runner 只有 Listener、沒有在跑 job |
| 23:48 前 | `set -a; . ../.env; set +a; python3 scripts/api_smoke.py`（eval-worktree） | PASS（arbiter-gpt:latest 回 AIS3_OK，1 請求，completion 70 tokens） |
| 23:48:36 | `tmux kill-session -t eval`；`bash scripts/eval_launch.sh gptoss-v3-r2` | 前置檢查 8 項全 ok（C: 剩 68 GB）；rc 0 |
| 23:48:39 | sessions.log：`start gptoss-v3-r2 concurrency=1 resume=0 head=1c7f896` | tmux session `eval`（視窗 tunnel／run／watch） |
| 23:53:44 | 5 分鐘檢查 | 1/40 列完成（`r0 V_reentrancy_unstake -> vuln (proven, 1x3t, 77.66s)`），ledger 10 個請求 |

- 預估結束：r1 主體 16:49～22:29 共 5 小時 40 分（含 18:44～18:51 中斷與兩筆 HTTP 500 各重試約 20 分鐘）。r2 預估 **10/30 05:00～05:30 跑完；最壞約 10/30 11:20（11.5 小時）**。
- 跑完後照 §7：看 `runs/gptoss-v3-r2.log` 結尾的 `--check`；有 infra 列就 requeue＋`--resume`；出現 VOID 不自己處理。other_error（例如 RemoteDisconnected）照規則不補跑。
- r2 在跑時主目錄不送任何 DGX 請求，P5 不繼續。這次啟動沒有 repo 內的改動，所以沒有 commit。

### 第 2 次結果（gptoss-v3-r2）

- 起訖：sessions.log `2026-10-29 23:48:39 start gptoss-v3-r2 concurrency=1 resume=0 head=1c7f896` → `2026-10-30 05:06:30 end gptoss-v3-r2 rc=0`（5 小時 18 分）。
- 2026-10-30 10:22:50 `python3 scripts/eval_requeue.py gptoss-v3-r2 --check`：`40 rows ok=40`（infra 0、other_error 0），rc 0；**不需要補跑**。
- 請求數：ledger 609，model_served 只有 `arbiter-gpt:latest`；models_seen 只有 `arbiter-gpt:latest`；沒有 ModelMismatch，沒有 VOID。
- **留到 P7b 人工檢查**：S_weak_randomness_flip_payout 這次是「修好的版本被證實可攻擊」，和 r1 的 S_unchecked_call_return_buyback、S_missing_deadline_signed_order 一起看。
- 指標這裡不算，留給 P7b。tmux `eval` session 保留（通道還在裡面）。

## 第 3 次啟動紀錄（gptoss-v3-r3，2026-10-30 下午，提前啟動）

**提前啟動的原因**：原訂 10/30 20:30。使用者 14:1x 決定提前，因為 DGX 已經閒置（P6 後續的修補統計和 liveness 實測在 13:59 前結束），使用者在場可以監看。**設定與 r1、r2 完全相同**：同一個 eval-worktree（eval-freeze）、同一支啟動腳本、同一組參數，預註冊文件沒有任何改動。

| 時間 | 動作 | 結果 |
|---|---|---|
| 14:18:30 | 主目錄 HEAD；`git -C ~/innoserve/eval-worktree rev-parse HEAD eval-freeze^{commit}`；`git status --porcelain` | 主目錄 f365b74；eval-worktree 兩者都是 1c7f896；只有 r1、r2 的 `summary.json` 兩個未追蹤檔，沒有其他改動 |
| 14:18:30 | `python3 scripts/eval_requeue.py gptoss-v3-r2 --check` | 40 rows ok=40；ledger 609 請求；model_served 只有 `arbiter-gpt:latest`；ModelMismatch 0 |
| 14:18 | `pgrep -af gptoss-v3`、程序清單、網頁 job、GitHub runner | 沒有評測程序、沒有 p7b、沒有 gate／patch_stats；網頁 job 全是 done；runner 只有 Listener（沒有 Worker） |
| 14:18:53 | `set -a; . ../.env; set +a; python3 scripts/api_smoke.py`（eval-worktree） | PASS（arbiter-gpt:latest，1 請求，completion 71 tokens） |
| 14:18:57 | `tmux kill-session -t eval`；`bash scripts/eval_launch.sh gptoss-v3-r3` | 前置檢查 8 項全 ok（run id 已預註冊；HEAD＝eval-freeze 1c7f896、追蹤檔乾淨；.env；沒有其他 gptoss-v3、沒有 `eval` session；C: 剩 51 GB；forge 1.8.6、tmux；ssh 金鑰登入可用；tunnel 回應 11434）；rc 0 |
| 14:19:00 | sessions.log：`start gptoss-v3-r3 concurrency=1 resume=0 head=1c7f896` | tmux session `eval`（視窗 tunnel／run／watch） |
| 14:24:12 | 5 分鐘檢查 | 1/40 列完成（`r0 V_reentrancy_unstake -> vuln (proven, 1x3t, 68.8s)`），ledger 14 個請求；三個視窗都在（dead=0）；tunnel `14:19:00 tunnel up`、11434 回 200；eval-worktree 追蹤檔仍然乾淨 |

- C: 剩 51 GB（r2 啟動時是 68 GB；少掉的主要是 10/30 重建沙箱映像和 P6 的工作目錄），仍高於腳本的 20 GB 門檻。
- 預估結束：r1 主體 5 小時 40 分（含 18:44～18:51 中斷與兩筆 HTTP 500 重試），r2 5 小時 18 分。r3 預估 **約 19:30～20:00 跑完；最壞約 10/31 01:50（11.5 小時）**。
- 跑完後照 §7：看 `runs/gptoss-v3-r3.log` 結尾的 `--check`；有 infra 列就 requeue＋`--resume`；other_error 照規則不補跑；出現 VOID 不自己處理。
- r3 在跑時，主目錄不送任何 DGX 請求：patch_stats、網頁上傳、api_smoke、demo_gate.sh 第 0 段、sandbox_assertions 第 7 條都算。PR 檢查會被 BLOCK_PATTERN 自動判成「無法判定」。
- 這次啟動沒有 repo 內的改動，沒有對應的 commit。同一時段主目錄的 commit a63ccd5（liveness 說明文字）沒有送 DGX 請求：用的是 `demo_gate.sh --no-smoke`，sandbox_assertions 第 7 條 SKIP。
