# 決賽 demo 排練：scripts/demo_gate.sh

- 日期：2026-10-28；起點 f9958a8
- 模型：**arbiter-gpt:latest**（只用在第 0 段的 api_smoke，以及 `--live` 的一次即時上傳）
- 沒有改動的檔案：agent.py、tools.py、verdict.py、patch.py、workspace.py、live.py、live_replay.py、gate.py、web.py、scripts/demo.sh（AIS3 版）
- 給人看的一頁：`~/innoserve/DEMO_RUNBOOK.md`
- 原始輸出：`reports/demo_rehearsal/`，包含 auto1、auto2、live、fallback 的 .txt／.tsv，以及兩張結果頁截圖

> 本報告數字只屬於 arbiter-gpt，不可與 AIS3 時期 nemotron 的數字混用。

## 1. scripts/demo_gate.sh

| 段 | 內容 |
|---|---|
| 0 前置 | 讀 `../.env` → `api_smoke.py`（`timeout 90`；失敗只警告）→ 檢查 forge、anvil、cast 是否在 PATH（cast 是 LiveChain 送交易用的，所以一併檢查）→ web 已經在跑就沿用，沒有就用 nohup 啟動並保持執行 → **先 POST `/replay` 產生 spark-test-2 的結果頁** |
| 1（`--live`） | 印出瀏覽器上傳步驟，附 Windows 路徑 `\\wsl.localhost\Ubuntu\...`。api_smoke 失敗時整段跳過，不上傳 |
| 2 預錄 | 印出第 0 段產生的結果頁網址，並從同一份 gate.json 印出判定、謂詞、4 個環境的 A/B/G、修補檢查、修補後 A/B/G，當作瀏覽器打不開時的備案 |
| 3 真鏈 | 先跑 `live_attack_stakingvault.py`（原合約，port 8600），再跑 `--patched spark-test-2`（port 8610）。結束碼和預期不符時會印警告 |
| 4 收尾 | `--live` 時印出已經等了幾秒，提醒回瀏覽器 |

- 段落之間的暫停：預設按 Enter；`--auto` 改成固定暫停，秒數用 `--pause N` 設定，預設 6 秒。每段計時都不含暫停，最後印出各段、合計與含暫停的總時間；加 `--timings FILE` 會另外寫成 TSV。
- 帶 `>>` 的行是主講要主動說的話：鏈上攻擊是已知參考攻擊、修補是 AI 產生的、未發現可證明攻擊不等於安全。
- 規格外多加了 `--live-upload`（要和 `--live` 一起用）：第 1 段改由 curl 送出和瀏覽器表單相同的 multipart 上傳，用在排練和無人錄影。不加這個旗標時，行為照規格，只提示在瀏覽器上傳。

### 為什麼預錄頁要在第 0 段先產生（照規格寫會卡住）
web.py 用 `_JOB_LOCK` 一次只跑一個 gate。第 1 段的即時上傳會占住這把鎖 2～8 分鐘。如果第 2 段才 POST `/replay`，或在瀏覽器按 spark-test-2 的「看結果」，就要排在即時稽核後面。所以把重新判定移到第 0 段，在上傳之前做；第 2 段只印網址。結果頁存在 `runs/gate/web/<id>.json`，GET 不需要那把鎖，伺服器重開後網址仍然有效。

## 2. 實測耗時（不含暫停）

| 執行 | 第 0 段 | 第 1 段 | 第 2 段 | 第 3 段 | 第 4 段 | 各段合計 | 含暫停 |
|---|---|---|---|---|---|---|---|
| `--auto` 第 1 次 | 15.1 | — | 0.0 | 13.5 | 0.0 | **28.6** | 46.8 |
| `--auto` 第 2 次 | 3.5 | — | 0.0 | 13.6 | 0.0 | **17.1** | 35.3 |
| `--auto --live --live-upload` | 3.5 | 0.1 | 0.0 | 13.5 | 0.0 | **17.1** | 41.3 |
| 備案演練（暫停 1 秒） | 3.9 | 0.0 | 0.0 | 跳過 | 0.0 | 3.9 | 8.0 |

各子步驟耗時：
- api_smoke 成功時 1.9 秒（`--live` 那次）。第 1 次的第 0 段 15.1 秒，扣掉其他步驟後大多是 api_smoke，但那次沒有分項計時，算不出精確數字；推測是 Ollama 閒置後重新載入模型，沒有查證。api_smoke 的分項計時是第 2 次之後才加的。
- 網頁重新判定 spark-test-2（forge，0 個 LLM 請求）：1.8、1.3、1.3、1.4 秒。
- 第 3 段的兩次鏈上執行合計 13.5～13.6 秒，和背景正在跑的即時稽核同時執行時也一樣（13.5 秒）。
- 第 2、4 段腳本本身是 0 秒，時間全花在講話和看頁面。

### --live 一次
- `api_smoke`：PASS，1.9 秒。
- 即時上傳：gate 247.3 秒（curl 等了 247.4 秒），**判定「未發現可證明攻擊（不等於安全）」**（agent_concluded_no_attack），7 回合，**7 個 LLM 請求**（稽核 7、修補 0），prompt 93,532 tokens、completion 9,060 tokens。
  - 模型兩次 run_exploit 都用 **victim_loss**（strict），都編譯也執行了，但被判 `predicate: no harm`／`exploit ran, extracted nothing`，之後呼叫 conclude_safe。
  - run_id `gate-StakingVault-20261028-221344-3f7406`，結果頁 `/result/164296cdf6f1`，截圖 `demo_rehearsal/shot_164296cdf6f1.png`。
- 腳本進到第 4 段時，即時稽核只跑了 32 秒。用 `--auto` 跑，或講得太快，回到瀏覽器時結果都還沒出來。runbook 已寫明第 2、3 段要講到分頁跳轉為止。
- 累計：repo 模式用 victim_loss 證實由 9/14 變成 **9/15**。DEMO_RUNBOOK 的備案 2 和腳本第 4 段的提示詞已經改用 9/15。這和你指示寫的「9/14」不同，原因是多了這一次資料。repo 模式耗時 125～465 秒的範圍不變（247 秒在範圍內），所以網頁說明不需要改。
- LLM ledger 總行數 109 → 116，多出的 7 行就是這次上傳的 7 個請求；api_smoke 不寫 ledger。

### 備案演練（不呼叫 LLM）
- 指令：`ARBITER_BASE_URL=http://127.0.0.1:1/v1 PATH=<去掉 ~/.foundry/bin> scripts/demo_gate.sh --auto --live --live-upload --pause 1`。.env 只設 AIS3_*，gateway 會先讀 ARBITER_BASE_URL，所以這樣可以模擬通道斷線，不用動 .env。
- api_smoke 大約 2 秒就失敗（connection refused、`max_retries=1`）→ 第 1 段印出「SKIPPED, nothing uploaded」→ 第 3 段印出「missing: forge anvil cast -- skip the chain」→ 第 2 段預錄照常。
- 預錄照常的原因是網頁伺服器是之前用完整 PATH 啟動的。如果本機真的沒有 forge，網頁重新判定也會失敗，第 2 段會印警告，並退回首頁的「看結果」。
- 第一版腳本在 api_smoke 失敗時仍然會印出上傳步驟，已改成整段跳過。改版前那次的輸出被同名檔覆蓋了，只留下改版後的 `fallback.txt`。
- 沒有演練「SSH 通道還在、但 DGX 沒有回應」的情況。這時 api_smoke 會等到 `timeout 90` 才放棄，第 0 段最長多 90 秒。

## 3. 用語檢查
- spark-test-2 預錄頁（`/result/282b8c64183a`）：`CLEAR` 0 筆、`safe` 0 筆、「安全」0 筆。
- 即時結果頁：`CLEAR` 0 筆、`safe` 0 筆，「安全」只出現在「不等於安全」，1 筆。
- **要你知道（web.py 不動，所以沒改）**：
  - 結果頁的 gate 結束碼那行寫「0＝通過」，放在「未發現可證明攻擊」旁邊，可能被讀成「通過＝沒問題」。runbook 已加上口頭說法：「0 是沒有擋部署，不是沒有漏洞」。
  - 結果頁「尚未完成的部分」列了「本地鏈重播 開發中」，但第 3 段在終端機做了鏈上 demo。兩者指的東西不同：網頁的重播頁還沒做，鏈上腳本已經做了。runbook 已寫說明；要不要改網頁上的這行字由你決定。

## 4. 首頁「其他紀錄」摺疊區：demo 時可能誤點的 run（只列出，沒有刪任何檔案）

首頁精選區是 spark-test-1～5，摺疊區目前有 **16 筆**：下表 15 筆，加上今天即時上傳新增的 1 筆。之後每次網頁上傳都會在 `runs/gate/` 多一筆 `gate-StakingVault-*`。

| run | 點下去會看到 | 風險 | 檔案 |
|---|---|---|---|
| `audit`（10/28 17:19） | 無法判定，畫面上有 AIS3 LiteLLM gateway 的 **HTTP 401 錯誤訊息** | **高**：錯誤訊息直接出現在畫面上 | `runs/audit.results.jsonl` |
| `gate-StakingVault-20261028-182059-747e83` | 已證實，但是 **eth_profit**（寬鬆謂詞，沒有 A/B/G 和修補） | 中：需要解釋已知陷阱 13 | `runs/gate/gate-StakingVault-20261028-182059-747e83/` |
| `gate-StakingVault-20261028-183127-36651a` | 同上，eth_profit | 中 | `runs/gate/gate-StakingVault-20261028-183127-36651a/` |
| `predexp-herm-1`、`predexp-herm-2` | 同上，eth_profit | 中 | `runs/gate/predexp-herm-{1,2}/` |
| `predexp-herm-3` | 未發現可證明攻擊 | 低 | `runs/gate/predexp-herm-3/` |
| `predexp-repo-1` | 未發現可證明攻擊（回合用完；有一筆 eth_profit 的 PoC 執行過，但沒有判成證實） | 中：PoC 清單會讓人混淆 | `runs/predexp-repo-1.results.jsonl` |
| `predexp-repo-2` | 已證實 victim_loss，**沒有修補紀錄** | 低到中：「修補呢？」 | `runs/predexp-repo-2.results.jsonl` |
| `predexp-repo-3` | 未發現可證明攻擊 | 低 | `runs/predexp-repo-3.results.jsonl` |
| `modetrial-repo-2`～`5` | 已證實 victim_loss，**沒有修補紀錄**：修補存在當時的 gate.json，沒有寫成 patches.jsonl | 低到中 | `runs/gate/modetrial-repo-{2..5}/` |
| `modetrial-repo-1` | 未發現可證明攻擊 | 低 | `runs/gate/modetrial-repo-1/` |
| `gate-StakingVault-20261028-194100-0a9e35` | 未發現可證明攻擊（瀏覽器長時間等待測試那次） | 低 | `runs/gate/gate-StakingVault-20261028-194100-0a9e35/` |
| `gate-StakingVault-20261028-221344-3f7406`（今天排練） | 未發現可證明攻擊 | 低 | `runs/gate/gate-StakingVault-20261028-221344-3f7406/` |

另外，**即時稽核在跑的時候，點任何一筆「看結果」都會排在後面**，這和 run 本身無關。

可以選的做法（由你決定，這次都沒做）：
- 把高風險的 `audit`，或摺疊區全部，搬到 `runs/` 以外的封存資料夾。web.py 只掃描 `runs/*.results.jsonl` 和 `runs/gate/*/`，所以搬走就不會出現在首頁。
- 不搬，只靠 runbook 提醒「demo 時不要打開摺疊區」。

## 5. 合併前檢查
- 8 個 probe（victim、forgery、halt、drain、sweep、latebinding、setup_forgery、gain）的結束碼全部是 0。
- `patch_probe.py` 5/5 as expected。
- `live_attack.py` PROVEN；`--patched` NOT PROVEN。
- agent.py、tools.py、live.py、live_replay.py、scripts/demo.sh 和 `innoserve-base` 零差異。workspace.py 和 innoserve-base 只差 `run_poc` 的新增（+17／−2，和之前相同）。verdict.py、patch.py、workspace.py、gate.py、web.py、demo.sh 從 f9958a8 起零差異。
- 這次 commit 只有 `scripts/demo_gate.sh`；runs/ 沒有 commit。
