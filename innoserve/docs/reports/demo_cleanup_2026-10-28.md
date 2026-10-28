# demo 清理：首頁摺疊區搬出、web.py 兩處用語、runbook 精簡

- 日期：2026-10-28；起點 9e676b1
- **0 個 LLM 請求**：所有 ledger（runs/ 加上 runs_archive/）總行數前 116、後 116。demo_gate.sh 第 0 段的 api_smoke 不寫 ledger。
- 沒有改動：agent.py、tools.py、verdict.py、patch.py、workspace.py、live.py、live_replay.py、gate.py。web.py 只改兩處顯示文字。
- 原始資料：`reports/demo_cleanup/`
  - 搬移清單 `move_list.txt`、封存檔案清單 `runs_archive_files.txt`
  - 搬移前後的首頁 HTML
  - 改版後 13 頁的 HTML（`pages/`）
  - 截圖
  - demo_gate.sh 的輸出 `auto.txt`／`auto.tsv`

## 0. 前置
- 備份 `ARBITER_backup/20261028_222433/` 裡有 RESTORE.md、bundle、tar。RESTORE.md 記錄的 innoserve-gate HEAD 是 `9e676b1a5428…`，符合條件，所以照原計畫搬移。
- 被搬走的 run 在備份 tar 裡也有一份（tar 是搬移前打包的）。

## 1. 首頁摺疊區：搬到 `~/innoserve/runs_archive/2026-10-28/`

### 搬移前列出的清單（共 27 項，都沒有被 git 追蹤）
`runs/` 根目錄的 15 個檔案：
- `audit.{input.json,results.jsonl,summary.json}`
- `predexp-repo-{1,2,3}.{input.json,ledger.jsonl,results.jsonl,summary.json}`

`runs/gate/` 底下的 12 個資料夾，整個搬：
- `gate-StakingVault-20261028-182059-747e83/`、`gate-StakingVault-20261028-183127-36651a/`、`gate-StakingVault-20261028-194100-0a9e35/`、`gate-StakingVault-20261028-221344-3f7406/`
- `modetrial-repo-{1..5}/`、`predexp-herm-{1,2,3}/`
- 資料夾裡有 input、results、ledger、summary、`repair.ledger.jsonl`、run.log，以及 repo 模式複製的合約資料夾。

這 16 個 run id 正好是 `demo_rehearsal_2026-10-28.md` 第 4 節的清單：表中 15 筆，加上排練的 `gate-StakingVault-20261028-221344-3f7406`。在 `runs/` 根目錄沒有其他屬於 `gate/` 底下這些 id 的檔案。

搬移時用 `mv -n`，保持相對路徑：`runs/X` 搬到 `runs_archive/2026-10-28/runs/X`。沒有任何一項失敗。

### 搬完之後
- `runs_archive/2026-10-28/runs/`：根目錄 15 個檔案，`gate/` 底下 12 個資料夾，總共 86 個檔案（完整清單見 `runs_archive_files.txt`）。
- **首頁摺疊區已經不見**：首頁 HTML 裡「其他紀錄」出現 0 次，搬移前是「其他紀錄（16 筆）」。首頁只列 spark-test-1～5。
- 沒有動的檔案：
  - spark-test-1～5 的所有檔案。
  - `runs/gate/web/`、`uploads/`、`demo/`。
  - AIS3 時期的 summary、h2h、casc2 等等。
  - 本來就不會出現在首頁的 `runs/gate/` 子資料夾：`gate-Broken-*` 4 個（編譯預檢的工作目錄，只有 ctx）、`gate-StakingVault-20261028-182039-faf2fd`（空的）、`replay-spark-test-*` 12 個（重播工作目錄）。這些資料夾裡都沒有 `*.results.jsonl`，所以 web.py 不會列出。

### 結果頁是否仍然打得開
`runs/gate/web/` 裡 12 個已存的結果頁全部回 **HTTP 200**，判定也和之前相同：
- spark-test-2 預錄頁 8 個，全部是「已證實可攻擊（擋部署）」，「部署時存入的 5 ether」那行說明也還在。這 8 個裡有 demo_gate.sh 第 0 段產生的 `282b8c64183a`、`b6ef0181b1f5`、`da79cc3f4a0e`、`be1d472f93cc`，以及這次新產生的 `835ff913a026`。
- 今天排練的即時結果頁 `/result/164296cdf6f1`：「未發現可證明攻擊（不等於安全）」。
- 原因：結果頁只讀 `runs/gate/web/<id>.json`。唯一會回頭讀 run 結果檔的是 `deploy_funding()`，它只用來顯示「部署時存入」的範例，找不到檔案時回傳空字串。
- 受影響的只有一頁：`f045a6d23118`（step 2b 的上傳頁，eth_profit）。它指向的結果檔已經搬走，但我確認過，就算讀封存資料夾裡的檔案，結果一樣是空字串，所以畫面沒有任何差別。

## 2. web.py 用語（只改顯示文字）
```diff
-    ("本地鏈重播", "交易與餘額的兩欄重播頁"),
+    ("網頁內的鏈上重播頁", "交易與餘額的兩欄重播頁；終端機版已完成（scripts/live_attack_stakingvault.py）"),
-...（1＝擋部署，2＝稽核未完成，0＝通過）
+...（1＝擋部署，2＝稽核未完成，0＝未擋部署（不代表沒有漏洞））
```
- 重啟網頁後，檢查首頁和 12 個結果頁，共 13 頁：
  - `CLEAR` 0、`safe` 0，「不等於安全」以外的「安全」0。
  - 「0＝通過」0。12 個結果頁都有新的結束碼說明。
  - 「本地鏈重播」0。13 頁都有「終端機版已完成（scripts/live_attack_stakingvault.py）」。
- 截圖：`demo_cleanup/shot_index.png`（首頁，沒有摺疊區）、`demo_cleanup/shot_spark-test-2_282b8c64183a.png`（spark-test-2 結果頁）。

## 3. DEMO_RUNBOOK.md
- 刪掉三條：
  - 備案 5 底下「首頁摺疊區『其他紀錄』demo 時不要打開」那行。
  - 「結果頁『尚未完成的部分』列了『本地鏈重播 開發中』……」那條。
  - 「不要說」那條裡「0＝通過」的口頭補救。這一條原本前半句是「不要說『安全』『CLEAR』『通過＝沒漏洞』」，我只拿掉關於「0＝通過」的部分，留下「不要說『安全』『CLEAR』。」
- 流程表第 1 段的要點加上「**建議在報告開場就送出，不要等到 demo 段**」。
- 備案 5 的其他內容（即時稽核在跑時，誤點「看結果」會排隊）照舊保留，因為這和摺疊區無關，仍然會發生。

## 4. 合併前檢查與整套重跑
- 8 個 probe 的結束碼全部是 0；`patch_probe.py` 5/5 as expected；`live_attack.py` PROVEN、`--patched` NOT PROVEN。
- `scripts/demo_gate.sh --auto`（不加 --live）：rc 0。各段耗時如下：

  | 段 | 耗時 |
  |---|---|
  | 第 0 段 | 14.9 秒 |
  | 第 2 段 | 0.0 秒 |
  | 第 3 段 | 13.2 秒 |
  | 第 4 段 | 0.0 秒 |
  | 各段合計 | **28.1 秒** |
  | 含暫停 | 46.3 秒 |

  - 原合約 PROVEN 2/0/7，修補版 NOT PROVEN 2/2/0。預錄頁判定和 A/B/G 都和之前相同。
  - 這次 api_smoke 花了 **13.3 秒**，距離上一次 LLM 請求大約 15 分鐘。這和排練第 1 次的 15.1 秒一致：閒置一段時間後，第一個請求比較慢；連續跑的時候只要 1.9 秒。這仍然是推測，沒有查 Ollama 的設定。runbook 原本就建議上台前 5 分鐘內先跑一次 api_smoke。
- 零差異：
  - agent.py、tools.py、live.py、live_replay.py、scripts/demo.sh 和 innoserve-base 相比。
  - workspace.py 和 innoserve-base 相比，只有 run_poc 的新增（+17／−2）。
  - verdict.py、patch.py、workspace.py、gate.py、demo_gate.sh 和 9e676b1 相比。
- commit 只包含 web.py。runs/ 和 runs_archive/ 都沒有 commit；runs_archive/ 在 `~/innoserve/` 底下，不在 repo 裡。

## 要你知道
- **`runs_archive/` 目前只有本機一份**，搬移前的備份 tar 裡也有這些檔案。之後如果重新備份，要把 `~/innoserve/runs_archive/` 加進 tar，因為它已經不在 `arbiter/runs/` 底下了。
- 往後每次網頁上傳，`runs/gate/` 都會再多一筆 `gate-StakingVault-*`，首頁摺疊區會重新出現。排練用的上傳在 demo 前要再搬一次；決賽當天現場上傳的那筆本來就應該出現在首頁。
