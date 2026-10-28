# gate --mode repo 試跑（修法 A）與預設值切換

- 日期：2026-10-28
- 模型：**arbiter-gpt:latest**（gpt-oss 120B，Ollama on DGX Spark），temperature 0.0
- 分支：`innoserve-gate`；forge 1.8.6
- agent.py、tools.py 沒有改動
- 原始輸出：`reports/mode_repo_trial/`（每次的 gate.json 與 stdout、api_smoke、事先寫下的切換條件、瀏覽器測試）

> 本報告數字只屬於 arbiter-gpt，不可與 AIS3 時期 nemotron 的數字混用。

## 事先定好的切換條件（跑之前寫下，跑完沒有修改）

條件寫在 `mode_repo_trial/PREREGISTERED_criterion.md`，跑之前記錄了時間戳與 sha256（`9e81099b…c807c3d`）：

> 把 `--mode` 預設改成 repo（網頁上傳也改走 repo＋--repair），必須同時滿足：
> 1. 5 次的「第一次 run_exploit 謂詞」全部是 victim_loss；
> 2. 5 次都沒有被判「無法判定（稽核未完成）」。
>
> 不符合就維持 hermetic，只回報結果。證實率不列入切換條件，照實記錄。

## 實作：gate.py `--mode {hermetic,repo}`

- `--mode repo`：把單檔複製到 `runs/gate/<run_id>/<檔案原本所在資料夾名>/<檔名>`，item 寫 `path`、`repo_root`。資料夾名稱沿用原檔所在的資料夾，因為 `cli.py audit <file>` 的 repo 名稱就是這樣來的。
  **確認模型收到的 user 訊息和 `cli.py audit` 逐字相同**：兩邊用程式重建後比較，結果完全一致（2447 字元）；5 次試跑的第一回合 prompt_tokens 都是 5248，和 spark-test 相同。
- 一樣不套 `triage_all`；一樣先做編譯預檢（沒有 import 的檔案兩種模式都檢查）。實測 Broken.sol 用 `--mode repo` 判「無法判定」、0 請求。
- A/B/G 與修補用 `exploit_from_row()` 轉成 hermetic，只限沒有 import 的檔案。
- 有 import 的檔案行為不變（照舊在原位置以 in_repo 跑）。

## 結果：5 次 `gate --file examples/StakingVault.sol --mode repo --repair`

先跑 `api_smoke.py`：`PASS: gateway at http://localhost:11434/v1 replied AIS3_OK`。

| run-id | 第一次謂詞 | 所有 run_exploit 謂詞（回合） | 判定 | 證實謂詞 | A/B/G（ETH，env 0／1／2／3） | 修補 | 請求（稽核＋修補） | 耗時 |
|---|---|---|---|---|---|---|---|---|
| modetrial-repo-1 | victim_loss | victim_loss(1) | 未發現可證明攻擊（agent_concluded_no_attack） | — | — | — | 4＋0＝4 | 174 秒 |
| modetrial-repo-2 | victim_loss | victim_loss(0)、victim_loss(1) | 已證實可攻擊 | victim_loss（strict） | 2/2/1、2/2/1、2/2/1、2/0/7 | 通過（2 輪） | 4＋2＝6 | 135 秒 |
| modetrial-repo-3 | victim_loss | victim_loss(0)、victim_loss(1) | 已證實可攻擊 | victim_loss（strict） | 2/2/1、2/2/1、2/2/1、2/0/7 | 通過（1 輪） | 4＋1＝5 | 130 秒 |
| modetrial-repo-4 | victim_loss | victim_loss(0)、victim_loss(1) | 已證實可攻擊 | victim_loss（strict） | 2/2/1、2/2/1、2/2/1、2/0/7 | 通過（2 輪） | 4＋2＝6 | 130 秒 |
| modetrial-repo-5 | victim_loss | victim_loss(0)、victim_loss(1) | 已證實可攻擊 | victim_loss（strict） | 2/2/1、2/2/1、2/2/1、2/0/7 | 通過（1 輪） | 4＋1＝5 | 125 秒 |

- finish_reason=length：0 次。
- 證實率 4/5，4 次都是 victim_loss，A/B/G 和 spark-test 一致，4 次的 LLM 修補都通過修補閘門。
- 修補輪數：2 次第 1 輪就過，2 次第 2 輪才過。
- 耗時為 gate 整個指令（稽核＋A/B/G 重現＋修補＋重新驗證）：125～174 秒。

## 判定：符合切換條件 → 已切換

| 條件 | 結果 |
|---|---|
| 1. 5 次的第一次謂詞都是 victim_loss | ✅ 5/5 |
| 2. 沒有任何一次「無法判定」 | ✅ 0/5（第 1 次是「未發現可證明攻擊」，不是「無法判定」） |

已改：
- `gate.py` 的 `--mode` 預設改成 `repo`（argparse 旁有註解，指向本報告）。
- 網頁上傳改成 `gate --file … --mode repo --repair`。
- 網頁上傳說明改成「一次稽核加修補約 2～3 分鐘（10/28 以 StakingVault 實測 5 次：125～174 秒）」。

## 順手修正：LLM 請求數漏算修補

gate.json 的 `llm_requests_this_invocation` 原本只算 run_arbiter（稽核）的請求，沒有算 `--repair` 的請求，網頁上的「本次 LLM 請求數」會少算。已改成總數＝稽核＋修補，另外新增 `llm_requests_audit`、`llm_requests_repair` 兩個欄位，網頁顯示「6（稽核 4、修補 2）」這種格式。
**上表 5 次試跑是在修正前跑的**，所以它們 gate.json 裡的 `llm_requests_this_invocation` 只有稽核的 4；表中的總數是用 `repair_usage.requests` 補算的。

## 瀏覽器長時間等待測試：沒有斷線，但耗時超出網頁上寫的範圍

- 方法：用測試頁（127.0.0.1:8766，不進 repo）載入後，以 DataTransfer 把 StakingVault.sol 放進 `<input type=file>` 並自動送出表單到 `http://127.0.0.1:8765/upload`。這和手動選檔上傳是相同的 multipart POST。瀏覽器是 Windows Edge headless，等到結果頁才 dump DOM。
- 結果：**沒有斷線**。伺服器紀錄 `POST /upload 303` → `GET /result/54df038420ab 200`，dump 出來的頁面標題是「ARBITER Gate 結果」。
- **這次 gate 本身跑了 364.5 秒**（`gate-StakingVault-20261028-194100-0a9e35`，repo 模式，6 個請求，判「未發現可證明攻擊」），瀏覽器總共等了 367 秒。比 5 次試跑最長的 174 秒還久，所以「等到最長那次」這項有涵蓋到，而且超過 300 秒也沒有斷線。
- **要注意**：網頁上寫的「約 2～3 分鐘」是照規格用這 5 次的實際數字，但 repo 模式其他實測明顯更久。predexp-repo 三次是 155、310、465 秒，這次瀏覽器上傳是 365 秒。目前 repo 模式共 9 次的耗時範圍是 **125～465 秒**；模型沒有很快找到攻擊時（conclude_safe 或回合用完）特別慢。建議改成「約 2～8 分鐘」並註明實測範圍，等你決定，這次沒改。
- 465 秒那種長度沒有在瀏覽器裡測過；伺服器端 `FILE_TIMEOUT` 是 900 秒。

## 用語與合併前檢查

- 5 次 gate.json／stdout 與瀏覽器 DOM：`CLEAR` 0 筆、`safe` 0 筆、「不等於安全」以外的「安全」0 筆。
- 8 個 probe 結束碼全 0；`patch_probe.py` 5/5 as expected；`live_attack.py` PROVEN、`--patched` NOT PROVEN。
- `agent.py`、`tools.py` 與 `innoserve-base` 零差異；`verdict.py`、`patch.py`、`workspace.py` 自 e7ebe8b 起零差異。

## 這次沒有處理的

- 累計 repo 模式的 victim_loss 證實（cli audit＋gate repo）：spark-test 4/5、predexp-repo 1/3、modetrial 4/5，加上瀏覽器那次 0/1，合計 **9/14**。決賽現場即時稽核仍有約三分之一機會沒證實；主線維持預錄。
- `run_exploit` 工具說明只列舊謂詞的問題沒有修（tools.py 不動），已記進第 7 節已知陷阱第 13 條，答辯時主動說明。
