# ARBITER Gate：InnoServe 2026 決賽作品

ARBITER Gate 是放在智慧合約**部署前**的證據閘門。它只把「真的在 EVM 上跑成功的攻擊」判定為「已證實可攻擊」，並且擋下部署。其他結果分成另外三級，**都不代表合約沒有漏洞**。

這個資料夾（`innoserve/`）放決賽版的文件、預錄 demo 素材和影片。程式碼在 repo 根目錄的 `arbiter/`。

## 從 AIS3 到 InnoServe

**來源**：AIS3 2026 專題 ARBITER（Team 011）。它的核心想法是：模型不能直接「回報」漏洞，必須寫出一個攻擊，由 harness 用 forge 編譯並執行；只有成功條件成立，才算數。而這個成功條件是模型看不到的。AIS3 時期的完整說明在 repo 根目錄的 `README.md` 與 `arbiter/README.md`、`arbiter/RESULTS.md`。

**起點**：公開 repo [yeee3642/arbiter-audit](https://github.com/yeee3642/arbiter-audit) 的 `arbiter-harness` 分支，commit `ead58aef4face495d47cce36fa08d78a9753321b`（2026-09-26）。本 repo 是決賽版的快照，沒有 git 歷史（見「歷史說明」）。

**InnoServe 期間的改善**：計算基準是 ead58ae。`agent.py`、`tools.py` 一行都沒改；`workspace.py` 只新增 `run_poc()` 的兩個選用參數。可以自己比對，見「如何驗證判定核心沒有改」。

| 項目 | 檔案 |
|---|---|
| LLM 端點可設定（`ARBITER_*` 優先，找不到再讀 `AIS3_*`） | `arbiter/arbiter/gateway.py`、`arbiter/cli.py`、`arbiter/scripts/api_smoke.py` |
| 四級判定：已證實可攻擊／未發現可證明攻擊（不等於安全）／無法判定／靜態提示；介面上不出現 CLEAR | `arbiter/arbiter/verdict.py` |
| A/B/G：同一個受害者在 4 個環境下，A＝無攻擊時取回、B＝有攻擊時取回、G＝攻擊者獲利 | `arbiter/arbiter/patch.py`（`reproduce`） |
| 修補閘門 0→L→3→1→2：重現→lint／行數→ABI→攻擊失效→誠實路徑；模型產生修補，閘門驗證 | `arbiter/arbiter/patch.py`、`arbiter/scripts/patch_probe.py` |
| 單檔閘門命令列（`--mode repo` 預設） | `arbiter/arbiter/gate.py` |
| 本機結果頁（只綁 127.0.0.1） | `arbiter/arbiter/web.py` |
| 本地鏈 demo：StakingVault 原合約被掏空，套上模型修補後攻擊失敗 | `arbiter/scripts/live_attack_stakingvault.py` |
| 決賽流程一鍵排練（含計時） | `arbiter/scripts/demo_gate.sh` |

## 數字分兩個時期，不要混用

| 時期 | 模型 | 數字從哪裡來 |
|---|---|---|
| AIS3（2026-07～09） | `ais3/nemotron-3-ultra-550b`（AIS3 課程 gateway） | 根目錄 README、`arbiter/RESULTS.md`。例如 40 筆 paired head-to-head：F1 0.5455 對上 Bastet 調校後的 0.6909 |
| InnoServe（2026-10） | `arbiter-gpt:latest`（gpt-oss 120B，自架 Ollama） | `innoserve/docs/reports/`。例如 StakingVault 在 repo 模式下以 victim_loss 證實 **9/15**；LLM 修補交叉驗證 15/15 失效，但**只有 2 種手法**；`patch_probe.py` 5/5 |

兩個時期的模型、端點和評估集都不同，不能互相比較。

## 一定要講清楚的兩件事

- **鏈上 demo 的攻擊是參考攻擊，不是模型寫的。** 它是 `arbiter/scripts/victim_probe.py` 的 DRAIN，在 2026-07-28 為了校正 victim_loss 判定而寫的已知攻擊。
- **修補是 arbiter-gpt 產生的**，並通過修補閘門（`innoserve/demo_runs/spark-test-{2,3,4}.patches.jsonl`）。修補只代表「針對此攻擊」通過驗證，不代表合約已經沒有漏洞。

## 資料夾

| 路徑 | 內容 |
|---|---|
| `innoserve/docs/CLAUDE.md` | 交接文件。第 7 節是 10/28 的本機進度與已知陷阱 |
| `innoserve/docs/DEMO_RUNBOOK.md` | 決賽 demo 一頁說明：檢查清單、每段要說的話、備案、實測耗時 |
| `innoserve/docs/reports/` | 每一步的報告與原始輸出（截圖、gate.json、鏈上 transcript） |
| `innoserve/demo_runs/` | 預錄 demo 素材：spark-test-1～5 的 results／ledger，加上 2～4 的 patches（arbiter-gpt，2026-10-28） |
| `innoserve/media/` | 程式地圖與評審 QA（PDF）、demo 動畫與操作教學影片（MP4＋SRT 字幕） |

文件裡的 DGX 主機位址與帳號已經改成 `<DGX 位址>`、`<user>`。

## 還原 demo

需要 WSL2 或 Linux、Python 3.11 以上、Foundry（forge／anvil／cast，實測版本 1.8.6）。

```bash
cd arbiter
mkdir -p runs && cp ../innoserve/demo_runs/* runs/      # 預錄素材放回 runs/（runs/ 在 .gitignore 裡）

# 只有即時稽核（--live）和 api_smoke 需要 LLM；預錄和鏈上 demo 不需要
cat > ../.env <<'ENV'
AIS3_API_KEY=local
AIS3_BASE_URL=http://localhost:11434/v1
AIS3_MODEL=arbiter-gpt:latest
ENV

python3 scripts/victim_probe.py          # 判定閘門雙向自檢，不需要網路
python3 scripts/patch_probe.py           # 修補閘門 5 個固定案例，應該是 5/5 as expected
scripts/demo_gate.sh --auto              # 決賽流程：預錄結果頁＋本地鏈原合約／修補版
```

- `demo_gate.sh` 會自己讀 `../.env`、啟動 `python3 -m arbiter.web`（http://127.0.0.1:8765/），並先產生 spark-test-2 的結果頁。
- 沒有 LLM 端點時，api_smoke 只會警告，其他段落照常執行。
- 加 `--live` 會多一段即時上傳稽核，要有可用的端點。
- `.env` 不在 repo 裡，也不要 commit。

## 歷史說明

- **這是決賽版的快照，沒有 git 歷史。** 完整歷史（AIS3 時期到決賽版）放在私人 repo，評審需要時可以邀請檢視。
- 文件和報告裡引用的 commit hash（例如 d09b90f、9e676b1）都在那份完整歷史裡，本 repo 查不到。InnoServe 的起點 ead58ae 例外，它在公開的 yeee3642/arbiter-audit 上。
- **AIS3 gateway 金鑰**：AIS3 時期有幾個早期 commit 的訊息提到 AIS3 gateway 金鑰外洩。該金鑰已經輪替，歷史中所有的值都已遮蔽為 `REDACTED`。本快照不含那些 commit。
- **Bastet 提示原文**：AIS3 時期曾使用 Bastet 的 detector 提示原文，依 Apache-2.0 授權，出處見根目錄的 `NOTICE`。本快照不含那些提示檔：`arbiter/arbiter/bastet_arm.py` 在執行時，才從 repo 外的資料夾讀取提示。

## 貢獻者

依 git log 統計（完整歷史）：
- **ericchen913900**：AIS3 時期的判定核心、閘門與評測。到起點 ead58ae 為止共 **133 個 commit**，全部是這位作者，包括 `agent.py`、`tools.py`、`workspace.py`、`evalsets/`、`scripts/`。
- **sam029031**：InnoServe 延伸。ead58ae 之後到本版共 15 個 commit，內容是上表的「InnoServe 期間的改善」。
- **AIS3 Team 011**：其他 AIS3 隊員以這個名義署名。

## 如何驗證判定核心沒有改

InnoServe 的起點是公開 repo `yeee3642/arbiter-audit` 的 `arbiter-harness` 分支，commit `ead58aef4face495d47cce36fa08d78a9753321b`。在本 repo 根目錄執行：

```bash
git clone -q https://github.com/yeee3642/arbiter-audit /tmp/arbiter-upstream
git -C /tmp/arbiter-upstream checkout -q ead58aef4face495d47cce36fa08d78a9753321b
(cd /tmp/arbiter-upstream && sha256sum arbiter/arbiter/*.py arbiter/cli.py) > /tmp/ead58ae.sha256
sha256sum -c /tmp/ead58ae.sha256
```

預期結果：21 個 `OK`，3 個 `FAILED`（`gateway.py`、`workspace.py`、`cli.py`，也就是下表中「有改」的三個），結束碼是 1。想看改了什麼，可以執行：
`git diff --no-index /tmp/arbiter-upstream/arbiter/arbiter/workspace.py arbiter/arbiter/workspace.py`

| 檔案 | ead58ae 的 sha256 | 本版的 sha256 | |
|---|---|---|---|
| `arbiter/arbiter/agent.py` | `fb98375114a6bdb8aefa729ecc1eaf716f9ea4543f0763230d2b1218346aae7e` | 相同 | 沒改 |
| `arbiter/arbiter/tools.py` | `ea7b3e3bfe81a5897ffd5362edc016fd3da7803c4a0d170cb1e16ff2d1eb65f4` | 相同 | 沒改 |
| `arbiter/arbiter/__init__.py` | `7c5ce8015fae5876cc95899dd088d6025e2b7e90713846035cc28d18c610d48e` | 相同 | 沒改 |
| `arbiter/arbiter/bastet_arm.py` | `c21e00b798d3d7aa7d804aa450f65d236d31210b9da73e71d60134bafc8d4842` | 相同 | 沒改 |
| `arbiter/arbiter/benchmark.py` | `035acc31e054c9c9a76bd17f9baa74f9f2e9e5dcfee8af738d7b22ac5594c538` | 相同 | 沒改 |
| `arbiter/arbiter/broadside.py` | `bc867fcba11c5cd3243a178199622fb4ab086c203497a4b1fda4655f691fd23d` | 相同 | 沒改 |
| `arbiter/arbiter/cascade_lib.py` | `987b70e2ef897c9cacc53fde321f9e2e4ddb278d0c0a075078e60042ae88f478` | 相同 | 沒改 |
| `arbiter/arbiter/citation.py` | `b7b459b482cbe9349112d324b9424c22be8118634e4134f319c5660d54268b07` | 相同 | 沒改 |
| `arbiter/arbiter/dump.py` | `44de72404b3f66f67a4fcdaf2eb992aa837148a6f98fcbbc4f9d3ee2a8aa8918` | 相同 | 沒改 |
| `arbiter/arbiter/evaluate.py` | `f2364e8e07a57b46516dab620ab6edd911adfee951e652ba4bf4b12335560465` | 相同 | 沒改 |
| `arbiter/arbiter/latebinding.py` | `a940a3902c0d1307bbf62debf8011a63d05b8f38a9467f35b8b4bc72d4d70818` | 相同 | 沒改 |
| `arbiter/arbiter/live.py` | `9cb3fdef6865192fdfe66a3684f773afe0283b69c63d597e232f4791393dff32` | 相同 | 沒改 |
| `arbiter/arbiter/live_replay.py` | `6e83ea34cc59320afc0d991c813e73c91e26717ecd7990239f7232bfb491e69a` | 相同 | 沒改 |
| `arbiter/arbiter/onchain.py` | `2c18c66036e7edc31bf8eb5f0da0684d0c856e7398675ca2271cac804161797c` | 相同 | 沒改 |
| `arbiter/arbiter/proposals.py` | `cb00570446e80fe5bb115bf1657e3e980ac00a5d8e1f20fc1968583cce014293` | 相同 | 沒改 |
| `arbiter/arbiter/prove.py` | `005dff0d16b2b0c8b58e915a4729b81ddf45f0174bc4423980f7568cf3bce1c4` | 相同 | 沒改 |
| `arbiter/arbiter/reconstruct.py` | `16c6b0546485833d23ee02e7ec1dd67a1a3a762c8992ff47513c267127b2f37c` | 相同 | 沒改 |
| `arbiter/arbiter/repo.py` | `fbc386e929697ed6c4738bdaa8c5395c04f74830d488c2613086c4fda36e6cb4` | 相同 | 沒改 |
| `arbiter/arbiter/run.py` | `382d924a97d0511a78df5e4b0a1fe6e9e598cab929b31f7926c84f02761aab0d` | 相同 | 沒改 |
| `arbiter/arbiter/score.py` | `ea4b72a98617249c4e7d82b5eb359b2dac041074e443f5377571997370125b99` | 相同 | 沒改 |
| `arbiter/arbiter/triage.py` | `358e545aca90f0c7c5c023a4301b08cec5b21100793fcbde36d03320d9568250` | 相同 | 沒改 |
| `arbiter/arbiter/workspace.py` | `a374deb91b9463303431c49bdf161f4e436b5b6d39738bc39b38a35b4242127d` | `00042b364927122b40c991caf61e7f9fc9dc4c0b30087a87aaede2db3ff025d3` | **有改**（+17／−2） |
| `arbiter/arbiter/gateway.py` | `8c03db70e6088b2f1fe86c7e66a55b613b1febb8f6f4f26ad325d073b46b3a23` | `af3dbdbebd22a4b4d3c6c7f167e848875125f28de154a9b4d582200c083120a7` | **有改**（+7／−4） |
| `arbiter/cli.py` | `55aeceb417035e0078900df63afd1407fd4a76a17626479026f62fc9f7c39215` | `005230bd01f3b206fc36a1ee66d26865ec59e7b1476f1573f9378b6433c27e48` | **有改**（+93／−9） |

改了什麼（行數是 `git diff --numstat` 的結果）：
- **`workspace.py`（+17／−2）**：只改 `run_poc()`，新增兩個選用參數 `match_contract`、`match_test`，有給值時才把 `--match-contract`／`--match-test` 加進 `forge test`。沒給時，指令和原本完全相同。修補閘門需要它，因為報告合約與 exploit 放在同一個測試檔，而 `_test_passed()` 只要看到任何一行 `[PASS]` 就算通過。
- **`gateway.py`（+7／−4）**：
  - API 金鑰改成依序讀 `ARBITER_API_KEY`，找不到再讀 `AIS3_API_KEY`。
  - `base_url` 參數預設值改成 `None`，依序讀 `ARBITER_BASE_URL` → `AIS3_BASE_URL` → 原本的預設值。
  - 錯誤訊息的文字跟著改。
  - 請求、重試、計費、限流的邏輯沒有改。
- **`cli.py`（+93／−9）**：
  - `--model` 預設改讀 `ARBITER_MODEL`／`AIS3_MODEL`。
  - `audit` 的輸出改用 `verdict.py` 的四級判定，不再印 CLEAR；稽核未完成時結束碼是 2。
  - 新增 `fix` 子命令（修補閘門）。
- **InnoServe 新增的檔案**（ead58ae 沒有，所以不在上表）：`arbiter/arbiter/verdict.py`、`patch.py`、`gate.py`、`web.py`，以及 `arbiter/scripts/` 底下的 `patch_probe.py`、`live_attack_stakingvault.py`、`live_replay_one.py`、`demo_gate.sh`。另外 `arbiter/scripts/api_smoke.py` 有修改（+10／−5）：先讀 `ARBITER_*`，`max_tokens` 改成 1024。

## 授權

沿用 repo 根目錄的 `LICENSE`（Apache-2.0）與 `NOTICE`；Bastet 相關的出處說明見 `NOTICE`。
