# REV 行顯示修正＋第二次本機備份

- 日期：2026-10-28；起點 239fe70 → commit **d09b90f**
- **0 個 LLM 請求**：所有 ledger（runs/ 加上 runs_archive/）總行數前 116、後 116。demo_gate.sh 的 api_smoke 不寫 ledger。
- 沒有改動：agent.py、tools.py、verdict.py、patch.py、workspace.py、live.py、live_replay.py、gate.py、web.py。這次只改 `scripts/live_attack_stakingvault.py` 的顯示。
- 原始輸出：`reports/rev_display_backup/`
  - original 和 patched-spark-test-2 兩次執行的 .txt／.json
  - demo_gate.sh 的 `demo_auto.txt`／`.tsv`

## 1. REV 行顯示

### 改之前（第 203 行）
```
    REV attack()                       tx=-  gas=0  (000000000000000000\": Error(\"eth transfer failed\")"}],"warnings":[]})
```
### 改之後
```
    REV attack()                       reverted: eth transfer failed
        （節點在估算 gas 時就拒絕，交易沒有送出上鏈）
```
- 取原因的方法：用正規式 `Error\(\\*"(.*?)\\*"\)` 從 step note 取出原因，note 裡的引號是跳脫過的。取不到時印「reverted（原因見 JSON transcript）」。
- 「估算 gas 時就拒絕」那行的出現條件：**原因有取到，而且這個步驟沒有 tx hash**。
  - 依據：我在 anvil 上部署 StakingVault，再用沒有部位的帳戶 `cast send … unstake() --json`。
  - 完整錯誤是 `"Failed to estimate gas: server returned an error response: error code 3: execution reverted: no position …"`，而且送完後發送者的 nonce 仍是 0。
  - `live.py` 只把錯誤的最後 200 字存進 note，「Failed to estimate gas」那段被截掉了。所以每一步沒辦法直接從 note 讀到這句，只能靠「沒有 tx hash」來判斷。
- **和指示不完全相同**：指示只要求修補版的 `attack()` 那行加註明。但原合約攻擊鏈上，受害者的 `unstake()` 也是同樣情況：沒有 tx hash、在估算 gas 時就 revert（`eth transfer failed`）。所以那一行也會出現這句註明。如果只想在 `attack()` 那行顯示，要把條件改成依步驟名稱判斷，我沒有這樣做。
- transcript JSON、判定規則、結束碼都沒有改。

### 驗證
| 執行 | 結束碼 | 判定 | A/B/G | 和 10/28 第 1 次的 JSON 相比 |
|---|---|---|---|---|
| 原合約 | 0 | PROVEN | 2/0/7（attacker_net 6.999911 ETH） | `verdict`、`meta`、兩條鏈的 transcript（每筆交易 hash、gas、note、餘額）**全部相同**，整份 JSON 解析後相等 |
| `--patched spark-test-2` | 0 | NOT PROVEN | 2/2/0 | 同上，全部相同 |

- `scripts/demo_gate.sh --auto`（不加 --live）：rc 0。
  - 各段耗時：第 0 段 14.6 秒、第 2 段 0.0 秒、第 3 段 15.3 秒、第 4 段 0.0 秒；各段合計 29.9 秒，含暫停 48.0 秒。
  - 輸出裡已經沒有 JSON 碎片（長串 `000000000000` 出現 0 次）。
  - api_smoke 12.8 秒，閒置後第一個請求又是 13 秒左右，和前兩次一致。

## 2. 第二次本機備份

**目的地**：`<本機備份位置>/20261028_224246/`。上一份 `20261028_222433/` 保留，內容沒動。

| 檔案 | 大小 | sha256 |
|---|---|---|
| `arbiter-audit.bundle` | 7,448,302 bytes | `d5021f4cdb2bb28afc7d7523a534e1e9527129baa1d17bb89d477eeadb43befa` |
| `innoserve-materials.tar.gz` | 1,560,442 bytes | `dce7193ef964427e71ad8ce1a323813e435a9d085f98c98d4031bfb6effa1142` |
| `RESTORE.md` | 4,766 bytes | `8b05b8ed6415cbf78ee5d4bf9f77e40fa05bbe21cd09a6d9be251f5e06f1c3f1` |

- 前置：開始時 `git status` 是乾淨的；d09b90f 先 commit，bundle 才會包含這次的修改。
- bundle：
  - `git bundle verify` 結果是 okay。
  - 本機 14 個 ref 全部在 bundle 裡，和本機逐一比對相同。
  - clone 到 `/tmp/arbiter-bundle-check.*` 後，innoserve-gate 是 `d09b90f4eddb…`、innoserve-base 是 `ead58aef…`，都和本機相同。
  - 在 clone 裡跑 `patch_probe.py`，結果 **5/5 as expected**。暫存 clone 已經刪除。
- tar：
  - 共 417 個項目，**新增 `innoserve/runs_archive/`**（151 個項目，其中 86 個檔案）。spark-test-1～5 的 results／ledger／patches 共 13 個檔案都在裡面。
  - 大小 1.5 MB，沒超過 50 MB。
  - 解開掃描結果：沒有 .env 檔、私鑰、ssh 設定檔、`sk-` 金鑰、anvil 私鑰或 `--private-key` 參數。64 位十六進位字串全部是交易 hash（`tx=` 或 `"tx":` 開頭）。`AIS3_API_KEY=local` 和 `=...` 是 CLAUDE.md 和報告裡的說明文字，不是金鑰。
  - 複製到目的地後用 `cmp` 比對過，和原檔一致。
- RESTORE.md 有一張表，寫明每個 tar 路徑的還原位置。`runs_archive/` 要還原到 **`~/innoserve/runs_archive/`**，和 arbiter-audit 同一層，不在 repo 裡；web.py 不會讀這個資料夾。
- tar 裡的這份報告和 CLAUDE.md 是打包當下的版本，報告還沒有補上本節的雜湊值。CLAUDE.md 已經寫好新備份的位置。

## 3. 合併前檢查
- 8 個 probe 的結束碼全部是 0；`patch_probe.py` 5/5 as expected；`live_attack.py` PROVEN、`--patched` NOT PROVEN。
- 零差異：
  - agent.py、tools.py、live.py、live_replay.py、scripts/demo.sh 和 innoserve-base 相比。
  - workspace.py 和 innoserve-base 相比，只有 run_poc 的新增（+17／−2）。
  - `arbiter/arbiter/` 底下全部檔案，和 239fe70 相比。
- commit d09b90f 只包含 `scripts/live_attack_stakingvault.py`（+24／−3）。runs/ 和 runs_archive/ 都沒有 commit。
