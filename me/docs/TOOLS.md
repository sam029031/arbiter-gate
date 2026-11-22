# ARBITER Gate × ME Network：鏈上稽核紀錄

ARBITER Gate 要求 AI 寫出能實際執行的攻擊程式，再用 AI 看不到的判定條件檢驗；證實可攻擊就擋下部署，並附上通過 7 項檢查的修補。
這個資料夾把結果放上 ME Network 測試網，讓 AI 產生的稽核結論**經得起追問與溯源**：任何人都能從鏈上查到「誰、在什麼時候、對哪一份程式碼、做出什麼判定、證據是哪些檔案」，並且自己重驗。

## 做了什麼

| 元件 | 作用 |
|---|---|
| `contracts/src/AuditRegistry.sol` | 稽核紀錄只能新增、不能修改或刪除。紀錄存原始碼、gate.json、攻擊程式、修補的雜湊。`deployAudited` 用 CREATE2 只部署和紀錄完全相同的 bytecode，判定 3（已證實可攻擊）和 0（稽核未完成）一律拒絕。 |
| `contracts/src/AuditEscrow.sol` | 用 MEC 付稽核費。稽核完成（判定 1/2/3）付給稽核者；判定 0 或逾期退給委託人。費用和判定結果無關，稽核者報比較好看的判定也拿不到更多。 |
| `me.py deploy` | gate.json → 紀錄 → 判定 1/2 經由登錄合約部署；判定 0/3 顯示合約的拒絕（`NotDeployable`）。 |
| `me.py verify` | 用地址、紀錄編號、原始碼檔案或交易雜湊查詢，並獨立重驗（見下方）。AuditRegistry 本身的地址也查得到（它自己的稽核紀錄以宣告連結）。 |
| `me.py demo` | 早上的實鏈示範（`scripts/me_live_demo.sh` 呼叫它），步驟見下方「實鏈示範」。 |
| `dogfood/` | 用 ARBITER Gate 稽核我們自己兩個合約的 gate.json（`AuditRegistry.gate.json`、`AuditEscrow.gate.json`），示範時原封不動登錄上鏈。 |
| 證據資料夾 | gate.json、原始碼、攻擊程式、修補、回歸測試專案、編譯設定（含 import 的檔案 `imports/`）、`manifest.json`（每個檔案的 sha256）。同樣的輸入一定產生同樣的檔案。 |

## 指令

```bash
export PATH=$HOME/.foundry/bin:$PATH        # 需要 Foundry（forge / cast），Python 只用標準函式庫

bash me/scripts/new_wallet.sh me-testnet     # 建立測試網錢包（密碼自己輸入），印出 0x 與 me1 地址
python3 me/me.py wallet balance <0x 或 me1>  # MEC 餘額
bash me/scripts/me_live_demo.sh me-testnet   # 實鏈示範：部署合約（含自我稽核）、兩個 StakingVault 情境、一筆委託，寫 me/EVIDENCE.md
ME_DEMO_JOB=<jobs 資料夾或編號> ME_DEMO_RID=<網頁結果編號> bash me/scripts/me_live_demo.sh me-testnet   # 改用新的稽核結果

python3 me/me.py preflight Contract.sol      # 用節點模擬部署，檢查 ME 能不能跑（PUSH0）
python3 me/me.py deploy runs/.../gate.json --source Contract.sol --account me-testnet
python3 me/me.py deploy runs/.../gate.json --source Contract.sol --patch --parent <紀錄編號> --account me-testnet
python3 me/me.py verify <地址|紀錄編號|交易> --evidence <證據資料夾> --rebuild --replay
python3 me/me.py escrow request --source Contract.sol --auditor 0x… --fee 0.01 --account me-testnet
python3 me/me.py escrow settle <委託> <紀錄> | refund <委託> | status <委託>
```

每個指令都有 `--network`（預設 `me-testnet`，也可 `anvil`）、`--rpc`、`--json`。送交易用 `--account <keystore 名稱>`，密碼只問一次、不顯示，存在只有自己能讀的暫存檔，結束時刪除（正常結束、Ctrl-C、`kill`／SIGTERM、關掉終端機的 SIGHUP 都會刪）；`--dev` 只能用在 anvil（chain 31337）。
`me_deploy.py`、`me_verify.py` 等同 `me.py deploy`、`me.py verify`。

## 實鏈示範（`me_live_demo.sh` → `me.py demo`）

每一步都記在 `me/deployments/<網路>.demo.json`，中斷後重跑會跳過已完成的步驟。所有輸入在送出第一筆交易前就檢查完。

| 步驟 | 做什麼 | EVIDENCE.md 那一列 |
|---|---|---|
| 1a | 部署 AuditRegistry（一般 CREATE：登錄合約不能經由自己部署） | 部署 AuditRegistry |
| 1b | 登錄 AuditRegistry 的稽核紀錄：sourceHash = `contracts/src/AuditRegistry.sol` 的 sha256、gateJsonHash = `dogfood/AuditRegistry.gate.json` 的 sha256、initcodeHash = Foundry 編譯產物的建立程式碼 | AuditRegistry 的稽核紀錄（用 ARBITER Gate 稽核自己的合約） |
| 1c | 先確認 AuditRegistry 鏈上的 codehash 等於編譯產物 runtime 的雜湊，再 `linkDeployment` → `LINK_CLAIMED` | 宣告 AuditRegistry 本身的位址 |
| 1d | 登錄 AuditEscrow 的稽核紀錄（initcode = 建立程式碼 + `abi.encode(AuditRegistry 位址)`） | AuditEscrow 的稽核紀錄 |
| 1e | AuditEscrow 經由部署閘門部署（`deployAudited` → `LINK_GATED`，位址事先預測）；之後的委託與結算都用它。判定 0/3 時改用一般部署並記下原因 | AuditEscrow 經由部署閘門部署（deployAudited） |
| 2–4 | 委託（0.001 MEC）→ StakingVault 判定 3 登錄、部署被拒、結算付款 → 修補後判定 1 經由閘門部署 | 原有的 7 列 |
| 5 | 寫 `me/EVIDENCE.md`：每個地址與交易、展示的功能，以及每份 gate.json 的產生時間（`generated_at`）與 `tool_commit` | |

輸入（都可以不給）：

- `ME_DEMO_JOB` / `--job`：StakingVault 的稽核結果（含 gate.json 的 `arbiter/runs/gate/jobs/<編號>`，也可以只給編號）；預設是 2026-11-06 的錄製。示範需要判定 3、而且有修補後再攻擊過（check 5）的修補，不符合就在送交易前停下。
- `ME_DEMO_RID` / `--rid`：同一份結果在網頁上的編號，結果頁的鏈上卡片讀 `<rid>.me.json`；預設的 `be2e752405bb` 只有在它就是同一份 gate.json 時才用。
- `dogfood/*.gate.json`（`--self-registry-gate`、`--self-escrow-gate` 可改路徑）：換成新的稽核結果只要把檔案放進去。gate.json 稽核的若是另一版原始碼（`artifact.sha256` 和 `contracts/src` 的檔案不同），正式網路一律拒絕登錄（anvil 排練只警告）；`ME_DEMO_DOGFOOD=0` / `--no-dogfood` 不做自我稽核。
- `ME_EVIDENCE_BASE_ROOT`：`me/evidence` 公開的位置（預設 GitHub 上的 raw 連結），紀錄的 evidenceURI 是其下的 `staking-vault/…` 與 `self/registry`、`self/escrow`；舊的 `ME_EVIDENCE_BASE_URL`（直接指 staking-vault）仍然有效。

如果 `me/deployments/<網路>.json` 來自沒有自我稽核的舊執行，不會重新部署：1b–1d 照做，既有的 AuditEscrow 維持原樣，1e 只在它的程式碼就是稽核過的版本時宣告它的位址（`LINK_CLAIMED`），EVIDENCE.md 會註明。

## 追問：verify 怎麼重驗

- `--evidence DIR`：重算每個證據檔案的 sha256，和鏈上紀錄的 `gateJsonHash / sourceHash / exploitHash / patchHash` 比對。改過一個位元組就會被抓到。
- `--rebuild`：用紀錄的編譯設定（solc 0.8.24、evm paris、optimizer 200、無 metadata hash、無 CBOR）重新編譯，比對 `initcodeHash` 與部署地址上的程式碼。有 import 的合約（AuditEscrow）用證據資料夾 `imports/` 裡的檔案一起編譯；compiler.json 的 `imports` 寫明對應關係。
- `--replay`：用 forge 重跑證據裡的攻擊：在原始碼上攻擊要成功，套用修補（或修補後的原始碼）後要失敗，沒有攻擊時一般使用者拿回的錢不能變少。
`deploy` / `register` 的中斷與重跑：
- 加了 `--escrow-request` 時，**送出任何交易之前**先查委託：還在等待稽核、指定的稽核者就是送交易的帳號、原始碼雜湊相同、還在期限內。任何一項不符就停下，什麼都不送。
- 紀錄一登錄就寫 me.json，之後每做完一步（部署或顯示拒絕、結算委託）再更新；還沒做完的步驟記在 `pending`。某一步失敗（例如網路斷線）會記在 me.json（`deploy.reason`、`escrow_request.settleError`），不會讓已登錄的紀錄消失。
- 重跑同一個指令時，若 me.json 裡的紀錄和這次要登錄的內容完全相同（鏈上 12 個欄位一樣、同一個稽核者）而且還有 `pending`，就接著做剩下的步驟，**不會重複登錄**。
- `escrow settle` 只有委託指定的稽核者能送；`escrow refund` 要等期限過後再加 1 小時的結算寬限，任何人都能送，費用一律退回委託人。

## 追問：verify 怎麼重驗

- `--evidence DIR`：
  - 重算每個證據檔案的 sha256，和鏈上紀錄的 `gateJsonHash / sourceHash / exploitHash / patchHash` 比對。改過一個位元組就會被抓到。
  - 用雜湊等於 `gateJsonHash` 的那份 gate.json，以登錄時同一個函式（`record.gate_fields`）重新推導 `verdict / predicateClass / evidenceTier / patchHash / model`，和鏈上比對；只有判定 3 能帶 `exploitHash`，而且攻擊程式的檔名要是 gate.json 這個漏洞的 PoC。**鏈上判定和它錨定的 gate.json 矛盾時，輸出最上面會有「！！」提示**，verify 以失敗結束。
  - 修補後的紀錄：上一版原始碼（雜湊等於上一版的 `sourceHash`）套用 `patch.diff`（雜湊等於 `patchHash`）之後，sha256 必須等於這一版的 `sourceHash`。多加一行後門就會被抓到。
  - gate.json 記錄的 tool commit 和鏈上 `toolCommit` 不同、或 gate.json 說產生結果的程式有未提交的修改，會顯示「提醒」。
- `--rebuild`：用紀錄的編譯設定（solc 0.8.24、evm paris、optimizer 200、無 metadata hash、無 CBOR）重新編譯，比對 `initcodeHash` 與**查詢的那個部署地址**上的程式碼（用紀錄編號查時，比對紀錄的第一個連結）。
- `--replay`：重跑**鏈上錨定的攻擊**：在原始碼上攻擊要成功，套用修補（或修補後的原始碼）後要失敗，沒有攻擊時一般使用者拿回的錢不能變少。重跑在沙箱裡進行：
  - 在暫存資料夾從零建立 Foundry 專案，只放入 sha256 和鏈上紀錄相同的檔案：原始碼（`sourceHash`，修補後的紀錄用上一版的原始碼）、攻擊程式（`exploitHash`，修補後的紀錄用上一版的）、修補（`patchHash`，或修補後紀錄自己的原始碼）。
  - 回歸測試由攻擊程式和 gate.json 的 A/B/G 量測重新產生（`arbiter.dump.regression_solidity`），誠實路徑的數量必須等於 gate.json 裡 A > 0 的環境數，不可能「0 個中 0 個通過」。
  - `foundry.toml` 由工具自己寫：ffi 關閉、沒有檔案讀寫權限、沒有 remappings、離線；forge 用乾淨的環境變數（沒有呼叫者的 `FOUNDRY_*`、金鑰或 token，HOME 是空的暫存資料夾）執行，只跑重新產生的 `TestArbiterRegression`；Linux 允許時再用 `unshare -rn` 隔離網路（fork 類 cheatcode 連不到任何主機）。
  - 需要的 solc 版本（優先用 gate.json 的 `static_analysis.solc`）不在本機時，先下載一次（這是唯一的網路存取），再用 `forge --use <solc 路徑> --offline` 執行。
  - 證據裡的 `regression.zip` **從不執行**：只把它和用錨定檔案重建的回歸專案逐位元組比對（額外檢查）。zip 多了檔案、測試被改過、或 foundry.toml 打開 ffi／檔案權限，都會列出來並判為不符。
  - 判定 1/2/0 的紀錄沒有 `exploitHash`；證據裡若還附了攻擊程式，就拿它在這份原始碼上跑一次，攻擊成功代表和鏈上判定矛盾，判為不符。
- 查交易：鏈上事件（Registered、Linked）以每次最多 10,000 個區塊（ME 節點 `eth_getLogs` 的上限）分段查，從紀錄的登錄時間對應的區塊開始找；查不到時只顯示「查不到」，不影響其他檢查。

## 信任模型（要講清楚的地方）

- **紀錄是稽核者的主張**，不是事實。合約只保證紀錄不會被改、內容自我一致（只有判定 3 能帶攻擊程式雜湊），以及登錄者是誰。判定對不對，要靠上面的重驗。
- **`deployAudited` 證明部署的程式碼就是稽核過的 bytecode**（連結種類 `LINK_GATED`）。`linkDeployment` 只是稽核者自己宣告某個地址（`LINK_CLAIMED`），要用 `--rebuild` 比對。示範裡 AuditEscrow 是 `LINK_GATED`；AuditRegistry 不可能經由自己部署，只能是 `LINK_CLAIMED`。
- 部署資訊檔的 `auditors` 名單只是部署者的背書；`verify` 會顯示紀錄的稽核者在不在名單內。
- **判定 1 是「沒有找到可證明的攻擊」，判定 2 是「只有靜態工具的提示、沒有證實」，都不等於安全。** 修補後的版本只有在修補後真的再被攻擊過（check 5）才記為判定 1，否則記為 0（未完成，不能部署）。
- `toolCommit`：取自 gate.json 的 `tool_commit`（ARBITER Gate 產生結果時的 git commit）；較早的 gate.json 沒有這個欄位時，用執行工具時的 git HEAD（工具會註明來源），也可用 `--tool-commit` 指定。EVIDENCE.md 逐份寫出 gate.json 的 `generated_at` 與 `tool_commit`。
- **判定 1 是「沒有找到可證明的攻擊」，不等於安全。** 修補後的版本只有在修補後真的再被攻擊過（check 5）才記為判定 1，否則記為 0（未完成，不能部署）。
- `sourceHash` 是 gate 稽核的那份文字的 sha256：UTF-8、換行統一成 LF（gate 讀上傳檔案時就是這樣讀的）。一般的 LF 檔案就等於 `sha256sum` 的結果；CRLF 換行的檔案（例如在 Windows 上存的）也能直接拿來 `deploy`、`verify --source`、`escrow request --source`，工具會用換行統一後的文字，證據的 `src/` 也存這份文字。
- `toolCommit`：取自 gate.json 的 `tool_commit`（產生結果的程式的 git commit）；gate.json 沒有記錄時用執行工具時的 git HEAD；可用 `--tool-commit` 指定內容相同的公開 commit。gate.json 說產生結果的程式有未提交的修改（`tool_commit_dirty: true`，或 `tool_commit_source` 寫著「有未提交的修改」）時，登錄的輸出、me.json 的 `record.toolCommitDirty`／`toolCommitSource`、證據的 manifest 和 `verify` 都會標示：這個 commit 不完全等於實際執行的程式碼。

### 重驗做不到的事（要講清楚）

- `--replay` 執行的是稽核者登錄（錨定）的那份攻擊程式。它裡面除了 AI 寫的攻擊，還有 gate 的判定範本（`TestArbiterVictim`、`arbiterRun`、`arbTrial`）。verify 不檢查這段範本是否和 `toolCommit` 那個版本的 gate 一模一樣（範本會隨版本改，而且含每次隨機抽的位址），所以惡意的稽核者可以登錄一份改過判定的攻擊程式；重跑能證明的是「登錄的這份證據跑出來就是這樣」，責任由登錄它的帳號承擔。
- 沙箱只重建單一合約檔的專案（攻擊程式只 import 被稽核的合約和 `./Vm.sol`）；有其他 import 的專案會明確拒絕重跑。
- 只有 `victim_loss`（受害者少拿回錢）的證明能重跑，和回歸測試的範圍相同；用其他條件證實的紀錄，`--replay` 會寫明無法重跑並判為不符，其餘檢查照常。
- 沒有可用的 `unshare`（macOS、限制 user namespace 的 Linux）時沒有網路隔離：fork 類 cheatcode 仍能連線（會暴露執行 verify 的機器的 IP），但沙箱裡讀不到檔案、金鑰或 token（環境變數只剩 PATH 這類不含秘密的值）；verify 會在結果裡寫明「沒有網路隔離」。

## ME 測試網注意事項

- **一定要用 `evm_version = "paris"` 編譯。** 節點底層是 go-ethereum 1.10.26，會拒絕 PUSH0（`invalid opcode: PUSH0`），雖然 chain_config 寫著 shanghai/cancun。solc 0.8.20 以後預設 shanghai，會產生 PUSH0。`me.py preflight` 會先用 `eth_estimateGas` 讓節點模擬，失敗時提示改用 paris。
- MEC 在 EVM 上是 18 位小數（1 MEC = 10^8 umec = 10^18 wei）；gas 價格 7 wei，每筆交易實際收 1 umec。整個示範 11 筆交易，anvil 實測共用 5,889,636 gas；工具用每筆實測值的 1.15 倍估算（共 7,135,000 gas，拒絕部署那筆以它的 gas 上限 400,000 計），最多需要約 0.0010002 MEC，其中 0.001 MEC 是委託費，結算後付回自己，實際花掉的約 11 umec。
- 瀏覽器（www.explorer-testnet.me）以 Cosmos 交易雜湊和 me1 地址為索引；工具會把 EVM 交易換成它所在的 Cosmos 交易雜湊再產生連結。瀏覽器打不開時，用 `cast receipt <交易> --rpc-url https://beta-hub-8545.explorer-testnet.me` 直接查。
- 測試網沒有標準的 CREATE2 deployer，所以由 AuditRegistry 自己做 CREATE2；建構子裡的 `msg.sender` 是登錄合約，擁有者請用建構子參數傳入。

## 測試

```bash
cd me/contracts && forge test                     # 合約測試
python3 me/scripts/me_registry_probe.py           # anvil 端到端（不需要 LLM、不需要有錢的金鑰），印出「N of M」
                                                  # 含實鏈示範的排練：自我稽核、中斷後續跑、重跑、舊部署補紀錄、餘額不足
```
