# 自我稽核：用 ARBITER Gate 稽核我們自己的合約

這裡放 ARBITER Gate 對 `me/contracts/src` 兩個合約的稽核結果。實鏈示範（`me/scripts/me_live_demo.sh`）把它們原封不動登錄上鏈：

| 檔案 | 稽核對象 | 鏈上怎麼用 |
|---|---|---|
| `AuditRegistry.gate.json` | `me/contracts/src/AuditRegistry.sol` | 登錄紀錄，再以 `linkDeployment` 宣告 AuditRegistry 本身的位址（`LINK_CLAIMED`；登錄合約不可能經由自己部署） |
| `AuditEscrow.gate.json` | `me/contracts/src/AuditEscrow.sol` | 登錄紀錄，再由 AuditRegistry 以 `deployAudited` 部署 AuditEscrow（`LINK_GATED`） |

- 紀錄的 gateJsonHash 是檔案本身的 sha256，檔案一個位元組都不能改。
- 換成新的稽核結果：用同樣的檔名放進來即可，不用改程式。
- gate.json 稽核的檔案（`files[].artifact.sha256`）必須就是目前 `me/contracts/src` 裡的那一份（`sha256sum me/contracts/src/*.sol` 對照）；稽核的是另一版原始碼時，正式網路一律拒絕登錄，anvil 排練只警告。
- 這兩份 gate.json 是 public_report 輸出，不含主機路徑；提交前仍請確認沒有密鑰或個人路徑。
