# 切換條件（跑 5 次之前寫下，跑完不得修改）

寫入時間：見檔案 mtime 與下方 date 輸出。

指令：`python3 -m arbiter.gate --file examples/StakingVault.sol --mode repo --repair`，5 次，每次新的 run-id，先跑 api_smoke.py。

**把 `--mode` 預設改成 repo（網頁上傳也改走 repo＋--repair），必須同時滿足：**
1. 5 次的「第一次 run_exploit 謂詞」全部是 victim_loss；
2. 5 次都沒有被判「無法判定（稽核未完成）」（not_executed）。

不符合就維持 hermetic，只回報結果。證實率不列入切換條件，照實記錄。
written at 2026-10-28 19:27:44 +0800
