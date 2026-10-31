<!-- arbiter-gate:comment -->
## ARBITER Gate：🔴 已證實可攻擊（擋部署）

這個 PR 改到的合約有已證實的攻擊，檢查不通過（擋合併）。

### 🔴 `src/StakingVault.sol`：已證實可攻擊（擋部署）

AI 寫出的攻擊，在模擬區塊鏈上真的成功了。有攻擊時，一般使用者領回的錢比沒有攻擊時少，差額落到攻擊者手上；也就是說，有人可以把其他存款人的錢領走。

**建議**：先不要合併。參考下方的修補，修好後再推一次 commit，系統會重新稽核。

這次改到的函式：`unstake`

**Re‑entrancy in unstake() allows attacker to drain the vault and cause honest users to lose their stake**（High）

- 有漏洞的函式：`unstake`（**就是這次改到的函式**）
- 證實方式：攻擊程式在模擬區塊鏈上執行，滿足 `victim_loss`（攻擊證明 `StakingVaultReentrancyVictimLossExploitPoc`）
- 損失重現（A/B/G）：已重現（合成層）

| 情境 | 受害者初始餘額 | 經過時間 | 攻擊回合 | A 沒攻擊時取回 | B 有攻擊時取回 | G 攻擊者獲利 |
|---|---|---|---|---|---|---|
| 0 | 10 ETH | 0 秒 | 1 | 1 ETH | 0 ETH | 6 ETH |
| 1 | 10000 ETH | 0 秒 | 1 | 1 ETH | 0 ETH | 6 ETH |
| 2 | 10 ETH | 604800 秒 | 1 | 1 ETH | 0 ETH | 6 ETH |
| 3 | 10 ETH | 0 秒 | 8 | 1 ETH | 0 ETH | 6 ETH |

A＝沒有攻擊時受害者取回的錢；B＝有攻擊時取回的錢；G＝攻擊者的獲利。B 比 A 少就是受害者被拿走的錢。
- 證據等級：第 2 階（3 階為本地真鏈重現）

**修補**：修補已通過驗證（針對此攻擊）（改 8 行；用同一個攻擊重打已失效，誠實使用者的取回金額不變）

<details><summary>修補 diff（忽略空白）</summary>

```diff
--- a/src/StakingVault.sol (whitespace ignored, display only)
+++ b/src/StakingVault.sol (whitespace ignored, display only)
@@ -29,11 +29,13 @@
         uint256 amount = stakeOf[msg.sender];
         require(amount > 0, "no position");
         require(block.timestamp >= stakedAt[msg.sender] + lockPeriod, "still locked");
+        // Effects: update state before external call to prevent re‑entrancy
+        stakeOf[msg.sender] = 0;
+        stakedAt[msg.sender] = 0;
+        totalStaked -= amount;
+        // Interaction: transfer ETH after state changes
         (bool ok, ) = msg.sender.call{value: amount}("");
         require(ok, "eth transfer failed");
-        totalStaked -= amount;
-        stakeOf[msg.sender] = 0;
-        stakedAt[msg.sender] = 0;
         emit Unstaked(msg.sender, amount);
     }
```
</details>

回歸測試：已產生（`TestArbiterRegression`），在這次執行的 Artifacts「arbiter-gate-regression」下載。把 `test/arbiter/` 放進 repo 後，之後每次修改這個檢查都會自動重跑同一個攻擊。

### repo 裡的回歸測試（TestArbiterRegression）

❌ 沒有通過：`testExploitBlocked()`

### 略過（不是可部署的合約）

- `test/arbiter/ArbiterRegression.t.sol`：路徑是測試、mock 或部署腳本
- `test/arbiter/Vm.sol`：路徑是測試、mock 或部署腳本


**修補建議**：已在 `src/StakingVault.sol` 第 32–36 行 附上 suggestion，可以在「Files changed」直接套用。

---

<sub>函式只記名稱：同名的多載（overload）會合成一筆。</sub><br>
<sub>檢查的 commit：`36f897309a12`（PR 的 head；之後推新的 commit 會重新檢查並更新這則留言）。</sub><br>
<sub>模型：arbiter-gpt:latest；這次送出 6 個 AI 請求；沙箱：on。</sub><br>
<sub>只有「已證實可攻擊」會擋合併；「無法判定」也不放行。其他結果都不代表合約沒有漏洞。</sub><br>
<sub>執行紀錄：https://github.com/sam029031/arbiter-gate-demo/actions/runs/40993511867</sub>

