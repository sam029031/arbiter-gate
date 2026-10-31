<!-- arbiter-gate:comment -->
## ARBITER Gate：🔴 已證實可攻擊（擋部署）

這個 PR 改到的合約有已證實的攻擊，檢查不通過（擋合併）。

### 🔴 `src/StakingVault.sol`：已證實可攻擊（擋部署）

AI 寫出的攻擊，在模擬區塊鏈上真的成功了。有攻擊時，一般使用者領回的錢比沒有攻擊時少，差額落到攻擊者手上；也就是說，有人可以把其他存款人的錢領走。

**建議**：先不要合併。參考下方的修補，修好後再推一次 commit，系統會重新稽核。

這次改到的函式：`unstake`

**Re‑entrancy in unstake() allows draining of vault**（high）

- 有漏洞的函式：`unstake`（**就是這次改到的函式**）
- 證實方式：攻擊程式在模擬區塊鏈上執行，滿足 `victim_loss`（攻擊證明 `ReentrancyDrainExploitPoc`）
- 損失重現（A/B/G）：已重現（合成層）

| 情境 | 受害者初始餘額 | 經過時間 | 攻擊回合 | A 沒攻擊時取回 | B 有攻擊時取回 | G 攻擊者獲利 |
|---|---|---|---|---|---|---|
| 0 | 10 ETH | 0 秒 | 1 | 2 ETH | 0 ETH | 3 ETH |
| 1 | 10000 ETH | 0 秒 | 1 | 2 ETH | 0 ETH | 3 ETH |
| 2 | 10 ETH | 604800 秒 | 1 | 2 ETH | 0 ETH | 3 ETH |
| 3 | 10 ETH | 0 秒 | 8 | 2 ETH | 0 ETH | 3 ETH |

A＝沒有攻擊時受害者取回的錢；B＝有攻擊時取回的錢；G＝攻擊者的獲利。B 比 A 少就是受害者被拿走的錢。
- 證據等級：第 2 階（3 階為本地真鏈重現）

**修補**：修補已通過驗證（針對此攻擊）（改 6 行；用同一個攻擊重打已失效，誠實使用者的取回金額不變）

修補閘門：重現 通過、改得乾淨 通過、介面不變 通過、同一招失效 通過、一般使用者不受影響 通過、專案自己的測試 通過、換手法再攻擊 通過
專案自己的測試（檢查 4）：修補前 3 個通過，修補後 3 個通過。

| 回合 | 誰 | 結果 | 細節 |
|---|---|---|---|
| 1 | 攻擊（原本的稽核） | 攻擊成功（已證實） | 假設：Reentrancy in unstake allows attacker to drain contract, causing victim to lose funds. |
| 1 | 修補 | 修補通過檢查 | 1 個提案 |
| 2 | 攻擊（換手法再攻擊） | 換手法攻擊：未成功（6 回合） | 6 回合、106.1 秒 |

**修補後再攻擊 1 次（6 回合）未成功**。「未成功」只代表這一次換手法沒有找到能成功的攻擊，不代表合約安全。

<details><summary>修補 diff（忽略空白）</summary>

```diff
--- a/src/StakingVault.sol (whitespace ignored, display only)
+++ b/src/StakingVault.sol (whitespace ignored, display only)
@@ -29,11 +29,13 @@
         uint256 amount = stakeOf[msg.sender];
         require(amount > 0, "no position");
         require(block.timestamp >= stakedAt[msg.sender] + lockPeriod, "still locked");
-        (bool ok, ) = msg.sender.call{value: amount}("");
-        require(ok, "eth transfer failed");
+        // Effects: update state before external call to prevent re‑entrancy
         totalStaked -= amount;
         stakeOf[msg.sender] = 0;
         stakedAt[msg.sender] = 0;
+        // Interaction: transfer ETH after state changes
+        (bool ok, ) = msg.sender.call{value: amount}("");
+        require(ok, "eth transfer failed");
         emit Unstaked(msg.sender, amount);
     }
```
</details>

回歸測試：已產生（`TestArbiterRegression`），在這次執行的 Artifacts「arbiter-gate-regression」下載。把 `test/arbiter/` 放進 repo 後，之後每次修改這個檢查都會自動重跑同一個攻擊。


**修補建議**：已在 `src/StakingVault.sol` 第 32–33 行、`src/StakingVault.sol` 第 36 行 附上 suggestion，可以在「Files changed」直接套用。

---

<sub>函式只記名稱：同名的多載（overload）會合成一筆。</sub><br>
<sub>檢查的 commit：`bea2d419b137`（PR 的 head；之後推新的 commit 會重新檢查並更新這則留言）。</sub><br>
<sub>模型：arbiter-gpt:latest；這次送出 11 個 AI 請求；沙箱：on。</sub><br>
<sub>只有「已證實可攻擊」會擋合併；「無法判定」也不放行。其他結果都不代表合約沒有漏洞。</sub><br>
<sub>執行紀錄：https://github.com/sam029031/arbiter-gate-demo/actions/runs/41006113509</sub>

