# LLM 修補交叉驗證：3 個修補 × 5 個已證實攻擊（2 種手法）

- 日期：2026-10-28
- 模型：**arbiter-gpt:latest**（gpt-oss 120B，Ollama on DGX Spark）。修補由它產生；交叉驗證本身**不呼叫 LLM**。
- 程式：`innoserve-gate` @ e363530，`arbiter.patch.verify_fix(..., run_all=True)`，hermetic 模式，forge 1.8.6
- 目標：`examples/StakingVault.sol`（4 筆結果的 source 完全相同，sha256 只有 1 種）

> 本報告數字只屬於 arbiter-gpt，不可與 AIS3 時期 nemotron 的數字混用。

## 做法

- 修補：spark-test-2、3、4 經 `patch.repair()` 被接受的 LLM 修補（各 6 行，`diff_line_count`）。
- 攻擊：spark-test-2～5 的已證實 victim_loss exploit（`pocs[]` 中 `passed && adjudicated` 那筆的完整 `solidity`），**原封不動**，只把 `import "arbiter-target/StakingVault.sol"` 改指向 `../src/Target.sol`。
- 每個攻擊先跑檢查 0（在原合約重現並量 A/B/G），再對每個修補跑完整閘門（0、L、3、1、2 全部執行）。
- 「攻擊失效」＝檢查 1 通過：同一 exploit 在修補版能編譯，且 4 個環境都不成立。

## 第一種手法：單次重入（spark-test-2～5 的 exploit）：12/12 攻擊失效

| 修補 ＼ 攻擊 | exploit 2 | exploit 3 | exploit 4 | exploit 5 |
|---|---|---|---|---|
| **patch 2** | 失效 | 失效 | 失效 | 失效 |
| **patch 3** | 失效 | 失效 | 失效 | 失效 |
| **patch 4** | 失效 | 失效 | 失效 | 失效 |

- 12 格的閘門結果都是 `0:pass L:pass 3:pass 1:pass 2:pass`，也就是 12 格都會被接受。
- 對角線（patch i 對 exploit i，i＝2、3、4）是修補時 LLM 面對的那個 finding。其餘 9 格是別次稽核產生的 exploit，exploit 5 從沒進過修補迴圈。
- 修補前（4 個 exploit 都相同）：A/B/G（ETH）依環境為 2/2/1、2/2/1、2/2/1、**2/0/7**。只有第 4 個環境（8 輪）讓受害者受損。
- 修補後（12 格都相同）：4 個環境的誠實取回 A 都是 2 ETH，和修補前一樣；有攻擊時 B＝2 ETH、G＝0。
- 失效訊息：`ARBITER: the attack reverted in every environment, or the victim's own path never worked`。重入的那一次 `unstake()` 因為部位已清零，在 `require(amount > 0)` revert，整筆攻擊回滾。always-revert 的假修補也是這句，所以由檢查 2 負責區分：12 格的檢查 2 都通過，誠實路徑完整。

## 第二種手法：DRAIN（victim_probe.py，最多重入 8 次）

不呼叫 LLM，也不改任何檢查。直接用 `scripts/victim_probe.py` 的 `DRAIN` 規格，以 `Workspace.compose_victim_loss(**DRAIN)` 對 `examples/StakingVault.sol` 組一次，之後不再重組。
DRAIN 原本就是寫給名為 `StakingVault`、有 `stake()`／`unstake()` 的合約，和這份示範合約的介面相同，所以規格**一字未改**，只把目標換成 StakingVault。

```solidity
contract Attacker {
    StakingVault public v;
    uint256 public hits;
    constructor(address _v) payable { v = StakingVault(payable(_v)); }
    function attack() external {
        v.stake{value: 1 ether}();
        v.unstake();
    }
    receive() external payable {
        if (hits < 8 && address(v).balance >= 1 ether) { hits++; v.unstake(); }
    }
}
```
- deploy：`StakingVault target = new StakingVault{value: 5 ether}();`
- 受害者：`target.stake{value: 2 ether}();` → `target.unstake();`

**檢查 0（原合約）：成立。** A/B/G（ETH）在 4 個環境都是 **2/0/7**：受害者沒被攻擊時取回 2，被攻擊時取回 0，攻擊者獲利 7（5 ETH 底池加受害者的 2 ETH 全部被掏空）。
模型的單次重入攻擊只在 8 輪環境受損（2/2/1 ×3、2/0/7）；DRAIN 在每個環境都受損，是比較強的攻擊。

| 修補 | DRAIN 攻擊 | 閘門（0/L/3/1/2） | 修補後 A/B/G（ETH，4 個環境） |
|---|---|---|---|
| **patch 2** | 失效 | pass/pass/pass/pass/pass | 2/2/0 ×4 |
| **patch 3** | 失效 | pass/pass/pass/pass/pass | 2/2/0 ×4 |
| **patch 4** | 失效 | pass/pass/pass/pass/pass | 2/2/0 ×4 |

失效訊息與前一節相同（`the attack reverted in every environment ...`）：第一次重入的 `unstake()` 遇到已清零的部位，在 `require(amount > 0)` revert。修補後受害者有沒有被攻擊都取回 2 ETH，攻擊者獲利 0。

**合計：3 個修補 × 5 個 exploit（2 種手法）＝ 15 格，15/15 攻擊失效，15 格都會被接受。**
原始資料：`xval_llm_patches_2026-10-28.json`（3×4）、`xval_llm_patches_2026-10-28.drain.json`（DRAIN 的完整 Solidity 與每格結果）。

## 限制（要一起引用）

1. **攻擊共 2 種手法，不是 5 種。** spark-test-2～5 的 4 個 `Attacker` 合約正規化空白後完全相同（sha256 前 10 碼 `7ee20436f2`），內容都是「stake 1 ETH，`receive()` 裡重入 `unstake()` 一次」，deploy 也相同，只差 harness 抽的地址，算 1 種手法。DRAIN（`receive()` 裡最多重入 8 次）是第 2 種。兩種都是對 `unstake()` 的重入，屬同一類漏洞；這份驗證**沒有涵蓋其他類別的攻擊**。
2. DRAIN 是人寫的參考攻擊，不是 arbiter-gpt 產生的；LLM 修補時從沒看過它，算留出驗證。單次重入那 4 個則是 arbiter-gpt 自己的 exploit，其中 exploit 5 也從沒進過修補迴圈。
3. 3 個修補是同一種解法（checks-effects-interactions：先清狀態再轉帳），只是寫法不同。
4. 通過修補閘門只代表：這些攻擊在 4 個環境都失效、誠實路徑沒受損、介面沒變。**不代表合約安全。**
5. patch 3 重寫了整個函式的縮排，patch 4 多縮排了 2 格。`diff_line_count` 不計空白，所以照樣算 6 行；功能不受影響，但 demo 畫面要注意。

## 三個修補

### patch 2（spark-test-2，第 1 輪接受）
```diff
@@ -21,11 +21,10 @@
         uint256 amount = stakeOf[msg.sender];
         require(amount > 0, "no position");
 
-        // Deliberate reentrancy bug: state is cleared after the external call.
+        // Fixed reentrancy: update state before external call.
+        totalStaked -= amount;
+        stakeOf[msg.sender] = 0;
         (bool ok, ) = msg.sender.call{value: amount}("");
         require(ok, "eth transfer failed");
-
-        totalStaked -= amount;
-        stakeOf[msg.sender] = 0;
     }
 }
```

### patch 3（spark-test-3，第 1 輪接受；整段重新縮排）
```diff
@@ -17,15 +17,13 @@
         totalStaked += msg.value;
     }
 
-    function unstake() external {
-        uint256 amount = stakeOf[msg.sender];
-        require(amount > 0, "no position");
-
-        // Deliberate reentrancy bug: state is cleared after the external call.
-        (bool ok, ) = msg.sender.call{value: amount}("");
-        require(ok, "eth transfer failed");
-
-        totalStaked -= amount;
-        stakeOf[msg.sender] = 0;
-    }
+function unstake() external {
+    uint256 amount = stakeOf[msg.sender];
+    require(amount > 0, "no position");
+    // Fixed reentrancy: update state before external call.
+    totalStaked -= amount;
+    stakeOf[msg.sender] = 0;
+    (bool ok, ) = msg.sender.call{value: amount}("");
+    require(ok, "eth transfer failed");
 }
+}
```

### patch 4（spark-test-4，第 0 輪抄錯行被 L 擋下，第 1 輪接受）
```diff
@@ -21,11 +21,10 @@
         uint256 amount = stakeOf[msg.sender];
         require(amount > 0, "no position");
 
-        // Deliberate reentrancy bug: state is cleared after the external call.
-        (bool ok, ) = msg.sender.call{value: amount}("");
-        require(ok, "eth transfer failed");
-
-        totalStaked -= amount;
-        stakeOf[msg.sender] = 0;
+          // Fixed reentrancy: update state before external call (checks-effects-interactions).
+          stakeOf[msg.sender] = 0;
+          totalStaked -= amount;
+          (bool ok, ) = msg.sender.call{value: amount}("");
+          require(ok, "eth transfer failed");
     }
 }
```
