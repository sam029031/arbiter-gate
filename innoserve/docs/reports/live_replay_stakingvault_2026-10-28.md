# StakingVault 的模型攻擊能不能用 live_replay 上本地鏈

- 日期：2026-10-28
- 攻擊來源：**arbiter-gpt:latest** 的 spark-test-2（victim_loss，`StakingVaultReentrancyExploitPoc`）；重播本身**不呼叫 LLM**（所有 ledger 檔總行數前後都是 109）
- 工具：anvil／forge／cast 1.8.6（commit 6bad0a6）；起點 144b61d
- `live_replay.py`、`live.py`、agent.py、tools.py、verdict.py、patch.py 都沒有改動
- 原始輸出：`reports/live_replay_stakingvault/`

> 本報告數字只屬於 arbiter-gpt，不可與 AIS3 時期 nemotron 的數字混用。

## 結論

**無法直接上鏈：轉譯成功（沒有 Untranslatable），但鏈上結果和合成層不一致。依指示停在這裡，沒有修改 live_replay，也沒有跑反向（修補版）。** 要不要改用 `live_attack.py` 的 WithdrawalQueue 當鏈上 demo，由使用者決定。

| | 合成層 env 0（受害者 10 ETH、1 輪） | 合成層 env 3（8 輪） | 鏈上 replay（1 輪） |
|---|---|---|---|
| 無攻擊取回（A） | 2 ETH | 2 ETH | **7 ETH** |
| 有攻擊取回（B） | 2 ETH | 0 ETH | **7 ETH** |
| 攻擊者獲利（G） | 1 ETH | 7 ETH | **0**（攻擊交易 revert） |
| 判定 | 不成立 | 成立 | NOT PROVEN |

## 前置檢查

- `anvil Version: 1.8.6`（`forge`、`cast` 同版）
- `live_attack.py`：`PROVEN on a live chain`；`live_attack.py --patched`：`NOT PROVEN`（照舊）

## 做法

新增 `scripts/live_replay_one.py`，只呼叫現有函式：
- 從結果檔取第一筆 `passed && adjudicated` 的 PoC。
- 依 `scripts/live_sweep.py` 的順序嘗試 `parse_poc`（victim 模板）→ `parse_poc_exploit` → `parse_poc_other`，交給對應的 `replay*`。
- 加 `--patches` 時，用 `patch.apply_diff` 把通過閘門的 diff 套到目標上再重播，這次因為停下來所以沒有執行。

## 正向：原合約重播（實際輸出）

```
exploit StakingVaultReentrancyExploitPoc (victim_loss) against the original target
  template victim
  world no attack  : victim recovered 7 ETH, attacker gain 0 ETH, target 7 ETH -> 0 ETH, exit_ok=True
      ok  deploy ArbWorld (setup)      tx=0x7966524d0f3e59dc2c75c314fa4f065fffe1ca4bf9dca2ff3224823e62c1c00c
      ok  enter()                      tx=0x8f09a9a647836f38fbba2619970954482e9bfc9176d3014611127df987839eb3  gas=45821
      ok  exit()                       tx=0x2d6a61ca7b56c53d8e0bb7b89c8e32b2d89945b376986f8cc46cd81017d7c346  gas=37168
  world with attack: victim recovered 7 ETH, attacker gain 0 ETH, target 7 ETH -> 0 ETH, exit_ok=True
      ok  deploy ArbWorld (setup)      tx=0x7966524d0f3e59dc2c75c314fa4f065fffe1ca4bf9dca2ff3224823e62c1c00c
      ok  enter()                      tx=0x8f09a9a647836f38fbba2619970954482e9bfc9176d3014611127df987839eb3  gas=45821
      ok  deploy AttackerFactory       tx=0x2b1221319df93d4f418a6a1c05da5e444554bf8952e1e861923ec1f5161f5252
      ok  build(address)               tx=0xb058d301d100016e2b6264e6960385310161c10b0386a39050a501888c703c20  gas=330240
      REV run()                        Error("attack reverted")
      ok  sweep()                      tx=0x76a86ae3ad040c8c833fb5ad05313b082f6b3c14d8800a505c80b198f7988f58  gas=36286
      ok  exit()                       tx=0x9a1ab53462f6234c5899b2d5d309f2a2bccd8e5557fe019a60aa93b88696718c  gas=37168
  shortfall 0 ETH  attacker_gain 0 ETH  extracted_from_contract 0 ETH
  live verdict: NOT PROVEN
```
（兩條鏈都從 genesis 開始，帳戶與 nonce 相同，所以前兩筆交易 hash 一樣。）

## 卡在哪裡：三個原因

轉譯步驟本身都成功：`parse_poc` 取出 Attacker、state、`arbSetup`／`arbEnter`／`arbExit`，`build_project` 產生的 `Live.sol` 也能編譯（轉譯後的專案存在 `live_replay_stakingvault/translated/`）。問題出在**轉譯後的語意和合成層不同**：

### 1. 攻擊者拿不到資金（攻擊交易 revert 的直接原因）——強
- 合成層（`workspace.py` `_VICTIM_ATTACKER_SETUP`）：`atk = new Attacker(address(target)); vm.deal(address(atk), 10 ether);` → `vm.deal` 直接改餘額，**不會呼叫 Attacker 的 `receive()`**。
- 鏈上（`live_replay.build_project`）：模型的 Attacker 建構子 `constructor(address _p)` 不是 payable（`ctor_payable=False`），所以 `AttackerFactory.build()` 改成 `new Attacker(t)` 後再 `atk.call{value: msg.value}("")` 匯款。
- 這筆匯款會**觸發模型寫的 `receive()`**：`if (!reentered) { reentered = true; p.unstake(); }` → 攻擊者此時沒有部位，`unstake()` 在 `require(amount > 0, "no position")` revert → 整筆匯款失敗，`funded` 被忽略 → 攻擊者 0 ETH → `attack()` 第一行 `p.stake{value: 1 ether}()` 失敗 → `run()` 回 `Error("attack reverted")`。
- 證據：`build(address)` 成功但 gas 330240；`run()` revert 訊息是 `attack reverted`；攻擊者獲利 0。程式碼對照見上。

### 2. 部署時的 5 ETH 在鏈上算成受害者的部位——強
- 合成層：`arbSetup()` 由測試合約自己執行（`this.arbSetup()`），StakingVault 建構子的 `stakeOf[msg.sender] = msg.value` 記在**測試合約**名下，受害者之後只存 2 ETH，所以 A＝2 ETH。
- 鏈上：setup 寫在受害者自己的 `ArbWorld` 建構子裡（`_LIVE_SOL`：「It runs setup in its constructor and holds the position」），部署 StakingVault 的就是受害者的合約，5 ETH 記在受害者名下 → 無攻擊取回 **7 ETH**（5＋2），目標合約 7 ETH → 0 ETH。
- 這讓「合約裡其他人的錢」消失了：整個池子都屬於受害者，就算攻擊成功，對照組的數字也已經和合成層不同。

### 3. 鏈上只重播 1 輪，而這個攻擊要 8 輪才讓受害者受損——強（結構限制）
- `replay()` → `run_world()` 固定 `endow_wei=10 ETH`，`run()` 只呼叫一次 `attack()`。
- 模型的攻擊只重入一次，合成層 4 個環境中只有 env 3（8 輪）是 2/0/7；單輪的 env 0 是 2/2/1，**本來就不成立**。
- 所以即使 1、2 都修好，這個 exploit 在現有 replay 架構下應該對應到 env 0，仍然是 NOT PROVEN；鏈上 demo 要成立，需要攻擊本身在單輪就造成受害者損失（例如 victim_probe 的 DRAIN，在 4 個環境都是 2/0/7）。

## spark-test-3～5

它們的 Attacker 合約和 spark-test-2 一字不差（正規化空白後 sha256 前 10 碼都是 `7ee20436f2`，見 `xval_llm_patches_2026-10-28.md`），`deploy_code`／`victim_enter`／`victim_exit` 也相同，只差 harness 抽的地址。上面三個原因都只取決於這些片段，所以結果會相同，沒有重跑。

## 可能的方向（使用者決定，這次都沒做）

| 方向 | 動到哪裡 | 說明 |
|---|---|---|
| a. 改用 `live_attack.py` 的 WithdrawalQueue 當鏈上 demo，畫面註明 | 無 | 現成、今天實測正反兩向照舊；但不是 StakingVault，也不是模型寫的攻擊 |
| b. 改 `live_replay.build_project`：非 payable 建構子改用其他方式注資（例如讓 factory 先存錢、或在 setup 用 anvil 的 `anvil_setBalance`），setup 改由第三個帳戶執行 | live_replay.py（這次規定不動） | 修 1、2；但 3 仍在，模型這個攻擊仍不會成立 |
| c. 用 DRAIN（人寫、單輪即掏空）上鏈示範 StakingVault | 可能要 b 一起做 | DRAIN 的 Attacker 建構子是 `payable`，可能避開原因 1；原因 2 仍在。未測 |
| d. 鏈上 demo 只放合成層 A/B/G，畫面標「本地鏈重播開發中」 | 無 | 和現在網頁一致 |

## 另一件事：網頁上傳說明已更新

改成：「一次稽核加修補約 2～8 分鐘（10/28 repo 模式實測 9 次：125～465 秒；找到攻擊時多半 2～3 分鐘，沒找到時較久）」。

和第 7 節的紀錄一致（9 次、125～465 秒），重新從原始紀錄核對過；但要註明這 9 次的組成：
- 3 次 `cli.py audit`（predexp-repo-1～3，**沒有修補**）：309、155、465 秒（run_arbiter 計時）
- 5 次 `gate --mode repo --repair`（modetrial-repo-1～5）：174、135、130、130、125 秒（gate 整個指令計時）
- 1 次網頁上傳（gate＋repair）：365 秒
- 找到攻擊的 5 次：125～155 秒；沒找到的 4 次：174～465 秒（「找到時多半 2～3 分鐘」成立）
- **沒算進去的**：spark-test-1～5 也是 repo 模式（`cli.py audit`，無修補），106～184 秒。算進去的話是 14 次、106～465 秒，文案的「約 2～8 分鐘」仍然涵蓋。

## 合併前檢查

- 8 個 probe 結束碼全 0；`patch_probe.py` 5/5 as expected；`live_attack.py` PROVEN、`--patched` NOT PROVEN
- agent.py、tools.py、live_replay.py、live.py 與 `innoserve-base` 零差異；verdict.py、patch.py、workspace.py、gate.py 自 144b61d 起零差異
- 首頁（重啟伺服器後）：`CLEAR` 0、`safe` 0、「不等於安全」以外的「安全」0；截圖 `live_replay_stakingvault/shot_index.png`
- LLM ledger 總行數：前 109、後 109
