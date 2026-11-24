# ARBITER Gate × ME 測試網：鏈上證據

網路 me-testnet（chain 400）｜RPC `https://beta-hub-8545.explorer-testnet.me`｜瀏覽器 https://www.explorer-testnet.me｜更新時間 2026-11-25 02:23（UTC+8）

這份文件只是索引。每一項都能用 `python3 me/me.py verify` 直接從鏈上重驗，不需要相信這份文件。
瀏覽器以 Cosmos 交易為索引；連結用的是 EVM 交易所在的 Cosmos 交易雜湊（查不到時才用 EVM 雜湊）。

## 合約

| 合約 | 地址 | 展示的功能 |
|---|---|---|
| AuditRegistry | [`0xf619857eb017adc46d1dfeb8131979e1a97fb402`](https://www.explorer-testnet.me/zh-TW/accountDetails/me17cvc2l4sz7kugmgal6upxxteux5hldqztgagjd) | 稽核紀錄只能新增、不能修改；判定 3（已證實可攻擊）和 0（稽核未完成）不能經由它部署。它自己的稽核紀錄是 #1，位址由稽核者宣告（LINK_CLAIMED），鏈上 codehash 等於編譯產物的 runtime 雜湊 |
| AuditEscrow | [`0x8014653f1122833bc925b1b8741a1a202c7b955f`](https://www.explorer-testnet.me/zh-TW/accountDetails/me1sq2x20c3y2pnhjf9kxu8gxs6yqk8h92lmvjtqr) | 用 MEC 付稽核費；稽核完成就付款，未完成或逾期就退款。由登錄合約依紀錄 #2 部署（LINK_GATED），委託與結算都用這個位址 |
| StakingVault（修補後） | [`0x86e3e9e68b402537f76806e735167237873a2f3c`](https://www.explorer-testnet.me/zh-TW/accountDetails/me1sm37ne5tgqjn0amgqmnn29njx7rn5teus9t8kt) | 由登錄合約部署，鏈上可查它就是紀錄 #4 稽核過的 bytecode |
| PrimeYieldVault（委託人部署） | [`0x61e01bef75c389ba16e5bf0342ad69de3b335867`](https://www.explorer-testnet.me/zh-TW/accountDetails/me1v8sphmm4cwym59h9hup59ttfmcanxkr8xyxukz) | 由委託人經登錄合約部署，鏈上可查它就是紀錄 #5 稽核過的 bytecode |

## 稽核結果（gate.json）

每筆紀錄的 gateJsonHash 是下表 gate.json 的 sha256，檔案就在證據資料夾裡。產生時間取自 gate.json 的 `generated_at`，產生結果的程式是 gate.json 的 `tool_commit`（ARBITER Gate 的 git commit）。

| 稽核對象 | 稽核結果 → 鏈上判定 | 產生時間（generated_at） | 產生結果的程式（tool_commit） | 模型 | gate.json sha256 | 證據資料夾 |
|---|---|---|---|---|---|---|
| StakingVault.sol（示範合約，可重入） | `proven_exploitable` → 3 已證實可攻擊 | 2026-11-22 17:10:05（UTC+8） | `06ca8ddc5747c249d147218a7b57b6ec70bda1a7`（ARBITER_TOOL_COMMIT） | arbiter-gpt | `0xe1e29262ce4ba8ae67fb4896e7e2ed962ebfb0a8a9d2dfe0f2bee066d03ee42c` | `me/evidence/staking-vault/original`、`me/evidence/staking-vault/patched` |
| AuditRegistry.sol（我們自己的合約） | `no_provable_attack` → 1 未發現可證明攻擊（不等於安全） | 2026-11-22 17:13:08（UTC+8） | `06ca8ddc5747c249d147218a7b57b6ec70bda1a7`（ARBITER_TOOL_COMMIT） | arbiter-gpt | `0x706d167600252ce62bd33f2b7c9950ea8e4cd94f300ea2663cc45fd02645f796` | `me/evidence/self/registry` |
| AuditEscrow.sol（我們自己的合約，專案模式） | `no_provable_attack` → 1 未發現可證明攻擊（不等於安全） | 2026-11-22 17:17:53（UTC+8） | `06ca8ddc5747c249d147218a7b57b6ec70bda1a7`（ARBITER_TOOL_COMMIT） | arbiter-gpt | `0x1d6ff5a7676db024a95af2dfddecbcacad07ea6d089be2a3206234c5307ad9a9` | `me/evidence/self/escrow` |
| PrimeYieldVault.sol（第二個錢包委託稽核的合約） | `no_provable_attack` → 1 未發現可證明攻擊（不等於安全） | 2026-11-25 00:30:44（UTC+8） | `fcca0e45c64505e3c800701b1e9a1236c3e9d04b`（ARBITER_TOOL_COMMIT） | arbiter-gpt | `0x5008075cea37a232041f5d8b69c689c21bd1f94f276019e4203b7ca954c83352` | `me/evidence/two-party` |

## 交易

| # | EVM 交易 | 瀏覽器（Cosmos 交易） | 展示的功能 |
|---|---|---|---|
| 1 | `0x6d5324b15a9cf0b771d613e51fbc21502fc8da8afe7f02e96b4fef9f019906aa`（區塊 5469647） | [93CE022BF4…](https://www.explorer-testnet.me/zh-TW/transactions/93CE022BF4EBEC991F8D1735EED50428208FCF248A5608504E53CEB394272BBF?netType=hub) | 部署 AuditRegistry（paris 編譯；ME 測試網不支援 PUSH0） |
| 2 | `0x838ffdd05389b7353cf26ace5e438090c4b3bbf3480dbc2cea9f48d790770080`（區塊 5469648） | [378A03E00F…](https://www.explorer-testnet.me/zh-TW/transactions/378A03E00F863A79291B707D2A672C8AE29D6B4F7092FB76622FCE388351F658?netType=hub) | **AuditRegistry 的稽核紀錄（用 ARBITER Gate 稽核自己的合約）**：紀錄 #1，判定 1（未發現可證明攻擊（不等於安全））；sourceHash = AuditRegistry.sol 的 sha256、gateJsonHash = 稽核結果 gate.json 的 sha256、initcodeHash = 部署它的建立程式碼（solc 0.8.24、paris、optimizer 200、無 metadata） |
| 3 | `0x30fc8fc11bdf14b7fcaa6cfa965cc04eb7d26f737f685d51d8a0d0515f072c42`（區塊 5469649） | [5FAC0A40F0…](https://www.explorer-testnet.me/zh-TW/transactions/5FAC0A40F0F29578E679D5CC091001BB71F940BFEEE8AD361241494E6241F55A?netType=hub) | **宣告 AuditRegistry 本身的位址**：linkDeployment(#1, AuditRegistry) → LINK_CLAIMED。登錄合約不可能經由自己部署，所以只能由稽核者宣告；鏈上 codehash `0xaea66826c7f3656ba9bdb46a4a52df0ae7f22352643d7456c2e000473cbb4141` 等於編譯產物 runtime 的 keccak256 |
| 4 | `0x8a20f9fecf2a0bca4bd62ede1e3d6ca7b72c952fdc531fd462d7e0feceef163b`（區塊 5469650） | [1116539B16…](https://www.explorer-testnet.me/zh-TW/transactions/1116539B16F6C2A9645935B7C69297CD9C5D64D6262FE64537410805AB4F880F?netType=hub) | **AuditEscrow 的稽核紀錄**：紀錄 #2，判定 1（未發現可證明攻擊（不等於安全））；initcodeHash = 建立程式碼 + abi.encode(AuditRegistry 位址)，所以只有接上這個 AuditRegistry 的 AuditEscrow 能依這筆紀錄經由閘門部署 |
| 5 | `0x47caa22ac73f588139cc8562835dcd8daffa38ccdca429cd5c8e76b9410ae9bb`（區塊 5469651） | [705D701A37…](https://www.explorer-testnet.me/zh-TW/transactions/705D701A37AC3CA952DD52CA3EBDA695274FDC63348DAA80103A96753B892D19?netType=hub) | **AuditEscrow 經由部署閘門部署（deployAudited）**：登錄合約依紀錄 #2 用 CREATE2 把稽核過的建立程式碼（含 abi.encode(AuditRegistry 位址)）部署到事先預測的位址（LINK_GATED）。這就是部署 AuditEscrow（MEC 付費委託，費用不隨判定改變）的交易，後面的委託與結算都用這個 AuditEscrow |
| 6 | `0xe5b3cbc4426975e3de019c92cdf00064b16001fad3ce8451ebce21a495841813`（區塊 5469652） | [B02055E0A2…](https://www.explorer-testnet.me/zh-TW/transactions/B02055E0A2CE87464AA323ECC5AA67F165B18BB3750E0C39F6E173A8297FDAF2?netType=hub) | 委託 #1：鎖住 0.001 MEC，指定稽核者與 StakingVault 原始碼的 sha256 |
| 7 | `0x04ed7518f071d2bb20dc1889f00285e29d89866a02b2bcf7e2d9104a688bba3d`（區塊 5469653） | [50B0F9B5DC…](https://www.explorer-testnet.me/zh-TW/transactions/50B0F9B5DC2E605BD2CDB212B78462FE9AE851DD2A1E47B82C027CFD170B23D6?netType=hub) | 紀錄 #3：AI 證實 StakingVault 可被重入攻擊（判定 3），原始碼、gate.json、攻擊程式、修補的雜湊上鏈 |
| 8 | `0x117d13432572f4be627a826486dee46295d657907835f0a4b008e10a58d26350`（區塊 5469654） | [2C8A11D0AD…](https://www.explorer-testnet.me/zh-TW/transactions/2C8A11D0ADDA2835BF1A6C61925989EDCC22A74AB872E4122ED7DA7CC908D5C5?netType=hub) | 對紀錄 #3 呼叫 deployAudited：合約拒絕部署（NotDeployable(3)），交易失敗是預期的 |
| 9 | `0xe445619d1ed093b0f567e1206faf325bc3750c6169b8c341fd2bc421a2c79500`（區塊 5469655） | [E84A5A759A…](https://www.explorer-testnet.me/zh-TW/transactions/E84A5A759A1BCE81EA12B31D245C0EACAA3BA0113331A99D9857F10F8051358E?netType=hub) | 紀錄 #3 結算委託 #1：稽核完成，費用付給稽核者（判定是 3 也照付） |
| 10 | `0xcf2df1daf4768040e983a0ea2c9311a65d19d1bf5436eaf069682c6f13ad29bc`（區塊 5469656） | [56840162E5…](https://www.explorer-testnet.me/zh-TW/transactions/56840162E5501F1934BD789F5C759579456459DB4F2548F16D055F50A2066D33?netType=hub) | 紀錄 #4：修補後的 StakingVault（判定 1，上一版 #3，patchHash 與建議修補相同） |
| 11 | `0x186dd32eb1f4103c5c5be9d9268fb202466f7b0aba1d992b454b4ed81bc9b98a`（區塊 5469657） | [B2B44CA7C6…](https://www.explorer-testnet.me/zh-TW/transactions/B2B44CA7C6FE4E3A756E9B7077138F1A547B31EAD486F5D5C423BCC57557D22E?netType=hub) | deployAudited：登錄合約用 CREATE2 把修補後、稽核過的 bytecode 部署到事先預測的地址（LINK_GATED） |

## 兩個錢包的託管示範

上表的交易都由同一個錢包送出：委託人、稽核者、部署者是同一個地址，託管結算等於付錢給自己。這一節另用第二個錢包當委託人，合約也由它部署。兩個錢包都由我們隊伍保管，展示的是合約在兩個不同地址之間照規則運作，不代表已經有外部的委託人。

委託稽核的合約是評測集 `arbiter/evalsets/v3_authored.json` 裡修好的 PrimeYieldVault（`S_first_depositor_share_inflation`，原樣放在 `me/examples/PrimeYieldVault.sol`），代表開發者要部署到 ME 的合約。稽核只跑一次，結果照實登錄。

| 角色 | 地址 |
|---|---|
| 稽核者（部署資訊列出的稽核者，和上表相同） | [`0xbe51c98b205109e24bd4f3d26c7b0cb66c370700`](https://www.explorer-testnet.me/zh-TW/accountDetails/me1hegunzeq2yy7yj7570fxc7cvkekrwpcqj0503p) |
| 委託人，也是部署合約的開發者（第二個錢包） | [`0xcf95101424f255e38428f534e8b5e52c81d62e40`](https://www.explorer-testnet.me/zh-TW/accountDetails/me1e723q9py7f278ppg756w3d099jqavtjq8s9px8) |

| # | EVM 交易 | 瀏覽器（Cosmos 交易） | 送出者 | 展示的功能 |
|---|---|---|---|---|
| 12 | `0x71aa94d38165103981cb3fb921014254a86fbc74cb8f260a03e42921cb506ce3`（區塊 5494882） | [D1CC816BCF…](https://www.explorer-testnet.me/zh-TW/transactions/D1CC816BCF3C333B6805C632BBAB592108713B52F7704AA62DAC474DA4DB7F4A?netType=hub) | 委託人 | 委託 #2：委託人鎖住 0.001 MEC，指定稽核者與 PrimeYieldVault.sol 的 sha256，期限 7 天 |
| 13 | `0xdafb41513de62685bb67d9c66eab1aa659791e8bda4aece9b877b60d9ee64af1`（區塊 5494883） | [E3AE0B59EE…](https://www.explorer-testnet.me/zh-TW/transactions/E3AE0B59EEB8DD71799091F0B0F92C4A7D87B5F58FFEEDB3BB5F9FCD5D7008DD?netType=hub) | 委託人 | 委託 #3：委託人再鎖住 0.001 MEC，期限 1 小時（合約允許的最短期限）；稽核者不處理這一筆 |
| 14 | `0x04aa173b48f8e6ce1d53b0ced52ab1234c97a9828754ade40b602443efd40a35`（區塊 5494999） | [2A7B6DB44E…](https://www.explorer-testnet.me/zh-TW/transactions/2A7B6DB44E83125DFDA8AF1D8BB6AC34C3CABE17FE90DD2B94398DB48CFFC728?netType=hub) | 稽核者 | 紀錄 #5：稽核者登錄 ARBITER Gate 對 PrimeYieldVault.sol 的稽核結果，判定 1（未發現可證明攻擊（不等於安全））；原始碼、gate.json 與建立程式碼的雜湊上鏈 |
| 15 | `0x003a9f7c5a51cea915ed34f2255e4d31d695dc18493b9d8ef0d2ee1ed835c437`（區塊 5495000） | [8043D33248…](https://www.explorer-testnet.me/zh-TW/transactions/8043D332488DC709DE678F61DAEAC8B040E64994C966992C1ABA24A7D350119A?netType=hub) | 稽核者 | 紀錄 #5 結算委託 #2：0.001 MEC 從合約付給稽核者（判定 1、2、3 都照付，費用和結論無關）；只有委託指定的稽核者能結算，而且只能用委託之後登錄的紀錄 |
| 16 | `0x6839901ae696e67e42f65b4c11e8392f102f9547a9398d2c969cd5f6c91629f2`（區塊 5495003） | [9561CBA3D0…](https://www.explorer-testnet.me/zh-TW/transactions/9561CBA3D0473DDC1F49060B3A3A5E796AD1F1501DBC32A75E522B9413E8F410?netType=hub) | 委託人 | **委託人用紀錄 #5 經由部署閘門部署 PrimeYieldVault**（deployAudited）：登錄合約用 CREATE2 把稽核過的 bytecode 部署到依「紀錄 #5、委託人地址、salt」事先預測的地址（LINK_GATED） |
| 17 | `0xae8863b5de7ea674a1253bdaf3d6d71185e81bebf4b85647be3d2b26ee4beb57`（區塊 5496359） | [A91C8E7ACD…](https://www.explorer-testnet.me/zh-TW/transactions/A91C8E7ACD6ECE0E031E7BDAE519C0E42878F7D8E75D40A384F1993BFB549CD9?netType=hub) | 委託人 | 委託 #3 過了期限再加 1 小時寬限都沒有結算：refundExpired 把 0.001 MEC 退回委託人（任何人都能送） |

## 重驗（任何人都可以跑）

```bash
python3 me/me.py verify 0x86e3e9e68b402537f76806e735167237873a2f3c --network me-testnet --evidence me/evidence/staking-vault/patched --rebuild --replay
python3 me/me.py verify 3 --network me-testnet --evidence me/evidence/staking-vault/original --replay
python3 me/me.py verify 0xf619857eb017adc46d1dfeb8131979e1a97fb402 --network me-testnet --evidence me/evidence/self/registry --rebuild
python3 me/me.py verify 0x8014653f1122833bc925b1b8741a1a202c7b955f --network me-testnet --evidence me/evidence/self/escrow --rebuild
python3 me/me.py verify 0x61e01bef75c389ba16e5bf0342ad69de3b335867 --network me-testnet --evidence me/evidence/two-party --rebuild
```

- `--evidence`：重算證據資料夾每個檔案的 sha256，和鏈上紀錄比對。
- `--rebuild`：用紀錄的編譯設定（solc 0.8.24、paris、optimizer 200、無 metadata）重新編譯，比對 initcodeHash 與鏈上程式碼（AuditEscrow import 的 AuditRegistry.sol 也在它的證據資料夾 `imports/` 裡）。
- `--replay`：用 forge 重跑攻擊：在原始碼上攻擊成功，套用修補後攻擊失敗。
- 瀏覽器打不開時：`cast receipt <EVM 交易> --rpc-url https://beta-hub-8545.explorer-testnet.me` 直接向節點查。

說明：紀錄是稽核者的主張；deployAudited 證明部署的程式碼就是稽核過的 bytecode，linkDeployment 只是稽核者的宣告（用 `--rebuild` 比對）；判定 1 代表沒有找到可證明的攻擊，判定 2 代表只有靜態工具的提示、沒有證實，兩者都不等於安全。
