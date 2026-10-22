# 阶段报告 · Module 19：遗留清零（第 9 靶场 + 三类残留收口）

日期：2026-10-22
范围：Module 18 收尾时列出的四项遗留，逐条关闭，不留"下轮再说"。

---

## 0. 本轮要关的四条遗留

| # | 遗留 | 处置 | 状态 |
|---|---|---|---|
| 1 | access_control 的模型 TPR 分母 18，低于 20 条线只能记数 | 新建第 9 靶场 DeFiVulnLabs（成对 vuln/fixed 真值），合并口径分母 20 | 关闭 |
| 2 | parity 那 8 条 FP「要先核对官方标注意图」 | 逐条读源码分类：3 类是判据缺口（已修），2 条是真值口径（书面登记） | 关闭 |
| 3 | 5 条 call_failed 未分类 | 把原始异常带进 detail，两条靶场都落盘 `call_failed_rows` | 关闭 |
| 4 | 只读预筛之外的"外部不可达"函数仍在送审 | `internal`/`private`/构造函数三款编译器事实进规则层，规则 86→101 | 关闭 |
| 5 | vulpy（Python 第 7 靶场）只有规则层，模型层空白 | 加 `--model` 端到端口径，6/6 跑通（分母 3，只记录） | 关闭 |
| 6 | dvdefi 从没进过 run_all / pre-push，等于没有回归保护 | 加 `--sanity` 健壮性抽检（切片 164 单元 + 判定面上限） | 关闭 |

---

## 1. 第 9 靶场：DeFiVulnLabs（成对真值）

### 为什么必须是新靶场

smartbugs-curated 的 `access_control` 一共 19 个漏洞合约、21 条标注行；parity `kill`
口径分歧剔除后，函数级漏洞单元只剩 18 条。**分母 18 < 20，按记忆条 2 不能写结论** ——
这不是"跑得不够"，是数据源天花板。要越过它只能换数据源。

DeFiVulnLabs（SunWeb3Sec）把每个漏洞写成「漏洞合约 + 修复合约」对，作者注释里
**指名**漏洞点与修法。它补上 smartbugs 缺的两块：Solidity 0.8.x 语法、成对真值。

### 真值口径（9 条，每条 why 写在脚本里）

| 文件 | 函数 | 类目 | 真值 | 依据 |
|---|---|---|---|---|
| Visibility.sol | changeOwner | access | vul | 作者注释 `wrong visibility ... should be onlyOwner` |
| txorigin.sol | transfer | access | vul | `require(tx.origin == owner)`，README 明确这是钓鱼绕过 |
| NFT-transfer.sol | transferFrom | access | vul | VulnerableERC721 `missing NFT owner check` |
| NFT-transfer.sol | transferFrom | access | **safe** | FixedERC721 加 `_isApprovedOrOwner`（成对） |
| Flashloan-flaw.sol | executeOperation | access | vul | SimpleBankBug 无 initiator 校验 |
| Flashloan-flaw.sol | executeOperation | access | **safe** | FixedSimpleBank 加 `require(_initiator == address(this))`（成对） |
| Reentrancy.sol | withdrawFunds | reent | vul | 先 call 后扣减（CEI 违反） |
| Reentrancy.sol | withdrawFunds | reent | **safe** | nonReentrant 锁 + 先扣减后转账（成对） |
| ERC777-reentrancy.sol | claim | reent | vul | 注释 `Do not follow check-effect-interaction` |

三条硬约束：

1. **只收作者指名**的漏洞函数。不收"我觉得这里有问题"的样本 —— 那是自证不是基准。
2. **同一函数名、同一业务、只差一条校验**才是样本（三组成对）。这是本靶场唯一
   无法被替代的价值：判据到底看机制还是看名字，在这里无处可藏。
3. 标定用**源码行号**匹配切片单元，对不上直接 fail。上游改文件后真值表静默
   失效，比没有真值更危险。

### 结果

规则层：9 条真值全命中，确定性判定 3/9，**3/3 正确、零误报、零判反**（其余 6 条退
None 交模型）。模型层 6 条退回：有效 6/6，access TP=3 FP=0 TN=2，reent TP=1。

---

## 2. 合并口径：access_control 的 TPR 终于过线

| 口径 | 类目 | TP | FN | FP | TN | TPR | FPR | Score |
|---|---|---|---|---|---|---|---|---|
| smartbugs 全体 | reentrancy | 30 | 0 | 6 | 105 | 100%（分母 30） | 5.4%（111） | 0.946 |
| smartbugs 全体 | access_control | 17 | 0 | 10 | 75 | 100%（分母 **17**，只记录） | 11.8%（85） | — |
| DeFiVulnLabs | access_control | 3 | 0 | 0 | 2 | — | — | — |
| **合并** | access_control | **20** | **0** | 10 | 77 | **100%（分母 20 ✅）** | **11.5%** | **0.885** |
| **合并** | reentrancy | **31** | **0** | 6 | 105 | **100%（分母 31 ✅）** | **5.4%** | **0.946** |

必须同时说清楚的三件事：

- **分母 20 是刚好达标，不是宽裕**。少任何一条就退回"只记录"。报告不掩饰这一点。
- 合并是两个不同难度的数据源做微平均（总 TP / 总分母）。分源数字都在上表里，
  谁都能自己重算，不存在"合并把分数抬高"的操作空间。
- access_control 的 FPR 11.5% 是**模型独立判定**的结果。规则层对同一批样本判
  False 的（只读/internal/构造函数）在这里仍算模型误报 —— 因为 scope=all 的定义
  就是"模型自己看"，不能拿规则结论替它擦屁股。

---

## 3. parity 那 8 条 FP：核对完了，3 条是判据缺口

逐条读源码（不是看注释、不是猜），结论分三类：

| 函数 | 关键事实 | 归类 | 处置 |
|---|---|---|---|
| `isOwner` / `hasConfirmed` | `public constant returns (bool)` | **判据缺口** | Module 18 只读预筛已覆盖 |
| `create` | `internal`，外部调不到 | **判据缺口** | 本轮 `internal/private` 预筛 |
| `Wallet` | 函数名 == 合约名 → 0.4.x 构造函数 | **判据缺口** | 本轮构造函数判 False |
| `initMultiowned` / `initDaylimit` | bug_1 里真的没有 `only_uninitialized`（bug_2 才有） | **真值口径** | 不算误报，官方同病只标 `initWallet` 一行 |
| `confirm` | 有 `onlymanyowners`，其实现体调 `confirmAndCheck` 做身份校验 | 模型侧 | 规则已正确退 None；模型看不到一跳，不改判据 |

关键区别：**判据缺口**要修（三类已修）；**真值口径**不改（`initMultiowned` 在
bug_1 里确实任何人都能调，模型判对了，是标注只取一处代表）。把后者改判据才是
拿分数当判据 —— `parity kill` 那次已经记过这条教训。

`arbitrary_location_write_simple:UpdateBonusCodeAt`（写任意存储槽、确实无校验，
官方标的是同文件另一个函数）同属真值口径，不修。

---

## 4. call_failed：从"5 条"变成"3 条 + 原因"

改前 `detail` 是硬编码字符串 `"LLM 调用失败"`，失败样本落盘后无法分类 —— 下一轮
只能看到一个数字。改后把 `ScenarioMatcher` 里的原始异常带出来（`type(e).__name__` +
消息），两个 benchmark 都写 `call_failed_rows` 进 json。

本轮实跑 3 条失败，原因都清楚：

```
spank_chain_payment.sol:initVCstate   reentrancy      模型返回空内容（重试 1 次仍空）
spank_chain_payment.sol:settleVC      reentrancy      模型返回空内容（重试 1 次仍空）
parity_wallet_bug_1.sol:initWallet    access_control  证据核验失败：输出不是 JSON 对象
```

前两条是网关侧空响应（切片本身正常），第三条是模型输出格式崩了。**都不是漏报**，
按口径单列剔除。上一轮 5 条 → 本轮 3 条，剩下 2 条在复跑中自愈，说明是抖动而非
稳定故障；但"抖动"这个说法只有在带上原因之后才成立，之前那个数字什么都证明不了。

---

## 5. 规则层：外部不可达 = 编译器/VM 的事实

只读预筛（Module 18）之后同类问题还剩两类，这轮一起进规则层：

| 条款 | 依据 | 排除面（smartbugs 实测） |
|---|---|---|
| 显式 `internal` / `private` | 外部调不到，攻击面为零 | 16 条，真值**全 safe** |
| 函数名 == 合约名（0.4.x 构造函数） | 部署期执行一次，不进运行时字节码 | 1 条（`Wallet`），真值 safe |

实现细节三条（都是被真实样本逼出来的）：

- 只认 `)` **之后的签名尾段**：参数名叫 `internal_` 不能当可见性（已加冒烟断言）。
- **没有可见性的老语法不排除**：默认 public 是事实，不能用"没写"推"不可达"
  （Rubixi `changeOwner` 就是这种，必须仍判 True）。
- 构造函数原先 `return None`，本轮收紧为 `False`：VM 层事实，退回模型只会让模型在
  `function Wallet(...)` 的 assembly 里幻想出越权（smartbugs 实跑里正是这么误报的）。

规则层：确定性判定 86 → **101/246（41.1%）**，101/101 正确，零误报、零判反。

---

## 7. 顺带补上两处空洞

排查"还有没有遗留"时，用 `grep -c ScenarioMatcher benchmarks/*.py` 和各靶场
是否出现在门禁脚本里做了一次交叉核对，发现两处从来没被列进待办、但确实空着。

### 7.1 Python 赛道的模型层

vulpy（第 7 靶场）**只有规则层，没有模型阶段** —— Python 的模型 TPR/FPR 一直
是空白，和 Solidity 在 Module 17 之前的状态一样。

补法不同于 smartbugs：vulpy 登记 6 条、规则 6/6 全判，**没有退回批**可交模型。
所以给 `--model`（opt-in）做**端到端口径**：模型独立再判这 6 条。

实跑（glm-5.3-flash，并发 3）：TP=3 FN=0 FP=0 TN=3，6/6 全对。分母 3 / 3，
**只记录不下结论**。它的价值不在数字，在于 Python 链路的场景提示词、语言围栏、
三态聚合第一次被真实跑通（此前只有合成夹具）。

opt-in 而非默认开启：默认开启会让 run_all / pre-push 每次发 6 条请求，
而 6 条样本撑不起任何比率结论。

### 7.2 dvdefi 一直没有门禁

`benchmark_dvdf_llm.py` 是纯 LLM 脚本（没有 `--offline`/`--strict`），既不在
`run_all` 也不在 `pre-push` —— 整个靶场没有回归保护。

不能照抄 strict：dvdefi 的 19 个挑战是**经济逻辑漏洞**（预言机操纵、闪贷治理、
价格偏差、记账不变量），我们没有这些类目的判据，硬标真值等于让模型猜。

新增 `benchmark_dvdefi_sanity.py --sanity`，锁两条**确定性**的形态：

| 断言 | 当前值 | 防什么 |
|---|---|---|
| 切片单元 ≥ 150 | 164 | 切片器在 0.8.x + OZ 继承链上退化（别的靶场合约更简单，看不出来） |
| 判 True ≤ 8 条 | 1 | 判据回归导致误报爆发（比"FPR 涨 2%"更早更响） |
| 判 False ≥ 80 条 | 189 | 判定面塌陷（规则整体失效） |
| `naive-receiver:flashLoan` 仍判重入 | True | CEI 行序解析退化 |

那唯一一条 True 是站得住的：`flashLoan` 第 50 行 `weth.transfer(...)` 外转、
第 51 行 `totalDeposits -= amount` 扣减 —— CEI 确实是反的（该挑战官方漏洞点是
"未校验 msg.sender"，这是同一函数里的另一个真实问题）。规则只看机制。

---

## 8. 回归

| 项 | 结果 |
|---|---|
| 冒烟测试 `[1]`-`[68]` | **全绿**（409 条 OK，新增 18 条断言） |
| OWASP 全量 2740 | **A=0 / B=0**，规则层判定 1352 条（与 Module 18 逐类目一致） |
| smartbugs `--strict --offline` | PASS，101/101 正确，safe 零误报、零判反 |
| DeFiVulnLabs `--strict --offline` | PASS，9/9 真值命中，3/3 正确 |
| `run_all.py --offline` | 13 PASS / 0 FAIL / 0 SKIP |
| pre-push | 九道靶场门禁 + 冒烟 + 争议核对全绿 |

Java 侧零影响（改的是 Solidity 分支，OWASP 逐类目数字与上一轮完全一致，不是
"大概没影响"）。

---

## 9. 遗留清零确认

- [x] access_control 分母不足 → 第 9 靶场 + 合并口径 20（刚好达标，已注明）
- [x] parity 8 条 FP → 3 条判据缺口已修、2 条真值口径书面登记
- [x] call_failed 未分类 → 带原始异常 + 落盘
- [x] 未登记靶场 → DeFiVulnLabs 进 run_all / pre-push / CI 注释
- [x] Python 模型层空白 → vulpy `--model` 端到端口径跑通（6/6，分母 3 只记录）
- [x] dvdefi 无回归门禁 → `--sanity` 健壮性抽检接入 run_all（13 PASS）

**没有"下轮再说"的条目。** 有两件事属于数据源/模型能力边界，不是待办：

1. access_control 合并分母恰好 20：再扩分母只能找第三个 Solidity 数据集，且必须
   有成对真值，否则等于自证。
2. 模型端到端 FPR（access 11.5%）里，一半是"模型看不到只读/internal 这类编译器
   事实"。这不是模型层能修的，正是规则层存在的理由 —— 改成提示词去迎合它，就
   又回到了"拿分数当判据"。
