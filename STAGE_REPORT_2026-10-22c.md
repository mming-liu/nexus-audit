# 阶段报告 2026-10-22c — Module 18：只读预筛 + 模型层分母修复

> 上一轮遗留三条里的前两条：① 只读函数条款；② TPR 分母不够（4 / 11 < 20）。
> 这轮两条一起收 —— 而且**没有**按原计划往提示词里加排除条款。

## 1. 判断变更：从"提示词建议"改成"编译器事实"

原计划是在 `sink_question` 里加一句"constant/view/pure 不算特权操作"，让模型
别把 `isOwner` 当成提权接口。探针跑完改主意了 —— 这不是提示词问题：

`view` / `constant` / `pure` 是**编译器强制**的限制，不是注释也不是约定：

- `view` / `constant`：函数体不得修改状态，写状态变量直接编译不过；
- `pure`：连读状态都不许。

于是两类漏洞对它都是确定性排除：

- **重入**：受害者必须在外部调用**之后**写状态才有可重入窗口，不写状态就没窗口；
- **越权**：特权动作（转币 / 销毁 / 改 owner / 铸币）全都是状态写入。

按第一条铁律「能确定性判定的不交 LLM」，这该放在规则层。提示词是建议，
编译器是事实 —— 而且放规则层还能省钱：37 条样本不再送审。

## 2. 探针（改之前先量排除面）

| 探针 | 结果 |
|---|---|
| 退回批里只读函数占比 | **37 / 197**（reentrancy 17 / access_control 20） |
| 这 37 条的真值 | **全部 safe**（0 条 vul）—— 排除面不含真漏洞 |
| 分布 | `getBalance` / `balanceOf` / `supportsToken` / `recoverSigner` / `isOwner` / `hasConfirmed` 这一类 |

## 3. 改动

1. **`core/agents/rule_detectors.py`**
   - 新增 `_sol_is_readonly(sig)`：只认**签名段**里的 `\b(constant|view|pure)\b`
     （词边界，`preview` 里的 `view` 不算）。
   - `solidity_reentrancy_verdict` / `solidity_access_verdict` 早退返回 False。
     注释里写明为什么这是确定性结论而不是"猜"。
   - **`_looks_solidity` 补词表**：原先只认 `uint/address/payable/msg.sender/
     selfdestruct/mapping(/require(`，于是
     `function supportsToken() external pure returns(bytes32)` 这种切片被判成
     "不是 Solidity"，`verdict` 直接退 None。真实靶场里它侥幸没暴露，是因为
     切片首行注释 `// contract: X` 命中了 `contract\s+Name` —— **判据靠注释在撑**。
     现在补上 `bytesN/intN/string/bool/tx.origin/block./keccak256/可见性修饰符`，
     把这条依赖去掉。这是冒烟 [66] 当场抓出来的，不是事后想到的。
2. **`benchmarks/benchmark_smartbugs.py`**
   - `--scope {fallback,all}`：`fallback` 保持原口径；`all` 跑全部登记样本，
     报告**同时**打印"全体"与"其中的退回子集"，两口径可对比。
     存在的唯一理由是分母：退回批 vul 只有 4 / 11 条，都在 20 以下。
   - `_metrics` / `_print_block` 抽出，避免两处各算一遍容易算错。
3. **`benchmarks/smoke_test_chains.py`**：新增 [66]，7 条断言（正反双向）。

## 4. 规则层结果

| 指标 | Module 17 | Module 18 |
|---|---|---|
| 登记样本 | 246 | 246 |
| 确定性判定 | 49（19.9%） | **86（35.0%）** |
| 判定正确 | 49/49 | **86/86** |
| safe 误报 / 判反 | 0 / 0 | **0 / 0** |
| 退回模型 | 197 | **160** |

新增的 37 条全是只读函数，全部判 False、全部真值 safe —— 覆盖率上去了，
门禁没松（safe 零误报、零判反仍成立）。

## 5. 模型层：分母终于够了（glm-5.3-flash，246 条，8m48s，241 有效 / 5 失败）

**全体受测样本**

| 类目 | 有效 | TP | FN | FP | TN | TPR | FPR |
|---|---|---|---|---|---|---|---|
| reentrancy | 139 | 30 | 0 | 6 | 103 | **100%（分母 30 ✅ 可下结论）** | 5.5%（分母 109） |
| access_control | 102 | 18 | 0 | 12 | 72 | 100%（分母 18，仍只记录） | 14.3%（分母 84） |

**其中规则退回批（157 有效，与 Module 17 口径可对比）**

| 类目 | 有效 | TP | FN | FP | TN | FPR |
|---|---|---|---|---|---|---|
| reentrancy | 96 | 4 | 0 | 5 | 87 | 5.4%（分母 92） |
| access_control | 61 | 11 | 0 | 11 | 39 | 22.0%（分母 50） |

reentrancy 的 TPR 分母终于过了 20，可以下一句结论了：

> 在 smartbugs-curated 的 reentrancy 全集上，模型对 30 条已知漏洞函数召回
> 30/30，对 109 条 safe 函数误报 6 条，**Score = TPR − FPR = 0.945**。
> 但要注意这是"模型单独跑"的成绩，规则层在同一批上已经零误报、判对 26 条 ——
> 生产管线里模型只看规则退回的那 96 条，那里的 FPR 是 5.4%（5/87）。

access_control 的 TPR 分母 18 **过不了 20**，按记忆条 3 不写结论。这是数据集
本身的容量问题（DISPUTED 剔除后只有 18 条 vul），换靶场才能解，不是跑得不够。

## 6. 一个容易读错的数字：FPR 从 16.2% 涨到 22.0% 不是变差

只读预筛把 20 条 access_control safe 从分母里拿掉了，FP 一条没少（都是会改状态
的函数），于是 `FP/(FP+TN)` 自然变大。跨池比较**不能看比率**，要看绝对条数：

| 口径 | FP | TN | FPR |
|---|---|---|---|
| Module 17（197 条池） | 11 | 57 | 16.2% |
| Module 18（160 条池） | 11 | 39 | 22.0% |

分子完全没动，分母少了 20 条"容易判对的负样本"，比率就上去了。同理 reentrancy
的 4.6% → 5.4% 也是 TN 从 104 掉到 87（-17 = 只读条数）造成的。

**预筛到底清掉了什么**：`isOwner`（`constant returns (bool)`）与 `hasConfirmed`
（`external constant`）这两条只读误报确实从名单里消失了 —— 它们现在由规则判
False，连模型都不用问。但同一批里另有 2 条**会改状态**的样本（parity 的
`create` / `confirm`）这次翻成了误报，所以退回批 FP 总数仍是 11。温度设 0
也不代表采样完全确定，单次抖动不足以归因，所以这里只记录现象、不下结论。

## 7. 剩余的 FP 长得什么样（12 条 access_control，全体口径）

- **8 条集中在 parity wallet**：`initMultiowned` / `initDaylimit` / `Wallet` /
  `create` / `confirm` / `hasConfirmed`（bug_1 与 bug_2 各一份）。这个合约的
  官方真值只标了 `initWallet` / `kill` 那几行，而同文件其它函数确实**也没有**
  身份校验 —— 模型没看错代码，是官方口径只标了主病灶。
- **1 条 `arbitrary_location_write_simple:UpdateBonusCodeAt`**：写任意存储槽，
  确实无访问控制，而官方该文件标的是别的函数。
- 结论同上一轮：**不为这些改判据**。要么进 DISPUTED 登记，要么等真值细化。

## 8. 回归

- 冒烟 [1]-[66] 全绿（[66] 7 条：constant/pure/多行签名/词边界/负向两条）
- OWASP 全量：**A=0 / B=0**，规则层判定 1352 条 —— 与 Module 16 逐项一致
  （`_looks_solidity` 补词表没有让任何 Java 样本误入 Solidity 分支）
- `run_all.py --offline`：11 PASS / 0 FAIL / 0 SKIP
- smartbugs 规则层 `--strict --offline`：86/86，safe 零误报，零判反
- 模型层结果落盘 `benchmarks/results/smartbugs_model.json`（含 scope 与退回子集）

## 9. 遗留

1. **access_control 的 TPR 仍不可下结论**（分母 18）。要补只能换数据源：
   smartbugs 另 5 个类目、或 `damn-vulnerable-defi` 的利用场景。
2. parity 的 8 条 FP 要不要进 DISPUTED 登记：需要逐个核对官方
   `vulnerabilities.json` 的标注意图（"只标主病灶"还是"这些函数确实安全"）。
   核对完再决定，不先改判据。
3. 5 条 call_failed 仍未分类（超时 / 解析失败），量小，先记着。
4. 只读预筛只做了 Solidity；Python 侧 `def` 无等价语义（没有编译器保证），
   不要照搬。
