# 阶段报告 2026-10-22b — Module 17：Solidity 模型阶段跑分

> 上一轮遗留清单的第一条：**smartbugs 的 197 条退回样本没有模型阶段跑分**。
> 这轮把它关掉，并顺手修掉实跑时暴露的一个诊断标签 bug。

## 1. 为什么这是个真窟窿（而不是"没跑而已"）

`benchmark_smartbugs.py` 的规则层只定论 49/246，剩下 197 条退回 —— 按设计
它们该交模型。但实际调用 `ScenarioMatcher.audit_unit_for(unit, ["reentrancy"])`
时，第一行就是 `cat = VC.get(key)`，而 `vuln_categories.CATEGORIES` 里
**根本没有 reentrancy / access_control**：

```
VC.get("reentrancy")      -> None
VC.get("access_control")  -> None
```

于是 `audit_unit_for` 立刻 `continue`，返回空列表。**模型层"跑了"，但一句话都没问。**
这就是"Solidity 赛道的模型 TPR/FPR 完全空白"的真正原因：不是缺 harness，
是缺类目。这也解释了为什么它不会报错 —— 空列表和"场景未命中"长得一模一样。

## 2. 探针（先量后动刀）

| 探针 | 结果 |
|---|---|
| 模型网关可达性（`LLM_BASE_URL` + 官方会话头） | 3.9s / 一次 `YES`；缺 `x-opencode-session` 时 403 |
| 退回批构成 | **197 = safe 182 + vul 15**（reentrancy 116 = 4 vul / 112 safe；access_control 81 = 11 vul / 70 safe） |
| 切片规模 | 字符数 min 90 / 中位 248 / max 2780（总计 71KB，单条很轻） |
| 分母检查 | FPR 分母够（109 / 68 ≥ 20）；**TPR 分母不够**（4 / 11 < 20） |

结论：FPR 可以下结论；TPR 只能记观测值 —— 按记忆条 3，分母 <20 不写结论。

## 3. 改动

1. **`core/agents/vuln_categories.py`**：注册 `reentrancy` / `access_control`。
   两者都 `needs_taint=False`（重入是**执行顺序**问题，权限是**身份校验**问题，
   都不是"外部输入是否可达"），且 `owasp=False` —— 否则会漏进 OWASP 2740 的
   默认类目范围，把 Web 跑分和三性质混成一锅。
   提示词里写死判据而不是类目名：重入问"外部调用**之后**是否仍写状态"；
   权限问"是否在链上比对 msg.sender"，并显式排除 `tx.origin`（可钓鱼绕过）、
   初始化状态门（`m_numOwners > 0` 不是身份校验）、以及"名字叫 onlyOwner
   但实现体没比对"。
2. **`benchmarks/benchmark_smartbugs.py`**：新增模型阶段（`--model` / `--offline` /
   `--concurrency` / `--limit`）。口径三条：
   - 只跑退回批（混进规则已判对的样本会稀释成规则分数）；
   - **空 hypothesis = 场景未命中（合法 TN）**，`flagged=None` 才是调用失败，
     单列剔除、绝不折算成"无漏洞"；
   - 模型层不参与 `--strict` 退出码 —— 非确定性不能当门禁。
3. **`benchmarks/run_all.py` / `.githooks/pre-push`**：给 smartbugs 补 `--offline`。
   这一条是防回归的关键：模型阶段默认开启，门禁里不带 `--offline` 就等于
   每次 push 发 197 条网络请求，既慢又不可复现。
4. **`core/agents/scenario_matcher.py`**：修"采样不一致"标签（见第 5 节）。
5. **`benchmarks/smoke_test_chains.py`**：新增 [65]，15 条断言。

## 4. 实跑结果（glm-5.3-flash，并发 8，7m13s）

| 类目 | 有效判定 | TP | FN | FP | TN | TPR | FPR |
|---|---|---|---|---|---|---|---|
| reentrancy | 113 | 4 | 0 | 5 | 104 | 100%（分母 4，只记录） | **4.6%**（分母 109） |
| access_control | 79 | 11 | 0 | 11 | 57 | 100%（分母 11，只记录） | **16.2%**（分母 68） |

- 调用失败 5 条（197 → 192）**已剔除**，不计为"无漏洞"。
- 规则层 49/49 正确、safe 零误报、零判反（与 Module 13 一致，未受影响）。
- **vulpy 侧无需模型阶段**：规则层 6/6 全覆盖、退回 0，模型阶段没有输入。
  上一轮遗留清单写的"vulpy/smartbugs 的 198+"其实是同一件事的两半 ——
  198 是 smartbugs 的 safe 分母，与 vulpy 无关。

必须说清楚的话：

- **TPR=100% 不是成绩**。分母 4 和 11 都远小于 20，这里的 100% 只能说明
  "这 15 条它都看出来了"，不足以支持"模型能用"的结论。要下这个结论，
  需要把 smartbugs 的 reentrancy 全 31 个合约的漏洞函数按官方行号重新
  登记（当前只映射到 30 vul 是因为按行号落在函数体内才算），下一轮做。
- **access_control 的 16.2% FPR 偏高**，值得警惕的是它的方向：全部
  11 条 FP 都是"场景判命中、属性判缺失"，即模型倾向于"这是特权操作且没校验"。
  这是模型层的保守偏差，不是规则层的 —— 规则层在同批数据上 FPR=0。

## 5. 顺手修掉的诊断 bug：单票不可能"采样不一致"

实跑日志里 192 条理由**全部**带 `（采样不一致）`。原因在
`scenario_matcher.audit_unit_for`：

```python
unanimous = bool(all_votes) and len(set(all_votes)) == 1
```

`votes=1`（默认，也是本次口径）时 `_vote` 返回空元组 `()`，于是
`unanimous` 恒 False，标签恒加。空票箱不可能是"不一致"—— 这个标签在说谎，
而读日志的人会误以为模型自我矛盾。

修法：`multi_vote = len(all_votes) > 1`，只有真投了 ≥2 票且票面不同才叫不一致。
置信度那两行不受影响（`miss == len(p_votes)` 在单票时恰好仍成立），
所以**判定结果与计数完全不变**，只有理由文本变干净。

冒烟 [65] 里加了正反两条断言锁死这个语义：单票不标、多票票面不同才标。

## 6. FP 机制复核（11 条 access_control + 5 条 reentrancy，人工看切片）

不是"模型幻觉"一种，至少三类：

| 形态 | 实例 | 判断 |
|---|---|---|
| 只读函数被当成特权操作 | `parity_wallet_bug_1:isOwner`（`constant returns (bool)`，只查表） | **真 FP**，场景步该被"只读函数"排除条款挡住 |
| 外部调用之后写状态，但被调方受信 | `ETH_FUND:Deposit` → `TransferLog.AddMessage(...)` 后 `lastBlock = block.number` | **口径灰区**：形态确实是 CEI 反序，官方未标（受信合约） |
| 同文件同病、官方只标了一行 | `parity_wallet_bug_1:initMultiowned/initDaylimit` | **口径灰区**：library 未初始化时可被任意人夺权，正是 bug_1 的病灶 |
| payable 写状态但无外转 | `spank_chain_payment:createChannel` 等 4 条 | 待复核（切片 380-418 行，外转可能在截断之后） |

结论：**不为这 4 类 FP 改判据**。第一类（只读）是判据缺口，可以在下一轮
往 `sink_question` 加排除条款后用同一批数据复测；其余三类属真值口径，
要么进 DISPUTED 登记，要么等官方真值细化 —— 改提示词去迎合它们，就是
拿分数当判据（记忆条 34 记的就是 parity `kill` 那次）。

## 7. 回归

- 冒烟 [1]-[65] 全绿（[65] 15 条断言，含正反双向）
- smartbugs 规则层 `--strict --offline`：49/49 正确，safe 零误报，零判反
- `run_all.py --offline`：11 项全 PASS（见 `benchmarks/results/run_all.md`）
- 模型层结果落盘 `benchmarks/results/smartbugs_model.json`（含分母，便于下次对比）

## 8. 遗留

1. TPR 分母不够（4 / 11）：需要扩大 Solidity 漏洞样本登记面。可选项：
   smartbugs 另 6 个类目（unchecked_low_level_calls / bad_randomness / …）
   或 `damn-vulnerable-defi` 的利用场景。
2. 只读函数条款：`sink_question` 加"constant/view/pure 不算特权操作"，
   用同一批 113 + 79 条复测，看 FPR 与 TPR 各自的位移。
3. 5 条 call_failed 的原因未分类（超时 vs 解析失败）—— 量小，先记着。
4. 记忆文件已从 3636 字符压到 2732 字符（≤3000 目标达成），新增的两条
   Solidity 模型层口径已并入第 17 条。
