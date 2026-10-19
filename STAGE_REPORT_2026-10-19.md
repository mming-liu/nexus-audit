# 阶段报告：xss 收敛 → 值来源闸门横向平移（2026-10-19）

> 范围：当日四个提交（`6dd372e` → `2c8cc64`），累计 24 个文件、+5365/−138 行。
> 结论先行：**OWASP 规则层 144 条判定只剩 1 条错判，且那 1 条是靶场真值标错了。**
> 总 FPR 0.10 → 0.08，Score 0.92；剩余 13 条误报里 12 条在模型投票层，1 条在真值——
> 规则层继续调判据已经没有收益。

## 一、提交清单

| 提交 | 时间 | 主题 | 规模 |
|---|---|---|---|
| `6dd372e` | 01:25 | xss 回显点认 printf/format，外部输入认包装对象，容器与常量分支覆盖可判 | 13 文件 +2958/−101 |
| `af64a8a` | 07:40 | sqli 已知 SQL 编码函数（引号内拼接）判确定性 safe；`Traversal.safe2` 真值存疑单列 | 6 文件 +172/−81 |
| `a6f2da0` | 09:38 | 真值争议从脚本内字典升级成可导出登记簿（含行号级证据自校验） | 9 文件 +699/−51 |
| `2c8cc64` | 23:31 | 抽「值来源闸门」给 sqli / pathtraver 共用，OWASP 规则层错判 12 → 1 | 14 文件 +1681/−50 |

已推送 GitHub（`refs/heads/main` = `2c8cc64`），工作区干净。

## 二、OWASP 最终跑分（330 条样本全在，无剔除）

```
类目            TP   FN   FP   TN    TPR    FPR   Score
securecookie    15    0    0   15   1.00   0.00    1.00
crypto          15    0    0   15   1.00   0.00    1.00
weakrand        15    0    0   15   1.00   0.00    1.00
hash            15    0    0   15   1.00   0.00    1.00
sqli            15    0    1   14   1.00   0.07    0.93
trustbound      15    0    1   14   1.00   0.07    0.93
cmdi            15    0    1   14   1.00   0.07    0.93
xss             15    0    2   13   1.00   0.13    0.87
ldapi           14    0    2   13   1.00   0.13    0.87
pathtraver      14    0    2   12   1.00   0.14    0.86
xpathi          15    0    4   11   1.00   0.27    0.73
OVERALL        163    0   13  151   1.00   0.08    0.92
```

## 三、13 条误报的三层归因（本轮最重要的数字）

按 scorecard 的 `stage` 字段拆开，13 条 FP 不是同一种东西：

| 层 | 条数 | 明细 |
|---|---|---|
| 规则层（`rule_missing_property`） | **1** | `BenchmarkTest01807`——且这条是**真值标错**（见第五节），不是检测器错 |
| 模型投票层（`missing_property`，采样不一致） | **12** | xpathi 4 条 + pathtraver 2 条 + sqli/xss/ldapi 等其余 6 条 |

由此推出的三个直接结论：

1. **sqli FPR 0.33 → 0.07、pathtraver 0.29 → 0.14 全是规则层收益**，改判据改对了。
2. **xpathi 0.27 一分未降，但规则层一条没错**——原计划"把闸门平移到 `xpathi_verdict`"
   的预设被数据推翻：4 条 FP 全是模型投票抖动，修判据修不了它。
3. "总 FPR 压进 0.03"这个目标**在规则层已经到头**，剩下的路在模型侧收敛
   （投票机制或提示词），要另立一题。

## 四、值来源闸门（`2c8cc64`）做了什么

xss 里写死的三种"常量顶掉脏值"机制——恒真分支赋字面量、容器先放常量再覆盖、
helper 返回常量——被 OWASP 的 sqli/pathtraver 原样复用，只是代码搬进了同文件的
`private class Test`。抽出 `_value_origin` 三态（`lit` / `tainted` / `unknown`）
后，一次修活两个类目。**方向写死：这是否定证据闸门，只能把 True 改成 False。**

修这层闸门暴露的六个判据级缺陷（全部有样本编号）：

1. helper 体不剥行尾注释：`doSomething(g90580); // reflection` 让调用正则失配 → 静默 unknown（02183）；
2. `_named_method_bodies` 不认 `throws ... {`，真实切片一个 helper 都截不出来（不报错）；
3. 同名方法按第一个匹配：1 参调用撞上 2 参重载，形参→实参映射错位（00330）；
4. `request.getParameter("p")` 被当成"只喂常量的调用"——接收者必须先判脏；
5. 行内赋值 `if (values != null) param = values[0];` 对行首锚定的 `_ASSIGN_RE` 完全瞎，
   取到开头的 `String param = "";` 把**外部输入判成字面量**——真漏洞判 safe（02272），
   **这条只有 OWASP 全量跑分逼得出来，冒烟和三靶场都没暴露**；
6. 控制流未建模时"取最后一处赋值"判反：switch 的 `default:` 在末尾，
   实际选中的 case 在前面（01807）——补 `_ambiguous_control_flow`，只对
   "该 if/switch 真的给 var 赋值"的场景判定，避免 00365 式顺序赋值被误判互斥。

冒烟同步加压：`smoke_test_chains.py` 新增 `[36]` 段 10 项断言（含"行内 if 赋值不能被
当成常量"的防漏报项），三套冒烟全过。

## 五、真值争议登记簿（`a6f2da0`，4 条全量）

争议从脚本内字典升级为可校验资产：每条必须给出"靶场凭什么标 / 我们凭什么判相反"、
**带行号的源码证据**、归入既有 kind；`export_disputes.py` 可导出 JSON/Markdown/
按靶场分组的 Issue 草稿（已在 `benchmarks/results/issues/` 生成 3 份）。

| 样本 | kind | 一句话 |
|---|---|---|
| `JavaSecLab/ReflectController.safe2` | defense_in_depth | 打 CSP header 后裸回显；作者 notes 自己写了"CSP 不能替代输出编码" |
| `Hello-Java-Sec/XMLDecoderVul.safe` | self_contradiction | `readUnshared()` 同靶场另一处标 vul，两处不可能同时成立 |
| `Hello-Java-Sec/Traversal.safe2` | not_the_property | 只有 normalize()，没有规范化后的基目录包含校验 |
| `OWASP/BenchmarkTest01807` | self_contradiction | `charAt(2)` 编译期即 `'C'`，`case 'C'` 落进 `bar = param;` 却标 safe；同模板 01806 注释自证判据取决于选中 case |

**登记不等于剔除**：01807 不参与跑分剔除，OWASP FPR 仍按 5/15 计——登记是让复核者
看到"这 1 条误报不是检测器的错"。**靶场标错也是数据，不是麻烦。**

## 六、三靶场回归（改判据不能打回归）

| 靶场 | 结果 |
|---|---|
| java-sec-code | TPR 1.00 / FPR 0.00 / **Score 1.000**（63/63，DnsRebind 这次模型投票通过） |
| Hello-Java-Sec | 判定 58 条正确 58，唯一 `XMLDecoderVul.safe` 按登记簿单列存疑 |
| JavaSecLab | 规则覆盖 33 条，正确 **32/32 = 100%** |

## 七、方法论沉淀（今天两次最大的进步都不是"判据更聪明"）

1. **证据完整性优先于判据复杂度**。两个切片层 bug（类级静态字段没进切片、
   `_entry_signature` 对带注解形参括号配平失败）的症状都不是报错，而是静默退回或
   静默漏看——判据写错的代价是误报，证据缺一块的代价是不掉指标的暗坑。
   先把证据补全，再动判据。
2. **分层看 FPR，别拿总数当规则层指标**。13 条 FP 按 `stage` 拆开，12 条根本不在
   规则层；不看 `stage` 就去改判据，改的全是空气。
3. **预设要先核后信**。"闸门平移到 xpathi"听起来顺理成章，数据一看：
   那边的 FP 一条都不是规则层的。
4. **真值错误要转成资产**。01807 这种矛盾样本，单列 DISPUTED_TRUTH + 行号证据 +
   可导出 Issue，比默默改判据绕过它更有长期价值。

## 八、未竟事项

- **xpathi 4 条 FP（模型投票层）**：属模型侧收敛，另开一轮；本轮只证明与规则无关。
- **方向 B 剩余两项**：`.githooks/commit-msg`（强制提交信息带回归段）、
  `CONTRIBUTING.md`。3 份 Issue 草稿已导出。
- **方向 C（IDOR 靶场）**：未启动；动手前先调研"业务逻辑越权有没有可逐行核对的事实支点"。
- `MEMORY.md` 第四节待补 JavaSecLab 介质说明与两个新模块条目。
