# 1 个样本的真值（expected results）与本机静态分析结论不一致

仓库：`OWASP-Benchmark/BenchmarkJava`　靶场：`OWASP`

在复现 [nexus-audit](https://github.com/mming-liu/nexus-audit) 的规则层评测时，以下样本的标注与代码事实不一致。每条都附了**行号级证据**，可以直接点进去核对；证据由脚本逐字比对过源码（行号写错会当场报错），不是凭印象写的。

| 样本 | 类目 | 靶场标注 | 本项目判定 | 分歧类型 |
| --- | --- | --- | --- | --- |
| `BenchmarkTest01807` | sqli | safe | vul | 同一靶场内标注自相矛盾 |

## 同一靶场内标注自相矛盾

这类分歧不需要讨论口径：同一个靶场内部，同一 API / 同一写法被标成了相反的结论。无论采信哪种口径，至少有一处需要修正。

### `BenchmarkTest01807`

**结论**：charAt(2) 恒为 'C'，case 'C' 落进 bar = param，却标 safe

`guess` 是字面量 "ABC"，`charAt(2)` 在编译期就是 `'C'`；switch 的 `case 'C': case 'D':` 直接落进 `bar = param;`，随后 `bar` 被拼进 "SELECT * from USERS where USERNAME='foo' and PASSWORD='" + bar + "'"，注入面成立。同模板的 BenchmarkTest01806 用 `charAt(1)`（'B' → `bar = "bob"`）标 safe，并在注释里写明「condition 'B', which is safe」—— 说明作者清楚这条判据取决于选中哪个 case；01807 换到 'C' 却没有同步改标注。**本条不参与跑分剔除**：OWASP 的 FPR 仍按 5/15 计，登记它是为了让复核者看到「这 1 条误报不是检测器的错」。

**源码证据**：

- `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01807.java:75`　`char switchTarget = guess.charAt(2);`
- `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01807.java:85`　`case 'C':`
- `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01807.java:87`　`bar = param;`
- `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01806.java:75`　`char switchTarget = guess.charAt(1); // condition 'B', which is safe`

## 我们的口径（供讨论）

判定一律基于**可逐行核对的事实**：某个防护函数到底拦的是什么、某个变量最后一次赋值来自常量还是请求参数、某条分支是否恒真。凡是没有事实支点的，我们退回「不可判」而不给结论 —— 所以这里列出的不是「我们猜你错了」，而是「这几行代码与标注对不上」。

如果认为其中某条的标注是对的（例如本类目的口径本就包含缓解措施），欢迎指出 —— 我们更愿意改自己的口径说明，而不是改判据去迁就分数。
