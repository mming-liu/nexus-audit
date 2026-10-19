# 2 个样本的真值（expected results）与本机静态分析结论不一致

仓库：`j3ers3/Hello-Java-Sec`　靶场：`Hello-Java-Sec`

在复现 [nexus-audit](https://github.com/mming-liu/nexus-audit) 的规则层评测时，以下样本的标注与代码事实不一致。每条都附了**行号级证据**，可以直接点进去核对；证据由脚本逐字比对过源码（行号写错会当场报错），不是凭印象写的。

| 样本 | 类目 | 靶场标注 | 本项目判定 | 分歧类型 |
| --- | --- | --- | --- | --- |
| `XMLDecoderVul.safe` | deserial | safe | vul | 同一靶场内标注自相矛盾 |
| `Traversal.safe2` | pathtraver | safe | vul | 拦的不是本类目关心的性质 |

## 同一靶场内标注自相矛盾

这类分歧不需要讨论口径：同一个靶场内部，同一 API / 同一写法被标成了相反的结论。无论采信哪种口径，至少有一处需要修正。

### `XMLDecoderVul.safe`

**结论**：同一 API（readUnshared）在同靶场另一处标 vul

`XMLDecoderVul.safe` 用 `new ObjectInputStream(bis).readUnshared()`；同靶场的 `Deserialization.readUnshared` 用同一个 API，却被标为 vul。readUnshared 只影响对象引用共享（读到重复引用抛异常），**不做任何类型过滤**，安全性质与 readObject 完全相同，CWE-502 同样适用。两处标注不可能同时成立，至少有一处错。本项目与「标 vul 的那一处」一致，故判 True。

**源码证据**：

- `src/main/java/com/best/hello/controller/Deserialization/XMLDecoderVul.java:52`　`* 替换XMLDecoder类，使用更安全的ObjectInputStream.readUnshared`
- `src/main/java/com/best/hello/controller/Deserialization/XMLDecoderVul.java:66`　`Object obj = ois.readUnshared();`
- `src/main/java/com/best/hello/controller/Deserialization/Deserialization.java:96`　`in.readUnshared();`

## 拦的不是本类目关心的性质

这类分歧的共同点：防护函数**存在**且**确实做了点什么**，但拦的不是本类目关心的那个性质。判定一个防护是否成立，要先写清「本类目要的是哪个性质」，再看这段代码是否提供了它 —— 而不是看「有没有调用名叫 normalize/check 的函数」。

### `Traversal.safe2`

**结论**：只有 normalize()，没有基目录包含校验

唯一防护是 `Paths.get(filePath).normalize().toString()`。normalize 只做**词法**规范化（消解 `.` 与 `..` 段），不判断结果是否仍在基目录内：`logs/../../etc/passwd` 规范化后是`../etc/passwd`，照样逃出 `logs/`。真正构成防护的是「规范化**之后**再校验包含关系」（`getCanonicalPath().startsWith(baseDir)` 或 `toRealPath()` 对照），本样本没有这一步。它拦的不是路径遍历关心的那个性质（是否限制在基目录内），与本类目口径不一致。

**源码证据**：

- `src/main/java/com/best/hello/controller/Traversal.java:84`　`String filePathSafe = Paths.get(filePath).normalize().toString();`

## 我们的口径（供讨论）

判定一律基于**可逐行核对的事实**：某个防护函数到底拦的是什么、某个变量最后一次赋值来自常量还是请求参数、某条分支是否恒真。凡是没有事实支点的，我们退回「不可判」而不给结论 —— 所以这里列出的不是「我们猜你错了」，而是「这几行代码与标注对不上」。

如果认为其中某条的标注是对的（例如本类目的口径本就包含缓解措施），欢迎指出 —— 我们更愿意改自己的口径说明，而不是改判据去迁就分数。
