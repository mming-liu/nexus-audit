# 靶场真值争议清单

共 **3** 条。每条都给出：靶场标注、本项目判定、源码证据、以及**分歧属于哪一类**。

> 说明：本清单**不修改**任何靶场的评测口径，也不参与本项目检测规则。它记录的是「同一份代码，两种口径下结论相反」的事实，供维护者复核。

| 靶场 | 样本 | 类目 | 靶场标注 | 本项目判定 | 分歧类型 |
|---|---|---|---|---|---|
| JavaSecLab | `ReflectController.safe2` | xss | safe（安全） | vul | 把纵深防御当修复 |
| Hello-Java-Sec | `XMLDecoderVul.safe` | deserial | safe（安全） | vul | 同一靶场内标注自相矛盾 |
| Hello-Java-Sec | `Traversal.safe2` | pathtraver | safe（安全） | vul | 拦的不是本类目关心的性质 |

## 把纵深防御当修复

这类分歧的共同点：样本确实加了某种**缓解措施**（CSP、WAF、连接池过滤），缓解能降低利用成功率，但不改变「存在注入面」这一事实。如果把这些样本标为 safe，评测会奖励「加了缓解但没修根因」的写法 —— 而这正是真实项目里最难被发现的坏习惯。建议：要么改为 vul，要么在类目定义里显式声明「本类目只判代码层修复」。

### `ReflectController.safe2`（JavaSecLab / xss）

**结论**：打 CSP header 后仍裸回显，CSP 不是输出编码

**靶场标注**：safe　**本项目判定**：vul（确定性规则）

方法设置了 Content-Security-Policy 响应头，但随后 `return payload;` 把请求参数原样交回响应体，没有任何输出编码。CSP 是浏览器侧的纵深防御，可降低脚本执行概率，但它不改变「用户输入原样进入 HTML」这一事实；一旦策略被放宽、被 script-src 'unsafe-inline' 覆盖，或数据被前端 innerHTML 二次渲染，注入即成立。值得注意的是作者自己在 @ApiOperation 的 notes 里写了「不能替代输出编码与安全模板/DOM用法」—— 标注与注释互相矛盾。本项目 xss 类目的口径是「输入是否原样进入响应体」，故判 True。

**源码证据**：

- `src/main/java/top/whgojp/modules/xss/controller/ReflectController.java:124`　`response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'");`
- `src/main/java/top/whgojp/modules/xss/controller/ReflectController.java:127`　`return payload;`


## 同一靶场内标注自相矛盾

这类分歧不需要讨论口径：同一个靶场内部，同一 API / 同一写法被标成了相反的结论。无论采信哪种口径，至少有一处需要修正。

### `XMLDecoderVul.safe`（Hello-Java-Sec / deserial）

**结论**：同一 API（readUnshared）在同靶场另一处标 vul

**靶场标注**：safe　**本项目判定**：vul（确定性规则）

`XMLDecoderVul.safe` 用 `new ObjectInputStream(bis).readUnshared()`；同靶场的 `Deserialization.readUnshared` 用同一个 API，却被标为 vul。readUnshared 只影响对象引用共享（读到重复引用抛异常），**不做任何类型过滤**，安全性质与 readObject 完全相同，CWE-502 同样适用。两处标注不可能同时成立，至少有一处错。本项目与「标 vul 的那一处」一致，故判 True。

**源码证据**：

- `src/main/java/com/best/hello/controller/Deserialization/XMLDecoderVul.java:52`　`* 替换XMLDecoder类，使用更安全的ObjectInputStream.readUnshared`
- `src/main/java/com/best/hello/controller/Deserialization/XMLDecoderVul.java:66`　`Object obj = ois.readUnshared();`
- `src/main/java/com/best/hello/controller/Deserialization/Deserialization.java:96`　`in.readUnshared();`


## 拦的不是本类目关心的性质

这类分歧的共同点：防护函数**存在**且**确实做了点什么**，但拦的不是本类目关心的那个性质。判定一个防护是否成立，要先写清「本类目要的是哪个性质」，再看这段代码是否提供了它 —— 而不是看「有没有调用名叫 normalize/check 的函数」。

### `Traversal.safe2`（Hello-Java-Sec / pathtraver）

**结论**：只有 normalize()，没有基目录包含校验

**靶场标注**：safe　**本项目判定**：vul（确定性规则）

唯一防护是 `Paths.get(filePath).normalize().toString()`。normalize 只做**词法**规范化（消解 `.` 与 `..` 段），不判断结果是否仍在基目录内：`logs/../../etc/passwd` 规范化后是`../etc/passwd`，照样逃出 `logs/`。真正构成防护的是「规范化**之后**再校验包含关系」（`getCanonicalPath().startsWith(baseDir)` 或 `toRealPath()` 对照），本样本没有这一步。它拦的不是路径遍历关心的那个性质（是否限制在基目录内），与本类目口径不一致。

**源码证据**：

- `src/main/java/com/best/hello/controller/Traversal.java:84`　`String filePathSafe = Paths.get(filePath).normalize().toString();`
