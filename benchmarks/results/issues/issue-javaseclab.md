# 1 个样本的真值（expected results）与本机静态分析结论不一致

仓库：`whgojp/JavaSecLab`　靶场：`JavaSecLab`

在复现 [nexus-audit](https://github.com/mming-liu/nexus-audit) 的规则层评测时，以下样本的标注与代码事实不一致。每条都附了**行号级证据**，可以直接点进去核对；证据由脚本逐字比对过源码（行号写错会当场报错），不是凭印象写的。

| 样本 | 类目 | 靶场标注 | 本项目判定 | 分歧类型 |
| --- | --- | --- | --- | --- |
| `ReflectController.safe2` | xss | safe | vul | 把纵深防御当修复 |

## 把纵深防御当修复

这类分歧的共同点：样本确实加了某种**缓解措施**（CSP、WAF、连接池过滤），缓解能降低利用成功率，但不改变「存在注入面」这一事实。如果把这些样本标为 safe，评测会奖励「加了缓解但没修根因」的写法 —— 而这正是真实项目里最难被发现的坏习惯。建议：要么改为 vul，要么在类目定义里显式声明「本类目只判代码层修复」。

### `ReflectController.safe2`

**结论**：打 CSP header 后仍裸回显，CSP 不是输出编码

方法设置了 Content-Security-Policy 响应头，但随后 `return payload;` 把请求参数原样交回响应体，没有任何输出编码。CSP 是浏览器侧的纵深防御，可降低脚本执行概率，但它不改变「用户输入原样进入 HTML」这一事实；一旦策略被放宽、被 script-src 'unsafe-inline' 覆盖，或数据被前端 innerHTML 二次渲染，注入即成立。值得注意的是作者自己在 @ApiOperation 的 notes 里写了「不能替代输出编码与安全模板/DOM用法」—— 标注与注释互相矛盾。本项目 xss 类目的口径是「输入是否原样进入响应体」，故判 True。

**源码证据**：

- `src/main/java/top/whgojp/modules/xss/controller/ReflectController.java:124`　`response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'");`
- `src/main/java/top/whgojp/modules/xss/controller/ReflectController.java:127`　`return payload;`

## 我们的口径（供讨论）

判定一律基于**可逐行核对的事实**：某个防护函数到底拦的是什么、某个变量最后一次赋值来自常量还是请求参数、某条分支是否恒真。凡是没有事实支点的，我们退回「不可判」而不给结论 —— 所以这里列出的不是「我们猜你错了」，而是「这几行代码与标注对不上」。

如果认为其中某条的标注是对的（例如本类目的口径本就包含缓解措施），欢迎指出 —— 我们更愿意改自己的口径说明，而不是改判据去迁就分数。
