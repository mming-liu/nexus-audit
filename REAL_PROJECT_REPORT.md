# 真实项目实战：java-sec-code（Spring Boot）

> 目标：验证引擎在**非模板化真实代码**上是否还能用。
> 靶场：JoyChou93/java-sec-code，80 个 Java 文件，Spring Boot 2.x，132 个 HTTP 入口。
> 日期：2026-10-18　模型：`longcat-2.5-preview-free`（免费档）

## 一、为什么要单独做这一轮

上一轮 OWASP Benchmark 得了 Score 0.98（TPR 1.00 / FPR 0.02），但那个 0.98 **不能外推**。
Benchmark 的每个用例都是「取参数 → 拼接 → sink」的固定模板，连变量名都在反复复用；
真实项目是 Service 分层、MyBatis Mapper、工具类封装、注解传参。

这轮的价值不在于再拿一个高分，而在于**找出 Benchmark 掩盖掉的失败模式**。
结果是：找出了 6 个，其中 4 个是 Benchmark 永远测不出来的。

## 二、真值怎么建立的

java-sec-code 是漏洞教学靶场，作者在**两处**标注了每个方法的性质：

1. **路由命名**：`/vuln`、`/vuln01`、`/vuln/xxx` → 有漏洞；`/sec`、`/sec01` → 安全写法
2. **紧邻 Javadoc**：`Vuln Code.` / `Vul Code.` / `safe Code.`

第 2 条覆盖率更高 —— `XSS.java` 的路由是 `/xss/reflect`、`/xss/safe`，没有 vuln 字样，
但注释明确写了 `Vuln Code.`。只用路由会把这 4 条 XSS 全部漏掉。

两处都判不出的（`/rce/runtime/exec`、`/ssrf/openStream` 这种只有方法体没有标注的）
一律标 unknown **排除出计算**，不猜、不硬凑。

| 项 | 数量 |
|---|---|
| 切片入口总数 | 132 |
| 可判定样本 | **66**（真漏洞 31 / 安全 35） |
| 真值来源 | 路由 62 / 注释 4 |
| 命名与注释均无法判定（排除） | 13 |
| 无对应类目（排除） | 53 |

## 三、三轮迭代的分数变化

每一轮都是**针对上一轮暴露的误报改一处根因**，不是调参：

| 轮次 | 改了什么 | TPR | FPR | Score |
|---|---|---|---|---|
| v1 初版 | — | 0.87 | 0.29 | 0.585 |
| v2 | 补 MyBatis Mapper 跨文件证据 + 防护调用（`startSSRFHook`）实现体 | 0.87 | 0.09 | **0.785** |
| v3 | 掐掉同文件/同类方法体的批量注入 | 0.84 | 0.11 | 0.724 |

v2 的 0.785 是这三轮里最高的，但**它不是最终结论**——第四节说明了原因。

### v1 → v2：两个真实缺陷

**缺陷 1：SQL 注入的真值藏在 Mapper 里，不在控制器里**

```java
// 路由 /sqli/mybatis/sec01 —— 方法体
return userMapper.findByUserName(username);
// 路由 /sqli/mybatis/vuln01 —— 方法体
return userMapper.findByUserNameVuln01(username);
```

两个方法体**完全同构**。真正的差别在 `UserMapper`：

```java
@Select("... username = #{username}")    // 安全：JDBC 预编译占位符
@Select("... username = '${username}'")  // 有漏洞：字符串拼接
```

不给模型看到 Mapper，它只能看方法名猜。新增 `core/context/java_impl_resolver.py`
解析 MyBatis 注解 / XML / 接口实现，切片尾部附「跨文件证据」块。

**缺陷 2：SSRF 的防护是零参数调用，被"只补带外部入参的调用"过滤掉了**

```java
@RequestMapping("/ssrf/ImageIO/sec")
public String ImageIO(@RequestParam String url) {
    SecurityUtil.startSSRFHook();   // ← 零参数，防护本体在这里
    HttpUtils.imageIO(url);
}
```

`startSSRFHook()` 不带任何参数，按「有没有外部入参」过滤时被整体丢弃，
模型只看到"没有 IP 校验"就判成漏洞。**8 条 SSRF 误报全部源于此**。
补上防护类调用（`start*/check*/is*` 前缀）的实现体后，这 8 条一次性归零。

### v2 → v3：又踩到一个坑

v2 里 `SpEL.spel_sec` 从"判对"退化成"误报"。查下去发现旧有的
`_resolve_cross_file_helpers` 会按方法名从**整个仓库**捞方法体，包括同一个文件里的：

```java
// 审的是 spel_sec（安全写法）
SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
// 但切片里被塞进了同文件的
StandardEvaluationContext context = new StandardEvaluationContext();  // ← 漏洞写法
```

审 sec 却看到 vuln 的代码，模型必然报漏洞。同理 `SQLI.mybatisOrderBySec04`
被塞进了三个 `jdbc_sqli_vul` 之类的兄弟方法。

修法：只认 `obj.method(...)` 形式的数据调用（不认裸调用 `foo(...)`），
且本文件内已定义的方法体不再从跨文件索引注入。

## 四、更重要的发现：引擎输出不稳定

v2 和 v3 之间，66 条样本里有 **10 条判定翻转**（15%）。这远超"随机波动"能解释的范围，
所以我做了一次定向复测：**同一份代码、同一个 prompt、`temperature=0`，连问三次**。

| 样本 | 真值 | 三次结果 | 一致？ |
|---|---|---|---|
| Cors.vuls1 | 有漏洞 | T, T, F | ✗ |
| Cors.vuls2 | 有漏洞 | T, F, F | ✗ |
| Cors.getCsrfToken_01 | 安全 | T, F, F | ✗ |
| Cors.getCsrfToken_02 | 安全 | F, F, F | ✓ |
| Cors.seccode | 安全 | F, F, F | ✓ |
| Cors.secCrossOrigin | 安全 | F, F, F | ✓ |
| Cors.getCsrfToken_03 | 安全 | F, T, T | ✗ |
| XSS.store | 有漏洞 | F, F, F | ✓（全错） |
| XSS.reflect | 有漏洞 | T, F, T | ✗ |
| XSS.show | 有漏洞 | T, T, T | ✓ |
| XSS.safe | 安全 | F, F, F | ✓ |

**12 条里 5 条抖动，抖动率 41.7%。**

这意味着：
- 单轮跑出来的 TPR/FPR **不具备可复现性**。v2 的 0.785 与 v3 的 0.724 之差，
  大部分不是"改进/退化"，而是采样噪声。
- 任何"再调一下 prompt 就能到 0.9"的判断都不可信 —— 你无法区分真提升和运气。
- 抖动样本里两条是 `Cors`（`Access-Control-Allow-Origin` 相关），
  两条是 SpEL/XSS —— 说明抖动不是集中在某一类"难样本"上，而是普遍的。

### 为什么 OWASP Benchmark 没暴露这个问题

Benchmark 的用例同质化极高：同一类目下 100 个样本的代码结构几乎一样。
模型对某一个模板判对之后，同类其余样本基本全对，抖动被模板一致性掩盖了。
真实项目里每个路由写法都不同，抖动就浮出来了。

**这是本轮最重要的产出：Benchmark 分数高 ≠ 引擎可用。**
一个 FPR 0.02 的跑分，掩盖了一个 41.7% 抖动率的判定器。

### 试过的第一个解法：三次采样取多数 —— 失败

发现抖动后第一反应是"多问几次取多数"，这是最自然的补救。我把它做了出来
（`ScenarioMatcher._vote`，并发发出 3 次请求，2 票以上为结论），然后做了 A/B 对照。

对照的**方法**很重要 —— 我第一次就搞错了：我拿 `votes=1` 和 `votes=3` 的
**总体 TPR/FPR** 去比（0.639 vs 0.667），得出"投票没用"。但那不是抖动指标。
抖动测的是"**同一批样本再跑一遍，结论变不变**"，不是"这一批里错了几条"。
投票改的是*一致性*，不是*准确率*。重写成 `benchmarks/ab_votes.py`，每种策略各跑
2 轮完整 66 样本评测，比较两轮之间的翻转数：

| 策略 | 轮次 | TPR | FPR | Score | 两轮翻转 | 成本 |
|---|---|---|---|---|---|---|
| `--votes 1` | run1 | 0.84 | 0.20 | 0.639 | **9/66 = 13.6%** | 1× |
| `--votes 1` | run2 | 0.90 | 0.23 | 0.675 | | |
| `--votes 3` | run1 | 0.84 | 0.17 | 0.667 | **9/66 = 13.6%** | 3× |
| `--votes 3` | run2 | 0.81 | 0.11 | 0.692 | | |

**投票没有降低抖动，一条都没有。** 66 条样本里同样是 9 条在两轮之间翻转，
成本翻了三倍。

原因不难理解：抖动是**采样级**的。如果模型对某个样本 3 次里有 2 次答错，
多数票就**稳定地答错** —— 投票只是把噪声从"每轮不一样"变成"每轮犯同一个错"。
它把一个随机判错的引擎变成了一个稳定判错的引擎。

结论：**投票不是降抖动的手段，默认关掉（`--votes` 默认改回 1）**。
唯一保留的用处是审计线索 —— `VulnHypothesis.votes` 记录原始票型，
1:2 分歧说明模型在这个样本上犹豫，`confidence` 相应从 0.7 降到 0.45，
下游可以据此把样本优先送人工复核。犹豫**可见了**，但判定**没有稳定**。

这也反过来强化了本项目的核心判断：**能确定的必须靠规则和代码事实，不能靠采样**。
采样级手段在这里全部失效，剩下能试的只有 prompt 级确定性
（例如强制模型先引用决定性的那一行代码再作答）。

### 事后修正：投票不是"没用"，而是"3 票太少"

上面的 A/B 只用了 3 票，而真正能说明问题的是**把 5 轮完整评测当作 5 次独立观测**，
逐条看每个样本的票型。这一步做出来之后，前面的结论需要修正一半。

| 稳定性 | 条数 | 占比 |
|---|---|---|
| 5 轮全对 | 42 | 64% |
| **5 轮结果不一致（抖动）** | **21** | **32%** |
| 5 轮全错 | 3 | 5% |

**抖动不是集中在某一类"难样本"上，而是集中在几个"新写的类目"上**：

| 类目 | 抖动/总数 | 类目 | 抖动/总数 |
|---|---|---|---|
| cmdi | 1/1 | sqli | 1/10 |
| cors | **7/8** | xxe | 3/17 |
| spel | 2/3 | ssrf | 3/16 |
| deserial | 2/3 | pathtraver / redir | 0/2 |
| xss | 2/4 | | |

`cors` 8 条里 7 条抖动，而 `sqli` 10 条里只有 1 条。差别在哪？
sqli 有 MyBatis `#{}` / `${}` 的**确定性规则**兜底，cors/spel/deserial 是新加的
6 个 Java 类目，纯靠模型判断。这再次印证：**抖动与"是否交给模型自由裁量"高度相关**。

再看 5 轮取多数与单轮的差别（同样 66 条、同样真值）：

| 口径 | TPR | FPR | Score |
|---|---|---|---|
| 单轮（5 轮实测范围） | 0.806 – 0.903 | 0.114 – 0.229 | 0.639 – 0.724 |
| **5 轮取多数（事后合并）** | **0.935** | **0.143** | **0.793** |

多数票确实比任何**单轮**都好，而且 TPR 终于超过了 0.9。所以正确表述是：

- ❌ "投票没用" —— 这句话**过了**。3 票确实没用，5 票有用。
- ✅ "**3 票太少**：3 票几乎必然是 2:1，而 2:1 只是把一次抽样变成了另一次抽样。
  要让多数票真正压过噪声，票数必须多到能跨越模型的实际错误率。"

但代价必须写清楚：这个 0.793 是**事后合并**出来的（5 次独立运行，不是内部投票），
需要 5 倍模型调用；而且它仍然修不了那 3 条"5 轮全错"的样本。
投票能让**边缘样本**稳定下来，不能让**确定性错误**变对。

## 五、逐类目结果（v6，八类规则化 + 跨路由串接 + 代码审计修复）

规则覆盖从 15 条扩到 64 条，同时补上跨路由串接。单次采样、未投票，结果如下。
（v6 相比 v5 唯一的变化：ssrf 收紧了一个过宽的兜底分支，覆盖数 64 → 63，
详见本节末尾。）

| 类目 | n | TP | FN | FP | TN | TPR | FPR | 规则直接判定 |
|---|---|---|---|---|---|---|---|---|
| cors | 8 | 2 | 0 | 0 | 6 | 1.00 | 0.00 | **8** |
| deserial | 4 | 3 | 0 | 0 | 1 | 1.00 | 0.00 | **4** |
| spel | 3 | 2 | 0 | 0 | 1 | 1.00 | 0.00 | **3** |
| xxe | 17 | 9 | 0 | 0 | 8 | 1.00 | 0.00 | **17** |
| sqli | 10 | 5 | 0 | 0 | 5 | 1.00 | 0.00 | **10** |
| ssrf | 15 | 6 | 0 | 0 | 9 | 1.00 | 0.00 | **15** |
| xss | 4 | 3 | 0 | 0 | 1 | 1.00 | 0.00 | **4** |
| redir | 2 | 0 | 0 | 0 | 2 | — | — | **2** |
| pathtraver | 2 | 1 | 0 | 0 | 1 | 1.00 | 0.00 | 0 |
| cmdi | 1 | 0 | 0 | 0 | 1 | — | — | 0 |
| **合计** | **66** | **31** | **0** | **0** | **35** | **1.00** | **0.00** | **63** |

**Score = TPR − FPR = 1.000**（可判定集合内全对，其中 63 条由规则直接判定，
只有 cmdi 1 条、pathtraver 2 条经模型）

演进轨迹：

| 口径 | Score | 模型调用量 | 抖动率 |
|---|---|---|---|
| 单轮 LLM（v3 历史区间） | 0.639 – 0.724 | 1× | 41.7% |
| 5 轮取多数 | 0.793 | 5× | 未测 |
| 规则前置 v4（15 条） | 0.823 | 1× | 显著下降 |
| **规则前置 v5（64 条）** | **1.000** | **0.05×** | **规则部分 0%** |
| 规则前置 v6（63 条，收紧 ssrf） | 1.000 | 0.05× | 规则部分 0% |

这一轮最值得记录的三个事实：

1. **规则判定是纯函数，抖动归零。** 64 条规则样本各重复跑 20 次，
   结果不一致的样本数 = 0。切片本身也验证了可复现性（三次切片摘要完全一致）。
   之前测得的 41.7% 抖动，来源就是"把客观题交给概率模型"。
2. **模型调用量从 67 次降到 3 次。** 这不只是省钱：调用越少，
   限流导致的失败样本越少，跑分越不容易被基础设施干扰。
3. **规则是在样本上做出来的，存在过拟合风险。** 1.000 不能读作"引擎零缺陷"。
   为此做了一次样本外检验：拿规则去判不在可判定集里的其余入口，
   只多出 4 条结论（`URLRedirect.setHeader/sendRedirect/redirect` 三条
   确实是作者写明的漏洞入口，`SSRF.openStream` 方法体确实是
   `new URL(url).openStream()` 无任何校验），**没有出现批量误判**。
   但真正的泛化能力要靠换项目验证，不能靠这一个靶场。

**v6 为什么把覆盖数从 64 降到 63。** 外部审计指出 `ssrf_verdict` 的兜底分支
过宽：只要方法体里有请求 sink、没挂 hook，就返回"有漏洞"，连它没识别出的
校验也一并当成"无校验"。这会让**漏报变成误报**——一个挂了自定义白名单的入口
被判成漏洞。现在改为：认不出校验方式时返回 `None`（交模型），
只对"能确认没有校验"的情况给确定结论。少判一条，换来不冤枉一条。
同一批审计还修掉了 `startsWith("http://")` 被误当白名单的问题：
裸协议名前缀拦不住 `http://127.0.0.1`，必须匹配到具体路径前缀才算。

`pathtraver` 与 `cmdi` 仍由模型判定，也仍是抖动来源 —— 这两类没有像
"AES vs DES""hook 有没有挂上"那样干净的事实支点，规则化收益不明确。

### 5.1 规则到底判了什么

63 条规则的覆盖面与依据：

| 类目 | 条数 | 判定依据（客观事实） |
|---|---|---|
| xxe | 17 | `disallow-doctype-decl=true` 或两个 `external-*-entities=false` 同时成立；**必须连取值判**，只看到 `setFeature` 会把结论全部反转 |
| ssrf | 15 | `SecurityUtil.startSSRFHook()` 是否挂上（socket 层校验，所有 HTTP 客户端绕不过）；退一步看是否阻断 `file://` |
| sqli | 10 | JDBC 形态（`createStatement`/`prepareStatement` + 拼接 vs `?`）+ MyBatis `${}` vs `#{}` + 白名单，优先级 C>A>B |
| cors | 8 | ACAO 取值是否为回显变量/`*`；是否先做 Origin 白名单校验；装配型的看 `allowedOrigins` 实际取值 |
| deserial | 4 | 是否用 `SafeConstructor`/`ObjectInputFilter` 白名单；黑名单不算防护 |
| xss | 4 | 反射型：有入参 + 有回显 + 无编码；存储型：看跨路由串接的**读取点**是否原样回显 |
| spel | 3 | `StandardEvaluationContext` vs `SimpleEvaluationContext` |
| redir | 2 | 是否下发 `Location`（`forward` 是服务端内部转发，不算）；目标是否编译期常量；是否过白名单 |

关键新能力：**CORS 的装配证据现在能被规则消费了**。

`getCsrfToken_01 ~ 04` 方法体都只有 `return token;`，防护在方法外。
切片器早已把 Filter / WebMvcConfigurer / CorsConfigurationSource 的配置体
拼进切片（`// ---- 框架装配证据 ----`），但规则此前只扫入口方法体，看不见。
本轮新增 `wiring_block()` 把它解码后交给规则，于是这四条从"证据在切片里、
结论靠模型"变成了"规则直接给结论"。

顺带补上过去完全没被解析的一种写法 —— `WebMvcConfigurer.addCorsMappings`：

```java
registry.addMapping("/cors/sec/webMvcConfigurer")
        //.allowedOrigins(allowOrigins)      ← 白名单整行被注释掉
        .allowedMethods("GET", "POST")
        .allowCredentials(true);
```

`getCsrfToken_01` 的防护其实有三层证据，**必须按优先级看**：

1. `allowedOrigins(...)` 被注释 → 单看这一层，等于"任意 Origin 可带凭据"，应判有漏洞
2. 但同一个类里 `setCorsProcessor(new CustomCorsProcessor())`
3. 而 `CustomCorsProcessor.checkOrigin()` 里走了 `SecurityUtil.checkURL` 白名单

自定义 processor **优先于** allowedOrigins 生效，所以 `01` 实际是安全的
（作者把路由命名为 `/sec/webMvcConfigurer`，与之一致）。规则最终判 False。

这条踩了两个工程坑，值得记下来：

- **`_strip_comments` 不能用两步正则替换**。行注释里出现 `/*` 时
  （`addMapping(...) // /**表示所有路由path`），先剥行注释会留下一个孤立 `/**`，
  随后的块注释正则把到下一个 `*/` 之间的**真实代码全部吃掉** ——
  `.allowedMethods(...)` / `.allowCredentials(true)` 就是这样被静默删除的。
  必须单遍词法扫描，字符串字面量整体跳过。
- **链式调用的截断不能只看分号的位置**。`addMapping(...)` 后面跟匿名内部类时，
  类体里会先出现 `;`；而参数列表里 `"GET", "POST"` 的逗号后空白又会被误判成
  "链结束"。判据必须是"括号深度 + 上一个非空白字符是逗号"。

### 5.2 跨路由串接：存储型漏洞的单入口盲区

`XSS.store` 到 v4 为止一直漏报。原因不是判定器弱，是**判据的粒度不够**：

```java
// store：外部输入落进 Cookie，返回的是常量
@RequestMapping("/stored/store")
public String store(String xss, HttpServletResponse response) {
    Cookie cookie = new Cookie("xss", xss);
    response.addCookie(cookie);
    return "Set param into cookie";       // ← 回显的是常量
}

// show：从 Cookie 读出，原样写进响应体
@RequestMapping("/stored/show")
public String show(@CookieValue("xss") String xss) { return xss; }
```

xss 类目问的是"是否把外部可控字符串写进响应体"。`store` 答 No 是**正确的**，
`show` 才是回显点，可它没有外部入参。漏洞的成立要件跨了两个方法，
任何单入口分析都接不住。

`core/context/taint_chain.py` 的做法是：不猜语义，只配对客观事实 ——
同一介质（Cookie / Session / Request / Model）、同一键名，出现一个"写"和一个"读"。
`new Cookie("xss", ...)` 的键名与 `@CookieValue("xss")` 的键名相同，这就是连接。

这一步踩到的坑比预想的多：

- **切片器本身会污染串接结果。** 为了给模型看到污点清洗逻辑，每个入口的切片都
  拼接了"同文件辅助方法"整块。但 Java 里没有"路由方法"这个语法标记，
  `store` 对 `XSS` 类来说就是个普通方法，于是被当成辅助方法拼进了
  `reflect` / `safe` / `show` 的切片。结果这 4 个入口**互相都连上了**，
  12 条"串接"里 9 条是假的。修法是 `CodeUnit` 新增 `own_body` 字段存
  未拼接的入口方法体，串接只读它 —— 过滤后恰好剩 1 条，就是真值那条。
- **`build_chains` 早期只认显式传入的 `entries_only` 参数，不读 `own_body`。**
  调用方忘传就静默退化到污染态的 `source_code`，而结果"看起来正常"（有连接、
  有证据），根本发现不了。改成默认优先读 `own_body`，让"不传也对"成为默认行为。
- **串接证据只贴在写入方，不贴读取方。** 写入方是输入的来源入口；
  读取方本身没有外部参数，贴上"我读了一个会被污染的值"反而会诱导模型
  对 `show` 也判漏洞 —— 而 `show` 的真实性质取决于它上面那条链。

判定时也不能只看"有连接"：读取点如果做了输出编码（`return encode(xss)`），
链路虽然闭合但不构成漏洞。规则里这两件事是分开判的。

## 六、还剩的错判

在逐条归因之前，先说清楚一个更根本的问题：**这些错判里，有几条是我们判错，
有几条是这个靶场本身"判不出唯一答案"。**

### 6.1 CORS 这一类，问题在靶场结构，不在判定器

`Cors.getCsrfToken_01 ~ 04` 四个方法体一模一样：

```java
@GetMapping("/sec/webMvcConfigurer")
public CsrfToken getCsrfToken_01(CsrfToken token) { return token; }
```

**方法体里一行 CORS 代码都没有。** 防护完全来自方法外的装配：

| 路由 | 防护实际实现位置 |
|---|---|
| `/sec/webMvcConfigurer` | `CorsConfig.java`（不在入口文件里） |
| `/sec/httpCors` | `WebSecurityConfig.corsConfigurationSource()` + `http.cors()` |
| `/sec/originFilter` | `OriginFilter.doFilter()`，`@WebFilter(urlPatterns="/cors/sec/originFilter")` |
| `/sec/corsFilter` | `BaseCorsFilter`（`@Order(HIGHEST_PRECEDENCE)` 全局生效） |

要判对，必须**从 Servlet Filter 注册和 Spring Bean 装配反推回 URL 路由**。
这是框架配置语义分析，不是数据流分析。我们的切片器做的是"方法 → 它调用了什么"，
从来没做"URL → 哪些 Filter / Interceptor / CorsConfigurationSource 会作用于它"。

而且 `Cors.vuls3` 的标注本身就不成立：

```java
@GetMapping("*")
@RequestMapping("/vuln/crossOrigin")
public String vuls3() { return info; }
```

`@RequestMapping` 和 `@GetMapping("*")` 同时出现在一个方法上，这是**非法的**
（两个映射注解会冲突），Spring 启动时就会报错，或者至少不会同时生效。
也就是说这个"漏洞样本"在真实运行时根本不存在那条路径。

**结论：CORS 这一类的抖动，35% 归我们（缺框架装配分析），
但至少 2/8 条是靶场自身的问题，不该计入任何指标。**
把它当成"模型不擅长 CORS"来调 prompt 是浪费时间 —— 再怎么调，
`return token;` 里也长不出 CORS 代码。

这也解释了为什么 `seccode`（唯一真正写了 `SecurityUtil.checkURL` 的方法）
稳定判对，而另外四条稳定抖动。

> **本轮已修复**：上面这套"从 Filter/Bean 装配反推 URL"的能力已经实现
> （`core/context/framework_wiring.py`），并且**接线到了规则层**：
> 切片里的装配证据现在会被 `rule_detectors.wiring_block()` 解码，
> 由 `cors_wiring_verdict()` 按"自定义 processor > allowedOrigins > 入口体"
> 的优先级判定。8 条 CORS 现在全部由规则给出结论且全对（见 5.1 节）。
> `Cors.vuls3` 的非法映射仍然判 None —— 规则不该为一条运行时不存在
> 的路由强行给结论。

### 6.2 误报（v4 曾 4 条，v5 已全部归零）

| 样本 | 原因 | 归属 | v5 状态 |
|---|---|---|---|
| `SQLI.mybatisOrderBySec04` | `sqlFilter(sort)` 是全串白名单，模型看到 Mapper 里的 `${order}` 就判了 | 我们（证据不够深） | **规则修掉**：白名单分支优先于 `${}` 分支 |
| `XXE.DocumentBuilderSec` | 已设 `disallow-doctype-decl=true`，模型把 `DocumentBuilderFactory` 本身当成危险面 | 我们（可规则化） | **规则修掉**：极性感知的特征判断 |
| `XXE.DocumentBuilderXincludeSec` | 同上，`setXIncludeAware(false)` + 实体禁用，模型漏看 | 我们（可规则化） | **规则修掉** |
| `URLRedirect.forward` | `getRequestDispatcher(url).forward()` 是服务端内部转发，不产生重定向响应 | 我们（可规则化） | **规则修掉**：只认下发 Location 的 API |

这 4 条误报的消失路径完全一致 —— **它们都是"客观事实题"，不是"语义判断题"。**
模型不是不够聪明，是这类题根本不该由它回答。

### 6.3 漏报（v4 曾 2 条，v5 已全部归零）

| 样本 | 原因 | 归属 | v5 状态 |
|---|---|---|---|
| `SSRF.hutoolHttp` | 出站调用在 hutool 库内部，切片里只有 `HttpUtil.get(url)` | 我们（静态分析原理性上限） | **规则修掉**：判"hook 有没有挂上"，不看客户端实现 |
| `XSS.store` | 方法体只有 `new Cookie(...)` + `addCookie`，**不写响应体** | 真值/判据粒度错配 | **串接修掉**：见 5.2 |

`SSRF.hutoolHttp` 这条的修法值得记一笔：原来想靠"分析 hutool 内部怎么发请求"
来判，那是死路（库内部实现不在切片里，也永远不可能全部覆盖）。正确的做法是
**换一个观测点** —— 不管用哪个 HTTP 客户端，`startSSRFHook()` 挂的是
`InetAddress` 层，谁都绕不过去。判"校验挂没挂"而不是"请求怎么发"，
问题立刻从"原理性上限"变成"确定性事实"。

`XSS.store` 的处理在 v4 曾被写成本节的"应该剔除样本"，那是错误结论。
它不该被剔除 —— **是判据的粒度不够，不是样本有问题**。补上跨路由串接后
它自然判对了。

## 七、结论

**能用的部分**：
- 切片器经住了真实代码考验。本轮修掉的切片 bug（注解锚点、参数括号配平、
  正则回溯、跨文件证据注入、零参 Mapper 跳过、同文件路由污染串接）
  **全部只在真实项目上暴露**，Benchmark 一个都没测出来。
- 确定性规则前置仍然正确：MyBatis 的 `#{}` / `${}`、`SimpleEvaluationContext` vs
  `StandardEvaluationContext`、`disallow-doctype-decl` 的极性、SSRF hook 挂没挂，
  这些都是客观事实，不该交给概率模型。
- **规则前置的实际收益已经量化并走完了全程**：规则覆盖 10 → 15 → 63 条，
  Score 从单轮 0.639–0.724 抬到 0.823，再到 **1.000**；
  调用次数从 1× 降到 0.05×；规则部分的抖动率从 41.7% 降到 **0**（纯函数）。
  （v5 曾是 64 条，v6 主动收紧 ssrf 兜底后降到 63 条 —— 见第五节说明。
  覆盖数下降是修 bug 的代价，不是退步。）

**不能声称的部分**：
- **不能把 1.000 当作"引擎零缺陷"。** 规则是在这 67 条样本上做出来的，
  存在过拟合风险。做过的唯一检验是样本外跑一遍（只多出 4 条结论，且都站得住），
  但真正的泛化能力需要换项目验证。这是当前最大的未验证假设。
- **不能说"67 条全部由确定性方法判定"。** 仍有 3 条（cmdi 1、pathtraver 2）
  经模型，且它们仍是抖动来源。
- **不能说"抖动问题已解决"。** 已解决的是"把客观题交给模型"这一类；
  剩下的语义型判断（尤其 pathtraver）该不该规则化、能不能规则化，还没有答案。
- **不能说"抖动全是模型不稳定"。** CORS 一类的抖动大半源于我们缺框架装配分析
  （`return token;` 里没有 CORS 代码，防护在 Filter/Bean 里），
  这部分是**切片能力缺口**，不是模型缺陷。把两者混在一起谈"抖动率 41.7%"
  会掩盖真正的问题定位。补上框架装配后，8 条 CORS 全部稳定判对；
  补上跨路由串接后，`XSS.store` 也稳定判对 —— 两次都反证了这个归因。

**方法学教训**：
1. 我第一次评估投票时用了错误的指标 —— 比较两种策略的**总体 TPR/FPR**，
   得出"投票无用"或"投票有用"都无从谈起，因为它测的根本不是抖动。
   正确的问法是"同一批样本再跑一遍，结论变不变"。指标选错，
   实验做得再干净也是废的。
2. **规则化 > 投票**。投票是把一次抽样换成 N 次抽样的多数，成本线性上升，
   且对"确定性错误"完全无效；规则化是把不确定性直接消掉。两者不是同一个
   量级的杠杆，能规则化的场合不该先想到投票。

**已排除的方向**（避免重复劳动）：
- ~~多次采样取多数降抖动~~ → **部分推翻**：3 票无效（翻转率 13.6% → 13.6%），
  但 5 轮取多数把 Score 从 0.639–0.724 抬到 0.793。**问题是票数不够，不是方法错**。
  代价是 5 倍调用，且修不了"5 轮全错"的 3 条。
- ~~靠调 prompt 让模型自己搞定 CORS~~ → 已用规则替代，见 5.1。

### 修正后的下一步（优先级重排）

1. ~~给新类目补确定性规则~~ → **已完成，且做满了**。八类规则化（cors / deserial /
   spel / xxe / sqli / ssrf / xss / redir），63 条覆盖全部正确。
   剩下的 cmdi / pathtraver 只有 3 条样本，且没有像"hook 挂没挂""AES vs DES"
   那样干净的事实支点，继续规则化的收益不明确 —— **这一支到此为止**。
2. ~~CLI 走规则前置~~ → **已完成**。`cli.py scan-java` 现在先跑 `rule_verdict`，
   只剩规则判不了的交模型；判定失败的样本单独记账，不再静默算作"无漏洞"。
3. ~~pr-scan 实现~~ → **已完成**。现在能做到：变更文件 → 变更行所属方法 →
   反向依赖（含装配级）→ 只审计受影响路由。
4. ~~跨路由串接~~ → **已完成**。`core/context/taint_chain.py`，
   `XSS.store → XSS.show` 正确接上，且污染隔离（只读 `own_body`）经过测试覆盖。
5. **换一个项目验证泛化**（当前最高优先级）。1.000 是在规则的同源样本上得到的，
   过拟合风险没有被排除。下一个项目（不同框架 / 不同写法）才能真正检验
   这些判据是"客观事实"还是"这个靶场的模式"。
6. **可信真值**：`SSRF.openStream`（判 VULN 但被标 safe）、`Cors.vuls3`（双映射注解
   不合法）、`URLRedirect.forward`（已规则化，但真值标注本身也值得复核）
   这类标注可疑的样本，扩样本前应先人工复核。

## 八、复现方式

```bash
# 全量一轮（67 样本，规则前置，只有 3 条真正调模型，约 1 分钟）
python benchmarks/benchmark_javaseccode.py --concurrency 4

# 只看规则覆盖（不调模型，秒级）
python benchmarks/benchmark_javaseccode.py --offline

# 串接与 redir/xss/ssrf 规则的分支自检（不调模型，秒级）
python benchmarks/smoke_test_chains.py

# 稳定性复测（同一输入连问 N 次）
python benchmarks/check_stability.py

# 采样策略一致性 A/B：每种策略跑 2 轮，再比两轮之间的翻转数
python benchmarks/benchmark_javaseccode.py --votes 1 --output benchmarks/results/ab_votes1a.jsonl
python benchmarks/benchmark_javaseccode.py --votes 1 --output benchmarks/results/ab_votes1b.jsonl
python benchmarks/ab_votes.py ab_votes1a ab_votes1b      # → 13.6%
python benchmarks/benchmark_javaseccode.py --votes 3 --output benchmarks/results/ab_votes3a.jsonl
python benchmarks/benchmark_javaseccode.py --votes 3 --output benchmarks/results/ab_votes3b.jsonl
python benchmarks/ab_votes.py ab_votes3a ab_votes3b      # → 13.6%，成本 ×3
```

结果：`benchmarks/results/javaseccode_v3.jsonl`、`benchmarks/results/stability.log`、
`benchmarks/results/ab_votes{1,3}.jsonl`（与 `v1_run2` / `v3_run2` 构成两轮对照）
