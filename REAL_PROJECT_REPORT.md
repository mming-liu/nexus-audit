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

## 五、逐类目结果（v3，最终一轮）

| 类目 | n | TP | FN | FP | TN | TPR | FPR |
|---|---|---|---|---|---|---|---|
| sqli | 10 | 5 | 0 | 1 | 4 | 1.00 | 0.20 |
| ssrf | 16 | 6 | 1 | 0 | 9 | 0.86 | 0.00 |
| xxe | 17 | 8 | 1 | 0 | 8 | 0.89 | 0.00 |
| cors | 8 | 1 | 1 | 2 | 4 | 0.50 | 0.33 |
| xss | 4 | 2 | 1 | 0 | 1 | 0.67 | 0.00 |
| spel | 3 | 2 | 0 | 0 | 1 | 1.00 | 0.00 |
| deserial | 3 | 1 | 1 | 0 | 1 | 0.50 | 0.00 |
| pathtraver | 2 | 1 | 0 | 0 | 1 | 1.00 | 0.00 |
| redir | 2 | 0 | 0 | 1 | 1 | 0.00 | 0.50 |
| cmdi | 1 | 0 | 0 | 0 | 1 | — | — |
| **合计** | **66** | **26** | **5** | **4** | **31** | **0.84** | **0.11** |

`cmdi` 只有 1 条可判定样本（`CommandInject` 类的另外两条命名无法判定），样本量不足以下结论。

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

### 6.2 误报 3 条

| 样本 | 原因 | 归属 |
|---|---|---|
| `Cors.getCsrfToken_01/02` | 防护在 Spring Security 的 `CorsConfiguration` 配置里，是运行时装配，单方法切片看不到 | **我们**（框架装配分析缺失） |
| `SQLI.mybatisOrderBySec04` | `sqlFilter(sort)` 的过滤实现在 `SecurityUtil` 里，但模型看到 Mapper 里的 `${order}` 就判了 | **我们**（证据注入不够深） |
| `URLRedirect.forward` | 作者未标注（真值靠注释判为安全），但 `request.getRequestDispatcher(url).forward()` 本身确实可疑 | **真值可疑** |

### 6.3 漏报：分三类，只有一类是我们的判定失误

| 样本 | 原因 | 归属 |
|---|---|---|
| `Cors.vuls1` | 类目定义要求"汇聚点存在且外部输入可达"，回显 `request.getHeader("origin")` 且带 `Allow-Credentials: true` 完全符合；模型判成 protected 是判定失误 | **我们**（可规则化） |
| `XXE.DocumentBuilderXincludeVuln` | xinclude 路径需要 `setXIncludeAware` 判断，模型误认为已禁用 | **我们**（可规则化） |
| `Deserialize.rememberMeVul` | 黑名单校验被当作"已有防护"，但黑名单本身可绕过 —— 这是**判据定义漏洞**：property 里没写"黑名单不算防护" | **我们**（类目定义缺陷） |
| `SSRF.hutoolHttp` | 出站调用在 hutool 库内部，切片里只有 `HttpUtil.get(url)` | **我们**（静态分析原理性上限） |
| `XSS.store` | 方法体是 `new Cookie(...)` + `addCookie`，**不写响应体**，按 xss 类目定义答 No 是正确的；它只在和 `XSS.show` 组成存储型链路时才算漏洞 | **真值/类目错配** |

最后一条值得单独说明：`XSS.store` 的真值标"有漏洞"是合理的（它确实是存储型 XSS
的写入端），但 xss 类目的问题问的是"是否写进 HTTP 响应体"。**真值和判据不在说同一件事**，
所以这条永远判不对，只会给抖动率贡献噪声。正确的处理是：在跨路由串接做出来之前，
把它从可判定样本里剔除，或者给它单独一个"存储型 XSS 写入端"的类目。

## 七、结论

**能用的部分**：
- 切片器经住了真实代码考验。本轮修掉的 4 个切片 bug（注解锚点、参数括号配平、
  正则回溯、跨文件证据注入）**全部只在真实项目上暴露**，Benchmark 一个都没测出来。
- 确定性规则前置仍然正确：MyBatis 的 `#{}` / `${}`、`SimpleEvaluationContext` vs
  `StandardEvaluationContext`，这些都是客观事实，不该交给概率模型。

**不能声称的部分**：
- 不能说"真实项目 Score 0.78"。单轮 66 样本 + 41.7% 抖动率，
  这个数字的置信区间宽到没有意义。
- 不能说"误报率 11%"。误判样本里有 1 条真值标错（`URLRedirect.forward`）、
  2 条靶场自身不成立（`Cors.vuls3` 双映射注解、`XSS.store` 判据与真值错配）、
  1 条静态分析原理上就看不到的运行时装配。
- **不能说"抖动全是模型不稳定"。** CORS 一类的抖动大半源于我们缺框架装配分析
  （`return token;` 里没有 CORS 代码，防护在 Filter/Bean 里），
  这部分是**切片能力缺口**，不是模型缺陷。把两者混在一起谈"抖动率 41.7%"
  会掩盖真正的问题定位。

**方法学教训**：我第一次评估投票时用了错误的指标 —— 比较两种策略的**总体 TPR/FPR**，
得出"投票无用"或"投票有用"都无从谈起，因为它测的根本不是抖动。
正确的问法是"同一批样本再跑一遍，结论变不变"。指标选错，
实验做得再干净也是废的；这次是靠 `ab_votes.py` 的 docstring 写清口径才没把错误结论写进报告。

**已排除的方向**（避免重复劳动）：
- ~~多次采样取多数降抖动~~ → **部分推翻**：3 票无效（翻转率 13.6% → 13.6%），
  但 5 轮取多数把 Score 从 0.639–0.724 抬到 0.793。**问题是票数不够，不是方法错**。
  代价是 5 倍调用，且修不了"5 轮全错"的 3 条。

### 修正后的下一步（优先级重排）

1. **给新类目补确定性规则**（最高优先）。抖动集中在 cors(7/8)、spel(2/3)、
   deserial(2/3) —— 这三个都是纯模型判断、没有规则兜底的类目。
   `cors` 的判据其实完全可判定（响应头是否回显 Origin 且带 `Allow-Credentials`），
   本来就该是规则而不是模型判断。规则化一处，抖动直接归零。
2. **prompt 级证据指认**：强制模型先引用决定性的那一行代码再作答。
   针对的是剩下无法规则化的部分。
3. **跨路由串接**：`XSS.store → XSS.show` 这类写入点 / 读取点分居两方法的漏洞。
4. **可信真值**：`URLRedirect.forward` 这类标注可疑，扩样本前应先人工复核。

## 八、复现方式

```bash
# 全量一轮（66 样本，约 15 分钟）
python benchmarks/benchmark_javaseccode.py --concurrency 4

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
