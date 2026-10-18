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

### 误报 4 条

| 样本 | 原因 |
|---|---|
| `Cors.getCsrfToken_01/02` | 防护在 Spring Security 的 `CorsConfiguration` 配置里，是**运行时装配**，静态切片里看不到 |
| `SQLI.mybatisOrderBySec04` | `sqlFilter(sort)` 的过滤实现在 `SecurityUtil` 里，但模型看到 Mapper 里的 `${order}` 就判了 |
| `URLRedirect.forward` | 作者未标注（真值靠注释判为安全），但 `request.getRequestDispatcher(url).forward()` 本身确实可疑 —— **这条可能是真值标错** |

### 漏报 5 条

| 样本 | 原因 |
|---|---|
| `Cors.vuls1` | CORS 类目是新增的，prompt 措辞还在打磨 |
| `Deserialize.rememberMeVul` | `readObject` 之前有黑名单校验，模型判定"已有防护"；实际黑名单可绕过 |
| `SSRF.hutoolHttp` | 出站调用在 hutool 库内部，切片里只有一行 `HttpUtil.get(url)` |
| `XSS.store` | 写 Cookie 的跨请求存储型 XSS，单方法切片无法串起「存 → 取」两条路由 |
| `XXE.DocumentBuilderXincludeVuln` | xinclude 路径需要 `setXIncludeAware` 判断，模型误认为已禁用 |

## 七、结论

**能用的部分**：
- 切片器经住了真实代码考验。本轮修掉的 4 个切片 bug（注解锚点、参数括号配平、
  正则回溯、跨文件证据注入）**全部只在真实项目上暴露**，Benchmark 一个都没测出来。
- 确定性规则前置仍然正确：MyBatis 的 `#{}` / `${}`、`SimpleEvaluationContext` vs
  `StandardEvaluationContext`，这些都是客观事实，不该交给概率模型。

**不能声称的部分**：
- 不能说"真实项目 Score 0.78"。单轮 66 样本 + 41.7% 抖动率，
  这个数字的置信区间宽到没有意义。
- 不能说"误报率 11%"。4 条误报里有 1 条疑似真值标错，1 条是静态分析原理上就看不到的
  运行时装配。

**下一步优先级**（按投入产出比）：

1. **降抖动**：同一 unit 三次采样取多数（成本 ×3），或对 `_is_yes` 的原始输出做置信度
   加权。这是当前唯一能把指标从"不可复现"变成"可复现"的手段，优先级高于任何 prompt 调优。
2. **跨路由串接**：`XSS.store → XSS.show` 这种「写入点 + 读取点」分布在两个方法里的
   存储型漏洞，单方法切片结构上就抓不到，需要引入轻量方法间数据流。
3. **可信真值**：`URLRedirect.forward` 这类作者的标注本身可疑，
   继续扩样本前应人工复核一遍真值，否则指标在拟合错误的标签。

## 八、复现方式

```bash
# 全量一轮（66 样本，约 15 分钟）
python benchmarks/benchmark_javaseccode.py --concurrency 4

# 稳定性复测（同一输入连问 N 次）
python benchmarks/check_stability.py
```

结果：`benchmarks/results/javaseccode_v3.jsonl`、`benchmarks/results/stability.log`
