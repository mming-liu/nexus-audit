# 阶段报告 · 2026-10-20

> 本轮主题：**从「教学靶场」落到「真实分层工程」**——第四个靶场接进来，
> 并借它把一条此前只存在于推理里的判据（**值域**）变成可逐行核对的事实。

---

## 一、结论先行

| 靶场 | 入口 | 真值 | 规则覆盖 | 规则正确率 | 安全样本 | 变化 |
|---|---:|---:|---:|---:|---:|---|
| OWASP Benchmark | 2740 | 2740 | 1352 判定 | A=0 / B=0 | — | 零回归 |
| java-sec-code | 132 | 65 | 65 | **1.000（Score）** | 34 | 零回归 |
| Hello-Java-Sec | 128 | 65 | 59（90.8%） | 58/58 = 100% | — | 零回归 |
| JavaSecLab | 227 | 63 | 42（66.7%） | 41/41 = 100% | 13 | **+6 覆盖** |
| **micro_service_seclab** | **20** | **20** | **19（95.0%）** | **19/19 = 100%** | **4** | **新增** |

三条必须先说的口径：

1. **`micro_service_seclab` 的 safe 样本只有 4 条。** 按项目铁律（FPR 分母 < 20
   时不得单独引用），本轮**任何"FPR = 0%"都不构成结论**，只能说"这 4 条
   误报陷阱全部判对了"。
2. **JavaSecLab 的 66.7% 不能与 Hello-Java-Sec 的 90.8% 横向比。** 两者退回样本
   的类目构成不同（JavaSecLab 剩的 21 条集中于 spel / pathtraver / redir，
   不是同一批难度）。
3. **OWASP 的 1352 条确定性判定与改前逐类目完全一致**，这是本轮唯一能说
   "零回归"的地方，其余靶场的"零回归"指判定结果逐条相同。

---

## 二、为什么第四个靶场值得单独花一轮

前三个靶场的漏洞几乎都长在**入口方法自己的文件里**：入口体就是 sink。
这让"跨文件调用链展开"这项能力长期**没有真实阻力**——把 `depth` 从 1 调到 4，
跑分一分不动，因为靶场里根本没有四跳链。

`l4yn3/micro_service_seclab` 是标准 Spring Boot 分层：

```
IndexController → IndexLogic → IndexDb → JdbcTemplate
IndexController → IStudentMapper(XML `${name}`) / (注解 @Select `${name}`)
IndexController → PersonRepository(Spring Data JPA)
```

`/sqlinjection/one` 的 sink 在 `IndexDb.getStudent()` 第 41 行，**距入口两跳**。
只展开 1 跳时，模型拿到的是 `return indexLogic.getStudent(username);` 这样一行，
看不到任何 SQL，必然答"没有注入"——**这不是保守，是把真漏洞判成安全**。

本轮实测：四跳切片把这 20 条里的 11 条 sqli 全部带到了 sink 所在方法体，
规则在 20 条上判 19 条，只有 fastjson 一条退回（见第五节）。

---

## 三、本轮最硬的一处：把「值域」变成判据

### 3.1 靶场给的是一对**逐字同构**的样本

```java
@PostMapping("/in")                                   // 真值：漏洞
public List<Student> in(@RequestBody List<String> user_list) {
    return indexLogic.getStudentWithIn(user_list);
}

@PostMapping("/longin")                               // 真值：安全
public List<Student> longin(@RequestBody List<Long> user_list) {
    return indexLogic.getStudentWithInLong(user_list);
}
```

两个 helper 的方法体**一个字符都不差**（连 `Joiner.on("','").join(name_list)`
都一样），唯一的差别是泛型实参 `List<String>` / `List<Long>`。作者在 `/longin`
上方直接写着：

> `// 这并不是一个注入，如果SAST扫描器将这个报为SQL注入漏洞，那么这是一个误报问题`

### 3.2 此前两条一起退回模型

旧判据 `_helper_concat_sql` 要求「拼接操作数是**裸变量**」：

```python
for v in _operand_vars(rhs):                 # 只认 `+ id +`
    if re.search(r"\b(?:String|Integer|...)\s+" + v, seg):
        return True
```

`Joiner.on("','").join(name_list)` 是函数调用、`username.get()` 是链式调用、
`String.valueOf(id)` 也是调用——**三种形态一个都看不见**，于是 4 条 SAFE
（`longin` / `objectint` / `jpaone` / `jpaWithAnnotations`）全部退回模型。
真漏洞 `in` 同样退回。

模型对"拼进 SQL 的是 `List`"没有类型信息，只能猜。**这就是把确定性问题
交给了抽样**。

### 3.3 新判据：不问"像不像拼接"，问"值能不能是 `'`"

```python
def _type_carries_taint(ty):
    # List<String> → 元素 String → True
    # List<Long>   → 元素 Long   → False
    # Optional<T>  → 递归 T
    # int/Integer/Long/...      → False
    # String/char/CharSequence  → True
    # Object/var/没见过的类      → None
```

再用 `_concat_operand_taint()` 对拼接右值**逐个操作数**问：
- 提取该操作数引用的标识符（`_expr_identifiers` 已经能穿过
  `Base64.decode(x)`、`org.apache.xxx.Foo.bar(y)` 这类链）
- 是形参 → 查声明类型（`_param_decl_types`，**保留泛型实参**）
- 是局部变量 → 查 `Type v = ...` 那一行
- 查不到 → `None`

三态聚合：有 `True` 就判漏洞；**全部 `False` 才判安全**；否则退回。

`_helper_concat_sql` 因此从 `bool` 改成 `bool | None`：

```
True  → 有操作数能带 `'` 进 SQL
False → 每一个操作数都被类型/字面量锁死为无害  ← 新增的"确认安全"
None  → 有操作数查不出来（即"我查不清"，不是"它没问题"）
```

**这一格的区分是本轮最关键的一处。** 旧版把第三态写成 `return False`（等同
"条件不成立，继续往下走"），于是"我查不出来"和"我确认它安全"混在一起——
`/longin` 恰好落在这个缝里。

### 3.4 效果

| 样本 | 真值 | 改前 | 改后 |
|---|---|---|---|
| `/in`（`List<String>`） | 漏洞 | None（退回） | **True** |
| `/longin`（`List<Long>`） | 安全 | None（退回） | **False** |
| `/objectint`（`Integer`） | 安全 | None（退回） | **False** |
| `/optinal_like`（`Optional<String>`） | 漏洞 | None（退回） | **True** |

四条里两条是方向护栏：`List<String>` 判 safe 是静默放行，
`Optional<String>` 判 safe 同样。冒烟测试对这两条单独加了断言。

---

## 四、另三处补强（都是真实样本驱动，不是预防性设计）

### 4.1 接口声明段：`_method_index()` 天生读不到 Spring Data 仓库

`_method_index()` 用 `METHOD_RE`（要求后面有 `{`）建索引，而仓库方法只有声明：

```java
public interface PersonRepository extends JpaRepository<Person, String> {
    public List<Person> findPersonByUsername(String username);
}
```

于是 `personRepository.findPersonByUsername(name)` 在索引里查不到，切片既不补
实现体、也不补声明。**"这个方法是框架派生查询"的唯一依据就在 `extends` 子句里**，
不贴接口头等于把证据又切掉了。

新增 `_interface_index()`：索引「方法名 → 接口头 + 该方法声明」，在方法体跳展开
之后单独成段（不占 `max_methods` 名额、不递归）。判据 `_jpa_derived_query_safe()`
要求两条同时成立：① 有 `extends <Spring Data 仓库接口>`；② **整段声明没有任何
字符串拼接**。② 是防漏报闸门——`@Query` 里手写 `+` 是真实写法。

### 4.2 JPA `createQuery`：JPQL 世界的 `prepareStatement`

JavaSecLab 的 `JPAController` 给了三个对照样本（vul1 / vul2 / safe），此前
全部退回模型，因为判据只认 `prepareStatement`。新增判据与 `prepareStatement`
**完全同构**：先 `_resolve_sql_var` 回溯源变量，再看文本里有没有拼接。

顺带修了 `_resolve_sql_var` 的一个真实缺陷：链式调用
`createQuery(jpql).setParameter(...)` 的实参段是 `jpql)\n.setParameter(...)`，
原来的 `rstrip(")")` 连方法名一起留下 → 不是纯标识符 → 原样返回，安全样本
（常量 JPQL + 绑定参数）被判成"查不出语句"。改为先取第一个 `)` 之前的标识符。

效果：JavaSecLab sqli **3/9 → 9/9**，整体覆盖 36 → 42。

### 4.3 Apache HttpClient 的变量形态 SSRF

`SSRF_SINK_RE` 里的 `execute\(\s*(?:new\s+)?Http\w*` 只认内联写法
`client.execute(new HttpGet(url))`。真实代码几乎都先声明变量：

```java
HttpGet get = new HttpGet(imageUrl);
HttpResponse response = client.execute(get);      // 实参是小写变量名
```

新增 `_httpclient_sink_hit()`：要求「构造实参不是字面量」+「有 `execute(`」。
目标写死的 `new HttpGet("http://fixed/")` 不算本类目对象。

---

## 五、已知缺口（不做，以及为什么不做）

### 5.1 FastJson 反序列化：唯一一条退回样本，**本轮不写判据**

```java
Teacher teachVO = JSON.parseObject(applyData, Teacher.class);   // fastjson 1.2.31
```

靶场标 vul（正确：1.2.31 的 `parse()` 阶段就处理 `@type`）。但不写的理由：

1. **版本是必要条件，而版本不在切片里。** 1.2.31 与 1.2.83（默认 safeMode）
   行为相反，判据拿不到 `pom.xml` 的版本号就只能猜。要补，先让切片器把
   `fastjson` 的 `<version>` 带进「配置回填」段。
2. **没有第二个靶场交叉验证。** 按项目方法论（"同一判据在两个靶场同时成立
   才算事实"），单靶场单样本不足以立判据；写出来大概率是
   "见到 `JSON.parseObject` 就报"，在真实项目上误报爆炸。
3. `parseObject(text, Foo.class)` 与 `parseObject(text)` 的 autoType 行为也不同，
   只认前者会漏掉后者（后者更常见）。

**触发条件写在这里**：找到第二个带明确 fastjson 版本的靶场，或拿到一个
真实项目的误报/漏报案例，再动手。

### 5.2 其余退回样本（JavaSecLab 21 条 / HJS 6 条）**未逐条处理**

本轮只动了「有真实样本驱动」的三处。存量退回样本按上轮归因表分类
（类目未实现 / 切片缺实现体 / 判据写窄），没有新证据前不动。
把退回率压低不是目标，**判错才是**。

---

## 六、本轮踩到的三个坑（都已写成代码注释）

### 6.1 同名函数静默覆盖：`_param_types`

我在文件里新写了一个 `_param_types(sig)` 保留泛型实参，而 4019 行的文件里
**已经有两个**同名函数（后写的胜出），我的版本被静默覆盖。症状：
`decls: {'name_list': 'List'}`——泛型实参丢了，`List<String>` 与 `List<Long>`
又变得无法区分，四条样本继续退回。

新函数改名 `_param_decl_types`，并在 docstring 里写明"不要与后面那个混用"。
**Python 的同名定义不报错、不警告，后写胜出**——这类 bug 只能靠"跑一遍看
输出是不是我预期的"发现，靠读代码发现不了。

### 6.2 Javadoc 里的 `${username}`：第 10 条的重演

新加的接口声明段把 `UserMapper` 的 Javadoc 一起带进来了：

```java
/**
 * If using simple sql, we can use annotation. Such as @Select @Update.
 * If using ${username}, application will send a error.
 */
@Select("select * from users where username = #{username}")
User findByUserName(@Param("username") String username);
```

规则读到注释里的 `${}` → 判成 MyBatis 字符串替换 → 把 `#{}` 安全样本判成注入。
**java-sec-code 从 1.000 掉到 0.971**，一条 FP。

修法：`_interface_index()` 里对每个方法声明做 `strip_java_comments()`。
注释是给人看的，不是契约；**不许模型被误导的东西，规则自己也不许读到。**

### 6.3 `_impl_segment` 的取段范围：第 30 条的重演

```python
i = source.find("跨文件证据")        # 旧写法：只找前缀
```

我新加的段头 `// ---- 跨文件证据：被调方法的接口声明 ----` 也是这个前缀，
于是整个接口声明段被当成"实现体段"吞进 MyBatis 判定。这和第 10/30 条是同一个
错误类型：**判据扫的范围比判据本身更容易错**。

改为锚定完整段头 `跨文件证据：以下为实现体`，只在找不到时退回前缀匹配。

---

## 七、门禁

新增 16 条冒烟断言（`smoke_test_chains.py` [41]–[44]），其中 **3 条是方向护栏**：

- `Optional<String>.get()` 解包后必须判**真漏洞**（判 safe 是静默放行）
- `List<String>` 拼进 IN 子句必须判**真漏洞**
- Javadoc 里的 `${}` 不许影响 MyBatis 判定

`pre-push` 钩子已挂冒烟 + `export_disputes.py --check`，本轮 16 条断言全部通过。

---

## 八、下一步

按用户给的两条路，本轮选了**第一条（固化第四靶场）**，理由：它本地已有、
20 条入口、且是唯一带真实分层结构的靶场——先用它把 `MAX_HOPS=4` 与新增的
值域判据锁死，再往外扩才有一个**可比基线**。

下一轮建议直接进入第二条：挑 `newbee-mall` 或 WebGoat 的 IDOR 模块做首次
盲测。届时要盯的不是分数，而是**断链样本的形态**：

- 多实现类（`Service` 接口有 2+ `*Impl`）→ 才会逼出接口消歧
- MyBatis `<include refid="Base_Column_List"/>` → 才会逼出 XML 递归展开
- 水平越权（订单/地址未校验 `userId`）→ 才会把 `authz` 的分母从 4 撑到 15+

在这三类样本出现之前，**不写那两块代码**。
