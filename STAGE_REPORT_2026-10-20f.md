# 两轮合并总结（d + e）

> 起点 `e13fef4`（三步收口：同名重载 / 主体入容器 / 别名路由）。
> 两次提交：`f7287d2`（d 轮）、`9e21b09`（e 轮）。

**一句话**：这两轮没有新增漏洞类目，做的都是同一件事的两面 —— **把"本该规则判、却在退回模型"的样本接回来**。
第一轮补的是*代码里已经写着、判据没读*的确定性事实（截断几何 / 容器穿透 / 依赖版本）；
第二轮补的是*代码里根本没写方法体、只写在签名和参数解析器里*的主体来源。

---

## 一、两次改动的边界

| | 第一次 `f7287d2` | 第二次 `9e21b09` |
|---|---|---|
| 主题 | 让"能判的判出来" | 让"主体看得见" |
| 起因 | 上轮退回率归因里"判据写窄"那 4 条 + newbee 两条存疑 | 第一次末尾的**零改动探针**挖出的机制（17/18 同因） |
| 新增文件 | `core/context/dependency_versions.py` | `core/context/argument_resolvers.py`、`benchmarks/benchmark_newbeemallapi.py` |
| 改动文件 | `rule_detectors.py`、`java_servlet.py`、`benchmark_newbeemall.py`、`diag_owasp_sqli_fp.py`、`smoke_test_chains.py` | 同左 + `.githooks/pre-push` |
| 规模 | 10 文件 **+807 / −52** | 9 文件 **+1043 / −10** |
| 判据新增 | `_path_suffix_cut_masks_taint`、`_container_flows_to_service`、fastjson 三态 | `parse_subject_params`、2e `_ownership_compared`、`has_any_subject` |
| 主要产出 | msseclab 19/20 → **20/20**；newbee 存疑 2 条转正 | newbee-mall-api authz True 18 → **1**；第 6 靶场固化 |

两轮的因果是接力的：**第一轮末尾只想"看一眼"第 6 个靶场有多难，探针直接指出 17 条误报同一个机制 —— 于是有了第二轮。**

---

## 二、第一次：三件"代码里写着、判据没读"的事实

### 2.1 后缀截断可以判 safe（不是"看起来没事"）

```
suffixName = fileName.substring(fileName.lastIndexOf("."));
```

`lastIndexOf(".")` 定位最后一个点 ⇒ 截出的串必然是「`.` + 一段不含点的尾巴」：

* 尾巴里没有点 ⇒ 无论原始名塞多少 `../`，都拼不出 `..`；
* 以 `.` 开头 ⇒ 不可能是绝对路径。

这是**字符串几何**，可逐字符核对，不是启发式。但"有截断"不等于"截断真挡住了值"，三条件必须同时成立：

| 条件 | 反方向护栏（冒烟 [49] 锁死） |
|---|---|
| ① 存在 `S = F.substring(F.lastIndexOf("."))` | 没有截断 → 维持 True |
| ② 除该赋值与 `F` 定义外，`F` 不再出现 | `new File(DIR + fileName)` → 维持 True |
| ③ 文件 API 实参的动态变量能沿赋值/append 链走到 `S` | 目录前缀来自请求参数 / 截断只为打日志 → 维持 True |

结果：newbee 两条 `upload` 由 DISPUTED 转正为 `PATH_SUFFIX_SAFE`，
`pathtraver` 分布 `0 True / 61 False / 12 None`。

### 2.2 DTO / Map 作主体载体：必须"放进去 + 送出去"两件事

newbee 73 个入口里 `.setUserId(` 只有 2 处，且都跟一句 `cartService.save(item)`。
旧判据只要求「setter 右式来自会话主体」—— **只 set 不传也判安全**，这是把"准备校验"当成"校验"。

收紧为双事实（`_container_flows_to_service()`，2b-2 与 2c 共用）：

```
item.setUserId(user.getUserId());   ← 右式必须溯源到 Session/Principal
cartService.save(item);             ← 且该 DTO（或被 new X(item) 包一层）真进了 Service
```

冒烟 [50] 三条反向断言：只 set 不传 → None；右式是客户端自带的 `order.getUserId()` → None。

### 2.3 版本是代码给不出的事实

`JSON.parseObject(x)` 在 fastjson 1.2.31 与 1.2.83 上是**两个相反结论**，代码本身永远看不出来。
新增 `dependency_versions.py`：父 pom 优先、还原 `${}`（限深 3，还原不了**不记假版本**）、
只收版本敏感组件、只渲染该仓库真有的那几个。

| 证据 | 结论 |
|---|---|
| fastjson `< 1.2.83` + `parseObject` + 外部输入 | True |
| `>= 1.2.83`（safeMode 默认开） | False |
| 显式 `setSafeMode(true)` / `setAutoTypeSupport(false)` | False |
| **无版本证据** | **None** |

实测提取：msseclab `fastjson 1.2.31`；HJS 6 个组件；JavaSecLab 5 个；**newbee 无敏感组件 → 一块都不注入**。
`msseclab` 覆盖率 **19/20 → 20/20（100%）**，退回率归零。

> 提醒：`dependency_versions.py` 影响切片内容 ⇒ 必须进 `_slicer_fingerprint()`，
> 否则缓存命中旧切片，3 秒"假通过"。这次回归耗时 11 分钟才算数。

---

## 三、第二次：主体写在签名上

### 3.1 问题的准确形状

```java
@PostMapping("/order")
public Result orders(@TokenToMallUser MallUser loginMallUser, PageParam p) {
    return Result.ok(orderService.getMyOrders(p, loginMallUser.getUserId()));
}
```

对只看方法体的判据，这种入口与"完全不取主体"的越权入口**逐字相同**：两者都没有
`session.getAttribute`、都没有 `getAuthentication()`。

探针实测：18 条判 True 里 **17 条是这个机制**，第 18 条是真越权。
**这个机制一天的误报量，比第 5 靶场 12 条真值里所有真漏洞还多。**

### 3.2 不按注解名猜

"注解名带 User 就是主体"是名字启发式。项目里叫 `@CurrentViewer` / `@LoginAccount` / `@Self` 的都有，
叫 `@UserAgent` 的恰恰不是。可核对的事实只有一条链：

| 事实 | 代码里的样子 |
|---|---|
| ① 参数由框架注入 | `implements HandlerMethodArgumentResolver` |
| ② 它认哪个注解 | `supportsParameter: parameter.hasParameterAnnotation(TokenToMallUser.class)` |
| ③ 它拿凭据换对象 | `webRequest.getHeader("token")` + `selectByToken(token)` |

三条缺一不可。只有 ①② 会把 `@CurrentTenant String tenant` 认成主体 —— 那只是过滤维度，
认错的后果是"多租户过滤"被当成"归属校验"（比漏报更难发现）。

### 3.3 关键的口径分离

注解形参只进入**主体变量集合**，不进入**是否校验过**的判断：

| 判据 | 用哪个主体集合 |
|---|---|
| 2b / 2b-2 / 2c（主体参与资源选择） | `has_any_subject` |
| 2a（主体 + 拒绝分支） | **仍只用 `has_subject`**（方法体内取主体） |
| 4）（入参直查 ⇒ 越权） | `not has_any_subject` |

"知道当前用户是谁" 和 "检查了资源归属" 保持两件事。

### 3.4 两个签名提取的坑

| 坑 | 症状 | 修法 |
|---|---|---|
| `@ApiOperation(value = "购物车列表(网页移动端不分页)")` | 中文也是 `\w`，`value = "…(` 像方法调用，括号配平停在**字符串内部** → 签名截半、注解块为空。同文件里另一条入口正常，症状像随机（实丢 3 条：53/62 而非 56/62） | 先算出字符串字面量与 `//` 行注释区间，配平时跳过 |
| `@RequestMapping({"/a","/b"})` | `split("{",1)[0]` 切点落在数组花括号上，签名整段丢失 | 配平右括号（类级数组路由同修） |

### 3.5 顺带补的 2e：显式归属比对

```java
MallUserAddress addr = service.getMallUserAddressById(addressId);
if (!loginMallUser.getUserId().equals(addr.getUserId())) {
    return ResultGenerator.genFailResult(...);
}
```

这是水平越权**最标准**的写法，却正好落在 2b/2c 的缝里：资源查询实参无主体（2b 落空）、
无 setter（2b-2 落空）、无容器（2c 落空），拒绝动作是 `genFailResult`（不在 `_AUTHZ_DENY_RE`）。
新增 2e，三件事实缺一不可：

1. 比较的一侧是主体变量的 `getXxxId()`
2. 另一侧是**另一个对象**的取值（自己跟自己比不算）
3. 比较在 `if (` 条件里，且方法内存在终止动作

实现上**先取 `if` 条件体再查**，不写长正则 —— 长度正则漏掉 `Objects.equals(a, b)` 时静默退回 None，不报错。

影响面：newbee-mall-api False 22 条（+2），**其余四个靶场零变化**。

### 3.6 第 6 靶场（`benchmark_newbeemallapi.py`）

不出 Score（无逐路由漏洞真值），锁三件事 + 两道方向护栏：

| 项 | 值 |
|---|---|
| 入口 | 62 |
| 含 Service 调用（按**入口体**数，不是整份切片） | 59 |
| 其中带进实现体（跨文件穿透） | **59** |
| 含 Mapper XML SQL | 52 |
| 形参主体注解块（反向护栏：少一条即失败） | **56** |
| Mapper XML `${}`（sqli 方向护栏） | **0** |

| authz | 修复前 | 修复后 |
|---|---|---|
| `True` | 18（17 条误报） | **1**（`/api/v1/paySuccess`，真越权） |
| `False` | 0 | 22 |
| 判 23 / 28 条，正确 **23/23** | — | FPR 0 / FN 0 |

5 条退回全是口径不是缺陷：4 条公开资源（分类/首页/详情/搜索）、1 条"只读自己"（`/user/info` 无入参）。

**真实漏洞（两个版本同构）**：`/paySuccess` 与 `/api/v1/paySuccess` 都不比 `userId`，
且不在登录拦截器 `addPathPatterns` 内 ⇒ 未登录即可把任意订单置为已支付。

---

## 四、两次改动后的全量基线

| 靶场 | 结果 | 本两轮变化 |
|---|---|---|
| OWASP 2740（全量） | **A = 0 / B = 0**，1352 条确定性判定逐类目一致 | 不变（两次都真重建缓存，9m21s / 11m） |
| java-sec-code | Score **1.000**（132 入口 / 65 样本） | 不变 |
| Hello-Java-Sec | 130 入口 / 60 覆盖 / **59/59** | 不变 |
| JavaSecLab | 227 入口 / 42 覆盖 / **41/41** | 不变 |
| micro_service_seclab | 20 入口 / **20/20（100%）** | 19 → **20** |
| newbee-mall（第 5） | 73 入口 / authz **13/13** / sqli 误报 0 / 后缀截断 **2/2** | 存疑 2 条转正 |
| newbee-mall-api（第 6，新） | 62 入口 / authz **23/23** / 形参主体 56/56 | 新建 |

**关键**：六个既有靶场除 msseclab 与 newbee 的存疑项转正外，一行判定都没动 ——
这两轮是"接回退回样本"，不是"推翻既有结论"。

---

## 五、护栏与工具

| 项 | 内容 |
|---|---|
| 冒烟 | [49] 后缀截断 6 条 / [50] 容器载主 3 条 / [51] fastjson 4 条 / [52] 形参主体 4 条 / [53] 归属比对 3 条，共 **20 条正反断言** |
| `pre-push` | 接入第 6 靶场 `--strict`；现在是 4 项 |
| 方向护栏（防"为了分数放宽"） | `PATH_SUFFIX_SAFE`、`RECOVERED_OVERLOADS`、`SUBJECT_PARAM_EXPECTED`、`SQli ${}`=0 |
| 缓存指纹 | 两次都补了新文件（`dependency_versions.py`、`argument_resolvers.py`），否则假通过 |

每条新判据都**同时**带一个反向断言（"不该判的仍不判"），否则下一轮很容易被宽松化。

---

## 六、遗留（明确挂起，未动）

| 事项 | 状态 | 理由 |
|---|---|---|
| `/manage-api/v1/logout` 判 None | 挂起 | `_AUTHZ_AUTHN_ROUTE_RE` 把 `logout` 当认证入口排除；但 logout 是**使用**身份。改动波及四个靶场所有 `/logout` 样本，属独立一轮 |
| 单接口多 `*Impl` 消歧 | 挂起 | 六个靶场**全部唯一实现，零样本**；硬写"同包 `*Impl` 优先"是对想象中的敌人造武器 |
| 管理端 30 条不判 | 口径 | 垂直权限需角色模型，超出静态 authz 范围 |
| 公开资源 4 条不判 | 口径 | "该不该公开"不是静态事实 |
| `extends AbstractResolver` 间接实现 | 能力边界 | `supportsParameter` 写在父类 → 索引不到 ⇒ 退回 None，**不会误判** |
| `Map.of` / builder 载体 | 无样本 | 已有 `params.put` + DTO setter 覆盖 |

---

## 七、这两轮真正沉淀下来的（方法论）

1. **"格式截断"可以是确定性安全**，只要它能用一个几何论证说明"值被挡在门外"，且三条件同时成立。
   这不是"看起来没事"，是可以逐字符核对的。
2. **版本是代码给不出的事实** —— 需求是"把外部事实注入切片"，而不是在代码里找更多线索。
3. **注解只能反查，不能猜名字**。判定一个注解是不是主体的唯一依据是"谁在解析它、拿什么换它"。
4. **"知道主体是谁" ≠ "检查了归属"**。口径一旦合并，误报会以"更安全"的面目出现。
5. **最标准的防护写法最容易落在判据缝里**（2e 的 `genFailResult`）。真值表要写得下去，
   必须让每条判据的边界话清楚：写完之后问一句"最规范的那条写法，我读到了吗"。
6. **签名解析必须跳字符串与注释** —— 症状是"同文件有的入口对、有的不对"，看起来像随机，
   实际是某个注解里的中文括号。
