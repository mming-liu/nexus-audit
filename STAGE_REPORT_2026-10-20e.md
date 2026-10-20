# 阶段报告 2026-10-20e：注解形参主体 → 第 6 靶场

从 `f7287d2` 往下的一轮。目标是上轮 Step 4 探针挖出的那件事：
**前后端分离项目的主体不在方法体里，而在签名上**。

---

## 一、问题的准确形状

`newbee-mall-api` 的控制器长这样：

```java
@PostMapping("/order")
public Result orders(@TokenToMallUser MallUser loginMallUser, PageParam p) {
    return Result.ok(orderService.getMyOrders(p, loginMallUser.getUserId()));
}
```

对只看方法体的判据，这类入口与"完全不取主体"的越权入口**逐字相同** ——
两者都没有 `session.getAttribute`、都没有 `getAuthentication()`。

上轮零改动探针实测：18 条判 True 里 **17 条是这个机制**，第 18 条是
`/api/v1/paySuccess`（真越权，与 Web 版同构）。也就是说：
**这个机制一天的误报量，比整个第 5 靶场 12 条真值里所有真漏洞还多。**

## 二、判据：不按注解名猜

"注解名带 User 就是主体"是名字启发式。项目里叫 `@CurrentViewer` /
`@LoginAccount` / `@Self` 的都有，叫 `@UserAgent` 的恰恰不是。

可逐行核对的事实只有一条链 —— 某个参数解析器同时满足：

| 事实 | 代码里的样子 |
|---|---|
| ① 参数由框架注入 | `implements HandlerMethodArgumentResolver` |
| ② 它认哪个注解 | `supportsParameter: parameter.hasParameterAnnotation(TokenToMallUser.class)` |
| ③ 它拿凭据换对象 | `webRequest.getHeader("token")` + `newBeeMallUserTokenMapper.selectByToken(token)` |

三条缺一不可。只有 ①② 会把 `@CurrentTenant String tenant` 认成主体 ——
那只是个过滤维度，认错的后果是"多租户过滤"被当成"归属校验"。

实现：`core/context/argument_resolvers.py`（索引）+ 切片注入
`// ---- 形参主体注解 ----` 块 + `rule_detectors.parse_subject_params()` 读回。

**关键的口径分离**：注解形参只进入"主体变量集合"，**不进入"是否校验过"的判断**。
`has_subject`（方法体内取主体）与 `has_any_subject`（还包含形参注入）是两个变量：

- 2b / 2b-2 / 2c（主体参与资源选择）：用 `has_any_subject`
- 2a（主体 + 拒绝分支）：**仍然只用 `has_subject`**
- 4)（入参直查 ⇒ 越权）：`not has_any_subject`

这个分离让"知不知道当前用户是谁"和"检不检查资源归属"保持两件事。

## 三、踩到的两个坑（都在签名提取上）

### 坑 1：字符串里的中文括号长得像方法调用

`_signature` 最初用 `\b\w+\s*\(` 找方法名，跳过字符串。但：

```java
@ApiOperation(value = "购物车列表(网页移动端不分页)", notes = "")
```

中文也是 `\w`，`value = "购物车列表(` 完全符合"标识符 + 左括号"。括号配平
停在**字符串内部**的 `)` 上，签名被截成半句 → 该入口的注解块为空。

症状极具迷惑性：同在 `NewBeeMallShoppingCartAPI` 里，
`updateNewBeeMallShoppingCartItem` 正常、`cartItemList` 和 `cartItemPageList`
丢块 —— 看起来像随机。实测因此丢 3 条（53/62 而不是 56/62）。

修法：先算出所有字符串字面量与 `//` 行注释的区间，配平时跳过。

### 坑 2：`@RequestMapping({"/a","/b"})` 的数组花括号

原实现 `text.split("{", 1)[0]` 会把切点放在数组花括号上，签名整段丢失。
改成配平右括号（本轮已覆盖类级数组路由）。

## 四、顺带补的 2e：显式归属比对

写第 6 靶场真值表时发现两条**规则判 None、人工核对应为 safe** 的入口：

```java
MallUserAddress addr = service.getMallUserAddressById(addressId);
if (!loginMallUser.getUserId().equals(addr.getUserId())) {
    return ResultGenerator.genFailResult(ServiceResultEnum.REQUEST_FORBIDEN_ERROR.getResult());
}
```

这是水平越权**最标准**的防护写法，却正好落在 2b/2b-2c 的缝里：
资源查询的实参里没有主体 id（2b 落空）、没有 setter（2b-2 落空）、
没有容器（2c 落空），而拒绝动作写成 `genFailResult`，
不在 `_AUTHZ_DENY_RE` 认的那几种里。

新增 2e，三件事实缺一不可：

1. 比较的一侧是主体变量的 `getXxxId()`
2. 另一侧是**另一个对象**的取值（`user.getUserId().equals(user.getUserId())` 自比不算）
3. 比较在 `if (` 条件里，且方法内存在终止动作

实现上先取 `if` 条件体再查，而不是写一条长正则 —— 长度正则漏掉
`Objects.equals(a, b)` 这种形态时，表现是"规则退回 None"，静默、不报错。

**影响面**：newbee-mall-api 22 条 False（+2），其余四个靶场**零变化**
（它们的 idor 样本都是 `request.getParameter` 直查，没有"先查资源再比对"的写法）。

## 五、第 6 靶场（`benchmark_newbeemallapi.py`）

不出 Score（无逐路由漏洞真值），锁三件事 + 一道方向护栏：

| 项 | 值 | 说明 |
|---|---|---|
| 入口 | 62 | 22 条用户侧 + 3 条管理员个人 + 30 条管理端 + 其他 |
| 含 Service 调用 | 59 | 按**入口体**数，不是整份切片 |
| 其中带进实现体 | **59** | 跨文件穿透全中，无断链 |
| 含 Mapper XML SQL | 52 | |
| 形参主体注解块 | **56** | 反向护栏：少一条即失败 |
| Mapper XML `${}` | **0** | sqli 方向护栏 |

authz 真值 28 条（29 safe + 1 vul，其中 1 条 safe 规则不表态）：

```
规则直接给出结论：23/28（覆盖 82%）
规则判定正确    ：23/23 = 100.0%
├ safe 22 条判对 22（FPR = 0.0%）
└ vul  1 条判对  1（漏报率 = 0.0%）
```

5 条退回的归因（不是判据缺陷，是口径）：4 条公开资源
（分类/首页/商品详情/搜索）、1 条"只读自己"（`/user/info` 无入参）。

**不登记的部分**（口径，不是猜测）：认证入口 3 条、`/manage-api/v1/logout`
（路由名命中 authz 第 0 步的认证入口排除）、管理端业务接口 30 条
（管理员本来就能操作全部资源，属垂直权限，按铁律不硬判 True）。

### 前后对比

| | 修复前 | 修复后 |
|---|---|---|
| authz=True | 18 条（17 条误报） | **1 条**（`/api/v1/paySuccess`，真越权） |
| authz=False | 0 条 | 22 条 |
| 形参主体块 | 0 条 | 56 条 |

## 六、全量回归

| 靶场 | 结果 |
|---|---|
| OWASP 2740 | **A=0 / B=0**，1352 条确定性判定逐类目一致（缓存真重建，9m21s） |
| java-sec-code | Score **1.000**（65 样本） |
| Hello-Java-Sec | 130 入口 / 60 覆盖 / **59/59** |
| JavaSecLab | 227 入口 / 42 覆盖 / **41/41** |
| micro_service_seclab | 20 入口 / **20/20**（100%） |
| newbee-mall（第 5） | 73 入口、authz 13/13、后缀截断 2/2 |
| newbee-mall-api（第 6，新） | 62 入口、authz 23/23、形参主体 56/56 |

冒烟新增 **[52] 4 条 + [53] 3 条**：

- [52] 注解形参作资源键 → False；只打日志 → None；
  无 resolver 证据时**注解名再像主体也不认**（裸形参直查仍判漏洞）；
  有证据但只凭主体存在不判安全
- [53] 归属比对 + 终止 → False；只比对不终止 → None；自己跟自己比 → None

第 6 靶场已接进 `pre-push`（`--strict`）。

## 七、已知缺口

1. **`/manage-api/v1/logout` 被判 None**：`_AUTHZ_AUTHN_ROUTE_RE` 把 `logout`
   一起当成"认证入口"排除了。logout 是**使用**身份而非建立身份，
   `logout(adminUser.getAdminUserId())` 本可由 2b 判 False。
   本轮没动 —— 改动会波及四个靶场里所有 `/logout` 样本，属独立一轮。
2. **管理端 30 条不判**：垂直权限需要角色模型，超出当前 authz 判据范围。
3. **公开资源 4 条不判**："这个接口该不该公开"不是静态可判定的事实。
4. **`extends AbstractResolver` 的间接实现**：`supportsParameter` 写在父类里时
   索引不到 → 不认（退回 None），不会误判。
5. **`updateMallUserAddress` 的 xss=True**：JSON API 不回显，属口径外误报，
   本靶场不评 xss，未登记真值，未改判据。
