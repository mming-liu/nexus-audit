# newbee-mall-api 零改动探针（Step 4 · 2026-10-20）

目标仓库：`newbee-ltd/newbee-mall-api`（前后端分离版，单 Maven 模块）
探针脚本：无（一次性 `JavaSlicer` + `rule_detectors` 直调，不改任何代码）

## 一、切片穿透率：这一层没有断链

| 指标 | 数值 |
|---|---|
| 入口 | **62**（15 个 `*API` 文件） |
| 入口体里出现 `XxxService.method(` | 59 |
| 其中切片里真的带进跨文件实现体 | **59 / 59（100%）** |
| 切片里出现 `[Hop N]` 段 | 62 |
| 含 Mapper XML SQL | 52 |
| Mapper XML 里 `${}` 出现次数 | **0** |

结论：**跨文件穿透与 MyBatis 段落在这份仓库上不需要任何改动**。
（单模块，所以"跨 Maven 子模块 4 跳"这一项本轮没有样本可测——它不是
"通过了"，是"不存在"。）

## 二、authz：18 条判 True，17 条是同一个机制造成的误报

主体不再来自 `HttpSession.getAttribute(...)`，而是**自定义注解注入的形参**：

```java
public Result cartItemList(@TokenToMallUser MallUser loginMallUser) {
    return ResultGenerator.genSuccessResult(
        service.getMyShoppingCartItems(loginMallUser.getUserId()));
}
```

`_AUTHZ_SUBJECT_RE` 认识 `@AuthenticationPrincipal`、`SecurityUtils.getSubject()`、
`session.getAttribute(...)`，不认识项目自定义的 `@TokenToMallUser` /
`@TokenToAdminUser` → `has_subject = False` → 落到第 4 条
"入参直查资源且无主体" → 判 True。

逐条核对 18 条：

| 形态 | 条数 | 说明 |
|---|---|---|
| 主体形参 `loginMallUser` / `adminUser`，且 `xxx.getUserId()` 用作资源键 | **11** | 误报：主体确实参与了资源选择 |
| 主体形参存在，但方法体只 `return service.list();`（列表/下拉，不按 id 取单条） | **6** | 误报：后台 6 条全在 `@TokenToAdminUser` 之下，越权面由注解解析器兜住 |
| `paySuccess` 无主体形参 | **1** | **真漏洞**（见下） |

`paySuccess` 在 API 版里与 Web 版完全同构：

```java
@GetMapping("/paySuccess")
public Result paySuccess(@RequestParam("orderNo") String orderNo,
                         @RequestParam("payType") int payType) {
    String payResult = newBeeMallOrderService.paySuccess(orderNo, payType);
```

不取主体、不比 `userId`、也不在 `@TokenToMallUser` 之下 ——
**未登录即可把任意订单置为已支付**。两个版本给出同一个结论，
说明它不是切片噪声，是设计缺陷。

## 三、修法（本轮不动，下一轮按此落地）

事实支点已经找到，且是**机制级**而非名字级：

```
src/main/java/ltd/newbee/mall/config/handler/
    TokenToMallUserMethodArgumentResolver.java   implements HandlerMethodArgumentResolver
    TokenToAdminUserMethodArgumentResolver.java  implements HandlerMethodArgumentResolver
```

每个 `HandlerMethodArgumentResolver` 的 `supportsParameter(...)` 里写着它认哪个注解，
`resolveArgument(...)` 里写着"从 token 查库拿 `MallUser`，查不到就 throw"。
这就是"形参确实是可信主体"的可逐行核对证据。

落地三步（与 `framework_wiring` 同构）：

1. 新建 `core/context/subject_resolvers.py`：扫 `implements HandlerMethodArgumentResolver`
   的类，取 `supportsParameter` 里的注解名 + `resolveArgument` 的返回类型，
   建 `注解 → (解析器, 主体类型)` 索引，并渲染成
   `// ---- 主体来源：@TokenToMallUser ← TokenToMallUserMethodArgumentResolver ----` 证据块。
2. `_AUTHZ_SUBJECT_RE` 之外新增 `_authz_injected_subject(body)`：
   入口签名里出现"被 resolver 支持的注解"修饰的形参 → 该形参名即主体变量，
   与 `_AUTHZ_SUBJECT_VAR_RE` 的结果合流（后续 2b / 2b-2 / 2c 三条分支全部复用）。
3. 该文件必须加进 `diag_owasp_sqli_fp._slicer_fingerprint()`。

**不许用"注解名里带 User/Token 就当主体"** —— 那是名字启发式，
换个 `@CurrentPrincipal` 就漏，而 `supportsParameter` 是框架的确定性契约。

## 四、未撞上的两件事（继续挂起，不造武器）

| 事项 | 探针结论 |
|---|---|
| 单接口多 `*Impl` 冲突 | 62 个入口全部唯一实现，**无样本** → 消歧继续挂起 |
| MyBatis `<include refid>` 含 `${}` | 全仓 Mapper XML 里 `${}` **0 次** → 不写展开 |

## 五、是否固化第 6 靶场

**暂不。** 理由与本轮之前一致：现在固化，等于把 17 条已知误报写进基线，
之后修好还要再改一次分母。正确顺序是 **先补 `subject_resolvers` → 再固化**，
那时基线里的 authz 才是 18 条真值（17 safe + 1 vul），而不是今天的
"18 条 True、17 条待解释"。
