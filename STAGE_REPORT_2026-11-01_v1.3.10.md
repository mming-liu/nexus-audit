# STAGE REPORT · v1.3.10（M313：A 板块 11 条开箱）

> 日期：2026-11-01 ｜ 基线：v1.3.9（b3c5158）
> 结论：11 条里 **2 条真实**（LZ-litchi 未授权任意文件读取、yshop 缺失权限校验），
> 其余 9 条为规则层假阳，已收口 4 个判据 + 1 个切片污染源。

## 一、逐条结论

| # | 仓库 | 类目 | 单元 | 结论 | 依据 |
| --- | --- | --- | --- | --- | --- |
| 1 | EnterpriseAgentFramework | sqli | BusinessUserDirectoryController.listBusinessUsers | FP | `.last("limit " + ((page-1)*pageSize))`，page/pageSize 都是 int 且 clamp |
| 2 | EnterpriseAgentFramework | sqli | PersonalMemoryIndexInternalController.apply | FP | `service.apply(event)` 被误当 MyBatis-Plus `.apply()` 拼接 |
| 3 | EnterpriseAgentFramework | sqli | PlatformAccountRoleController.listAuditEvents | FP | `.last("limit " + safeLimit)`，safeLimit 是 int |
| 4 | EnterpriseAgentFramework | sqli | RetrievalController.test | FP | 切片里混入 package-lock 拍平块，规则被带偏 |
| 5 | EnterpriseAgentFramework | sqli | RuntimeTraceCenterController.listGuardDecisions | FP | `.last("limit " + safeLimit(limit, 200))`，int 返回值 |
| 6 | skyeye | pathtraver | StencilsetRestResource.getStencilset | FP | 只读 classpath 常量 `getResourceAsStream("stencilset.json")` |
| 7 | skyeye | redir | IndexController.toLogin | FP | `new RedirectView("/", true, false)` 编译期常量 |
| 8 | skyeye | xss | IndexController.toLogin | FP | `new ModelAndView("login")` 常量视图（+ 配置块污染） |
| 9 | LZ-litchi | redir | FileController.getFileContent | FP-leaning | `sendRedirect(buildFileAccessUrl(...))`，目标由文件配置域拼成，仅 Host 头可影响，不构成开放重定向 |
| 10 | LZ-litchi | xss | VectorImageController.uploadImage | FP | 有 `@PreAuthorize`，无反射/回显 sink |
| 11 | yshop-oa-crm | authz | CrmFlowController.deleteFlowStep | **真** | 同类其他方法都有 `@PreAuthorize`，此方法没有（CWE-862） |

## 二、手动发现（规则未覆盖）

**LZ-litchi 未授权任意文件读取**：`GET /admin-api/infra/file/{configKey}/get/{path}`
带 `@PermitAll`，path 从 request URI 取、URL 解码后直接进
`LocalFileClient.getFilePath() = basePath + File.separator + path`，无规范化。
本地存储 + `returnType=1` 配置下可匿名读任意文件（CWE-22，估算 CVSS 7.5）。
规则没报 pathtraver，是因为 sink 在 Hop 的 `LocalFileClient` 里、A 行先被 redir 占了。

## 三、判据收口

| 判据 | 修法 |
| --- | --- |
| sqli 数字拼接 | `_java_numeric_expr()`：拼接实参只含 int/long 变量、`Math.max/min`、整型方法返回值时不判注入 |
| sqli 业务 apply | `_MP_CONCAT_EXIT_RE` 去掉裸标识符分支；新增 `_MP_BARE_ARG_RE`，只有 String 形参或拼接赋值变量才算 |
| pathtraver classpath | 全是 `getResourceAsStream("常量")` 时判 False |
| redir 常量 | `REDIR_CONST_TARGET_RE` 增加 `new RedirectView("...")` |
| 切片污染 | `ConfigResolver` 跳过 `package-lock.json / yarn.lock / *.lock` |

## 四、advisory 草稿（未提交）

- `.cache/advisories/lz-litchi/ADVISORY.md` —— 未授权任意文件读取（High，CVSS 7.5）
- `.cache/advisories/yshop-oa-crm/ADVISORY.md` —— 审批步骤删除缺失权限校验（CWE-862，~4.3）

## 五、门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔ **1,794 项**（新增 [298] 10 项） |
| cli.py doctor | PASS（12 段全绿） |

## 六、遗留

- LZ 的任意文件读取需要在真实部署（本地存储 + returnType=1）下复现确认；
  若维护者用的是 S3/DB 存储，则影响面降级。
- yshop 的 `getFlowUserIds`（line 94）同样缺 `@PreAuthorize`，建议一并报。
