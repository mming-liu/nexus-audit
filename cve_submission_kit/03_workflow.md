# 傻瓜式三步交单手册（WorkFlow-Engine / sqli / searchMapStr 九路由）

> 模板版本：playbook-1.4.1 ｜ 状态：ZERO_RECORD_FRESH
> HEAD：e91293ca1db478fd4e692a23e9f263bbe61dd4d9（2026-11-06）
> GitHub Issue #4 已提：https://github.com/risesoft-y9/WorkFlow-Engine/issues/4
> 结论：CWE-89，PR:L，CVSS 3.1 8.8 High；九条路由合并 1 单。

## Step 1：点哪个网址

- GitHub Issue：https://github.com/risesoft-y9/WorkFlow-Engine/issues/4
- GitHub 私密 Advisory：https://github.com/risesoft-y9/WorkFlow-Engine/security/advisories/new
- MITRE / CVE.org：https://www.cve.org/ReportRequest/ReportRequestForNonCNAs

## Step 2：GitHub 页面填什么

### Title

~~~text
[SQLI] WorkFlow-Engine searchMapStr SQL injection in 9 /vue routes
~~~

### Description（直接复制）

~~~text
The WorkFlow-Engine repository at commit e91293ca1db478fd4e692a23e9f263bbe61dd4d9 contains a SQL injection issue (CWE-89) in the table-query path. Nine authenticated endpoints accept a searchMapStr JSON string; the JSON values are passed through WorkListServiceImpl -> ItemDoingApiImpl / ItemRecycleApiImpl -> Y9TableServiceImpl and concatenated directly into LIKE and equality predicates without parameter binding. Affected endpoints: POST /vue/doing/doingList4All, POST /vue/doing/doingList4Dept, POST /vue/doing/doingList4DuBan, POST /vue/recycle/recycleList, POST /vue/recycle/recycleList4All, POST /vue/recycle/recycleList4Dept, POST /vue/todo/todoList, POST /vue/todo/todoList4Other, GET /vue/todo/todoList4TaskDefKey. Any authenticated user who can reach /vue/* can alter the SQL predicate and read or modify database contents. The code is unfixed at the referenced commit. Source: https://github.com/risesoft-y9/WorkFlow-Engine/issues/4
~~~

## Step 3：CVE.org 表单 6 个框

| 字段 | 预填值 |
|---|---|
| Vendor | risesoft-y9 |
| Product | WorkFlow-Engine |
| Version affected | through main (unfixed as of 2026-11-06) |
| Vulnerability Type | CWE-89 |
| Affected Component | Y9TableServiceImpl.java:310-358；入口 DoingRestController / RecycleRestController / TodoRestController |
| Suggested Description | Nine authenticated /vue endpoints accept searchMapStr; its JSON values are concatenated into LIKE and equality predicates in Y9TableServiceImpl without parameter binding, allowing SQL injection. CWE-89; PR:L. |

## Step 3B：CVE Services（MITRE CNA-LR）逐框填写

| CVE Services 字段 | 预填值 |
|---|---|
| Problem types | CWE-89，描述填 SQL 注入 |
| Vendor or project | risesoft-y9 |
| Product name | WorkFlow-Engine |
| Purl | pkg:github/risesoft-y9/WorkFlow-Engine |
| Source repository | https://github.com/risesoft-y9/WorkFlow-Engine |
| Program routines (OSS) | DoingRestController.doingList4All / doingList4Dept / doingList4DuBan; RecycleRestController.recycleList / recycleList4All / recycleList4Dept; TodoRestController.todoList / todoList4Other / todoList4TaskDefKey |
| References | https://github.com/risesoft-y9/WorkFlow-Engine/issues/4 |

### Versions 表（versionType 选 custom）

| 列 | 值 |
|---|---|
| Affected | y |
| Version (or start of a range) | 0 |
| <= Version (range) | through main (unfixed as of 2026-11-06) |
| Default status | y |

### Description（整段粘贴）

~~~text
The WorkFlow-Engine repository at commit e91293ca1db478fd4e692a23e9f263bbe61dd4d9 is affected by a SQL injection vulnerability (CWE-89). Nine authenticated endpoints accept a searchMapStr JSON string; its values are concatenated directly into LIKE and equality predicates in Y9TableServiceImpl without parameter binding. Affected endpoints: /vue/doing/doingList4All, /vue/doing/doingList4Dept, /vue/doing/doingList4DuBan, /vue/recycle/recycleList, /vue/recycle/recycleList4All, /vue/recycle/recycleList4Dept, /vue/todo/todoList, /vue/todo/todoList4Other, /vue/todo/todoList4TaskDefKey. Any authenticated user who can reach /vue/* can alter the SQL predicate and read or modify database contents. The code is unfixed as of main (2026-11-06).
~~~

### 过审三要素

- 根因句：searchMapStr JSON values are concatenated directly into LIKE and equality predicates without parameterization or identifier validation.
- 影响句：read or modify database contents as an authenticated user with /vue/* access.
- 修复状态句：unfixed as of main (2026-11-06).

### 表单问题区固定答法

| 问题 | 答法 |
|---|---|
| 确认已阅读 CNA-LR 主页信息 | yes |
| CVE partner onboarding 注册组织 | 留空（个人报告者） |
| 是否已联系供应商要 CVE | no（已有公开 Issue #4） |
| 是否现在就在 CVE List 公开 | yes |
| Additional Information | 公开 Issue #4 已提，供 CNA 引用 |

### Tags

若厂商 7 天不回应，加 unsupported-when-assigned；有回应则不加。

### 单 CNA 红线

Nine routes are one root cause; submit one CVE, not nine. Do not open a second CNA.

## 提交前检查

- [ ] HEAD 仍是 e91293ca1db478fd4e692a23e9f263bbe61dd4d9
- [ ] 重查 Y9TableServiceImpl.java 仍拼接
- [ ] 确认 /vue/* 在目标部署由该 Filter 覆盖
- [ ] 九条路由写在同一份 advisory 的 affected endpoints
