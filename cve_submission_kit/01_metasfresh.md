# 傻瓜式三步交单手册（metasfresh / sqli）

> 模板版本：playbook-1.4.1 ｜ 状态：ZERO_RECORD_FRESH
> HEAD：a962d77698039c378ec457ac76fe7e64defffeac（2026-10-29）
> GitHub Issue #27079 已提；厂商超 8 天未回应。
> 结论：CWE-89，CVSS 3.1 待定；单路由。

## Step 1：点哪个网址

- GitHub 私密 Advisory（优先）：https://github.com/metasfresh/metasfresh/security/advisories/new
- GitHub Issue：https://github.com/metasfresh/metasfresh/issues/27079
- MITRE / CVE.org：https://www.cve.org/ReportRequest/ReportRequestForNonCNAs

## Step 2：GitHub 页面填什么

### Title

~~~text
[SQLI] DebugRestController.stressTest_massCacheInvalidation in DebugRestController.java
~~~

### Description（直接复制）

~~~text
The metasfresh repository at commit a962d77698039c378ec457ac76fe7e64defffeac contains a SQL injection issue (CWE-89) in backend/de.metas.ui.web.base/src/main/java/de/metas/ui/web/debug/DebugRestController.java (line 454), entry DebugRestController.stressTest_massCacheInvalidation. The affected parameter is concatenated directly into the SQL statement without parameterization or identifier validation, allowing an attacker to read or modify database contents. The code is unfixed at the referenced commit. Source: https://github.com/metasfresh/metasfresh/blob/a962d77698039c378ec457ac76fe7e64defffeac/backend/de.metas.ui.web.base/src/main/java/de/metas/ui/web/debug/DebugRestController.java#L454
~~~

## Step 3：CVE.org 表单 6 个框

| 字段 | 预填值 |
|---|---|
| Vendor | metasfresh |
| Product | metasfresh |
| Version affected | through master branch new_dawn_uat (unfixed as of 2026-10-30) |
| Vulnerability Type | CWE-89 |
| Affected Component | backend/de.metas.ui.web.base/src/main/java/de/metas/ui/web/debug/DebugRestController.java:454 |
| Suggested Description | The metasfresh repository at commit a962d77698039c378ec457ac76fe7e64defffeac contains a SQL injection issue (CWE-89) in DebugRestController.stressTest_massCacheInvalidation. The affected parameter is concatenated directly into SQL without parameterization. The code is unfixed at the referenced commit. |

## Step 3B：CVE Services（MITRE CNA-LR）逐框填写

| CVE Services 字段 | 预填值 |
|---|---|
| Problem types | CWE-89，描述填 SQL 注入 |
| Vendor or project | metasfresh |
| Product name | metasfresh |
| Purl | pkg:github/metasfresh/metasfresh |
| Source repository | https://github.com/metasfresh/metasfresh |
| Program routines (OSS) | DebugRestController.stressTest_massCacheInvalidation |
| References | https://github.com/metasfresh/metasfresh/issues/27079 |

### Versions 表（versionType 选 custom）

| 列 | 值 |
|---|---|
| Affected | y |
| Version (or start of a range) | 0 |
| <= Version (range) | through master branch new_dawn_uat (unfixed as of 2026-10-30) |
| Default status | y |

### Description（整段粘贴）

~~~text
The metasfresh repository at commit a962d77698039c378ec457ac76fe7e64defffeac is affected by a SQL injection vulnerability (CWE-89) in DebugRestController.stressTest_massCacheInvalidation of backend/de.metas.ui.web.base/src/main/java/de/metas/ui/web/debug/DebugRestController.java (line 454). The affected parameter is concatenated directly into the SQL statement without parameterization or identifier validation, allowing an attacker to read or modify database contents. The code is unfixed as of new_dawn_uat (2026-10-30).
~~~

### 过审三要素

- 根因句：the parameter is concatenated directly into the SQL statement without parameterization or identifier validation.
- 影响句：read or modify database contents.
- 修复状态句：unfixed as of new_dawn_uat (2026-10-30).

### 表单问题区固定答法

| 问题 | 答法 |
|---|---|
| 确认已阅读 CNA-LR 主页信息 | yes |
| CVE partner onboarding 注册组织 | 留空（个人报告者） |
| 是否已联系供应商要 CVE | no |
| 是否现在就在 CVE List 公开 | yes |
| Additional Information | 留空 |

### Tags

厂商超 8 天未回应，可加 unsupported-when-assigned；若后续有回应则不加。

### 单 CNA 红线

只投 MITRE；不要再投 GitHub CNA。审核期间 CAN 号与细节不得对外披露。

## 提交前检查

- [ ] HEAD 仍是 a962d77698039c378ec457ac76fe7e64defffeac
- [ ] Issue #27079 仍无厂商回复
- [ ] 不在公开 Issue 贴可利用 payload
