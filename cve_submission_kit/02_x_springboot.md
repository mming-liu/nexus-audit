# 傻瓜式三步交单手册（x-springboot / pathtraver / SysGenController.create）

> 模板版本：playbook-1.4.1 ｜ 状态：ZERO_RECORD_FRESH
> HEAD：f4acf07c6b134af9ad3e6284d65b40997087b14f（2026-10-30）
> GitHub Issue #47 已提：https://github.com/yzcheng90/x-springboot/issues/47
> 结论：CWE-22 / CWE-73；默认 PR:H，CVSS 3.1 7.2；若授权低权角色则 PR:L 8.8。

## Step 1：点哪个网址

- GitHub Issue：https://github.com/yzcheng90/x-springboot/issues/47
- GitHub 私密 Advisory：https://github.com/yzcheng90/x-springboot/security/advisories/new
- MITRE / CVE.org：https://www.cve.org/ReportRequest/ReportRequestForNonCNAs

## Step 2：GitHub 页面填什么

### Title

~~~text
[CWE-22] Arbitrary path write via /sys/gen/create (GenUtils.maker)
~~~

### Description（直接复制）

~~~text
POST /sys/gen/create binds the request body to MakerConfigEntity and calls GenUtils.maker(). The user-controlled filePath, packagePath and moduleName are concatenated into the output path, then passed to new FileWriter(filePath + path). The code performs no normalize(), no canonical-path root check, and no whitelist, so a caller with the SysGenCreate permission can write generated .java/.xml/.sql/.js/.vue files outside the intended output directory. The default permission setup only allows the super administrator (userId == "1"); if SysGenCreate is granted to a lower-privileged role, that role can write. The code is unfixed at commit f4acf07c6b134af9ad3e6284d65b40997087b14f. This is CWE-22 / CWE-73, not an unauthenticated issue.
~~~

## Step 3：CVE.org 表单 6 个框

| 字段 | 预填值 |
|---|---|
| Vendor | yzcheng90 |
| Product | x-springboot |
| Version affected | through master (unfixed as of 2026-10-30) |
| Vulnerability Type | CWE-22 / CWE-73 |
| Affected Component | SysGenController.java:47-51 -> GenUtils.java:152-153 |
| Suggested Description | Authenticated arbitrary path write in /sys/gen/create; filePath/moduleName from the request JSON are concatenated into the output path without normalization or a root check. CWE-22 / CWE-73; default PR:H, or PR:L if SysGenCreate is granted to a low-privileged role. |

## Step 3B：CVE Services（MITRE CNA-LR）逐框填写

| CVE Services 字段 | 预填值 |
|---|---|
| Problem types | CWE-22 / CWE-73，描述填 路径遍历 / 任意文件写入 |
| Vendor or project | yzcheng90 |
| Product name | x-springboot |
| Purl | pkg:github/yzcheng90/x-springboot |
| Source repository | https://github.com/yzcheng90/x-springboot |
| Program routines (OSS) | SysGenController.create -> GenUtils.maker |
| References | https://github.com/yzcheng90/x-springboot/issues/47 |

### Versions 表（versionType 选 custom）

| 列 | 值 |
|---|---|
| Affected | y |
| Version (or start of a range) | 0 |
| <= Version (range) | through master (unfixed as of 2026-10-30) |
| Default status | y |

### Description（整段粘贴）

~~~text
The x-springboot repository at commit f4acf07c6b134af9ad3e6284d65b40997087b14f is affected by an authenticated arbitrary path write (CWE-22 / CWE-73) in SysGenController.create -> GenUtils.maker. The request body fields filePath, packagePath and moduleName are concatenated into the output path without normalization or a root check, allowing a caller with the SysGenCreate permission to write generated files outside the intended directory. The default configuration only grants SysGenCreate to the super administrator (userId == "1"); if the permission is granted to a lower-privileged role, that role can write. The code is unfixed as of master (2026-10-30).
~~~

### 过审三要素

- 根因句：filePath / packagePath / moduleName from the request JSON are concatenated into the output path without normalization or a canonical-root check.
- 影响句：write generated .java/.xml/.sql/.js/.vue files at arbitrary writable filesystem paths, potentially overwriting source or web-served files.
- 修复状态句：unfixed as of master (2026-10-30).

### 表单问题区固定答法

| 问题 | 答法 |
|---|---|
| 确认已阅读 CNA-LR 主页信息 | yes |
| CVE partner onboarding 注册组织 | 留空（个人报告者） |
| 是否已联系供应商要 CVE | no |
| 是否现在就在 CVE List 公开 | yes |
| Additional Information | 留空 |

### Tags

厂商未回应前不加 unsupported-when-assigned；先观察 7 天。

### 单 CNA 红线

Issue #47 是公开 bug，不与 GitHub 私密 Advisory 同时投；只选一个 CNA。

## 提交前检查

- [ ] HEAD 仍是 f4acf07c6b134af9ad3e6284d65b40997087b14f
- [ ] 不要把本条写成 unauthenticated
- [ ] 不要与 CVE-2025-6731 / uploadApk 合并
- [ ] 不在公开 Issue 贴实际 target 路径
