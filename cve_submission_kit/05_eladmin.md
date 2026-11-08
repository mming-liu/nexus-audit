# 傻瓜式三步交单手册（eladmin / authz / S3StorageController.uploadS3Storage）

> 模板版本：playbook-1.4.1 ｜ 状态：ZERO_RECORD_FRESH
> HEAD：646c58c30f2e9aecf998b054f05f4d9ba0008995（2026-11-02）
> GitHub Issue #926 已提：https://github.com/elunez/eladmin/issues/926
> 结论：CWE-862，PR:L，CVSS 3.1 6.5-8.1；与 CVE-2026-108706 / Issue #903 严格区分。
> **CAN：CAN-2026-2042692（2026-11-08 已提交，PUBLISHED）**

## Step 1：点哪个网址

- GitHub Issue：https://github.com/elunez/eladmin/issues/926
- GitHub 私密 Advisory：https://github.com/elunez/eladmin/security/advisories/new
- MITRE / CVE.org：https://www.cve.org/ReportRequest/ReportRequestForNonCNAs

## Step 2：GitHub 页面填什么

### Title

~~~text
[CWE-862] Missing storage:add authorization on S3StorageController.uploadS3Storage
~~~

### Description（直接复制）

~~~text
The eladmin repository at commit 646c58c30f2e9aecf998b054f05f4d9ba0008995 contains a missing authorization issue (CWE-862) in S3StorageController.uploadS3Storage (POST /api/s3Storage). The method has no @PreAuthorize annotation, while the equivalent local-storage upload LocalStorageController.createFile requires @el.check("storage:add") and the same S3 controller requires storage:list for query/download and storage:del for delete. Spring Security uses anyRequest().authenticated(), so any authenticated low-privileged user can upload a file to the configured S3 bucket and create an S3Storage record. This is the write-side counterpart of CVE-2026-108706 (downloadS3Storage, same file) but a distinct method and impact. The code is unfixed at the referenced commit. Source: https://github.com/elunez/eladmin/issues/926
~~~

## Step 3：CVE.org 表单 6 个框

| 字段 | 预填值 |
|---|---|
| Vendor | elunez |
| Product | eladmin |
| Version affected | through 2.7 / commit 646c58c30f2e9aecf998b054f05f4d9ba0008995 (unfixed) |
| Vulnerability Type | CWE-862 |
| Affected Component | eladmin-tools/src/main/java/me/zhengjie/rest/S3StorageController.java:69-78 |
| Suggested Description | S3StorageController.uploadS3Storage (POST /api/s3Storage) lacks the storage:add authorization required by the equivalent LocalStorageController.createFile; any authenticated low-privileged user can upload to the S3 bucket and create a storage record. CWE-862; PR:L. |

## Step 3B：CVE Services（MITRE CNA-LR）逐框填写

| CVE Services 字段 | 预填值 |
|---|---|
| Problem types | CWE-862，描述填 Missing Authorization |
| Vendor or project | elunez |
| Product name | eladmin |
| Purl | pkg:github/elunez/eladmin |
| Source repository | https://github.com/elunez/eladmin |
| Program routines (OSS) | S3StorageController.uploadS3Storage |
| References | https://github.com/elunez/eladmin/issues/926 |

### Versions 表（versionType 选 custom）

| 列 | 值 |
|---|---|
| Affected | y |
| Version (or start of a range) | 0 |
| <= Version (range) | through 2.7 / commit 646c58c30f2e9aecf998b054f05f4d9ba0008995 |
| Default status | y |

### Description（整段粘贴）

~~~text
The eladmin repository at commit 646c58c30f2e9aecf998b054f05f4d9ba0008995 is affected by a missing authorization vulnerability (CWE-862) in S3StorageController.uploadS3Storage (POST /api/s3Storage). The method lacks the @PreAuthorize annotation, while the equivalent LocalStorageController.createFile requires @el.check("storage:add") and the same S3 controller requires storage:list for query/download and storage:del for delete. Spring Security uses anyRequest().authenticated(), so any authenticated low-privileged user can upload a file to the configured S3 bucket and create an S3Storage record. This is a distinct method from CVE-2026-108706 (downloadS3Storage) in the same file. The code is unfixed at the referenced commit.
~~~

### 过审三要素

- 根因句：uploadS3Storage lacks the @PreAuthorize("storage:add") permission annotation that is the function-level authorization mechanism used by the equivalent storage upload.
- 影响句：any authenticated low-privileged user can upload to the enterprise S3 bucket and create a storage record.
- 修复状态句：unfixed at commit 646c58c30f2e9aecf998b054f05f4d9ba0008995.

### 表单问题区固定答法

| 问题 | 答法 |
|---|---|
| 确认已阅读 CNA-LR 主页信息 | yes |
| CVE partner onboarding 注册组织 | 留空（个人报告者） |
| 是否已联系供应商要 CVE | no（已有公开 Issue #926） |
| 是否现在就在 CVE List 公开 | yes |
| Additional Information | 公开 Issue #926 已提；请与 CVE-2026-108706 区分 |

### Tags

若厂商 7 天不回应，加 unsupported-when-assigned。

### 单 CNA 红线

Do not merge uploadS3Storage with CVE-2026-108706 (downloadS3Storage) or CVE-2026-77036 (AliPay/Email/Generator/GenConfig). One CVE for this method only.

## 提交前检查

- [ ] HEAD 或目标 tag 的 S3StorageController.java:69 仍无 @PreAuthorize
- [ ] 确认部署存在无 storage:add 的低权账号
- [ ] 不要把 download 的 CVE-2026-108706 当成本条重号
- [ ] 不在公开 Issue 贴桶地址或上传 payload
