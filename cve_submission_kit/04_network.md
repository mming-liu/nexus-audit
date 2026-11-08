# 傻瓜式三步交单手册（Network-Drive / pathtraver / uploadChunk1 + mergeFile）

> 模板版本：playbook-1.4.1 ｜ 状态：ZERO_RECORD_FRESH
> HEAD：973d777c3e02756749dab3b3399859a9fb79a44e（2026-11-06）
> GitHub Issue #2 已提：https://github.com/risesoft-y9/Network-Drive/issues/2
> 结论：CWE-22，PR:L，CVSS 3.1 8.1 High；两个 endpoint 合并 1 单。

## Step 1：点哪个网址

- GitHub Issue：https://github.com/risesoft-y9/Network-Drive/issues/2
- GitHub 私密 Advisory：https://github.com/risesoft-y9/Network-Drive/security/advisories/new
- MITRE / CVE.org：https://www.cve.org/ReportRequest/ReportRequestForNonCNAs

## Step 2：GitHub 页面填什么

### Title

~~~text
[CWE-22] Path traversal in Network-Drive chunk upload/merge (UploaderController)
~~~

### Description（直接复制）

~~~text
The Network-Drive repository at commit 973d777c3e02756749dab3b3399859a9fb79a44e contains an authenticated path traversal / arbitrary file write (CWE-22) in the chunk upload and merge endpoints. POST /vue/uploader/chunk (UploaderController.uploadChunk1) and POST /vue/uploader/mergeFile (UploaderController.mergeFile) take Chunk.identifier / Chunk.filename (and FileInfo.identifier / filename) from the request and concatenate them into the upload path via FileUtils.generatePath. The resulting path is passed to Files.write / Files.createFile without normalize() or a canonical-root check. A ../ sequence in identifier or filename escapes the intended upload directory. Any authenticated user who can reach /vue/uploader can write files outside the upload root. The code is unfixed at the referenced commit. Source: https://github.com/risesoft-y9/Network-Drive/issues/2
~~~

## Step 3：CVE.org 表单 6 个框

| 字段 | 预填值 |
|---|---|
| Vendor | risesoft-y9 |
| Product | Network-Drive |
| Version affected | through main (unfixed as of 2026-11-06) |
| Vulnerability Type | CWE-22 |
| Affected Component | UploaderController.java:110-152；FileUtils.java:24-37 |
| Suggested Description | uploadChunk1 and mergeFile concatenate user-controlled identifier / filename into the upload path without normalization or a root check, allowing an authenticated user to write outside the upload directory. CWE-22; PR:L. |

## Step 3B：CVE Services（MITRE CNA-LR）逐框填写

| CVE Services 字段 | 预填值 |
|---|---|
| Problem types | CWE-22，描述填 路径遍历 / 任意文件写入 |
| Vendor or project | risesoft-y9 |
| Product name | Network-Drive |
| Purl | pkg:github/risesoft-y9/Network-Drive |
| Source repository | https://github.com/risesoft-y9/Network-Drive |
| Program routines (OSS) | UploaderController.uploadChunk1 / UploaderController.mergeFile |
| References | https://github.com/risesoft-y9/Network-Drive/issues/2 |

### Versions 表（versionType 选 custom）

| 列 | 值 |
|---|---|
| Affected | y |
| Version (or start of a range) | 0 |
| <= Version (range) | through main (unfixed as of 2026-11-06) |
| Default status | y |

### Description（整段粘贴）

~~~text
The Network-Drive repository at commit 973d777c3e02756749dab3b3399859a9fb79a44e is affected by an authenticated path traversal / arbitrary file write (CWE-22) in UploaderController.uploadChunk1 (POST /vue/uploader/chunk) and UploaderController.mergeFile (POST /vue/uploader/mergeFile). The endpoints concatenate user-controlled Chunk.identifier / Chunk.filename (and FileInfo.identifier / filename) into the upload path via FileUtils.generatePath, then pass the result to Files.write / Files.createFile without normalize() or a canonical-root check. A ../ sequence escapes the intended upload directory; any authenticated user who can reach /vue/uploader can write outside it. The code is unfixed as of main (2026-11-06).
~~~

### 过审三要素

- 根因句：identifier / filename are concatenated into the upload path without normalization or a canonical-root check.
- 影响句：write files outside the upload directory as an authenticated /vue/uploader user.
- 修复状态句：unfixed as of main (2026-11-06).

### 表单问题区固定答法

| 问题 | 答法 |
|---|---|
| 确认已阅读 CNA-LR 主页信息 | yes |
| CVE partner onboarding 注册组织 | 留空（个人报告者） |
| 是否已联系供应商要 CVE | no（已有公开 Issue #2） |
| 是否现在就在 CVE List 公开 | yes |
| Additional Information | 公开 Issue #2 已提，供 CNA 引用 |

### Tags

若厂商 7 天不回应，加 unsupported-when-assigned。

### 单 CNA 红线

uploadChunk1 and mergeFile share one root cause; one CVE, not two. Do not merge with WorkFlow SQLi.

## 提交前检查

- [ ] HEAD 仍是 973d777c3e02756749dab3b3399859a9fb79a44e
- [ ] 重查 UploaderController / FileUtils 仍无 normalize
- [ ] 不写实际绝对路径；不公开 payload
