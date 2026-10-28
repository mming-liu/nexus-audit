# 傻瓜式三步交单手册（newbee-mall-api / xss）

> 模板版本：playbook-1.0 ｜ 事实源：live_hunt.json
> 本文**不是**漏洞成立的法律证明；提交前请人工复核版本影响面与可达性。
> 状态：ZERO_RECORD_FRESH ｜ HEAD：0879d5a1fac0c2a42c99eaf70d8b2f6e92aa05a4

## Step 1：点哪个网址

- GitHub 私密 Advisory（优先）：
  https://github.com/newbee-ltd/newbee-mall-api/security/advisories/new
- GitHub Issue（仓库未开启私密 Advisory 时）：
  https://github.com/newbee-ltd/newbee-mall-api/issues/new
- MITRE / CVE.org 申请表：
  https://www.cve.org/ReportRequest/ReportRequestForNonCNAs

## Step 2：GitHub 页面填什么

### Title

```
[XSS] NewBeeAdminUploadAPI.upload in NewBeeAdminUploadAPI.java
```

### Description（直接复制）

```
The newbee-mall-api repository at commit 0879d5a1fac0c2a42c99eaf70d8b2f6e92aa05a4 contains a xss issue in src/main/java/ltd/newbee/mall/api/admin/NewBeeAdminUploadAPI.java (line 49), entry NewBeeAdminUploadAPI.upload. The rule layer reports it as a deterministic P0 root cause (CWE-79). Source permalink: https://github.com/newbee-ltd/newbee-mall-api/blob/0879d5a1fac0c2a42c99eaf70d8b2f6e92aa05a4/src/main/java/ltd/newbee/mall/api/admin/NewBeeAdminUploadAPI.java#L49. No verified automatic patch is included; a manual fix is required.

Repository: https://github.com/newbee-ltd/newbee-mall-api
Affected file: src/main/java/ltd/newbee/mall/api/admin/NewBeeAdminUploadAPI.java:49
Entry point: NewBeeAdminUploadAPI.upload
HEAD permalink: https://github.com/newbee-ltd/newbee-mall-api/blob/0879d5a1fac0c2a42c99eaf70d8b2f6e92aa05a4/src/main/java/ltd/newbee/mall/api/admin/NewBeeAdminUploadAPI.java#L49
Affected routes: 1
CWE: CWE-79
Fix: manual patch required (no verified patch in this pack)
```

## Step 3：CVE.org 表单 6 个框

| 字段 | 预填值 |
|---|---|
| Vendor | newbee-ltd |
| Product | newbee-mall-api |
| Version affected | unknown, pending maintainer confirmation |
| Vulnerability Type | CWE-79 |
| Affected Component | src/main/java/ltd/newbee/mall/api/admin/NewBeeAdminUploadAPI.java:49 |
| Suggested Description | The newbee-mall-api repository at commit 0879d5a1fac0c2a42c99eaf70d8b2f6e92aa05a4 contains a xss issue in src/main/java/ltd/newbee/mall/api/admin/NewBeeAdminUploadAPI.java (line 49), entry NewBeeAdminUploadAPI.upload. The rule layer reports it as a deterministic P0 root cause (CWE-79). Source permalink: https://github.com/newbee-ltd/newbee-mall-api/blob/0879d5a1fac0c2a42c99eaf70d8b2f6e92aa05a4/src/main/java/ltd/newbee/mall/api/admin/NewBeeAdminUploadAPI.java#L49. No verified automatic patch is included; a manual fix is required. |

## 提交前检查

- [ ] HEAD 仍是 0879d5a1fac0c2a42c99eaf70d8b2f6e92aa05a4（若已变化，重新跑 live-hunt）
- [ ] fix.patch 能在目标仓 git apply --check 通过
- [ ] 版本影响面已由维护者/README/tag 确认；否则保留 unknown, pending maintainer confirmation
- [ ] 不在公开 issue 里贴未修复细节，先走私密 Advisory
