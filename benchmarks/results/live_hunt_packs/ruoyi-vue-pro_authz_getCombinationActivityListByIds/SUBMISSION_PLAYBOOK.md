# 傻瓜式三步交单手册（ruoyi-vue-pro / authz）

> 模板版本：playbook-1.0 ｜ 事实源：live_hunt.json
> 本文**不是**漏洞成立的法律证明；提交前请人工复核版本影响面与可达性。
> 状态：ZERO_RECORD_FRESH ｜ HEAD：3ebbfb0c7694ea5154d045638674897f3dcea181
> HEAD 提交日期：2026-10-25（3.8 天前）

## Step 1：点哪个网址

- GitHub 私密 Advisory（优先）：
  https://github.com/YunaiV/ruoyi-vue-pro/security/advisories/new
- GitHub Issue（仓库未开启私密 Advisory 时）：
  https://github.com/YunaiV/ruoyi-vue-pro/issues/new
- MITRE / CVE.org 申请表：
  https://www.cve.org/ReportRequest/ReportRequestForNonCNAs

## Step 2：GitHub 页面填什么

### Title

```
[AUTHZ] CombinationActivityController.getCombinationActivityListByIds in CombinationActivityController.java
```

### Description（直接复制）

```
The ruoyi-vue-pro repository at commit 3ebbfb0c7694ea5154d045638674897f3dcea181 contains a authz issue in yudao-module-mall/yudao-module-promotion/src/main/java/cn/iocoder/yudao/module/promotion/controller/admin/combination/CombinationActivityController.java (line 93), entry CombinationActivityController.getCombinationActivityListByIds. The rule layer reports it as a deterministic P0 root cause (CWE-285). Source permalink: https://github.com/YunaiV/ruoyi-vue-pro/blob/3ebbfb0c7694ea5154d045638674897f3dcea181/yudao-module-mall/yudao-module-promotion/src/main/java/cn/iocoder/yudao/module/promotion/controller/admin/combination/CombinationActivityController.java#L93. No verified automatic patch is included; a manual fix is required.

Repository: https://github.com/YunaiV/ruoyi-vue-pro
Affected file: yudao-module-mall/yudao-module-promotion/src/main/java/cn/iocoder/yudao/module/promotion/controller/admin/combination/CombinationActivityController.java:93
Entry point: CombinationActivityController.getCombinationActivityListByIds
HEAD permalink: https://github.com/YunaiV/ruoyi-vue-pro/blob/3ebbfb0c7694ea5154d045638674897f3dcea181/yudao-module-mall/yudao-module-promotion/src/main/java/cn/iocoder/yudao/module/promotion/controller/admin/combination/CombinationActivityController.java#L93
Affected routes: 1
CWE: CWE-285
Fix: manual patch required (no verified patch in this pack)
```

## Step 3：CVE.org 表单 6 个框

| 字段 | 预填值 |
|---|---|
| Vendor | YunaiV |
| Product | ruoyi-vue-pro |
| Version affected | unknown, pending maintainer confirmation |
| Vulnerability Type | CWE-285 |
| Affected Component | yudao-module-mall/yudao-module-promotion/src/main/java/cn/iocoder/yudao/module/promotion/controller/admin/combination/CombinationActivityController.java:93 |
| Suggested Description | The ruoyi-vue-pro repository at commit 3ebbfb0c7694ea5154d045638674897f3dcea181 contains a authz issue in yudao-module-mall/yudao-module-promotion/src/main/java/cn/iocoder/yudao/module/promotion/controller/admin/combination/CombinationActivityController.java (line 93), entry CombinationActivityController.getCombinationActivityListByIds. The rule layer reports it as a deterministic P0 root cause (CWE-285). Source permalink: https://github.com/YunaiV/ruoyi-vue-pro/blob/3ebbfb0c7694ea5154d045638674897f3dcea181/yudao-module-mall/yudao-module-promotion/src/main/java/cn/iocoder/yudao/module/promotion/controller/admin/combination/CombinationActivityController.java#L93. No verified automatic patch is included; a manual fix is required. |

## 提交前检查

- [ ] HEAD 仍是 3ebbfb0c7694ea5154d045638674897f3dcea181（若已变化，重新跑 live-hunt）
- [ ] fix.patch 能在目标仓 git apply --check 通过
- [ ] 版本影响面已由维护者/README/tag 确认；否则保留 unknown, pending maintainer confirmation
- [ ] 不在公开 issue 里贴未修复细节，先走私密 Advisory
