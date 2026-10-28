# 傻瓜式三步交单手册（Sentinel / log_injection）

> 模板版本：playbook-1.0 ｜ 事实源：live_hunt.json
> 本文**不是**漏洞成立的法律证明；提交前请人工复核版本影响面与可达性。
> 状态：ZERO_RECORD_FRESH ｜ HEAD：a3f40ba8e900c8489bd520274739f17235a7721c
> HEAD 提交日期：2026-05-27（154.2 天前）

## Step 1：点哪个网址

- GitHub 私密 Advisory（优先）：
  https://github.com/alibaba/Sentinel/security/advisories/new
- GitHub Issue（仓库未开启私密 Advisory 时）：
  https://github.com/alibaba/Sentinel/issues/new
- MITRE / CVE.org 申请表：
  https://www.cve.org/ReportRequest/ReportRequestForNonCNAs

## Step 2：GitHub 页面填什么

### Title

```
[LOG_INJECTION] ClusterAssignController.apiAssignSingleClusterServersOfApp in ClusterAssignController.java
```

### Description（直接复制）

```
The Sentinel repository at commit a3f40ba8e900c8489bd520274739f17235a7721c contains a log_injection issue in sentinel-dashboard/src/main/java/com/alibaba/csp/sentinel/dashboard/controller/cluster/ClusterAssignController.java (line 70), entry ClusterAssignController.apiAssignSingleClusterServersOfApp. The rule layer reports it as a deterministic P0 root cause (CWE-117). Source permalink: https://github.com/alibaba/Sentinel/blob/a3f40ba8e900c8489bd520274739f17235a7721c/sentinel-dashboard/src/main/java/com/alibaba/csp/sentinel/dashboard/controller/cluster/ClusterAssignController.java#L70. No verified automatic patch is included; a manual fix is required.

Repository: https://github.com/alibaba/Sentinel
Affected file: sentinel-dashboard/src/main/java/com/alibaba/csp/sentinel/dashboard/controller/cluster/ClusterAssignController.java:70
Entry point: ClusterAssignController.apiAssignSingleClusterServersOfApp
HEAD permalink: https://github.com/alibaba/Sentinel/blob/a3f40ba8e900c8489bd520274739f17235a7721c/sentinel-dashboard/src/main/java/com/alibaba/csp/sentinel/dashboard/controller/cluster/ClusterAssignController.java#L70
Affected routes: 1
CWE: CWE-117
Fix: manual patch required (no verified patch in this pack)
```

## Step 3：CVE.org 表单 6 个框

| 字段 | 预填值 |
|---|---|
| Vendor | alibaba |
| Product | Sentinel |
| Version affected | unknown, pending maintainer confirmation |
| Vulnerability Type | CWE-117 |
| Affected Component | sentinel-dashboard/src/main/java/com/alibaba/csp/sentinel/dashboard/controller/cluster/ClusterAssignController.java:70 |
| Suggested Description | The Sentinel repository at commit a3f40ba8e900c8489bd520274739f17235a7721c contains a log_injection issue in sentinel-dashboard/src/main/java/com/alibaba/csp/sentinel/dashboard/controller/cluster/ClusterAssignController.java (line 70), entry ClusterAssignController.apiAssignSingleClusterServersOfApp. The rule layer reports it as a deterministic P0 root cause (CWE-117). Source permalink: https://github.com/alibaba/Sentinel/blob/a3f40ba8e900c8489bd520274739f17235a7721c/sentinel-dashboard/src/main/java/com/alibaba/csp/sentinel/dashboard/controller/cluster/ClusterAssignController.java#L70. No verified automatic patch is included; a manual fix is required. |

## 提交前检查

- [ ] HEAD 仍是 a3f40ba8e900c8489bd520274739f17235a7721c（若已变化，重新跑 live-hunt）
- [ ] fix.patch 能在目标仓 git apply --check 通过
- [ ] 版本影响面已由维护者/README/tag 确认；否则保留 unknown, pending maintainer confirmation
- [ ] 不在公开 issue 里贴未修复细节，先走私密 Advisory
