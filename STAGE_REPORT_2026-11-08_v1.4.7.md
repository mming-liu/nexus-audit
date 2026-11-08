# STAGE REPORT · v1.4.7（M353–M356：大单体识别、三大底座深扫）

> 日期：2026-11-08 ｜ 基线：v1.4.6（7864b3b）
> 结论：M353 修好 org-hunt 的工具库误杀与主仓排序；M354 深扫
> jeecg-boot / RuoYi-Vue-Plus / warm-flow / mybatis-flex，未产出新 A；
> M355 门禁 1,944 项全绿。第 6 单仍是 eladmin S3 upload。

## 一、M353：大单体主仓识别

### 1.1 发现的真问题

第二波 org-hunt 跳过了 jeecgboot/JeecgBoot，不是 min_units，而是
is_tool_lib 误杀：JeecgBoot 的 GitHub topics 同时带
cli / codegenerator / low-code / mcp，旧逻辑对
slug + description + topics 整体跑 _TOOL_LIB_RE，于是 48k 星主仓被当成
工具库丢掉。

修复：

- slug + description 命中工具词，仍直接丢；
- 仅 topics 命中工具词时，若同时存在 platform / admin / low-code /
  erp / business / system 等业务信号，则保留；
- driver / ComfyUI-plugin / HACS 等真工具仍被过滤（反向断言通过）。

### 1.2 排序与深度

org_hunt 新增 _repo_priority：

- 名称含 boot / admin / server / cloud / system / framework 的主仓优先；
- 同组按 stars、pushed_at 排序；
- 选中主仓时，max_roots 自动抬到 35，避免跨模块 Controller 被 20 截断。

修复后 jeecgboot 列表首位从 jeewx-boot 变为 **JeecgBoot**；第二轮实际
选中 jeecgboot/JeecgBoot。

## 二、M354：三大底座深扫

### 2.1 jeecgboot/JeecgBoot

- 组织 1 / 业务仓 1 / 实扫 1 / 根因 10 / A 0 / B 10；
- 10 条全部是 LOW_SEVERITY_LOG_INJECTION（CWE-117 日志伪造），
  被降噪为 B，不是 SQLi / 授权缺失；
- 导出、图表设计、自定义 SQL 接口本轮没有新的 A。

### 2.2 dromara/RuoYi-Vue-Plus

- 15 条根因 / A 0 / B 15；
- 14 条 DUPLICATE_ISSUE_OR_GHSA（FlwTaskController、SysConfigController
  等已有公开记录）；1 条 PATCHED_UPSTREAM（TestDemoEncrypt 已不在 HEAD）；
- 没有新的文件操作/动态数据源 A。

### 2.3 dromara/warm-flow

- 10 条根因 / 机器 A 7 / B 3；
- 7 条全部是 WarmFlowController 设计器接口的 authz；
- **不能按产品漏洞交单**：该仓是 Maven SDK / 类库，不是业务应用；
  controller 类注释明确写“设计器 Controller 可选择是否放行，放行可与
  业务系统共享权限”，鉴权由集成方负责；
- 3 条 B：1 条 DUPLICATE_ISSUE_OR_GHSA，2 条 UNKNOWN；
- 没有 WorkFlow-Engine 同类的 searchMapStr 动态 SQLi A。

### 2.4 dromara/mybatis-flex

- 1 条根因 / A 0 / B 1（UNKNOWN）；
- 数据权限层没有产出可交单的新 A。

### 2.5 结论

本轮 0 条新 A。第 6 单仍是 eladmin S3StorageController.uploadS3Storage；
第 7 单未出现。三大底座的高星不等于高漏洞密度：JeecgBoot 的切片主要是
低危日志注入，RuoYi-Vue-Plus 已被公开 Issue/GHSA 覆盖，warm-flow 的
authz 是 SDK 设计边界。

## 三、M355：门禁

- smoke_test_chains.py：**PASS，1,944 项**
- triage_fallbacks.py --check-floor：**16/16**
- cli.py doctor：**PASS（12 段全绿）**

新增 [321] 后的 M353 断言：

- topics 的 cli/codegenerator 不否掉低代码主仓；
- driver 仍按工具库过滤；
- boot 单体主仓排在普通工具仓前。

## 四、M356：下一步

1. 不再用 jeecgboot 这类 AI 低代码主仓堆 limit；下一轮换有明确
   Controller 层的行业后台（ERP/CRM/医疗/物流），并用 live-hunt 精确锁仓。
2. warm-flow 的 authz 只能作为集成方安全提示，不能当产品 CVE；若要做
   工作流 SQLi，应继续看 WorkFlow-Engine 同类 searchMapStr 拼接。
3. 第 4/5/6 单的 GitHub Issue 已于 2026-11-08 公开提交（见下节）；
   CVE 仍待你本人走 CNA/邮件流程。第 2/3 单待你本人走 CNA/邮件流程。

## 五、GitHub 披露记录（2026-11-08）

| 单 | 仓库 | Issue | 建议 CWE / 定级 |
|---|---|---|---|
| 4 | risesoft-y9/WorkFlow-Engine | https://github.com/risesoft-y9/WorkFlow-Engine/issues/4 | CWE-89 / PR:L / 8.8 |
| 5 | risesoft-y9/Network-Drive | https://github.com/risesoft-y9/Network-Drive/issues/2 | CWE-22 / PR:L / 8.1 |
| 6 | elunez/eladmin | https://github.com/elunez/eladmin/issues/926 | CWE-862 / PR:L / 6.5-8.1 |
| 3 | yzcheng90/x-springboot | https://github.com/yzcheng90/x-springboot/issues/47 | CWE-22/73 / PR:L / 7.2 |

未重复提交：metasfresh 已有 Issue #27079；ruoyi-vue-pro 已有 Issue #1328
且修复已合入；eladmin AliPay 已由 #903 / CVE-2026-77036 覆盖。

Issue 正文只放最小复现与修复建议，没有公开武器化 payload；CVE 提交时可直接
引用上表 URL。
