# STAGE REPORT · v1.3.9（M311 → M312）

> 日期：2026-11-01 ｜ 基线：v1.3.8（3df9b63）
> 结论：选靶从"全局按 pushed_at 混排"改为"按语言分桶 + Round-Robin"，
> 富矿词池与组件库过滤同步升级。

## 一、09:00 那轮 A=0 的结构性原因

- 候选 14 个里 13 个 Python（django 词池当天爆量），Java 只剩 1 个
  spring-boot-admin，Solidity 0 个 —— 全局混排截断把 Java 全挤出了前 10；
- 14 个里 8 个是组件库/类型桩/Linter（django-stubs、djLint、django-auditlog、
  django-layout、django-bolt、strawberry、huey、spring-boot-admin）；
- DefectDojo / weblate / pretalx 这类 OWASP 旗舰与高星项目早被翻烂。

## 二、M311：跨语言配额 + 富矿词池

| 项 | 旧 | 新 |
| --- | --- | --- |
| 合并方式 | 全语言按 pushed_at 混排后截断 | 按语言分桶 → 桶内（有 Issues → 最近 push → stars）→ 按 java/python/solidity 轮流取 #1、#2… |
| Java 词池 | spring-boot/admin/cms/erp/crm/mall | mybatis-plus、sa-token、shiro、"spring-boot" admin、erp、crm、mall、oa、cms、mes、wms |
| Python 词池 | fastapi/django/flask/admin/backend/cms/saas/erp | fastapi admin、fastapi cms、django erp、django crm、django mall、flask admin、rag admin |
| 星级 / 页大小 | 300–30000，per_page = limit×2 | 150–10000，per_page = max(30, limit×3) |

新增 `_merge_round_robin()`：桶内去重排序后轮转交织，重复仓跨语言只保留一次。

## 三、M312：组件库过滤

- 词表补：stubs、djlint、linter、auditlog、graphql、huey、celery、defectdojo、spring-boot-admin；
- 结构规则：仓库名以 django-/flask-/fastapi-/spring- 开头，且描述含
  library/plugin/extension/middleware/reusable/package/adapter → 判组件库。

## 四、门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔ **1,783 项**（新增 [297] 10 项） |
| cli.py doctor | PASS（12 段全绿） |
| 单测抽查 | 轮转顺序 java→python→solidity；Python 爆量时前 4 名各半；6 个组件库全部剔除、ERP/框架本身不误杀 |

## 五、实盘重跑

TBD
