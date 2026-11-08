# CVE 自动提交结果 · 2026-11-08

> 目标：用 MITRE CVE form API 直投，替代网页手填。
> 实现：core/context/mitre_cna.py + python cli.py cve-submit（v1.5.0）。
> 结论：6 单全部有 CAN，均为 PUBLISHED；等待 MITRE 审核分配正式 CVE。

## 一、6 单结果

| 单 | 标的 | 仓库 | CWE | CAN | 状态 |
|---|---|---|---|---|---|
| 1 | ruoyi-vue-pro | YunaiV/ruoyi-vue-pro | CWE-862 | CAN-2026-2041058 | PUBLISHED（已有） |
| 2 | metasfresh | metasfresh/metasfresh | CWE-89 | CAN-2026-2042689 | PUBLISHED |
| 3 | x-springboot | yzcheng90/x-springboot | CWE-22/73 | CAN-2026-2042693 | PUBLISHED |
| 4 | workflow-engine | risesoft-y9/WorkFlow-Engine | CWE-89 | CAN-2026-2042690 | PUBLISHED |
| 5 | network-drive | risesoft-y9/Network-Drive | CWE-22 | CAN-2026-2042691 | PUBLISHED |
| 6 | eladmin | elunez/eladmin | CWE-862 | CAN-2026-2042692 | PUBLISHED |

CAN 是预留/跟踪号，不是最终 CVE；MITRE 审核后会另行分配 CVE-2026-xxxxx。

## 二、API 契约（从官方前端源码提取）

Base：https://cveform-api.mitre.org/api

| 操作 | 请求 |
|---|---|
| Reserve CAN | POST /cve-id?amount=1&cve_year=2026&short_name=... |
| Load record | GET /cve/{id}；404 回退 GET /cve-id/{id} |
| Submit create | POST /cve/{id}/cna，body {"cnaContainer": ...} |
| Submit update | PUT /cve/{id}/cna |

Headers：Authorization: Bearer + CVE-API-ORG / CVE-API-USER /
CVE-API-KEY: redacted。

## 三、实际踩到的 3 个契约点

1. Reserve 参数在 query string，不是 JSON body。
2. cnaContainer 必须有 providerMetadata.orgId（从
   GET /api/org/{short_name} 的 UUID 取）。
3. problemTypes[].descriptions[] 必须有 lang。

另：400 schema 错误不能靠 PUT 重试掩盖；只有 404 / CVE_RECORD_DNE
才回退 PUT。

## 四、命令

    python cli.py cve-submit --list
    python cli.py cve-submit --target metasfresh --dry-run
    python cli.py cve-submit --target metasfresh --reserve-and-submit --token "<login line>"
    python cli.py cve-submit --status CAN-2026-2041058 --token "<login line>"

## 五、证据

提交响应落盘（已 gitignore）：

- benchmarks/results/cna_submissions/CAN-2026-2042689_20261108T100342Z.json
- benchmarks/results/cna_submissions/CAN-2026-2042690_20261108T104746Z.json
- benchmarks/results/cna_submissions/CAN-2026-2042691_20261108T104839Z.json
- benchmarks/results/cna_submissions/CAN-2026-2042692_20261108T104923Z.json
- benchmarks/results/cna_submissions/CAN-2026-2042693_20261108T105025Z.json

## 六、后续

- 等待 MITRE 邮件/审核；第 1 单已等待约 11 天，1–3 周正常。
- 满 3 周仍无 CVE，可用 CVE 表单 Other 类型 follow-up，附 CAN 与 GitHub Issue。
- 不要重复提交同一漏洞，避免重复 CAN。
- refresh token（rt）会轮换且 reuse 会撤销会话；自动刷新需一次未使用的 rt，
  否则继续用 8 分钟 access_token 更稳。
