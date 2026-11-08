# STAGE REPORT · v1.5.0（M353–M356：MITRE CVE form API 直投客户端）

> 日期：2026-11-08 ｜ 基线：v1.4.7（a5d5239）
> 结论：从官方前端源码钉死 cveform-api 契约，完成
> core/context/mitre_cna.py + python cli.py cve-submit；6 个标的可离线生成
> CVE 5.2 JSON；冒烟 1,952 项全绿。未用过期 token 发任何写请求。

## 一、M353：钉死 cveform-api 契约

官方前端源码：mitre/mitre-cve-roles/cve-id-request/index.html +
static/cve5sw.js。

| 操作 | 方法与路径 | 说明 |
|---|---|---|
| Reserve CAN | POST /api/cve-id | body: amount, cve_year, short_name |
| Load record | GET /api/cve/{id} | 404 时回退 GET /api/cve-id/{id} |
| Submit create | POST /api/cve/{id}/cna | body: {cnaContainer: ...} |
| Submit update | PUT /api/cve/{id}/cna | 已有记录时更新 |

Base：https://cveform-api.mitre.org/api（__API_UUID__ 为空）。
Headers：Authorization: Bearer；CVE-API-ORG；CVE-API-USER；
CVE-API-KEY: redacted（Google 登录路径）。

前端提交的是 cnaContainer，不是完整 CVE_RECORD；x_CAN 在加载时会被
delete，服务端根据 CAN 元数据补 cveMetadata。客户端按此实现，避免盲猜。

## 二、M354：客户端能力

- parse_login_blob：整行 login success、纯 JSON、裸 JWT 三种输入；
  解出 email / sub / sid / iss / iat / exp / remaining_sec / expired；
  8 分钟窗口过期时 CLI 明确拒绝写操作。
- build_cna_record：CVE 5.2 + cnaContainer；含 descriptions、affected
  （vendor/product/versions/packageURL/programFiles/programRoutines）、
  problemTypes CWE、references、metrics CVSS 3.1；有 org UUID 时补
  providerMetadata。
- validate_cna_record：本地必填/类型预检，6 个标的均 0 错误。
- CveFormClient：reserve_can / load_record / status / submit_record /
  org_info；提交先 GET 判断 RESERVED 还是 PUBLISHED，再 POST/PUT；
  响应落盘 benchmarks/results/cna_submissions/（已 gitignore）。

## 三、M355：6 个内置标的

| key | repo | CWE | CVSS |
|---|---|---|---|
| ruoyi-vue-pro | YunaiV/ruoyi-vue-pro | CWE-862 | 8.1（已有 CAN-2026-2041058） |
| metasfresh | metasfresh/metasfresh | CWE-89 | 8.8 |
| x-springboot | yzcheng90/x-springboot | CWE-22 | 7.2 |
| workflow-engine | risesoft-y9/WorkFlow-Engine | CWE-89 | 8.8 |
| network-drive | risesoft-y9/Network-Drive | CWE-22 | 8.1 |
| eladmin | elunez/eladmin | CWE-862 | 6.5 |

## 四、M356：CLI 与门禁

- python cli.py cve-submit --list
- python cli.py cve-submit --target metasfresh --dry-run
- python cli.py cve-submit --status CAN-2026-2041058 --token "<line>"
- python cli.py cve-submit --target metasfresh --reserve-and-submit --token "<line>"

门禁：

- smoke_test_chains.py：PASS，1,952 项（[322] 覆盖解析、6 标的校验、
  mock reserve+submit 闭环）
- triage_fallbacks.py --check-floor：16/16
- cli.py doctor：PASS

## 五、Token 验证与安全

用用户提供的示例 token 探测 GET /api/me：HTTP 401 unauthorized，证明
base URL 与认证头可达；该 token 已过期（remaining -1043s），未发任何
reserve / submit 写请求。

Token 不落盘、不写日志；提交响应落盘目录已 gitignore。

## 六、拿到新 token 后只需一条命令

    python cli.py cve-submit --target metasfresh --reserve-and-submit --token "<整行 login success>"

先查第 1 单状态：

    python cli.py cve-submit --status CAN-2026-2041058 --token "<整行 login success>"
