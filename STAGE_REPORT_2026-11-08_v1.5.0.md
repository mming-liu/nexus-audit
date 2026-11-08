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
| Reserve CAN | POST /api/cve-id?amount=...&cve_year=...&short_name=... | 参数在 query string |
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

## 五、6 单全部有 CAN（2026-11-08）

| 单 | 标的 | CAN | 状态 |
|---|---|---|---|
| 1 | ruoyi-vue-pro | CAN-2026-2041058 | PUBLISHED（已有） |
| 2 | metasfresh | CAN-2026-2042689 | PUBLISHED |
| 3 | x-springboot | CAN-2026-2042693 | PUBLISHED |
| 4 | workflow-engine | CAN-2026-2042690 | PUBLISHED |
| 5 | network-drive | CAN-2026-2042691 | PUBLISHED |
| 6 | eladmin | CAN-2026-2042692 | PUBLISHED |

metasfresh / WorkFlow / Network / eladmin / x-springboot 均为：

- HTTP 200，state=PUBLISHED；
- 服务端 message：submission was successfully created（邮件通知后续 activity）；
- 响应落盘 benchmarks/results/cna_submissions/。

首次提交踩到 3 个契约细节，均已回写客户端：

1. reserve 参数在 query string，不在 JSON body
   （前端 post('cve-id', args) 的 args 是 query）；
2. cnaContainer 必须有 providerMetadata.orgId，orgId 从
   GET /api/org/{short_name} 的 UUID 取；
3. problemTypes[].descriptions[] 必须有 lang。

另修 submit_record：400 schema 错误不再被 PUT 重试掩盖；只有 404 /
CVE_RECORD_DNE 才回退 PUT。

## 六、Token 验证与安全

- 旧 token 探测 GET /api/me：HTTP 401 unauthorized，确认过期。
- 新 token 连续提交 5 单成功；token 不落盘、不写日志。
- 提交响应落盘目录已 gitignore。

## 七、当前状态

6 单全部有 CAN，等待 MITRE 审核/分配正式 CVE。后续只需查状态：

    python cli.py cve-submit --status CAN-2026-2041058 --token "<整行 login success>"

如果某单需要更新描述/版本范围：

    python cli.py cve-submit --target metasfresh --can CAN-2026-2042689 --submit --token "<line>"

完整自动提交结果、API 契约、6 个 CAN 与证据路径：

- [cve_submission_kit/CVE_AUTO_SUBMIT_2026-11-08.md](cve_submission_kit/CVE_AUTO_SUBMIT_2026-11-08.md)
