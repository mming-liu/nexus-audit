# nexus-audit 离线门禁计分板

生成时间：2026-10-23 23:40:22

| 门禁 | 结果 | 耗时 | 尾行 |
|---|---|---|---|
| 冒烟测试 [1]-[79] | PASS | 89.9s | CHAIN SMOKE TEST PASS ✔ |
| 争议登记核对 | PASS | 0.5s | ✔ 证据核对通过：4 条争议，全部能逐字对上源码 |
| OWASP 全量 | PASS | 4.1s |   规则层合计判定 1352 条 |
| java-sec-code | PASS | 3.7s | 明细已写入 C:\myFloders\git\nexus-audit\benchmarks\results\javase |
| Hello-Java-Sec | PASS | 2.4s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\helloja |
| JavaSecLab | PASS | 6.8s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\javasec |
| micro_service_seclab | PASS | 0.9s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\mssecla |
| newbee-mall | PASS | 2.3s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\newbeem |
| newbee-mall-api | PASS | 2.6s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\newbeem |
| vulpy (Python) | PASS | 0.7s | STRICT 门禁：通过 ✔（零误报 / 零静默放行 / 零退回） |
| smartbugs-curated (Solidity) | PASS | 0.8s | STRICT 门禁：通过 ✔（safe 零误报 / 零判反） |
| DeFiVulnLabs (Solidity 成对真值) | PASS | 1.1s | STRICT PASS ✔ （零误报 / 零判反 / 真值表全命中） |
| damn-vulnerable-defi (健壮性抽检) | PASS | 1.0s | SANITY PASS ✔ （切片 164 单元、判定面未爆炸、CEI 行序解析正常） |
| not-so-smart-contracts (Solidity) | PASS | 0.7s | STRICT PASS ✔ （零误报 / 零判反 / 真值表全命中） |
| RuoYi (Java 多模块) | PASS | 15.3s | STRICT PASS ✔ （零误报 / 零判反 / 跨模块穿透在线 / 注解语义在线） |
| pygoat (Python Flask labs) | PASS | 0.7s | STRICT PASS ✔ （作者指名 9/9 全 True / 零计划外 True / 覆盖在线） |
| eladmin-mp (MyBatis-Plus) | PASS | 2.4s | STRICT PASS ✔ （零误报 / 零判反 / @el.check 注解语义在线） |
| VAmPI (Connexion/OpenAPI) | PASS | 0.6s | STRICT 门禁：通过 ✔（零误报 / 零判反 / 零退回） |
| mall (生产级多模块对照) | PASS | 13.1s | STRICT 门禁：通过 ✔（登记全判对 / 全库零 True / 零退回） |
| 覆盖地板门禁 | PASS | 0.5s | 9 项地板全部达标 ✔ |

**20 PASS / 0 FAIL / 0 SKIP**
