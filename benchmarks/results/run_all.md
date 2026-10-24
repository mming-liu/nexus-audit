# nexus-audit 离线门禁计分板

生成时间：2026-10-24 10:38:18（--jobs 4）

| 门禁 | 结果 | 耗时 | 尾行 |
|---|---|---|---|
| 冒烟测试 [1]-[93] | PASS | 66.6s | CHAIN SMOKE TEST PASS ✔ |
| 争议登记核对 | PASS | 0.5s | ✔ 证据核对通过：4 条争议，全部能逐字对上源码 |
| 覆盖地板门禁 | PASS | 0.5s | 10 项地板全部达标 ✔ |
| OWASP 全量 | PASS | 4.7s |   规则层合计判定 1352 条 |
| java-sec-code | PASS | 6.6s | 明细已写入 C:\myFloders\git\nexus-audit\benchmarks\results\javase |
| Hello-Java-Sec | PASS | 1.3s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\helloja |
| JavaSecLab | PASS | 1.1s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\javasec |
| micro_service_seclab | PASS | 1.9s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\mssecla |
| newbee-mall | PASS | 5.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\newbeem |
| newbee-mall-api | PASS | 5.5s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\newbeem |
| vulpy (Python) | PASS | 1.1s | STRICT 门禁：通过 ✔（零误报 / 零静默放行 / 零退回） |
| smartbugs-curated (Solidity) | PASS | 1.2s | STRICT 门禁：通过 ✔（safe 零误报 / 零判反） |
| DeFiVulnLabs (Solidity 成对真值) | PASS | 1.5s | STRICT PASS ✔ （零误报 / 零判反 / 真值表全命中） |
| damn-vulnerable-defi (健壮性抽检) | PASS | 1.5s | SANITY PASS ✔ （切片 164 单元、判定面未爆炸、CEI 行序解析正常） |
| not-so-smart-contracts (Solidity) | PASS | 1.0s | STRICT PASS ✔ （零误报 / 零判反 / 真值表全命中） |
| RuoYi (Java 多模块) | PASS | 1.0s | STRICT PASS ✔ （零误报 / 零判反 / 跨模块穿透在线 / 注解语义在线） |
| pygoat (Python Flask labs) | PASS | 0.9s | STRICT PASS ✔ （作者指名 9/9 全 True / 零计划外 True / 覆盖在线） |
| eladmin-mp (MyBatis-Plus) | PASS | 3.3s | STRICT PASS ✔ （零误报 / 零判反 / @el.check 注解语义在线） |
| VAmPI (Connexion/OpenAPI) | PASS | 0.8s | STRICT 门禁：通过 ✔（零误报 / 零判反 / 零退回） |
| mall (生产级多模块对照) | PASS | 1.4s | STRICT 门禁：通过 ✔（登记全判对 / 全库零 True / 零退回） |
| WebGoat (教学关卡成对真值) | PASS | 5.1s | STRICT 门禁：通过 ✔（零误报 / 零判反 / 零退回） |

**21 PASS / 0 FAIL / 0 SKIP**
