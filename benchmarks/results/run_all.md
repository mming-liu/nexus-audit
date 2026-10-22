# nexus-audit 离线门禁计分板

生成时间：2026-10-22 23:34:57（--jobs 4）

| 门禁 | 结果 | 耗时 | 尾行 |
|---|---|---|---|
| 冒烟测试 [1]-[73] | PASS | 47.2s |   OK  M25：pickle 无等价安全 API，不生成补丁: 0 |
| 争议登记核对 | PASS | 0.5s | ✔ 证据核对通过：4 条争议，全部能逐字对上源码 |
| OWASP 全量 | PASS | 3.7s |   规则层合计判定 1352 条 |
| java-sec-code | PASS | 3.9s | 明细已写入 C:\myFloders\git\nexus-audit\benchmarks\results\javase |
| Hello-Java-Sec | PASS | 2.3s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\helloja |
| JavaSecLab | PASS | 4.6s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\javasec |
| micro_service_seclab | PASS | 0.9s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\mssecla |
| newbee-mall | PASS | 2.3s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\newbeem |
| newbee-mall-api | PASS | 2.4s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\newbeem |
| vulpy (Python) | PASS | 0.9s | STRICT 门禁：通过 ✔（零误报 / 零静默放行 / 零退回） |
| smartbugs-curated (Solidity) | PASS | 0.9s | STRICT 门禁：通过 ✔（safe 零误报 / 零判反） |
| DeFiVulnLabs (Solidity 成对真值) | PASS | 1.3s | STRICT PASS ✔ （零误报 / 零判反 / 真值表全命中） |
| damn-vulnerable-defi (健壮性抽检) | PASS | 0.7s | SANITY PASS ✔ （切片 164 单元、判定面未爆炸、CEI 行序解析正常） |
| not-so-smart-contracts (Solidity) | PASS | 0.9s | STRICT PASS ✔ （零误报 / 零判反 / 真值表全命中） |
| RuoYi (Java 多模块) | PASS | 9.8s | STRICT PASS ✔ （零误报 / 零判反 / 跨模块穿透在线 / 注解语义在线） |
| pygoat (Python Flask labs) | PASS | 0.7s | STRICT PASS ✔ （作者指名 9/9 全 True / 零计划外 True / 覆盖在线） |

**16 PASS / 0 FAIL / 0 SKIP**
