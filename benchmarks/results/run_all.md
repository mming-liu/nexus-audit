# nexus-audit 离线门禁计分板

生成时间：2026-10-25 11:56:02（--jobs 4）

| 门禁 | 结果 | 耗时 | 尾行 |
|---|---|---|---|
| 冒烟测试 [1]-[122] | PASS | 175.2s | CHAIN SMOKE TEST PASS ✔ |
| 争议登记核对 | PASS | 0.1s | ✔ 证据核对通过：4 条争议，全部能逐字对上源码 |
| 覆盖地板门禁 | PASS | 0.1s | 16 项地板全部达标 ✔ |
| OWASP 全量 | PASS | 759.3s |   规则层合计判定 1341 条 |
| java-sec-code | PASS | 8.8s | 明细已写入 C:\myFloders\git\nexus-audit\benchmarks\results\javase |
| Hello-Java-Sec | PASS | 2.9s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\helloja |
| JavaSecLab | PASS | 17.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\javasec |
| micro_service_seclab | PASS | 0.7s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\mssecla |
| newbee-mall | PASS | 2.1s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\newbeem |
| newbee-mall-api | PASS | 2.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\newbeem |
| vulpy (Python) | PASS | 0.2s | STRICT 门禁：通过 ✔（零误报 / 零静默放行 / 零退回） |
| smartbugs-curated (Solidity) | PASS | 0.6s | STRICT 门禁：通过 ✔（safe 零误报 / 零判反） |
| DeFiVulnLabs (Solidity 成对真值) | PASS | 0.7s | STRICT PASS ✔ （零误报 / 零判反 / 真值表全命中） |
| damn-vulnerable-defi (健壮性抽检) | PASS | 0.9s | SANITY PASS ✔ （切片 164 单元、判定面未爆炸、CEI 行序解析正常） |
| not-so-smart-contracts (Solidity) | PASS | 0.4s | STRICT PASS ✔ （零误报 / 零判反 / 真值表全命中） |
| RuoYi (Java 多模块) | PASS | 0.3s | STRICT PASS ✔ （零误报 / 零判反 / 跨模块穿透在线 / 注解语义在线） |
| pygoat (Python Flask labs) | PASS | 0.3s | STRICT PASS ✔ （作者指名 10/10 全 True / 零计划外 True / 覆盖在线） |
| eladmin-mp (MyBatis-Plus) | PASS | 2.4s | STRICT PASS ✔ （零误报 / 零判反 / @el.check 注解语义在线） |
| VAmPI (Connexion/OpenAPI) | PASS | 0.2s | STRICT 门禁：通过 ✔（零误报 / 零判反 / 零退回） |
| mall (生产级多模块对照) | PASS | 0.7s | STRICT 门禁：通过 ✔（登记全判对 / 全库零 True / 零退回） |
| WebGoat (教学关卡成对真值) | PASS | 9.3s | STRICT 门禁：通过 ✔（零误报 / 零判反 / 零退回） |
| My-Blog (野战实弹) | PASS | 0.9s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\myblog. |
| litemall (野战实弹) | PASS | 1.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\litemal |
| Employee-Management-System (Python 野战) | PASS | 0.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\flaskcr |
| compound-protocol (Solidity 生产协议) | PASS | 1.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\compoun |
| uniswap-v3-core (Solidity DEX) | PASS | 0.3s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\uniswap |
| compound-finance/comet (Solidity 0.8.x) | PASS | 1.3s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\comet.j |
| DjanGoat (Django urls.py 路由表) | PASS | 0.4s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\djangoa |
| waynboot-mall (Sa-Token 双端商城) | PASS | 30.7s |   | 1 条 `hardcoded_secret`（`WxController.jsSdkInit`） | 正则跨语句 |
| Synthetix V3 (Diamond 代理) | PASS | 311.5s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\synthet |
| sushiswap-zapper (0.5.x 主网合约) | PASS | 0.3s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\sushiza |
| jeecg-boot (全局鉴权拦截器) | PASS | 71.1s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\jeecg.j |
| flaskr (Flask 官方教程应用) | PASS | 0.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\flaskr. |
| mall4j (主体链多模块商城) | PASS | 3.9s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\mall4j. |
| Aave V3 (借贷协议·逻辑库委托) | PASS | 1.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\aavev3. |
| OpenZeppelin (标准安全基元库) | PASS | 4.8s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\openzep |
| FastAPI (Python 异步真实模板) | PASS | 0.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\fastapi |

**37 PASS / 0 FAIL / 0 SKIP**
