# nexus-audit 全语言计分板（规则层·离线可复现）

生成时间：2026-10-25 00:26:20

| 靶场 | 单元 | 规则判定 | 判对 | 误报 | 判反 | 覆盖率 |
|---|---|---|---|---|---|---|
| smartbugs-curated (Solidity) | 680 | 205 | 205 | 0 | 0 | 30% |
| DeFiVulnLabs (Solidity) | 314 | 9 | 9 | 0 | 0 | 3% |
| not-so-smart-contracts (Solidity) | 204 | 7 | 7 | 0 | 0 | 3% |
| vulpy (Python) | 33 | 6 | 6 | 0 | 0 | 18% |
| RuoYi (Java 多模块) | 305 | 159 | 159 | 0 | 0 | 52% |
| pygoat (Python Flask labs) | 129 | 10 | 10 | 0 | 0 | 8% |
| eladmin-mp (MyBatis-Plus) | 65 | 53 | 53 | 0 | 0 | 82% |
| VAmPI (Connexion/OpenAPI) | 14 | 7 | 7 | 0 | 0 | 50% |
| mall (生产级多模块对照) | 246 | 16 | 16 | 0 | 0 | 7% |
| WebGoat (教学关卡成对真值) | 179 | 6 | 6 | 0 | 0 | 3% |
| compound-protocol (Solidity 生产协议) | 450 | 444 | 444 | 0 | 0 | 99% |
| uniswap-v3-core (Solidity DEX) | 67 | 66 | 66 | 0 | 0 | 99% |
| FastAPI (Python 异步真实模板) | 9 | 9 | 9 | 0 | 0 | 100% |
| compound-finance/comet (Solidity 0.8.x) | 435 | 432 | 432 | 0 | 0 | 99% |
| DjanGoat (Django urls.py 路由表) | 36 | 12 | 12 | 0 | 0 | 33% |

**计分板靶场合计：误报 0 · 判反 0（A/B 方向错误 = 0）**

> 模型层数字（TPR/FPR）不进计分板：非确定性，离线不可复现。
> Java 教学靶场（OWASP/java-sec-code/Hello-Java-Sec/JavaSecLab/msseclab/newbee 双库）的 json 不产本表五字段，数字见各自脚本输出。
