# nexus-audit 全语言计分板（规则层·离线可复现）

生成时间：2026-10-23 08:41:28

| 靶场 | 单元 | 规则判定 | 判对 | 误报 | 判反 | 覆盖率 |
|---|---|---|---|---|---|---|
| smartbugs-curated (Solidity) | 641 | 175 | 175 | 0 | 0 | 27% |
| DeFiVulnLabs (Solidity) | 323 | 8 | 8 | 0 | 0 | 2% |
| not-so-smart-contracts (Solidity) | 208 | 7 | 7 | 0 | 0 | 3% |
| vulpy (Python) | 33 | 6 | 6 | 0 | 0 | 18% |
| RuoYi (Java 多模块) | 305 | 159 | 159 | 0 | 0 | 52% |
| pygoat (Python Flask labs) | 119 | 9 | 9 | 0 | 0 | 8% |
| eladmin-mp (MyBatis-Plus) | 65 | 53 | 53 | 0 | 0 | 82% |

**计分板靶场合计：误报 0 · 判反 0（A/B 方向错误 = 0）**

> 模型层数字（TPR/FPR）不进计分板：非确定性，离线不可复现。
> Java 教学靶场（OWASP/java-sec-code/Hello-Java-Sec/JavaSecLab/msseclab/newbee 双库）的 json 不产本表五字段，数字见各自脚本输出。
