# nexus-audit 离线门禁计分板

生成时间：2026-10-26 12:06:36（--jobs 4）

| 门禁 | 结果 | 耗时 | 尾行 |
|---|---|---|---|
| 冒烟测试 [1]-[250] | PASS | 258.0s | CHAIN SMOKE TEST PASS ✔（已执行 1503 项断言） |
| 争议登记核对 | PASS | 0.1s | ✔ 证据核对通过：4 条争议，全部能逐字对上源码 |
| 覆盖地板门禁 | PASS | 0.1s | 16 项地板全部达标 ✔ |
| 确定性重现（--check） | PASS | 0.1s | REPRO CHECK PASS ✔（sha256 ae2bc347471ec52e，50 仓根因/聚类/排序守恒） |
| 跨仓聚类一致性（--check） | PASS | 0.1s |   [OK] 多仓共现簇 15 ≥ 8 |
| OWASP 全量 | PASS | 4.0s |   规则层合计判定 1341 条 |
| java-sec-code | PASS | 2.5s | 明细已写入 C:\myFloders\git\nexus-audit\benchmarks\results\javase |
| Hello-Java-Sec | PASS | 0.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\helloja |
| JavaSecLab | PASS | 0.3s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\javasec |
| micro_service_seclab | PASS | 0.3s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\mssecla |
| newbee-mall | PASS | 1.9s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\newbeem |
| newbee-mall-api | PASS | 2.1s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\newbeem |
| vulpy (Python) | PASS | 0.2s | STRICT 门禁：通过 ✔（零误报 / 零静默放行 / 零退回） |
| smartbugs-curated (Solidity) | PASS | 0.5s | STRICT 门禁：通过 ✔（safe 零误报 / 零判反） |
| DeFiVulnLabs (Solidity 成对真值) | PASS | 0.6s | STRICT PASS ✔ （零误报 / 零判反 / 真值表全命中） |
| damn-vulnerable-defi (健壮性抽检) | PASS | 0.3s | SANITY PASS ✔ （切片 164 单元、判定面未爆炸、CEI 行序解析正常） |
| not-so-smart-contracts (Solidity) | PASS | 0.3s | STRICT PASS ✔ （零误报 / 零判反 / 真值表全命中） |
| RuoYi (Java 多模块) | PASS | 0.3s | STRICT PASS ✔ （零误报 / 零判反 / 跨模块穿透在线 / 注解语义在线） |
| pygoat (Python Flask labs) | PASS | 0.2s | STRICT PASS ✔ （作者指名 10/10 全 True / 零计划外 True / 覆盖在线） |
| eladmin-mp (MyBatis-Plus) | PASS | 2.0s | STRICT PASS ✔ （零误报 / 零判反 / @el.check 注解语义在线） |
| VAmPI (Connexion/OpenAPI) | PASS | 0.1s | STRICT 门禁：通过 ✔（零误报 / 零判反 / 零退回） |
| mall (生产级多模块对照) | PASS | 0.6s | STRICT 门禁：通过 ✔（登记全判对 / 全库零 True / 零退回） |
| WebGoat (教学关卡成对真值) | PASS | 3.5s | STRICT 门禁：通过 ✔（零误报 / 零判反 / 零退回） |
| My-Blog (野战实弹) | PASS | 0.7s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\myblog. |
| litemall (野战实弹) | PASS | 1.0s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\litemal |
| Employee-Management-System (Python 野战) | PASS | 0.1s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\flaskcr |
| compound-protocol (Solidity 生产协议) | PASS | 1.1s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\compoun |
| uniswap-v3-core (Solidity DEX) | PASS | 0.3s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\uniswap |
| compound-finance/comet (Solidity 0.8.x) | PASS | 0.8s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\comet.j |
| DjanGoat (Django urls.py 路由表) | PASS | 0.3s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\djangoa |
| waynboot-mall (Sa-Token 双端商城) | PASS | 7.1s |   | 1 条 `hardcoded_secret`（`WxController.jsSdkInit`） | 正则跨语句 |
| Uniswap V2 (整数互斥锁) | PASS | 0.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\uniswap |
| fastapi-realworld (多模块 APIRouter) | PASS | 0.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\fastapi |
| django-realworld (DRF 类视图) | PASS | 0.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\django_ |
| eladmin-JPA (双生对照) | PASS | 3.7s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\eladmin |
| MakerDAO dss (auth 映射守卫) | PASS | 0.3s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\makerda |
| flasky (多蓝图装饰器鉴权) | PASS | 0.3s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\flasky. |
| mall-tiny (JWT + MyBatis-Plus + CORS) | PASS | 0.8s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\mall_ti |
| OZ Upgradeable (initializer 语义) | PASS | 3.8s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\openzep |
| My-Blog-layui (双生对照) | PASS | 1.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\my_blog |
| Synthetix V3 (Diamond 代理) | PASS | 141.0s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\synthet |
| sushiswap-zapper (0.5.x 主网合约) | PASS | 0.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\sushiza |
| jeecg-boot (全局鉴权拦截器) | PASS | 26.4s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\jeecg.j |
| flaskr (Flask 官方教程应用) | PASS | 0.1s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\flaskr. |
| mall4j (主体链多模块商城) | PASS | 3.0s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\mall4j. |
| Aave V3 (借贷协议·逻辑库委托) | PASS | 1.1s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\aavev3. |
| OpenZeppelin (标准安全基元库) | PASS | 2.9s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\openzep |
| FastAPI (Python 异步真实模板) | PASS | 0.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\fastapi |
| halo (RouterFunction 函数式路由) | PASS | 0.8s | STRICT PASS ✔（0 注解入口 / RouterFunction 90 文件 / 0 True / 锚点 Tr |
| sanic (异步路由) | PASS | 0.6s | STRICT PASS ✔（15 入口 / 0 True / 锚点 False） |
| litestar (guards 路由) | PASS | 1.0s | STRICT PASS ✔（29 入口 / 0 True / guards 文件 19） |
| starlette (Route+requires) | PASS | 0.2s | STRICT PASS ✔（0 装饰器入口 / Route+requires 就位 / 0 True） |
| django-oauth-toolkit (OAuth2 授权服务器) | PASS | 0.6s | STRICT PASS ✔（18 入口 / 0 True / csrf 锚点 True） |
| flask-admin (后台管理) | PASS | 0.5s | STRICT PASS ✔（15 入口 / 0 True / csrf 锚点 True） |
| Sentinel (Dashboard 权限) | PASS | 6.6s | STRICT PASS ✔（56 入口 / 0 True / 锚点 True） |
| aave-v3-periphery (外围合约) | PASS | 0.6s | STRICT PASS ✔（139 入口 / 计划外 True 0 / 已知真阳性 1 / 补丁 True->False |
| morpho-blue (极简借贷核心) | PASS | 0.2s | STRICT PASS ✔（80 入口 / 0 True / 锚点 True） |
| flask-jwt-extended (装饰器语义) | PASS | 0.1s | STRICT PASS ✔（3 路由 / jwt_required+fresh 全 False / 0 True） |
| ruoyi-vue-pro (基础模块 RBAC) | PASS | 64.7s | STRICT PASS ✔（302 入口 / 0 True / PreAuthorize False / PermitA |
| solmate (requiresAuth 权限门) | PASS | 0.2s | STRICT PASS ✔（144 入口 / 0 True / Owned False） |
| spring-boot-demo (SecurityConfig 全量认证 + RBAC EL) | PASS | 2.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\springb |
| xxl-job (@XxlSso 角色门 + 资源组权限) | PASS | 3.4s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\xxl_job |
| flask-realworld (Flask-JWT-Extended 主体链) | PASS | 0.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\flask_r |
| v3-periphery (公开 swap + Multicall) | PASS | 0.4s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\v3_peri |
| kkFileView (zip_slip 真实解压) | PASS | 8.7s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\kkfilev |
| full-stack-fastapi-template (Annotated 依赖) | PASS | 0.2s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\fastapi |
| solady (Yul 权限门) | PASS | 5.1s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\solady. |
| apollo (自定义 Spring EL) | PASS | 6.1s | 结果写入 C:\myFloders\git\nexus-audit\benchmarks\results\apollo. |

**68 PASS / 0 FAIL / 0 SKIP**
