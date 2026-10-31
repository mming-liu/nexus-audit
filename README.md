# nexus-audit — AI 自动化漏洞挖掘工程框架

按《AI 自动化漏洞挖掘：商业化与代码落地完整执行计划》初始化的四层解耦工程骨架。

当前覆盖 **Java / Python / Solidity** 三条赛道：规则层先做确定性判定（编译器/VM
能证明的事实不交给模型），模型只接手规则判不了的部分；**21 个真实外部靶场**全部接
`--strict` 离线门禁，`pre-push` 与 `run_all.py`（68 项）各有一道（见
[多语言靶场](#多语言靶场21-个仓库全部离线门禁)）。

开工前可跑只读自检：`python cli.py doctor` —— 依赖就位 / 40 类规则注册表
verdict 路由全覆盖 / 缓存指纹算法稳定 / 35 类补丁器就位 / PoC 合成器三语言自检 /
覆盖地板达标 / SCOREBOARD 与现算结果同步 / 正则卫生零死正则 / 交单四件套完备 /
能力矩阵与补丁注册表双向恒等 / matrix --check 的 CWE+CVSS 全覆盖 / 跨次运行确定性重现，十二段报告，exit 0 即全部就绪。

> 野战口径（`benchmarks/results/wild_hunt.json`）：**50 个真实开源仓库 /
> 15,800 个入口 / 208 个独立根因 / 126 个跨仓簇（15 个多仓共现）**。

## v1.2 双模式（M267 → M280）

- **活水首杀**：`python cli.py live-hunt owner/repo` —— 拉远端默认分支 HEAD →
  **HEAD 提交年龄硬门禁（默认 180 天，超龄直接 `STALE_REPO` 进板块 B）** →
  `verify_unit_alive_on_head()` 存活校验 → NVD / CIRCL / GitHub Advisory / Issue
  四态查重 → 只把 `ZERO_RECORD_FRESH` 放进 `LIVE_HUNT_REPORT.md` 板块 A；
  每个 FRESH 包生成 `SUBMISSION_PLAYBOOK.md`（Step 1/2/3 零占位符）。
  板块 A 每行都带 `HEAD 提交日期`，一眼可验是不是 2026 活仓；
  **Controller 没写 `@PreAuthorize` 不等于无鉴权**——`authz_guard.py`
  会核 `ServiceImpl` 上的 `@CrmPermission` / `@PreAuthorize` /
  `@SaCheckPermission` / 方法体 `hasPermission()`，命中即判 `service_guard` 进 B。
- **客户离线交付**：`python cli.py client-audit <dir|zip|file>` —— 默认 100%
  离线，生成 `01_EXECUTIVE_SUMMARY.md` / `02_DETAILED_AUDIT_REPORT.md` /
  `03_PATCH_BUNDLE/` / `04_REGRESSION_TESTS/` / `05_RETEST_VERIFICATION.md`。
- **单文件/片段直扫**：`python cli.py scan --snippet Foo.java` 或
  `... --stdin --lang python`；缺全局装配时 `authz/cors` 只进 NEEDS_HUMAN，
  其余规则照跑并验证补丁 `True → False`。
- 计费边界：`LLM_ALLOW_PAID_FALLBACK` 默认 0，Tier-1 免费全灭时只保留
  待复核队列，不静默降级付费。

## v1.3 全自动巡猎（M285 → M292）

- **每日自动巡猎**：`python cli.py daily-hunt --languages java,python,solidity --days 14 --limit 10 --evict-cache`。
  `target_scout.py` 按 `pushed:>{近 14 天} stars:300..30000 archived:false fork:false`
  抓 Java / Python / Solidity 新仓，剔除 demo / tutorial / ctf / interview 教学仓，
  优先保留开启 Issues 的仓；`daily_hunt_state.json` 记录 `last_scanned_sha` 与
  `exported_roots`：同 HEAD 直接 0.1 秒跳过，只报“新引入或尚未导出”的
  `ZERO_RECORD_FRESH` 根因；`--evict-cache` 提取完代码行证据即删
  `.cache/upstream/<repo>`，连续挂机一年也不会撑爆磁盘。
- **陌生野仓零噪音（板块 A 提纯）**：`wild_noise.py` 把 `/app-api/`、`/public/`
  下的 `get*List` / `get*Page` 公开只读接口（`PUBLIC_READONLY_ENDPOINT`）与
  `DemoController`（`DEMO_CONTROLLER`）压进板块 B；反向对 authz 提拔
  “同文件其它写接口都带 `@PreAuthorize` / `@RequiresPermissions`、唯独当前写接口
  漏加”的高置信度真洞（`AUTHZ_SIBLING_GUARD`，板块 A 置顶并标注置信度）。
- **售前免费试扫预览单**：`python cli.py client-audit <dir|zip|file> --presale-preview`
  —— 只出一页纸 `00_PRESALE_PREVIEW.md` + 管理层摘要，不生成补丁 / PoC / 复测。
- **调度交给 harness，不写进仓库**：不生成 `.github/workflows/nexus-daily-hunt.yml`，
  也不注册 Windows 计划任务（不出现 `scripts/register_daily_hunt_task.ps1`）。
  每天 09:00 由 harness 的定时任务把上面那条 `daily-hunt` 命令投给执行终端，
  跑完直接看根目录 `LIVE_HUNT_REPORT.md` 的「今日巡猎」与板块 A。

### v1.3.1 靶向制导（M293 → M296）

- **抓仓不再裸搜**：按语言轮询业务限定词（Java：`spring-boot/admin/cms/erp/crm/mall`，
  Python：`fastapi/django/flask/admin/backend/cms/saas/erp`，Solidity：`vault/staking/lending/swap`），
  并剔除 `driver/sdk/plugin/sphinx/cli/desktop/eval` 纯工具库；克隆后 `total_units == 0`
  的纯库标 `ZERO_ENTRY_LIB` 顺延，**不占当天 10 个名额**。
- **本地控制通道识别**：命中 `AF_UNIX` + `SO_PEERCRED`/`LOCAL_PEERCRED`/`socket_path`
  的接口标 `LOCAL_UNIX_SOCKET_SERVER` 进板块 B（ssh-agent / docker.sock 同类，
  设计上不可从网络到达）。
- **Python 兄弟守卫**：`Depends(get_current_*)` / `Security(...)` / `@login_required` /
  `@jwt_required` / `IsAuthenticated` 与 Java 注解同权；野仓模式下没有 HIGH 反差、
  又不在 `/admin` 的裸 authz 一律标 `UNVERIFIED_WILD_AUTHZ` 进 B。
- **缓存清理进 `finally`**：扫描失败/超时也删 `.cache/upstream/<repo>`；新增
  `--repo-timeout`（默认 900s）单仓软超时。

### v1.3.2 语言闸门（M297 → M298）

- `_looks_solidity()` 先排除 Python 切片（有 `def`、无 `pragma solidity`）：
  Solidity 专有类目不再落到 `.py` 入口；
- `wild_noise` 新增 `RULE_LANGUAGE_MISMATCH`：`reentrancy` / `unchecked_low_level_calls` /
  `tx_origin` / `delegatecall_untrusted` 出现在非 `.sol` 文件 → 板块 B；
- Python 业务限定词把 `panel` 换成 `cms` / `saas` / `erp`（实测 `panel` 只捞到桌面 UI）。
- **API 预算**：未配 `GITHUB_TOKEN` 时 GitHub core 限额 60 次/小时，建议每日跑
  `--max-roots 5`（每仓最多复核 5 条根因）；配 token 后可放开。
### v1.3.4 Python SQLi 收口（M301 → M303）

- **`text(...)` 包装剥开看内层**：`conn.execute(text("SELECT 1"))` 判安全，
  `text(f"...{name}")` 仍判注入（SQLAlchemy 的 `text()` 只是"这是 SQL 文本"的标记）；
- **ORM 语句对象不算 SQL 文本**：`stmt = select(Model).where(...)` 后再
  `session.execute(stmt)` 判安全（`sql_delete/sql_insert/sql_update` 同）；
- **裸标识符只认真形参**：旧实现"入口区域找不到赋值就 return True"，把
  `select(ListingMonitorTask)` 的模型类名当成客户端可控值；现在按 sink 所在
  函数找局部赋值，找不到时只认 `def` 的形参（排除 self/cls/db/session/conn/file
  与全大写常量），其余返回 None；
- **跨跳归属**：sink 在 Hop 段、但入口根本没调用那个辅助函数 → 不进证据链
  （`upload_image` 把同模块别的 service 的 `session.execute` 带进来，就是这样误报的）；
- **无参入口守卫**：入口既没有请求形参也不读 `request` → 直接判安全；
- **`NO_SQL_SINK` 兜底**：Python sqli 但入口文件没有任何 SQL 执行语句 → 板块 B；
  `target_scout` 工具词补 `testcontainers`。

### v1.3.3 冷却期免克隆（M299 → M300）

- **克隆前 7 天冷却期**：`daily_hunt.py` 遍历 `scout_daily` 返回的**完整候选池**
  （不是先 `items[:limit]` 截断），在 `sync_fn(slug)` 之前先看账本
  `last_scanned_at`：距上次扫描不足 `--cooldown-days`（默认 7 天）的仓，
  无论远端是否又推了新 Commit，直接 0 秒记 `SKIPPED (cooldown_7d)` 并顺延，
  直到真正扫满 `--limit` 个**近 7 天没碰过**的新仓。`--cooldown-days 0` 关闭。
- **开发工具过滤词扩充**：`target_scout.py` 的非业务黑名单补入
  `generator/codegen/datamodel/telemetry/observability/logfire/spring-tools/citrus/test-framework/testing-framework`
  与 `ide-/vscode-/intellij-/eclipse-` 前缀，把 10 个实扫名额留给真正的
  ERP / CMS / CRM / 商城 / AI 业务后台与 DeFi 协议。
- **A=0 只刷新不落库**：当日板块 A 为 0 时不把空报告提交进 Git（状态记忆在
  `daily_hunt_state.json`），历史有效视图不被空快照覆盖。

## 目录结构

```text
nexus-audit/
├── cli.py                           # 命令行入口与 GitHub Action CI/CD 触发入口
├── config/
│   ├── settings.yaml                # 大小模型路由配置 (Qwen3-Coder 初筛 + DeepSeek-R1 复核)
│   └── rules/                       # 自定义 Semgrep 路由规则与 Slither 敏感函数过滤器
├── core/
│   ├── models.py                    # 统一数据契约：CodeUnit, CallEdge, VulnHypothesis, PoCResult
│   ├── slicer/                      # 第1层：代码切片与调用图提取
│   │   ├── web_treesitter.py        # Tree-sitter 提取 Web API 路由与参数（借鉴 vulnhuntr）
│   │   ├── web_codeql_bridge.py     # CodeQL 污点流 Source/Sink 桥接器（借鉴 IRIS）
│   │   └── web3_slither.py          # Slither API 提取状态修改函数与修饰符（借鉴 GPTScan）
│   ├── context/                     # 第2层：按需跨文件上下文检索
│   │   ├── symbol_indexer.py        # 全局符号表索引
│   │   └── tool_handlers.py         # get_symbol_code / find_middleware 工具实现
│   ├── agents/                      # 第3层：双阶段对抗式推理与状态机
│   │   ├── router.py                # 统一异步客户端（OpenAI / DeepSeek / vLLM）
│   │   ├── scenario_matcher.py      # GPTScan 式 Scenario + Property 两步法
│   │   ├── skeptic_reviewer.py      # 反方挑刺 Agent
│   │   └── state_parser.py          # PentestGPT 式 Reasoning-Generation-Parsing 状态机
│   └── sandbox/                     # 第4层：动态沙箱实证与自动补丁
│       ├── web_docker_verifier.py   # 双测试账号 HTTP 越权重放与响应差异对比
│       ├── web3_foundry_runner.py   # Foundry 测试合约生成与 forge test（借鉴 Buttercup / OSS-Fuzz-Gen）
│       └── patch_generator.py       # 修复验证闭环生成 Git Diff 安全补丁
├── prompts/                         # 外部化 YAML 提示词模板（防御合规视角）
├── benchmarks/                      # 自动化回归测试与误报率跑分脚本
└── reference_repos/                 # 标杆开源项目参考（vulnhuntr / GPTScan 等，见 README）
```

| 文件 | 职责 |
|---|---|
| `core/slicer/java_servlet.py` | Servlet / Spring MVC / JAX-RS 入口切片，含跨文件辅助方法与配置取值回填 |
| `core/context/config_resolver.py` | 解析 .properties/.yaml/.json，把代码里引用的配置键回填进切片 |
| `core/context/java_impl_resolver.py` | MyBatis 注解/XML、接口实现体的跨文件证据（`#{}` vs `${}` 的真值在这里） |
| `core/context/taint_chain.py` | 跨路由串接：按介质+键名把「写入点」与「读取点」配对，存储型 XSS 靠它判定 |
| `core/agents/vuln_categories.py` | 40 类漏洞的 Scenario/Property 定义（11 类 OWASP + Java 生态 + Python Web + Solidity 链上 + 凭证/JWT + 上传/签名重放 + NoSQL/日志注入 + ERC20/预言机 + CSRF/正则 DoS + JNDI/文件删除） |
| `core/agents/rule_detectors.py` | 客观事实的确定性判定（40 类判据入口，先于 LLM 执行） |
| `benchmarks/benchmark_owasp.py` | OWASP Benchmark 跑分（TPR/FPR/Score，含断点续跑与误差归因） |
| `benchmarks/benchmark_javaseccode.py` | 真实项目（java-sec-code）评测，真值取自路由命名 + 作者注释 |
| `benchmarks/benchmark_vulpy.py` | Python Web 靶场（bad/good 成对真值），`--strict` 零退回门禁 |
| `benchmarks/benchmark_smartbugs.py` | Solidity 靶场（官方行号真值），`--scope all` 出模型 TPR/FPR |
| `benchmarks/benchmark_defivulnlabs.py` | Solidity 成对 vuln/fixed 真值（0.8.x），真值表按行号匹配防漂移 |
| `benchmarks/run_all.py` | 一键跑全部离线门禁，输出 Markdown 计分板 |
| `benchmarks/export_disputes.py` | 争议登记核对：每条口径分歧的证据必须逐字对上源码 |
| `benchmarks/check_stability.py` | 判定稳定性复测：同一输入连问 N 次，测抖动率 |
| `benchmarks/smoke_test_chains.py` | 判据链路断言 `[1]`-`[170]`（不调模型，秒级） |
| `benchmarks/ab_votes.py` | 采样策略一致性 A/B：两种策略各跑 2 轮，比两轮之间的翻转数 |
| `benchmarks/offline_baseline.py` | 对照组：纯 sink 关键词匹配 |

## OWASP Benchmark 跑分

```bash
# 全量 11 类，每类采样 40 条（真/假各半）
python benchmarks/benchmark_owasp.py --per-category 40 --concurrency 6

# 对照组（不调 LLM）
python benchmarks/benchmark_owasp.py --offline --per-category 40

# 只看某几类，或关闭确定性规则对比 LLM 真实能力
python benchmarks/benchmark_owasp.py --categories sqli,xss --no-rules
```

口径：`Score = TPR − FPR`（OWASP 官方）。调用失败的样本会被标记并剔除，
不计入分数 —— 否则限流会被伪装成极低的误报率。

## 野战模式：一键扫描未知仓库（M58–M84）

```bash
# 野战一键：全类目规则普查 + 根因折叠 + 确定性补丁 + PoC + 披露草稿 + 四类产物
python cli.py scan <目标仓库> --auto --fix --emit-poc poc_out \
    --advisory-dir advisories --graph --sarif report.sarif --html report.html

# 增量 CI：只报基线之后的新增根因（存量技术债不刷屏）
python cli.py scan <目标仓库> --auto --baseline baseline.sarif
```

工作方式（两级漏斗，规则先行、模型兜底）：
- 第一级：按语言自动遍历全部规则类目（Java/Python 走 Web 类目全集，
  Solidity 走合约 4 类目）。规则判 True 直接归 **P0 [Confirmed]**（不调
  模型），判 False 静默排除；
- **根因折叠（M71）**：CORS 等全局装配证据相同的 P0 按配置体哈希归并为
  一个独立根因，同时保留 `p0_route_level_hits` 与
  `p0_unique_root_causes`；报告/HTML/SARIF 只出根因卡，标注受影响路由数；
- 第二级：规则退 None 的对用"外部输入行 + 敏感 Sink 行"静态事实门控 ——
  无事实（纯计算函数等）直接过滤，真有 Sink 的才进模型复核队列
  （实测过滤率 100%，毫秒级/单元）；
- **第 16 类补丁（M75）**：全局 CORS 通配 + 凭据 → 固定白名单，一条配置
  补丁消解整组继承路由；
- **状态互斥锁（M79）**：Solidity 自定义 `modifier lock()`（前检 + 加锁 +
  `_;` + 解锁）按结构识别为安全，Uniswap V3 67 个生产入口 0 误报；
- **JWT 验签（M81/M82）**：`jwt_weakness` 命中 `alg=none` / 关验签 /
  `parseClaimsJwt`；第 22 类补丁器强制验签并重切自检；
- **CVSS 3.1（M83）**：GHSA/SARIF/HTML 统一输出标准向量、浮点分值与
  `security-severity`（GitHub Code Scanning 原生徽章）；
- **增量基线（M84）**：`--baseline prev.sarif` 抑制存量根因，只报本次净增；
- **披露草稿（M77）**：`--advisory-dir` 按独立根因生成 GHSA 草稿，含
  Affected Component / CWE / CVSS / Mermaid / PoC / Verified Patch；
- 报告固定按 **P0 [Confirmed] → P1 [High-Confidence 模型双引证] →
  P2 [Review-Needed 存疑候选]** 三档渲染（Markdown 分区 / HTML 折叠
  卡片 / SARIF `properties.priority`），HTML 为零外部依赖单文件。

**二十五个**真实开源项目（6,868 个入口，Java 11 + Python 6 + Solidity 8）的实弹数据与逐条源码复核见
[`WILD_HUNT_REPORT.md`](WILD_HUNT_REPORT.md)；复现脚本
`benchmarks/wild_hunt.py`（所有数字落盘 `benchmarks/results/wild_hunt.json`）。

## 多语言靶场：47 项离线门禁（44 个靶场/校验 + 冒烟 / 争议 / 地板 / 聚类对账）

```bash
# 一键跑全部（不调模型，约 1 分钟；任一靶场 strict 失败即退出非零）
python benchmarks/run_all.py --offline

# 单个靶场（模型层默认关闭，--offline 是门禁用的显式口径）
python benchmarks/benchmark_smartbugs.py --strict --offline
python benchmarks/benchmark_defivulnlabs.py --strict --offline
python benchmarks/benchmark_vulpy.py --strict
```

| 语言 | 靶场 | 真值来源 | 门禁 |
|---|---|---|---|
| Java | OWASP Benchmark（2740 例） | 官方 `expectedresults` | A=0 / B=0 |
| Java | java-sec-code / Hello-Java-Sec / JavaSecLab / micro_service_seclab | 路由命名 + 作者注释 | `--strict` |
| Java | newbee-mall / newbee-mall-api | 路由 + 实体/签名 | 穿透基线 |
| Java | mall（Spring Boot 电商） | 作者指名 + MBG `Example` 参数化机制 | `--strict` 全库零 True |
| Java | RuoYi | `dataScope` 切面口径 | `--strict` |
| Python | vulpy（bad/ vs good/） | **成对代码 diff** | 零误报 / 零静默放行 / 零退回 |
| Python | pygoat | 20 lab 真值表 | `--strict` |
| Python | VAmPI（Connexion/OpenAPI） | 路由 + BOLA 机制口径 | `--strict` |
| Java | WebGoat（教学关卡） | 攻击关/修复关**成对**真值 | `--strict`（sqli 门 6/6） |
| Java | My-Blog（真实个人博客） | M63 盲测逐条人工核查 | `--strict` 零误报 / 真值 3/3 |
| Java | litemall（20k Star 小程序商城） | M64 盲测逐条人工核查 + 全局 CORS 配置继承 | `--strict` 零误报 / 真值 3/3 |
| Python | Employee-Management-System（真实 Flask CRUD） | M72 盲测逐条人工核查 | `--strict` 零误报 / 真值 2/2 |
| Solidity | compound-protocol（生产级 DeFi） | M73 生产 `contracts/` 零 True 压测 | 450 入口 / 四类 0 误报 / 三锚点 False |
| Solidity | Uniswap V3（生产级 DEX） | M79 自定义状态互斥锁 `lock()` 结构识别 | 67 生产入口 / 0 True / mint/burn/swap/flash/collect 全 False |
| Python | FastAPI + SQLAlchemy 2.0（真实模板） | M80 async / Depends / ORM 表达式 | 9 异步入口 / 0 True / users authz 全 False |
| Solidity | MakerDAO dss（0.6.x 旗舰 CDP） | M136 `auth` 映射守卫 + 内联算术封装 | 234 入口 / 五类 0 True / 正反锚点成立 |
| Python | flasky（多蓝图 + 自定义装饰器） | M137 `// Auth-Guard:` 证据头 + 公开只读面 | 39 入口 / 0 True / 8 条守卫证据 |
| Java | mall-tiny（JWT + MyBatis-Plus） | M138 Spring Security 三件套 + 全局 CORS 折叠 | 40 入口 / cors 外 0 True / 1 个全局根因 |
| Solidity | OZ Upgradeable（可升级基元库） | M143 initializer / onlyInitializing / onlyProxy 语义边界 | 2,017 入口 / 五类 0 True |
| Java | My-Blog-layui（Layui 后台） | M144 与 My-Blog 双生对照 | 64 入口 / 真值 3 条全中 / 计划外 0 |
| Solidity | compound-finance/comet（Compound V3） | M87 0.8.15 unchecked + 自定义错误 | 435 入口 / 0 True / 四锚点 False |
| Python | DjanGoat（OWASP RailsGoat 的 Django 版） | M88 urls.py 路由表真值 11 条 + M90 redir 1 条 | 36 入口 / 23 路由证据 / 真值 12/12 / 0 误报 |
| Solidity | OpenZeppelin 标准安全基元库 | M95 零误报极限压测（**反向门禁**） | 576 生产入口 / 0 True / 全库 2558 也 0 True |
| Solidity | Aave V3（逻辑库委托 + ACL 角色表） | M96 身份函数形态 + 反向锚点 | 275 生产入口 / 0 True / mocks 真漏洞仍判 True |
| Java | waynboot-mall（Sa-Token 双端商城） | M97 Sa-Token 语义 + 全局 CORS 折叠 | 163 入口 / 163 命中折叠成 1 根因 / cors 外零 True |
| Java | mall4j（SecurityUtils.getUser() 主体链） | M98 主体链全覆盖 | 139 入口 / C 端五控制器 authz 零 True / CORS 折叠成 1 |
| Solidity | damn-vulnerable-defi | 无真值（经济逻辑漏洞） | 健壮性抽检：切片 164 单元、True ≤8 |
| Solidity | smartbugs-curated | 官方行号 `vulnerabilities.json` | safe 零误报、零判反（parity kill 记 DISPUTED） |
| Solidity | DeFiVulnLabs | **成对 vuln/fixed，按行号标定** | 零误报 / 零判反 / 真值表全命中（9/9 满贯） |
| Solidity | nssc | 作者注释**指名**漏洞（honeypots 是陷阱口径不收） | 真值 (file, start_line) 精确匹配 |
| Solidity | dvdefi（形态抽检） | — | 抽检基线 |

三条口径贯穿所有靶场：

1. **兜底只能 `return None`** —— 判不了就退回，不许把"不确定"伪装成 True/False；
2. **模型层不进 `--strict`** —— 模型非确定性不能当门禁，只出指标；
   调用失败样本单列剔除（带原始异常），绝不折算成"无漏洞"；
3. **分母 < 20 只记录不下结论**（TPR/FPR 都是），`Score = TPR − FPR`。

`pre-push` 会依次跑 **21 道快速门禁**（16 段靶场基线 + 冒烟 + 争议登记核对 +
覆盖地板）；全量 **68 项**由 `benchmarks/run_all.py --offline` 承担
（含第 68 项确定性重现与跨仓聚类对账）。CI 上没有靶场仓库，因此全量 strict 由本地钩子承担
（见 `.githooks/pre-push`）。

规则层现状：**40 类判据入口**（`rule_detectors.verdict()` 统一路由，空源码必须
退 None）+ **35 类确定性补丁器**（命中→补丁→重切片→规则翻 False→finally 字节级
还原的自检闭环，`--fix` 触发）。冒烟断言 `[1]`-`[250]`（1,503 项），秒级不调模型。

第四层另有 **PoC Harness 合成器**（`--emit-poc`）：把"规则层已判 True 的那条"
翻译成离线可跑的验证骨架 —— Solidity Foundry `.t.sol` / Python pytest /
Java Spring MockMvc，三语言各自带自检（语法解析 / 结构完整度），合成失败不抛
异常而是退回错误信息。

## 真实项目评测（比 Benchmark 更能说明问题）

```bash
# 66 条可判定样本，约 15 分钟
python benchmarks/benchmark_javaseccode.py --concurrency 4

# 判定稳定性复测（同一输入连问 3 次）
python benchmarks/check_stability.py
```

**结论要先看抖动率再看分数**：实测同一份代码、`temperature=0` 连问三次，
12 条样本里 5 条结果不一致（41.7%）。单轮 TPR/FPR 因此不具备可复现性，
详见 [`REAL_PROJECT_REPORT.md`](REAL_PROJECT_REPORT.md)。

采样级补救的效果取决于票数：`--votes 3`（三次取多数）在两轮 A/B 里翻转率仍是
9/66 = 13.6%，与 `--votes 1` 完全相同——3 票几乎必然是 2:1，等于把一次抽样
换成另一次抽样。但把 5 轮完整评测事后合并取多数，Score 从 0.639–0.724 抬到
**0.793**（TPR 0.935 / FPR 0.143）。所以 `--votes` 默认 1（单轮跑分用），
需要更高召回时用 5 票的代价换。


```bash
pip install -r requirements.txt
export LLM_API_KEY="your-opencode-go-key"
export LLM_BASE_URL="https://opencode.ai/zen/go/v1"
export LLM_MODEL="beam-free"                   # Tier-1 免费模型
export LLM_TIER2_MODEL="glm-5.3-flash"        # Tier-2 付费 flash（可换 deepseek-v4.1-flash）
python cli.py --help
```

## 开发路线（4 周冲刺）

1. **第1周**：slicer + context 层，Tree-sitter 符号索引与 3 轮跨文件索取循环
2. **第2周**：web3_slither + scenario_matcher，大小模型漏斗路由
3. **第3周**：sandbox 层，Docker/Foundry 验证器 + 3 轮编译报错自愈
4. **第4周**：cli.py PR 增量扫描与 GitHub Action 集成

## 开发路线（进度）

- [x] 第1周：slicer + context 层
- [x] 第2周：web3_slither + scenario_matcher，大小模型漏斗路由
- [x] 第3周：sandbox 层，Docker/Foundry 验证器
- [x] 第4周：PR 增量扫描 —— `pr-scan` 已实现变更行→方法→反向依赖（含装配级）
- [x] 第5周：Java 赛道打通 + OWASP Benchmark 跑分（11 类，Score 0.98）
- [x] 第6周：真实项目（java-sec-code）评测，暴露 4 个仅真实代码可见的切片缺陷
- [x] 降判定抖动：规则化 cors / deserial / spel / xxe / sqli / redir / xss / ssrf
      八类，规则覆盖 10 → **63/66 条**。真实项目 Score 0.823 → **1.000**
      （TPR 1.00 / FPR 0.00），且规则判定是可复现的纯函数
- [x] 外部代码审计修复（6 处真实缺陷）：
      跨文件实现未回写切片、兄弟路由方法污染辅助段、ssrf 兜底过宽、
      Web3 静态置信度冒充"已复现"、Skeptic 硬编码 `python` 且未接 Java 赛道、
      `matches()` 空括号被当白名单证据
- [x] 跨路由串接：存储型 XSS 这类「写入点 + 读取点」分居两方法的漏洞
      —— `core/context/taint_chain.py`，按介质（Cookie/Session/Request/Model）
      与键名配对，`XSS.store → XSS.show` 被正确接上
- [x] Cite-Before-Verdict：模型必须先逐字符引用它据以判断的那一行，
      本地核验该行**真实存在于切片且不是注释行**，核验不过的采样直接作废。
      这能整类掐掉"编造一行代码来解释结论"的幻觉型误报。
- [x] CI 集成：`--github-comment` 双通道输出 —— 行级 annotation 挂到 PR 的
      Files Changed 代码行下方，Markdown 报告写入 `$GITHUB_STEP_SUMMARY`
      渲染成看板（两个通道都**不需要 Token 权限**）。
- [x] **换项目验证泛化（Hello-Java-Sec，零改动迁移）**：规则在同源靶场上是
      63/63，换一个作者/命名/工具类后覆盖率降到 **47.7%**，规则侧正确率
      **31/31**。首次盲测暴露 5 类规则缺陷（注释里的"修复写法"被当防护、
      白名单判据绑死函数名、未知清洗函数被兜底判漏洞、`${}`+数字类型误报、
      存储型 XSS 写库被判"链不闭合"），已全部修正并补进 smoke `[17]`。
      详细数据见 `REAL_PROJECT_REPORT.md` 第九节。

### own_body 的使用边界（别越界）

`CodeUnit.own_body` 只存入口方法自己那几行。它**只**该给两类逻辑用：

| 消费者 | 为什么 |
|---|---|
| `taint_chain` | 判"本方法自己写了什么介质"，必须排除同文件兄弟方法 |
| `rule_detectors` 的入口体截取 | 判"这个入口上的注解/配置"，同理 |

而 `ScenarioMatcher`、`SkepticReviewer` 这类**推理型** agent 必须拿
`source_code`：清洗逻辑常常写在同文件私有方法或 Service 实现层，那些证据
只在 `source_code` 里。曾让 Skeptic 改读 `own_body`，结果 `XSS.safe` 只剩
`return encode(xss);`，`encode` 的逐字符转义体全被挡住 —— 质检员看不见
清洗逻辑，本该推翻的误报反而被放过去了。`smoke_test_chains.py` 的
`[14]` 组用例把这条边界钉住了。


## 安全合规

提示词统一使用防御合规视角（"静态数据流可达性分析""权限修饰符一致性核对"），
零攻击敏感词；敏感场景走本地 vLLM 私有化部署，源码不出内网。
