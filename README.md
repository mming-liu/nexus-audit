# nexus-audit — AI 自动化漏洞挖掘工程框架

按《AI 自动化漏洞挖掘：商业化与代码落地完整执行计划》初始化的四层解耦工程骨架。

当前覆盖 **Java / Python / Solidity** 三条赛道：规则层先做确定性判定（编译器/VM
能证明的事实不交给模型），模型只接手规则判不了的部分；11 个真实外部靶场全部接
`--strict` 离线门禁，`pre-push` 与 `run_all.py` 各有一道（见
[多语言靶场](#多语言靶场11-个仓库全部离线门禁)）。

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
| `core/agents/vuln_categories.py` | 20 类漏洞的 Scenario/Property 定义（11 类 OWASP + Java 生态 + Python Web + Solidity 链上） |
| `core/agents/rule_detectors.py` | 客观事实的确定性判定（17 类已有判据入口，先于 LLM 执行） |
| `benchmarks/benchmark_owasp.py` | OWASP Benchmark 跑分（TPR/FPR/Score，含断点续跑与误差归因） |
| `benchmarks/benchmark_javaseccode.py` | 真实项目（java-sec-code）评测，真值取自路由命名 + 作者注释 |
| `benchmarks/benchmark_vulpy.py` | Python Web 靶场（bad/good 成对真值），`--strict` 零退回门禁 |
| `benchmarks/benchmark_smartbugs.py` | Solidity 靶场（官方行号真值），`--scope all` 出模型 TPR/FPR |
| `benchmarks/benchmark_defivulnlabs.py` | Solidity 成对 vuln/fixed 真值（0.8.x），真值表按行号匹配防漂移 |
| `benchmarks/run_all.py` | 一键跑全部离线门禁，输出 Markdown 计分板 |
| `benchmarks/export_disputes.py` | 争议登记核对：每条口径分歧的证据必须逐字对上源码 |
| `benchmarks/check_stability.py` | 判定稳定性复测：同一输入连问 N 次，测抖动率 |
| `benchmarks/smoke_test_chains.py` | 判据链路断言 `[1]`-`[68]`（不调模型，秒级） |
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

## 多语言靶场：11 个仓库、全部离线门禁

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
| Solidity | damn-vulnerable-defi | 无真值（经济逻辑漏洞） | 健壮性抽检：切片 164 单元、True ≤8 |
| Python | vulpy（bad/ vs good/） | **成对代码 diff** | 零误报 / 零静默放行 / 零退回 |
| Solidity | smartbugs-curated | 官方行号 `vulnerabilities.json` | safe 零误报、零判反 |
| Solidity | DeFiVulnLabs | **成对 vuln/fixed，按行号标定** | 零误报 / 零判反 / 真值表全命中 |

三条口径贯穿所有靶场：

1. **兜底只能 `return None`** —— 判不了就退回，不许把"不确定"伪装成 True/False；
2. **模型层不进 `--strict`** —— 模型非确定性不能当门禁，只出指标；
   调用失败样本单列剔除（带原始异常），绝不折算成"无漏洞"；
3. **分母 < 20 只记录不下结论**（TPR/FPR 都是），`Score = TPR − FPR`。

`pre-push` 会依次跑九道靶场门禁 + 冒烟 + 争议核对；CI 上没有靶场仓库，
因此全量 strict 由本地钩子承担（见 `.githooks/pre-push`）。

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
export LLM_API_KEY="your-api-key"
export LLM_BASE_URL="https://api.deepseek.com/v1"
export LLM_MODEL="deepseek-reasoner"
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
