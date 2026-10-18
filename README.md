# nexus-audit — AI 自动化漏洞挖掘工程框架

按《AI 自动化漏洞挖掘：商业化与代码落地完整执行计划》初始化的四层解耦工程骨架。

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

## 快速开始

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

## 安全合规

提示词统一使用防御合规视角（"静态数据流可达性分析""权限修饰符一致性核对"），
零攻击敏感词；敏感场景走本地 vLLM 私有化部署，源码不出内网。
