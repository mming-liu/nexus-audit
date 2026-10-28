# nexus-audit 变现作战计划（整理核实版 2026-10-27）

> 原始材料经代码库核实后整理。标注 ✅（已核实）/ ⚠️（夸大，需修正）/ ❌（不存在，忽略）。

## 一、能力核实表

| 材料说法 | 核实结果 |
|---|---|
| `cli.py watch` 增量首杀监控 + 四件套 | ✅ 真实（M152，watch_bundles/ 输出交单件） |
| `cli.py ci-init` 生成 GitHub/GitLab/Watchtower CI | ✅ 真实（M235，含 watchtower.cron） |
| `pr-scan` + SARIF + Auto-Fix 补丁 PR | ✅ 真实（PR 行级 review 载荷 + suggestion 格式） |
| Solidity 切片器 + DeFi 规则可打 Web3 竞赛 | ⚠️ 切片器真实，但 **8 个 Solidity 仓实战全 0 True**——Web3 是四条路里实战验证最弱的，不能按"立即可做"排第一 |
| `beam-free` 免费初筛、`OpenCode Go` 二级复核 | ❌ 代码库里不存在，忽略 |
| "50 仓白皮书" | ⚠️ 实际为 25 仓（6,868 入口 / 1,504 路由 P0 / 94 根因 / 0 误报），数字按真的说 |
| "35 类 Auto-Fix" | ⚠️ 实际 20 类补丁 / 25 类规则，别超报 |
| JeecgBoot 两个越权接口本周拿 CVE | ⚠️ 已核实 master 已修、疑似 GHSA-63v7-3c98-c3mj 重复，**先私密报告查重**，不能承诺编号 |
| Huntr（Protect AI / Palo Alto 旗下）给 AI/ML 开源真金白银 | ✅ 平台真实，且 FastAPI/Flask 生态正中 Python 切片器射程 |
| Code4rena 已迁 Immunefi | 未核实， Sher­lock / Cantina / Immunefi 平台本身真实 |

## 二、四条路径（按"能力-市场匹配度"重排）

| 排序 | 路径 | 收益区间 | 启动周期 | 匹配度判断 |
|---|---|---|---|---|
| **1** | Python AI/ML 开源赏金（Huntr / HackerOne IBB） | $200–$5,000/单 | 2–4 周 | **最高**。RAG 后台/Agent 框架/MCP Server 的 ssrf、pathtraver、unrestricted_upload、deserial 正是 Python 切片器强项，且平台真发钱 |
| **2** | 白盒审计私单（CVE 背书 + 25 仓白皮书） | ¥5,000–¥50,000/单 | 2–6 周立信誉 | **最稳**。差异化 = 零误报根因报告 + 已验证 fix.patch + 回归脚本；单机成本近零 |
| **3** | Web3 审计竞赛（Sherlock/Cantina）与新 commit 首杀（watch + Immunefi） | $500–$50,000/单 | 需先补课 | 潜力最大但 **Solidity 实战 0 True**，先在公开老仓练手出真阳，再上竞赛 |
| **4** | CI Micro-SaaS 开源核心 + 付费 Pro | $29–$199/月/团队 | 1–2 个月封装 | 长线睡后收入，`ci-init`/`pr-scan`/SARIF 底座已齐，但缺销售渠道，最后做 |

## 三、落地打法（去幻觉版）

### 路径 1：Huntr 定向扫描（本周可开张）
1. 从 Huntr 挑 3 个热门 Python Agent/RAG 仓库（优先 FastAPI + 文件上传/URL 拉取/pickle 加载面）
2. `python cli.py scan --auto <repo>` 出 P0/P1/P2 → 人工确认真阳
3. 用 `hunt` 交单四件套格式写报告（含复现步骤 + 修复建议），提交 Huntr
4. 同批仓库挂 `python cli.py watch <repo> --bundle-dir watch_bundles` 持续盯新 commit

### 路径 2：审计私单（与路径 1 并行积信誉）
- 第一步：newbee-mall-api 文件上传等**未重复**漏洞走 GHSA 私密报告 → CVE；JeecgBoot 两条先查重
- 第二步：README 顶部挂 `Discovered CVEs` + 25 仓实测大表（WILD_HUNT_REPORT.md）
- 第三步：报价单按行计价（市场价 ~0.5 万/万行，10 万行 Java ≈ 1.3 万起）；交付物 = 零误报根因报告 + fix.patch + 回归测试
- 注意合规：个人报告定位"内部整改参考"；等保/验收级报告需挂靠有 CNAS/CMA 资质机构

### 路径 3：Web3 补课后再战
- 先挑 3 个**已退役**的老竞赛仓库（历史 known-issue 公开可验）跑 `scan --web3`，把切片+规则调到能复现历史真阳
- 之后再进 Sherlock/Cantina 首日竞赛；Immunefi 中腰部协议用 `watch` 挂机抢新 PR

### 路径 4：产品化（第 2 个月后再启动）
- 开源核：CLI + 基础规则 + 25 仓评测报告引流（V2EX / 先知 / r/netsec / X）
- Pro 层：`pr-scan` PR 增量拦截 + Auto-Fix suggestion + Watchtower 私有部署

## 四、本周三步走（修正版）

1. **荣誉资产**：newbee-mall-api 报告提交 GHSA 私密报告；JeecgBoot 两条按"affected ≤3.9.5 / 已修 / GHSA 查重中"口径发——**不承诺本周拿号**
2. **大仓筛真洞**：用现有 `scan --auto` 对 ruoyi-vue-pro 等大仓新根因过一遍 LLM 复核，找第二个未公开真洞
3. **开张选边**：主攻路径 1 → 从 Huntr 挑 3 个 Python AI 仓跑首轮；主攻路径 3 → 先做 Web3 老仓复现补课

## 五、红线（不变）

只碰开源代码 / 授权 scope；GHSA 私密报告优先于公开 issue；不发未修复漏洞细节与可武器化 PoC；不卖 exp。
