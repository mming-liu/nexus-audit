# 阶段报告 2026-10-24d：M71–M78 全局根因折叠 + 三语言野战扩军

**范围**：`Module 71` → `Module 78`
**基线**：`c7c72a7`（M70b，冒烟 `[1]`–`[109]`，23/23 PASS）
**状态**：代码与数据已落盘；M78 全量门禁与文档收口见 §5

---

## 1. 一页摘要

| 项 | 结果 |
|---|---|
| 真实仓库 | **9 个**（Java 7 + Python 1 + Solidity 1） |
| 入口 | **1,478 个** |
| 规则判定对 | **21,332 次** |
| P0 路由级命中 | **630 条** |
| 独立根因 P0 | **42 个**（4 份全局 CORS + 38 条端点/文件级） |
| 确认缺陷 | **626 条**（另 3 条流程 + 1 条设计功能单列） |
| 确认的规则层误报 | **0 条** |
| 二级漏斗派发模型 | **0 条**（16,007 条假候选全过滤，100%） |
| 自动修复自检 | **3 条**（litemall CORS + JWT 密钥；Employee 弱密钥） |
| 新增规则/补丁 | 第 16 类 CORS 配置补丁器 |
| 新增靶场 | Employee（第 25）、compound（第 26） |
| 冒烟 | `[1]`–`[115]`，**678 项 PASS** |
| 全量门禁 | `run_all --offline --jobs 4` **25 PASS / 0 FAIL / 0 SKIP** |
| `doctor` | **22 类规则 + 16 类补丁器 + 14 项地板，PASS** |
| 9 个真实仓库 strict | **9/9 exit 0** |

---

## 2. 九个真实仓库

数据源：`benchmarks/results/wild_hunt.json`（`benchmarks/wild_hunt.py` 实跑）。

| 项目 | 语言 | 入口 | 判定对 | P0 | 根因 | CORS | 非 CORS | 过滤 | strict |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| newbee-mall | Java | 73 | 1,387 | 6 | 6 | 0 | 6 | 100% | ✔ |
| newbee-mall-api | Java | 62 | 1,178 | 66 | 5 | 62 | 4 | 100% | ✔ |
| RuoYi | Java | 305 | 5,795 | 1 | 1 | 0 | 1 | 100% | ✔ |
| eladmin-mp | Java | 65 | 1,235 | 76 | 12 | 65 | 11 | 100% | ✔ |
| mall | Java | 246 | 4,674 | 253 | 8 | 246 | 7 | 100% | ✔ |
| My-Blog | Java | 54 | 1,026 | 3 | 3 | 0 | 3 | 100% | ✔ |
| litemall | Java | 219 | 4,161 | 223 | 5 | 219 | 4 | 100% | ✔ |
| Employee-Management-System | Python | 4 | 76 | 2 | 2 | 0 | 2 | 100% | ✔ |
| compound-protocol | Solidity | 450 | 1,800 | 0 | 0 | 0 | 0 | 100% | ✔ |
| **合计** | — | **1,478** | **21,332** | **630** | **42** | **592** | **38** | **100%** | **9/9** |

完整证据、Mermaid、修复 diff 见 [`WILD_HUNT_REPORT.md`](WILD_HUNT_REPORT.md)。

---

## 3. 模块落点

### M71 全局配置根因去重折叠

- `_root_cause_key`：CORS 结论完全来自 `框架装配证据` 时按配置体哈希归并；
  文件级密钥按文件归并；其余按 `(类目, 文件, 行, 单元)` 独立；
- Markdown / HTML / SARIF 只渲染根因卡，保留 `p0_route_level_hits`；
- `--summary-json` 新增 `p0_route_level_hits` / `p0_unique_root_causes` /
  `p0_route_by_cat` / `p0_unique_by_cat` / `root_causes`；
- litemall 实测：223 条路由级 → **5 个根因**；7 仓合计 628 → 40；
- 冒烟 `[109]`：3 条继承路由折叠为 1 个根因，MD/SARIF/HTML 三端一致。

### M72 真实 Python Flask-SQLAlchemy 仓（第 25 靶场）

- `Thinal-Fernando/Employee-Management-System`：4 路由；
- 真值 2 条：`delete(id)` 对象级 authz + `app.secret_key = "123"` 弱密钥；
- 规则补 Flask `app.secret_key` 上下文与短密钥（`{1,}`）；
- `benchmark_flaskcrud.py --strict` 零误报；`--fix` 把弱密钥改为
  `os.environ.get("SECRET_KEY")` 并自检通过；
- 冒烟 `[110]`。

### M73 compound-protocol 生产级 DeFi（第 26 靶场）

- 只扫 `contracts/`：450 个合约入口 / 976 次判定；
- `reentrancy` / `access_control` / `arithmetic` /
  `unchecked_low_level_calls` **0 条 True**；
- 三锚点 False：`Timelock.setPendingAdmin`、`CToken.transfer`、
  `ExponentialNoError.mul_ScalarTruncate`；
- `benchmark_compound.py --strict`；SCOREBOARD 99% 覆盖；
- 冒烟 `[111]`。

### M74 mall 唯二模型候选收口

- 2 条候选均为 `AlipayController.pay/webPay` 的
  `response.getWriter().write(alipayService.pay(param))`；
- 读 Alipay SDK 源码：`pageExecute → WebUtils.buildForm`，
  `buildHiddenField` 对 value 做 `"`→`&quot;` 转义；用户可控 `subject`
  在 hidden input 的**属性值状态**，`<`/`>` 不构成标签；
- 判 False；mall `llm_dispatched` 2→0，filter 99.94%→100%；
- `--summary-json` 增加 `model_candidates` 明细；冒烟 `[112]`。

### M75 第 16 类 CORS 配置补丁器

- 按装配证据 `来源 X.java` 归并，每个配置文件只打一处补丁；
- `.allowedOriginPatterns("*")` / `.addAllowedOrigin("*")` → 固定白名单；
- 重切片验证代表性路由 `cors` 翻 False，finally 字节级还原；
- litemall 实测：1 处配置补丁消解 219 条继承路由；
- `doctor` 16 类；冒烟 `[113]`。

### M76 PoC 合成器新增 cors / hardcoded_secret

- Python：恶意 Origin + credentials 探测、用提取密钥离线签发管理员 JWT；
- Java：MockMvc 同类模板；
- 四份模板全部 `ast.parse`/结构自检通过；冒烟 `[114]`。

### M77 advisory_exporter + `--advisory-dir`

- 按独立根因生成 GHSA 草稿（3 条继承路由只出 1 份）；
- 含 Affected Component / CWE / Mermaid / PoC Harness / Verified Patch；
- 冒烟 `[115]`。

---

## 4. 关键工程判断

1. **根因折叠要同时保留两个数**：路由级 630 与根因级 42 缺一不可。只报
   42 会丢兼容性，只报 630 会把 592 条 CORS 刷屏。两个字段并列，报告默认
   按根因渲染。
2. **第三方 SDK 的安全性可以读源码定论**：Alipay `buildHiddenField` 只做
   `"`→`&quot;`，在属性值状态已足够；这不是"信厂商"，是逐行核对。
3. **生产协议零误报比多抓一条更有价值**：Compound 450 入口 0 True，
   证明规则层不是只在靶场上好看。
4. **CORS 配置补丁必须按配置归并**：219 条路由来自 1 份 `CorsConfig`；
   按路由打补丁既慢又会重复改同一文件。

---

## 5. M78 验收

- [x] `wild_hunt.py` 刷新 9 仓（Java + Python + Solidity），同时展示
      路由级 P0 与根因 P0
- [x] `run_all.py --offline --jobs 4` **25 PASS / 0 FAIL / 0 SKIP**
- [x] 冒烟 `[1]`–`[115]` **678 项 PASS**
- [x] `cli.py doctor` exit 0（22 类规则 + 16 类补丁器 + 14 项地板）
- [x] 9 个真实仓库 `benchmark_* --strict` 全 exit 0
- [x] `SCOREBOARD.md` / `run_all.md` / `triage_fallbacks.md` 同步
- [x] `README.md` / `WILD_HUNT_REPORT.md` 更新
- [x] `MEMORY.md` ≤3,000 字符
- [x] `pre-push` 门禁全绿、远端 `main` 同步

---

## 6. 提交

| 提交 | 内容 |
|---|---|
| `c2ed672` | M71 根因去重折叠 |
| `8f5051e` | M72–M77 Python/Solidity 扩军 + CORS 补丁 + PoC/Advisory |
| 本报告 | M78 数据/文档/最终门禁 |

---

## 7. 边界

- 切片单位仍是路由入口；配置/工具类密钥靠文件级普查补扫；
- 592 条 CORS 是 4 个根因的继承计数，不是 592 个独立缺陷；
- Compound 只扫生产 `contracts/`，`tests/` harness 不在生产面；
- 披露草稿是人工复核前的 GHSA 模板，提交上游前仍需维护者确认；
- 模型层未参与本轮数字。

---

*生成：2026-10-24｜基线 `c7c72a7`｜数据 `benchmarks/results/wild_hunt.json`*
