# 阶段报告 2026-10-24c：M63–M70 首轮真实野生仓库实弹狩猎与淬火

**范围**：`Module 63` → `Module 70`（首轮真实开源项目野战）
**基线**：`575be69`（M62 收官，冒烟 `[1]`–`[101]`，21/21 PASS）
**状态**：M63–M69 已落盘；M70 全量门禁与文档收口（见 §5）

---

## 1. 一页摘要

| 项 | 结果 |
|---|---|
| 真实仓库 | **7 个**（从未进入过本仓库、未做任何改造） |
| 路由入口 | **1,024 个** |
| 规则判定对 | **19,456 次**（unit × 类目） |
| P0 规则实锤 | **628 条** |
| 确认缺陷 | **624 条**（另 3 条流程待确认 + 1 条设计功能，单列不静默） |
| 确认的规则层误报 | **0 条** |
| CORS 配置继承 | **4 份配置 / 592 条路由暴露面** |
| 非 CORS 缺陷面 | **36 条** |
| 二级漏斗 | 15,121 条假候选直接过滤，仅 2 条派发模型（**99.99%**） |
| 自动修复 | litemall JWT 密钥 → 环境变量，自检 **1 条通过** |
| 新增靶场 | My-Blog（第 23）、litemall（第 24） |
| 新增规则 | `hardcoded_secret`（第 22 类，CWE-798） |
| 新增补丁器 | 第 15 类（硬编码密钥 → 环境变量） |
| 冒烟 | `[1]`–`[108]`，**654 项全 PASS** |
| 全量门禁 | `run_all --offline --jobs 4` **23 PASS / 0 FAIL / 0 SKIP** |
| `doctor` | **22 类规则 + 15 类补丁器 + 正则卫生，PASS** |
| 7 个真实仓库 strict | **7/7 exit 0**（零误报 / 零漏报 / 零判反） |

---

## 2. 七个真实仓库实测数据

数据源：`benchmarks/results/wild_hunt.json`（`benchmarks/wild_hunt.py` 实跑）。

| 项目 | 入口 | 判定对 | P0 | CORS | 非 CORS | 过滤率 | 规则耗时 | 墙钟 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| newbee-mall | 73 | 1,387 | 6 | 0 | 6 | 100% | 578 ms | 1.9 s |
| newbee-mall-api | 62 | 1,178 | 66 | 62 | 4 | 100% | 496 ms | 1.9 s |
| RuoYi | 305 | 5,795 | 1 | 0 | 1 | 100% | 2,229 ms | 16.8 s |
| eladmin-mp | 65 | 1,235 | 76 | 65 | 11 | 100% | 1,193 ms | 3.4 s |
| mall | 246 | 4,674 | 253 | 246 | 7 | 99.94% | 2,568 ms | 13.6 s |
| My-Blog | 54 | 1,026 | 3 | 0 | 3 | 100% | 619 ms | 1.8 s |
| litemall | 219 | 4,161 | 223 | 219 | 4 | 100% | 3,626 ms | 30.0 s |
| **合计** | **1,024** | **19,456** | **628** | **592** | **36** | **99.99%** | **11.3 s** | **69.4 s** |

完整逐条证据、Mermaid 污点图、修复 diff 见
[`WILD_HUNT_REPORT.md`](WILD_HUNT_REPORT.md)。

---

## 3. 规则层淬火：真实项目打回的三个通用机制

### 3.1 M63 My-Blog：公开内容 vs 归属资源、SSRF 接收者语义

- 盲测 11 条 P0 → 逐条回读收敛到 **3 条真阳**（MD5 密码哈希 + 2 条弱随机文件名）；
- authz 五条是公开博客内容页：按"路由语境"补公开内容豁免，而不是按形参名；
- SSRF 三条里的 `StringUtils.hasText(linkUrl)` 是**校验谓词**不是 HTTP 发送：
  把 SSRF 判据拆成"真客户端强 sink / 谓词非 sink / `*Service`+url 弱 sink 须旁证"三分；
- `AdminLoginInterceptor` 前缀覆盖 + `MyBlogWebMvcConfigurer.addPathPatterns`
  驱动切片器补 `[global-authz]` 标记；
- 新增第 23 靶场 `benchmark_myblog.py`（接入 `slice_cache.py`），冒烟 `[102]`。

### 3.2 M64 litemall：20k Star 多模块、`@LoginUser Integer userId`

- 盲测 **288 条 P0 → 222 条**（219 CORS 配置继承 + 3 条真阳）；
- `@LoginUser Integer userId` 基础类型形参本身即主体：`argument_resolvers.py` +
  `authz_verdict` 补齐"带自定义 Resolver 注解的基础类型形参 = 主体 ID"；
- `@Sort`/`@Order` 是 Bean Validation 白名单注解：切片器打 `[param-validated]`，
  MBG `ORDER BY` 出口按可达性判，sqli 40→0；
- Shiro `filterChainDefinitionMap.put("/admin/**","authc")` 并入前缀覆盖机制，
  authz 21→0；wx 模块显式 token 鉴权 → `[explicit-auth-module]`；
- path sink 需与入口形参相关（`request.getInputStream()` 排除），pathtraver 5→0；
- 新增第 24 靶场 `benchmark_litemall.py`，冒烟 `[103]`。

### 3.3 M65 二级 Sink 漏斗相关性

- 四大项目候选池 6 条，逐条解剖后全部是"有 Sink 但实参与输入行无交集"；
- `build_rule_diagnostic` 增加轻量相关性：候选 Sink 行括号内必须至少含一个
  非字面量标识符，且与输入行有交集/赋值链可达；
- 假候选 6→0，真阳退回样本 0 漏网；mall 保留 2 条真候选（支付宝）；
- 冒烟 `[104]`。

### 3.4 M66 狩猎简报与 HTML 漏斗仪表盘

- `--summary-json`：`total_units` / `total_pairs_evaluated` / `p0_confirmed` /
  `funnel_filtered_out` / `funnel_filter_rate` / `llm_dispatched` /
  `patches_verified` / `pocs_generated`；
- HTML 顶部展示漏斗过滤率与类目热力条；SARIF `properties.priority` 透传；
- 冒烟 `[105]`。

### 3.5 M67 第 22 类 `hardcoded_secret`

- 凭证词必须落在标识符末尾（`secret` / `secret_key` / `jwtSecret` /
  `accessKeySecret` / `privateKey` / `signingKey`），避免 VAmPI
  `secret_content="secret for bookTitle"` 这类书籍正文字段误报；
- JWT / Flask `SECRET_KEY` 签发上下文短弱密钥也判 True（`'random'` 的可猜测性
  就是危害）；`os.environ` / `System.getenv` / `@Value("${...}")` 读取判 False；
- 文件级普查：`scan --auto` 额外扫配置/工具类（伪单元，单独
  `secret_files_flagged`），补出入口切片看不到的 `VAmPI config.py`、
  `litemall JwtHelper.java`；
- 冒烟 `[106]`。

### 3.6 M68 第 15 类补丁器

- Python：`SECRET_KEY = "..."` → `os.environ.get("SECRET_KEY")`，缺 `import os`
  自动补齐；Java：`String jwtSecret = "..."` → `System.getenv("JWT_SECRET")`；
- 重切片按语言分流（`WebTreeSitterSlicer` / `JavaSlicer`），并在重切前清
  `java_impl_resolver._FILE_CACHE`（否则读旧内容、自检恒 True）；
- 文件级伪单元免重切片，直接对补丁后全文重跑规则；
- 冒烟 `[107]`（Python + Java 双分支 + 字节级还原）。

### 3.7 M69 野战误报淬火与档案

- SpEL 裸 `.getValue()`：`Cookie.getValue()` / `Map.Entry.getValue()` 是 FP，
  只认表达式型接收者；
- path sink 整行标识符相交：局部 `File file` 与形参 `MultipartFile file` 同名
  遮蔽是 FP，只取 sink 调用实参并上溯赋值链；`request.getParameter` 赋值链算
  外部输入；
- 上述两类 FP 由冒烟 `[108]` 锁成回归断言；
- 产出 `WILD_HUNT_REPORT.md` 与 `benchmarks/wild_hunt.py`。

---

## 4. 门禁与产物

### 4.1 全量门禁

```
python benchmarks/run_all.py --offline --jobs 4
→ 23 PASS / 0 FAIL / 0 SKIP
```

（冒烟 + 争议核对 + 地板 + 20 个靶场/回归并行；任一 FAIL 快速失败。）

### 4.2 冒烟

- `[1]`–`[108]`，**654 项断言全 PASS**；
- 新增：`[102]` My-Blog、`[103]` litemall、`[104]` 漏斗相关性、`[105]`
  summary-json/HTML、`[106]` hardcoded_secret、`[107]` 第 15 类补丁器、
  `[108]` SpEL/路径 FP 回归锁。

### 4.3 医生与生成物

```
python cli.py doctor   → PASS
  22 类规则 / 15 类补丁器 / 缓存指纹 / 覆盖地板 12 项 / SCOREBOARD 同步 / 正则卫生
```

- `benchmarks/results/SCOREBOARD.md`、`run_all.md` 由全绿跑刷新；
- `benchmarks/results/wild_hunt.json` 为 M69 数据源；
- `WILD_HUNT_REPORT.md` 为客户/白帽社区可读档案。

### 4.4 提交

| 提交 | 内容 |
|---|---|
| `718ca8c` | M63 My-Blog 野战首战 + 第 23 靶场 + 三项淬火 |
| `73ba807` | M64 litemall 野战 + 第 24 靶场 + 五项淬火 |
| `14c7fa3` | M65 二级漏斗相关性校验 |
| `55323cd` | M66 `--summary-json` + HTML 漏斗仪表盘 |
| `2bbe1a5` | M67+M68 第 22 类 `hardcoded_secret` + 第 15 类补丁器 |
| `c5d71ef` | M69 野生项目实弹档案 + 三项 FP 淬火 + 文件级密钥普查 |
| 本报告 | M70 全量门禁、文档收口、阶段报告 |

---

## 5. M70 验收

- [x] `run_all.py --offline --jobs 4` **23 PASS / 0 FAIL / 0 SKIP**
- [x] 冒烟 `[1]`–`[108]` **654 项 PASS**
- [x] `cli.py doctor` exit 0（22 类规则 + 15 类补丁器 + 正则卫生）
- [x] 7 个真实仓库 `benchmark_* --strict` 全 exit 0
- [x] `SCOREBOARD.md` / `run_all.md` / `triage_fallbacks.md` 与结果同步
- [x] `README.md` 更新（22 类 / 15 补丁器 / 23 项门禁 / 108 段冒烟 / 野战档案）
- [x] `MEMORY.md` 压缩至 3,000 字符内（2,596 字符）
- [x] `pre-push` 增补 My-Blog / litemall 基线
- [x] 本报告落盘并推送远端 `main`

---

## 6. 经验与边界

**经验**

1. 真实项目的第一价值不是"多扫出几条"，而是**打回规则的宽形态**。本轮 6 条
   确认 FP 全部来自真实代码的合法形态（公开内容路由、校验谓词、同名局部变量、
   `Cookie.getValue`、书籍正文字段），没有一条能靠靶场夹具提前想到。
2. 配置继承要按"受影响路由"计数：4 份 CORS 配置 = 592 条路由暴露面，不是
   592 个独立漏洞；报告必须把两者分开，否则数字会吓人也会失真。
3. 规则层 True 不等于漏洞：RuoYi 管理员建表、eladmin 找回密码流程必须回读
   角色/流程语义，单列不静默——这正是"0 确认误报"能成立的前提。
4. 文件级密钥普查补上了入口切片的盲区；但它也说明"只扫路由"的边界仍然存在。

**边界**

- 入口切片之外、又不像配置文件的密钥仍可能漏；
- 全局 CORS 的 592 条是配置继承计数，不是 592 个独立缺陷；
- 模型层未参与本轮数字；mall 的 2 条候选复核结果不在本报告内；
- Windows 沙箱受限模式禁止 `ProcessPoolExecutor` 管道，`--jobs 4` 需完全权限；
  这是环境约束，不是代码缺陷。

---

## 7. 下一轮建议

1. **配置/依赖清单扫描**：把 `pom.xml` / `package.json` / `requirements.txt`
   的已知 CVE 版本比对并入 `scan --auto`（fastjson 版本已是既有机制，可推广）。
2. **跨文件主体链再扩**：VAmPI 的 `resp['sub']` 与 litemall `@LoginUser` 已覆盖，
   下一批补 Spring Security `@AuthenticationPrincipal` 的 `UserDetails` 子类。
3. **模型层闭环**：把 mall 的 2 条真候选跑完 Cite-Before-Verdict + Skeptic，
   补齐 P1 的实弹样本。
4. **CORS 修复器**：把"通配 + 凭据"配置改成显式白名单，纳入第 16 类补丁器。

---

*生成：2026-10-24｜基线 `575be69`｜数据 `benchmarks/results/wild_hunt.json`*
