# 阶段报告 2026-10-24f —— M87 → M102（16 模块纯增量连跑）

> 一句话：**17 个真实开源仓库 / 4,791 个入口 / 953 条路由级 P0 / 65 个独立根因 /
> 65 份 GHSA 披露草稿 / 规则层 0 误报**；33 项离线门禁全绿，冒烟 `[1]`–`[140]`，
> `doctor` exit 0。

---

## 一、前半程（M87–M94）：补齐语法拼图与批量狩猎基础设施

| 模块 | 交付物 | 关键事实 |
|---|---|---|
| M87 | Solidity 0.8.x `unchecked` **分区** + 自定义错误中止；`benchmark_comet.py` | 435 入口 / 0 True。修的是**真判反**：`.0.8 + unchecked { counter++; }` 之后的 `uint x = total + amount;` 由编译器插桩回滚，旧判据却判 True |
| M88 | Django `urls.py` 路由表通道（`url`/`re_path`/`path` 三代）；Django 请求源识别 | DjanGoat 13 → **36** 入口 / 23 条路由证据（旧路径 9 条入口还是 `@require_http_methods(["GET"])` 里 "GET" 碰巧命中 `get`） |
| M89 | 第 **24** 类 `ssti`（CWE-1336） | Velocity/FreeMarker/Jinja2 真阳 4 条、0 误报。Thymeleaf 视图名注入**明确不判**（类级 `@Controller` 不在方法级切片，HJS 的 `fragmentVul/fragmentSafe` 只差一个 `@ResponseBody`）—— 召回缺口如实登记 |
| M90 | Python/Django 开放重定向支 + 第 **18** 类补丁器 | 六仓只命中 1 条（DjanGoat `sessions_index`）；补丁注入 `url_has_allowed_host_and_scheme` 同源校验，重切翻 False |
| M91 | `cli.py hunt`（多仓批跑 + Portfolio 大屏 + 披露草稿） | 关键设计：hunt 内部**再调一次 `cli.py scan`**，与手工命令同一条路径，大屏数字必然对得上 |
| M92 | SARIF 2.1.0 严格合规校验器（9 条硬规则） | 接进 doctor 常驻：自产 SARIF 必须零错误，故意写坏的文档必须被逐条拦住（当前 8 类） |
| M93 | `cli.py benchmark-gen`（野战仓 → 回归门禁） | 自动化的是**抄写**不是判断：docstring 明写"锁的是相对生成时刻不漂，不是真值绝对正确" |
| M94 | 冒烟 `[130]`：七件事逐项挂回既有基础设施 | 缓存指纹 / doctor 计数 / CLI 帮助 / run_all 作业表 —— 漏挂即红 |

## 二、后半程（M95–M102）：六个新野战仓实弹狩猎

### 2.1 OpenZeppelin —— 零误报极限压测（8 → 0 条 True）

OpenZeppelin 是 Web3 的标准安全基元库，任何一条 True 都是误报。逐条定位后补了五类
判据，全部是**纯增量**：

| OZ 样本 | 误报机制 | 补齐 |
|---|---|---|
| `Ownable2Step.acceptOwnership` | 身份先落局部变量 `address sender = _msgSender()` 再比较 | `_sol_identity_alias_check` |
| `Governor.relay` / `TimelockController._execute` / `Governor._executeOperations` / `GovernorTimelockAccess._executeOperations` | success 交给 `Address.verifyCallResult`，但 Address.sol 实现体不在证据段 | `_sol_handed_to_opaque` ⇒ None（不硬判 True） |
| `RelayedCall.relayCall` | `return addr.call{...}(...)` 直接上交返回值 | 语句以 `return` 开头 ⇒ checked |
| `draft-ERC7579Utils._call` | TRY 模式**刻意不 revert**（ERC-7579 规范：发事件交给上层） | `_sol_var_inspected_by_helper`：看过即消费 |
| `ERC721.safeTransferFrom` | 转发壳，权限在 `transferFrom → _update → _checkAuthorized` | `_sol_unqualified_callee_uses_sender` ⇒ None |

结果：**576 生产基元入口 / 0 True**，全库 2,558 入口同样 0 True。门禁另设
**反向锚点**（Aave `mocks` 里真的无权限 `selfdestruct` 必须判 True）—— 零误报不能靠
"全判 False"换来。

### 2.2 六个新仓的最终数字

| 仓库 | 入口 | 路由级 P0 | 独立根因 | 正确结论 |
|---|---|---|---|---|
| compound-finance/comet | 435 | 0 | 0 | 0.8.15 生产合约零误报 |
| DjanGoat | 36 | 12 | 12 | 11 条人工核查真阳 + 1 条 redir 真阳 |
| OpenZeppelin | 576（全库 2,558） | 0 | 0 | 标准库零误报 |
| Aave V3 | 275 | 0 | 0 | 逻辑库委托 + ACL 角色表零误报 |
| waynboot-mall | 163 | 163 | **1** | 163 条全部是同一份全局 CORS 通配+凭证（CWE-942） |
| mall4j | 139 | 148 | 10 | 1 个全局 CORS 根因 + 主体链全覆盖；9 条公开资源查询**如实登记**为人工复核面 |

### 2.3 后半程另外三个"消误报"的机制

- **M97 pathtraver sink 交集闸**：waynboot 6 条误报的 `new File(...)` 全在 Hop 2 的
  `ExcelUtil.getAbsoluteFile(filename, path)`，两个形参由服务端配置填充。判据：
  sink 只在辅助段时，要求与入口体标识符有交集，否则退 None。
- **M97 hardcoded_secret 跨语句收紧**：`appSecret;` 下一行的 `resultJsonStr = "https://…"`
  被拼成"幽灵赋值"。名字前加 `(?<![\w$])`、`[:=]` 两侧与值都不许跨行。
- **M97 根因折叠剥别名**：装配证据第一行带路由别名，同一份全局配置算出不同签名。

## 三、门禁与不变性

| 项 | 数值 |
|---|---|
| `run_all --offline --jobs 4` | **33 PASS / 0 FAIL / 0 SKIP** |
| 冒烟断言 | `[1]`–`[140]`，约 **780 项** |
| `cli.py doctor` | exit 0（24 类规则 / 18 类补丁器 / 16 项地板 / SARIF 自检 / 白皮书对账） |
| Solidity 五仓规则层 | **0 条 True**（Compound V2/V3、Uniswap V3、OZ、Aave V3） |
| Java 六套靶场 | HJS 59/59、JavaSecLab 40/40、msseclab 20/20 判定正确率 100% |
| Python 五套靶场 | pygoat 作者指名 10/10、vulpy 6/6、VAmPI 7/7、FastAPI 0 True、Flask CRUD 2/2 |

### 三处需要说明的数字变化（都是上升，不是放宽）

1. `M94 access_control 退回桶 531 → 526`：身份别名/身份函数/主体源三处补齐让 5 条从
   None 变确定性结论，**决策力 +5**。
2. `M130 run_all 作业表 30 → 33`：新增 OpenZeppelin / Aave V3 / waynboot-mall / mall4j
   四个靶场（扣掉合并计数）。
3. 覆盖地板 / SCOREBOARD 随各仓判定数上升而刷新（compound 444 → 445 等）。

## 四、诚实的缺口清单

| 缺口 | 原因 | 处置 |
|---|---|---|
| Thymeleaf 视图名注入（HJS `thymeleafVul` / JavaSecLab `vul1`） | 类级 `@Controller` 不在方法级切片；只按"方法无 `@ResponseBody`"判会把所有 `@RestController` 的字符串拼接判成注入（HJS 自己就摆着这对只差一个注解的样本） | 不判，代码里写清理由，登记为召回缺口 |
| `User.objects.raw("...%s..." % x)`（Django） | `.raw(` 不在 Python sqli sink 词表里 | 登记在 DjanGoat 基准 docstring，不掩盖 |
| mall4j 9 条公开资源查询（商品/公告/配送费/验证码 + 后台文件上传） | 规则层无法仅凭代码区分"公开目录"与"他人资源" | 冻结成 `REVIEW_NEEDED` 清单，涨一条就红 |
| `cli.py matrix` 34 处覆盖缺口 | 部分是探针语料没有样本（如 Java 的 crypto/hash/weakrand 入口），部分是判据确实缺失 | 矩阵把它显式化，缺口数冻结在冒烟 `[139]` 里 |

## 五、复现

```bash
python benchmarks/run_all.py --offline --jobs 4          # 33 项门禁
python cli.py doctor                                     # 自检 exit 0
python benchmarks/wild_hunt.py --advisory-dir benchmarks/results/advisories
python cli.py hunt <repoA> <repoB> ... --html portfolio.html
python cli.py matrix                                     # 24 类 × 三语言四维矩阵
python cli.py benchmark-gen <repo> --out benchmarks/benchmark_x.py
```
