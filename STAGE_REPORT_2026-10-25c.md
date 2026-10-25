# 阶段报告 2026-10-25c —— M135 → M150（16 模块纯增量连跑）

> 一句话：**30 个真实开源仓库 / 8,364 个入口 / 98 个独立根因 / 98 份 GHSA 披露草稿
> / 规则层 0 误报**；**47 项**离线门禁全绿，冒烟 **`[1]`–`[185]`（1,072 项断言）**，
> `doctor` **九段**自检 exit 0，跨仓聚类 8 个多仓共现簇、计数守恒。

---

## 一、五个新野战仓（M136–M144）—— 30 仓里程碑

| 仓库 | 语言 | 入口 | 独立根因 | 这轮逼出来的机制 |
|---|---|---|---|---|
| **MakerDAO dss** | Solidity | 234 | 0 | `auth` 授权映射（`wards[msg.sender] == 1`）与合约内联 `add/sub` 回卷封装 |
| **flasky** | Python | 39 | 0 | 无括号装饰器入索引 + `// Auth-Guard:` 证据头 + 公开只读面 |
| **mall-tiny** | Java | 40 | 1 | Spring Security/JWT + MyBatis-Plus 零误报；全局 CORS 折叠成 1 个根因 |
| **OZ Upgradeable** | Solidity | 1,119 | 0 | `initializer`/`reinitializer`/`onlyInitializing`/`onlyProxy` 语义边界 |
| **My-Blog-layui** | Java | 64 | 3 | 与 M63 的 My-Blog 双生对照（MD5 口令 ×2 + 模板 `[[${…}]]` 回显 ×1） |

语言分布达到 **Java 13 / Python 7 / Solidity 10 = 30**。五个新仓全部
`git clone --depth 1` 实跑，不是"登记了但没跑"。

## 二、四处机制修正（都是被真实代码逼出来的）

### M136：`wards[msg.sender] == 1` 不是余额检查

dss 的授权写在自己的映射里：

    modifier auth { require(wards[msg.sender] == 1, "Vat/not-authorized"); _; }

现有判据 `_SOLIDITY_MSGSENDER_MEMBER_RE` 只认"裸真值 / `!= 0` / `&&`"三种形态，
**显式等值**写法整个漏掉 —— `rely`/`deny`/`file`/`cage` 会被判成"缺访问控制"
（把安全判成漏洞，方向错误）。新增判据要求同时满足两条：槽位是**调用者键控**的
（`<映射>[msg.sender]`）+ 与**真值常量**做**恒等**比较。刻意只认 `==`：
`require(balance[msg.sender] >= wad)` 是余额充足性检查，把它算成授权会吃掉
真正的越权（冒烟 `[174]` 专门锁了这条边界）。

算术侧同理：dss 不用 SafeMath，而是手写

    function _add(uint x, int y) internal pure returns (uint z) {
        z = x + uint(y);
        require(y >= 0 || z <= x);   // 回卷回验
    }

既不是 `.add()` 也不是 `require((z = x + y) >= x)` 的字面形态，判据只能退 None。
新增"结果变量被紧随其后的 require 与操作数比大小"这一机制，`_add`/`_sub` 由
None → **False**（有证据的安全），而真漏洞形态（无回验的算术）一条没放。

### M137：鉴权声明在装饰器上，不在函数体里

flasky 的 `@admin_required` / `@permission_required(...)` 是**无括号装饰器**，
而 `ROUTE_DECORATOR_RE` 要求装饰器带 `(...)` —— 它们从来没进过索引，
`edit_profile_admin` 的守卫声明整条丢失。三处修：

1. 无括号装饰器也进装饰器块（仍按"紧邻 def 的连续装饰器块"限定范围）；
2. 切片头部写 `// Auth-Guard: <名字>`，并把装饰器**实现体**从仓库里找出来贴进
   证据段 —— 名字不算证据，`abort(403)` / `return forbidden(...)` 才算；
3. **公开只读面**：`/user/<username>`、`/posts/<id>/comments/` 这类分页列举
   不是对象级越权面。口径与 Java 侧 `_is_public_catalog_read` 一致：必须先
   **正面认出**路由指向公开内容 + 无写动作 + 不碰私有资源；认不出照旧判 True/None。

反向锚点：把 `edit_profile_admin` 的守卫证据整段摘掉后，authz 从 False 翻成
**True** —— 证明判 False 靠的是那道守卫。

### M138：全局 CORS 是 1 个根因，不是 40 个

mall-tiny 的 `GlobalCorsConfig` 同时 `addAllowedOriginPattern("*")` 与
`setAllowCredentials(true)`。40 条路由级命中全部来自同一份配置文本，按 waynboot
的既有口径折叠成 **1 个全局根因**，并要求承载组件唯一（`[cors-config] GlobalCorsConfig`）。
锚点用**真正的修法**（通配 → 显式白名单）验证：换成 `addAllowedOrigin("https://…")`
后必须翻 False；摘掉整段装配证据后必须退 None（缺证据不是"有漏洞"）。

### M143：一次性初始化 ≠ 缺授权

OZ 可升级库里 553 个 `onlyInitializing`、25 个 `initializer`、5 个 `reinitializer`。
`initializer` 只能成功执行一次，它的风险形态是**部署竞态**，与"任意时刻可调的
特权入口缺授权"不是同一类判断 —— 判 True 是把缺证据当漏洞，判 False 又会洗白
真·抢跑问题。按铁律**退 None**，并在判据里写明原因。

另外两处边界：`fallback`/`receive`/`constructor` 不写 `function` 关键字，作用域
定位失败会让"内部不可达"误判成 False（把问题洗成安全）；Foundry 的 `*.t.sol`
测试合约与 `*.s.sol` 脚本不上链，切片层按**文件后缀**排除（dss 的测试放在
`src/` 里，按目录排除会漏）。

## 三、三个新规则类目 + 三个新补丁器（M139–M142）

| 类目 | CWE | 判 True | 判 False |
|---|---|---|---|
| 28 `unsafe_reflection` | CWE-470 | 反射名字来自入口形参/请求取值且无白名单 | 字符串字面量、`ALLOWED_*.contains(x)`、`x in ALLOWED`、`switch` 白名单 |
| 29 `zip_slip` | CWE-22 | `ZipEntry.getName()` 流进路径/输出流无前缀校验；`extractall` 无 `filter` | `getCanonicalPath()/normalize()` + `startsWith`；PEP 706 `filter="data"` |
| 30 `delegatecall_untrusted` | CWE-829 | 目标来自形参（或本函数刚写入的槽）且无保护 | `address(this)`、ERC-1967 `_implementation()`、`onlyOwner`/`auth`/`onlyProxy`、一次性初始化、顶层无条件 `revert` 的演练函数 |

补丁器 #23/#24/#25 都走"命中 → 改 → 重切片 → 规则翻 False → finally 字节级还原"：

- **#23**：反射调用前插 `Set` 白名单守卫（保住动态性，只收窄取值集合）；
- **#24**：`new File(dest, entry.getName())` 之后插规范化前缀校验；Python 侧
  `extractall(dest)` → `extractall(dest, filter="data")`；
- **#25**：`target.delegatecall(...)` 前插 `require(target == address(this))`。

三个补丁的产物都能被**自己的判据**复核（冒烟 `[176]`–`[178]` 真跑临时仓库验翻转）。

## 四、两处门禁闭环（M135 / M145）

- **M135 跨仓聚类对账**：`cross_repo_clusters.py --check` 断言"簇内根因数之和 ==
  采集的独立根因总数"与"多仓共现簇 ≥8"。已接进 `run_all` 第 47 项与 `doctor`
  第 `[9/9]` 段 —— 同一断言两个入口。当前 **98 根因 / 53 簇 / 8 个多仓簇**（恰好落在门禁下界上 —— 下界不是摆设）。
- **M145 供应链 × 静态交叉印证**：30 仓的构建清单（Maven + Python requirements）
  对到人工维护的 advisory 表，**3 个仓命中已知 CVE**，其中 **2 个是"双重实锤"**
  （DjanGoat、django-realworld：组件 CVE 与代码级 P0 同时成立）。flasky 有 6 条
  组件 advisory 但代码侧 0 根因，如实记作"仅组件"。

## 五、冒烟 `[171]`–`[185]` 与 1,000+ 断言

15 组新断言、共 **1,072 项已执行断言**（不是静态调用点计数 —— `check()` 里加了
计数器，`[185]` 拿它做里程碑判据）。覆盖：三个新规则的正反例、M136/M143 的
机制边界、三个补丁器的重切片翻转、flasky 守卫证据头、`--synth-poc` 零副作用、
30 仓语言分布、聚类对账、供应链交叉印证、门禁/类目/补丁器数量总锚。

## 六、诚实的偏差清单（不藏）

1. **`zip_slip` 在 30 仓里 0 覆盖**：没有任何仓做解压落盘。矩阵如实显示三门语言
   全空，正反例由冒烟夹具锁定 —— 不拿合成语料把矩阵格子涂绿。
2. **RuoYi 的 `shiro.version = 3.0.0`** 不命中任何 advisory：这个版本号在
   Shiro 上游不存在（国内脚手架的常见手写版本），数值比较 3.0.0 > 1.7.1 不落在
   受影响区间。报告如实记"未命中"，不硬凑 CVE。
3. **OZ Upgradeable 的两个口径**：`scan` 报 1,119 入口（排除 mocks），
   `benchmark --strict` 报 2,017 入口（含 mocks）。两者都写清在哪本账上。
4. **五新仓需另克隆**：`reference_repos/*` 在 `.gitignore` 里，`run_all` 用
   `need` 守卫把它们标成 SKIP 而不是 FAIL；本机已全部克隆并实跑。

## 七、验收数字

| 门禁 | 结果 |
|---|---|
| `run_all.py --offline --jobs 4` | **47 PASS / 0 FAIL / 0 SKIP**（并发段 709s + 冒烟 153s） |
| `smoke_test_chains.py` | `[1]`–`[185]` 全绿，**1,072 项断言** |
| `cli.py doctor` | 九段全绿，exit 0（30 类规则 / 25 类补丁器） |
| `cross_repo_clusters.py --check` | 98 根因 / 53 簇 / **8 个多仓簇** / 计数守恒 |
| `advisories/INDEX.md` | 30 个仓目录 / **98 份草稿** / 零断链 / CVSS 9.8→4.3 降序 |
| 规则层误报 | **0**（`benchmark_* --strict` 30/30 exit 0） |
