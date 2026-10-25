# 阶段报告 2026-10-25b —— M119 → M134（16 模块纯增量连跑）

> 一句话：**25 个真实开源仓库 / 6,868 个入口 / 94 个独立根因 / 94 份 GHSA 披露草稿
> / 规则层 0 误报**；41 项离线门禁全绿，冒烟 **`[1]`–`[170]`**，
> `doctor` **八段**自检 exit 0。

---

## 一、四个新野战仓（M119–M122）

| 仓库 | 入口 | 独立根因 | 这轮逼出来的机制 |
|---|---|---|---|
| **Uniswap V2** | 29 | 0 | 整数型状态互斥锁 `uint unlocked = 1 → 0 → 1` —— M79 的三段式判据挂"状态翻转"而非字面量，整数形态天然通过 |
| **fastapi-realworld** | 19 | 0 | **跨行装饰器**：`@router.post(\n "",\n …)` 让 19 条路由只切出 6 条 |
| **django-realworld** | 11 | 2 | **DRF 类视图**：`as_view()` / `router.register` 两条通道 + `permission_classes` 类属性注入 |
| **eladmin（JPA）** | 66 | 10 | 与 eladmin-mp 双生对照；`crypto` 证据归属修正（4 条 Hop 3 误报清零） |

### M119 的反向锚点（这条比"0 条 True"重要）

摘掉 `swap`/`mint`/`burn` 的 `lock` 修饰符后，`with=False → without=None`。
我最初把锚点写成"去锁后必须判 True"，跑完发现断言错了：摘锁后 CEI 证据不足
本来就该退 None。锚点改成断言"**失去保护**"，并在注释里写清为什么 ——
一个把"缺证据不下结论"逼成"必须判 True"的锚点，是假锚点。

### M121 的读写分治

DRF 把鉴权声明放在类属性上，方法体里一个字都没有。判据按动作分两类：

- **读**（`list`/`retrieve`/`get`）→ False（公开读被允许）
- **写**（`update`/`destroy`/…）且只要求 `IsAuthenticated` → **True**（BOLA）
- `IsAdminUser` / `IsOwnerOrReadOnly` / 方法体比对 `request.user` → False
- **先取现成资源**（`self.queryset.get(...)`）才谈得上越权 —— `create`、
  "收藏"、"关注"、登录注册不取现成资源，判 True 只会造假阳

结果：10 个 DRF 动作，**恰好 1 条真 BOLA**（`ArticleViewSet.update`
缺 `IsOwnerOrReadOnly` 且直接 `queryset.get(slug)` 拿别人的文章）。

### M122 踩到的最隐蔽的坑

`entry_body()` 会**剥掉注释**，而跨文件/Hop 证据段恰恰是**用注释行分隔**的
（`// 来自 EncryptUtils.java:46 [Hop 3]`）。剥完注释，证据段的**代码**就混进
body 了 —— 于是别的方法里的 `Cipher.getInstance("DES/…")` 被算到了当前入口头上。
修法：先对**原始 source** 按标记切段，再看入口那一段。

## 二、两个新规则类目（M123/M124）

- **第 26 类 `mass_assignment`（CWE-915）**：整包灌入（`User(**request.json)` /
  `BeanUtils.copyProperties(map, u)`）+ 目标含权限字段 + 无白名单，三件缺一不可。
  三参重载 `copyProperties(m, u, "isAdmin")` 是 Spring 的官方排除列表 → False。
- **第 27 类 `bad_randomness`（SWC-120）**：区块变量 + 组合成随机数 + 流向价值转移
  ⇒ True；`require(block.timestamp >= t)` 只做冷却期 ⇒ False；VRF/commit-reveal
  ⇒ False。判据顺序是坑：先把"冷却期"挡掉，再看 `transfer`，否则
  `require(时间) → transfer` 会被误判成伪随机。

实测：smartbugs-curated 上 **7 条真阳**（`etheraffle.chooseWinner`、
`lottery.makeBet`、`open_address_lottery.participate`、`ether_lotto.play` 等，
全是 lottery/raffle 合约）；OpenZeppelin / Compound / Aave / Synthetix /
Uniswap / Comet 上 **0 条**。

## 三、第 21/22 类补丁器（M125）

- **21：`_fix_java_mass_assignment`** —— 补 Spring 三参重载的排除列表
  `copyProperties(src, dst, "id", "role", "isAdmin", "password")`。
  不做全字段白名单：那是业务重构，不是确定性补丁。
- **22：`_fix_java_weakrand`** —— `new Random()` → `new java.security.SecureRandom()`。
  同一接口（`SecureRandom` 是 `Random` 的子类），调用方一行不用改。

两个补丁都走"命中→改→重切片→规则翻 False→finally 字节级还原"的闭环。

## 四、两个交付能力（M126/M127）

- **跨仓库同源缺陷聚类**：按「类目 + 根因类型 + 框架组件」聚类，`global-config`
  根因按**配置体签名**归并（它的 `file` 存的是代表入口，不是配置类）。
  94 个根因 → 51 个簇、**8 个跨仓共现**；计数守恒是硬约束。
- **GitLab SAST v15**（`scan --gitlab-sast`）：与 SARIF 并列为第二条 CI 交付路径。
  三个拒收点都按"错就拒收"处理 —— severity 枚举映射、相对 POSIX 路径、
  **确定性 uuid**（每次变 uuid 会让 GitLab 把同一漏洞当新增重复计数）。

## 五、冒烟 `[170]` 里程碑：八大交付格式大联考

一次演练同时校验 8 种产物：Markdown / HTML / SARIF / GitLab-SAST /
Mermaid 污点图 / PoC / 自动补丁 diff / GHSA 披露草稿 + PR review 载荷，
并断言**演练后目标仓库工作树零污染**。

## 六、门禁与不变性

| 项 | 数值 |
|---|---|
| `run_all --offline --jobs 4` | **41 PASS / 0 FAIL / 0 SKIP** |
| 冒烟断言 | **`[1]`–`[170]`**（920+ 项） |
| `cli.py doctor` | exit 0（27 类规则 / 22 类补丁器 / **8 段**自检） |
| 野战场 | 25 仓 / 6,868 入口 / 1,504 路由级 P0 / 94 根因 / 94 草稿 / **0 条误报** |
| Solidity 生产库 | 八仓（Compound V2/V3、Uniswap V2/V3、OZ、Aave V3、Synthetix、sushiswap）**全 0 True** |
| 覆盖矩阵 | 27 类 × 三语言，缺口 41 处（已冻结，涨一条就红） |

## 七、复现

```bash
python benchmarks/run_all.py --offline --jobs 4          # 41 项门禁
python cli.py doctor                                     # 八段自检 exit 0
python benchmarks/wild_hunt.py --advisory-dir benchmarks/results/advisories
python benchmarks/cross_repo_clusters.py                 # 跨仓同源聚类
python cli.py scan <repo> --auto --offline \
       --sarif out.sarif --gitlab-sast gl-sast-report.json
```
