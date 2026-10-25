# 阶段报告 2026-10-25a —— M103 → M117（15 模块纯增量连跑）

> 一句话：**21 个真实开源仓库 / 6,743 个入口 / 84 个独立根因 / 84 份 GHSA 披露草稿
> （带一键复现命令与总目录）/ 规则层 0 误报**；37 项离线门禁全绿，
> 冒烟 `[1]`–`[150]`，`doctor` 七段自检 exit 0。

---

## 一、两个遗留缺口的收口（M103 / M104）

上一轮诚实结论里挂着的两条召回/复核缺口，这轮都用**补证据**而不是放松判据解决了。

### 缺口一：Thymeleaf 视图名注入（M89 时判不了）

M89 的结论是"方法级切片里没有类级 `@Controller` 证据，判不了"。M103 没有去猜，
而是**让切片器把这条证据写进头部**：

```
// Full-Route: /vul/ssti/vul1
// Controller-Kind: @Controller          ← 新增
```

判据随即变成三件可核对的事实：① 头部 `@Controller`（不是 `@RestController`）；
② 方法自身无 `@ResponseBody`；③ `return "<字面量>" + <形参>` 且不是 `redirect:`。

实测结果（这是缺口闭合的硬证据）：

| 仓库 | 样本 | 判定 |
|---|---|---|
| Hello-Java-Sec | `thymeleafVul` / `thymeleafSafe` | **True / False** |
| Hello-Java-Sec | `fragmentVul`（`::` 片段选择器）/ `fragmentSafe`（多一个 `@ResponseBody`） | **True / False** |
| JavaSecLab | `vul1` / `vul2` / `safe1`（白名单） | **True / True / False** |
| 8 个 Java 生产仓（含 jeecg 487 入口） | 全部 | **0 True** |

### 缺口二：mall4j 的 9 条"公开目录查询"

第一版实现用的是**否定式**判据（"不含 user_id 就算公共目录"），结果把冒烟里三条
本该 True/None 的护栏全翻成 False —— 否定式证据在安全判定里永远不够用。改成
**正面认出目录**（路由前缀或 Service 名命中 prod/notice/captcha/category…）+ 无写动作
+ 非管理端 + 不碰私有资源，四件缺一不可：

- 6 条公开查询（商品详情 / 公告 / 验证码×2 / 销量榜）→ 确定性 **False**
- 按单号查物流（`orderService`）→ 仍 **True**（真 IDOR，猜单号就能读别人物流）
- 后台两个未鉴权上传 + 1 条收藏 XSS → 留在 `REVIEW_NEEDED`（9 → 4）

## 二、新的规则与补丁（M105 / M106）

- **第 25 类 `header_injection`（CWE-113）**：`setHeader`/`addHeader` 的值里直接
  出现请求读取或裸形参，且没有 `URLEncoder.encode`/`safeHttpHeader`/`replaceAll("[\r\n]")`
  这类清洗，也没有前置 `if (!check(x)) throw` 守卫。
  精度关键在**先剥掉方法调用链**再取标识符 —— 否则 `file.getName()`、`data.length`
  里的 `file`/`data` 会被当成形参。12 个 Java 仓实测只有 2 条 True，全部真阳。
- **第 19/20 类补丁器**（20 类里程碑）：视图名白名单守卫、响应头 CRLF 清洗。
  两个补丁都刻意避开了"看起来修了、实际改坏业务"的写法：不用 `@ResponseBody`
  （会把渲染视图改成输出字符串，页面白屏），头值清洗**整体加括号**（不加只洗最后
  一段拼接，等于没修）。

## 三、四个新野战仓（M107–M110）：21 仓 / 6,743 入口

| 仓库 | 入口 | 独立根因 | 这轮逼出来的机制 |
|---|---|---|---|
| **flaskr**（Flask 官方教程） | 8 | 0 | **堆叠装饰器**：`@bp.route` 与 `def` 之间隔 `@login_required`，旧逻辑只认紧邻上一行 → `create/update/delete` 三条路由**根本不在切片里**（5 单元而非 8） |
| **Synthetix V3** | 1,264（生产范围） | 0 | 谓词式鉴权 `require(isOwner())`、反向条件 `if (X != sender) revert`、身份别名 + 取反校验调用 `if (!_isApprovedOrOwner(_msgSender(), id)) revert` |
| **sushiswap-zapper** | 75 | 0 | 0.5.x 的 `modifier onlyOwner { require(isOwner(), …) }` 三层套娃 —— 谓词判据的来源 |
| **jeecg-boot** | 458 | 24（冻结） | **全局鉴权拦截器**：xxl-job 打包进来的 160 个后台接口靠 `permissionInterceptor` 统一拦，方法体里零主体判断 |

顺带修掉一个**静默失效**：`_sol_block_body(text, close + 1)` 要求下标正落在 `{`
上，而 `)` 与 `{` 之间几乎总有空白 —— 块体永远取到空串，判定不报错、只是永远
False。新增 `_sol_block_body_at` 先跳空白。

jeecg 的 24 个根因逐条核查后是它已知的公开问题（xxl-job 反序列化、登录模块 MD5、
Mapper `${}` 拼接、OAuth 回调开放重定向、config 内置 JWT 默认密钥），按类目**冻结
计数**，涨一条就红。

## 四、交付物工程化（M111 / M112 / M117）

- **披露包总目录**：84 份草稿按 CVSS 降序汇总成一份 `INDEX.md`，每份草稿新增
  **Quick Reproduction Command** 小节（三条命令都是现在就能跑的形态 —— 写一条
  不存在的 `--unit` 出来比没有这一节更糟）与 **[Auto-Fix Verified]** 徽章。
- **GitHub PR 行级 review 载荷**（`pr-scan --gh-comments`）：符合 REST API 的
  `comments[]`，带 ```suggestion 一键采纳补丁。三条硬约束都处理了：POSIX 相对路径、
  同一 `(path,line)` 合并（GitHub 会 422）、**多 hunk 的 diff 不给建议**（行数对不上
  会把文件改坏）。
- **doctor 第七段**：披露包完整性 —— 草稿数 == 根因总数、INDEX 零断链、CVSS 降序。

## 五、门禁与不变性

| 项 | 数值 |
|---|---|
| `run_all --offline --jobs 4` | **37 PASS / 0 FAIL / 0 SKIP** |
| 冒烟断言 | `[1]`–`[150]` |
| `cli.py doctor` | exit 0（25 类规则 / 20 类补丁器 / **7 段**自检 / 正则卫生零问题） |
| 野战场 | 21 仓 / 6,743 入口 / 1,427 路由级 P0 / 84 根因 / 84 草稿 / **0 条 benchmark 误报** |
| Solidity 生产库 | 七仓（Compound V2/V3、Uniswap V3、OZ、Aave V3、Synthetix、sushiswap）**全 0 True** |
| M52 退回桶 | 526 → **518**（M108 三个谓词判据让 8 条从 None 变确定性结论） |

## 六、本轮**未**完成的部分（如实登记）

| 项 | 状态 | 说明 |
|---|---|---|
| M113–M116 边界冒烟 `[151]`–`[154]` | **未做** | 计划里是四组高密度边界夹具（`@Controller` vs `@RestController` 成对、`check_author=False` 判反、Solidity 库级权限、21 仓披露包断链）。当前 [141]/[146]/[149] 已覆盖其中大部分断言点，但**没有专门的负向夹具** |
| `[155]`（doctor 第七段冒烟） | **未做** | doctor 第七段本身已实现并 exit 0，缺的是把它写进冒烟的固定断言 |
| 冒烟编号跨度 | `[1]`–`[150]` | 与计划里承诺的 `[1]`–`[155]` 差 5 条 |

这三项都不影响 37 项门禁与 21 仓零误报的结论，但按"数字不许注水"的规矩，
它们必须写在报告里而不是被含糊带过。

## 七、复现

```bash
python benchmarks/run_all.py --offline --jobs 4          # 37 项门禁
python cli.py doctor                                     # 七段自检 exit 0
python benchmarks/wild_hunt.py --advisory-dir benchmarks/results/advisories
python cli.py pr-scan --base origin/main --gh-comments pr-review.json
python cli.py matrix                                     # 25 类 × 三语言四维矩阵
```
