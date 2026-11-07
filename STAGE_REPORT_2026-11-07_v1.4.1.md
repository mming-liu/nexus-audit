# STAGE REPORT · v1.4.1（M329–M332：把容器实证固化进规则层）

> 日期：2026-11-07 ｜ 基线：v1.4.0（b412b12）
> 结论：oinone 正式收口为"不可利用、不交单"；M329 把单段 @PathVariable
> 豁免固化进 pathtraver；M330 支持无括号 Spring 路由并完成 x-springboot
> 本地越界写盘实证；扩量巡猎 8 仓，机器 A 1 条经人工复核为 CLI 假阳性。
> **本轮没有提交任何 CVE/Advisory。**

## 一、oinone-pamirs 收口（不交单）

- 现有 `REPRODUCTION_VERDICT.md` 已闭环：Spring Boot 3.3.13 / Tomcat 10.1.61
  / Spring MVC 6.1.21 默认配置，字面 `../` 404、`%2f/%5c` 400、双重编码因
  PathPatternParser 不做二次解码而拿不到 `../`。
- 处理：代码缺陷保留（建议修 canonical path），但**不交 CVE、不追加时间戳**。
- M329 目标：让同类"源码拼接但容器不可达"的单元从规则层直接归零，不再占
  `--max-roots` 名额。

## 二、M329：单段 @PathVariable 豁免

文件：`core/agents/rule_detectors.py`。

- 新增 `_single_segment_pathvar_params(source)`：
  - 从入口签名提取 `@PathVariable` 形参；
  - 路由里的每个 `{...}` 必须是纯单段名（`{*path}`、`{id:.*}`、
    `{id:[0-9]+}` 一律不豁免）；
  - 切片出现 `URLDecoder.decode` / `AntPathMatcher` /
    `PATH_WITHIN_HANDLER_MAPPING_ATTRIBUTE` 时不豁免。
- `pathtraver_verdict` 从 `_entry_params` 剔除这些形参；若剔除后既无
  `@RequestParam/@RequestBody` 也无 Hop DTO，直接返回 `None`（不是 False：
  代码缺陷仍在，只是不可达）。

验证：

| 样本 | 结果 |
| --- | --- |
| oinone `LocalFileClient.getStaticFile` 真实切片 | `True` → **None** |
| `@RequestParam` 路径拼接 | True |
| `@RequestBody MakerConfigEntity` → FileWriter | True |
| `@PathVariable` + `URLDecoder.decode` | True |
| `{*path}` 通配 | True |
| 16 个基准靶场地板 | 16/16 达标 |

## 三、M330：无括号 Spring 路由 + x-springboot 实证

文件：`core/slicer/java_servlet.py`。

- `SPRING_ROUTE_RE` 的括号改为可选：`@GetMapping` / `@PostMapping` 等
  无括号方法级注解现在可切片；无方法级子路径时继承类级
  `@RequestMapping` 前缀。
- 合成样例：类 `@RequestMapping("/api")` + 裸 `@GetMapping` /
  `@PostMapping` → `route_path=/api`；带参 `@GetMapping("/x")` → `/api/x`。
- 该能力让历史基准切出更多**真实**入口，基线随之更新（不是检测回归）：

| 靶场 | 旧单元 | 新单元 | 说明 |
| --- | --- | --- | --- |
| mall4j | 139 | 193 | 54 条裸路由；人工复核面 4→9 |
| spring-boot-demo | 19 | 23 | 裸路由；全局标记 23/23 |
| xxl-job | 36 | 41 | 裸路由；authz/deserial 仍 0 True |
| waynboot | 163 | 205 | 仍 0 非 CORS 误报 |

`benchmarks/results/SCOREBOARD.md` 已按当前 `results/*.json` 重建；
`benchmark_mall4j.py` 的 `REVIEW_NEEDED` 更新为 9，并修复 Windows GBK
stdout 打印 ✔/✘ 的崩溃（`triage_fallbacks.py` 同样修复）。

### x-springboot 本地实证

- 程序复刻 `GenUtils.getFileName()` 的 `moduleName` 拼接 +
  `new FileWriter(filePath + path)`，参数：
  `filePath=.tmp/gen_repro_safe`、`moduleName=../../../../../../../../pwn`。
- 编译运行：PyCharm JBR 25，`javac --release 17`（本机无独立 JDK 17）。
- 结果：`ESCAPED=true`，目标
  `C:\myFloders\git\nexus-audit\pwn\controller\SysUserController.java`
  内容 `PWNED_BY_GENUTILS_PATH`；证据后已删除该越界文件。
- 证据：`benchmarks/results/daily_hunt_packs/x-springboot_pathtraver_create/LOCAL_REPRO.md`
- 手册已补：维护者 `czx <yzcheng90@qq.com>`（2026-10-30 最近提交）、
  GitHub 私密 Advisory 入口、公开 `/security-advisories` API 返回 `[]`
  （私密通道是否开启需登录 UI 确认）。**不公开贴 PoC。**

## 四、metasfresh 状态（交给你填 CNA 前确认）

- `#27079`：state **OPEN**，仅 1 条评论（我们 2026-11-02 的 72h 追问），
  `updatedAt=2026-11-02T13:31:24Z`，维护者仍无回复。
- 远端默认分支 `new_dawn_uat`，`pushed_at=2026-11-07T03:12:44Z`，仓库活跃。
- `DebugRestController.java` 最近一次提交仍是
  `7dc152d7503cfa046cc6f4c89ef983aeb6913f89` / 2025-01-31，**未修改**。
- 因此 7 天协调窗口条件成立；MITRE CNA-LR 表单仍需你本人登录提交，助手
  不代填、不伪造 CAN。

## 五、M331/M332：门禁与扩量巡猎

- 新增 `[311]`（M329 豁免 + 保真）与 `[312]`（M330 裸路由）。
- `smoke_test_chains.py`：**PASS，1,880 项**。
- `cli.py doctor`：**PASS（12 段全绿）**。
- `triage_fallbacks.py --check-floor`：**16/16 达标**。

扩量命令：

~~~text
python cli.py daily-hunt --languages java,python --days 21 --limit 8 \
  --max-roots 5 --cooldown-days 7 --evict-cache --repo-timeout 300
~~~

结果：**候选 27 / 实扫 8 / 跳过 18 / 失败 0 / 根因 28 / 机器 A 1 / B 27**；
`recent_90d_roots=12`（M326 的最近提交提权实际生效）。

### 唯一 A 的人工复核：DEMOTE

- 机器判定：`shelly-manager` / `sqli` / `list_devices` @
  `packages/cli/src/cli/commands/device_commands.py:100`。
- 实际：第 100 行是 Click 装饰器 `@device_targeting_options`，
  `list_devices` 是本地 CLI 命令，不是 HTTP 路由，也没有 SQL 拼接。
- 结论：**假阳性，不交单**。证据见
  `benchmarks/results/daily_hunt_packs/shelly-manager_sqli_list_devices/REVIEW.md`。
- 因此本轮真实可交单 A = **0**；新猎场产出集中在 Home Assistant/IoT 的
  authz UNKNOWN（27 条 B），需要下一轮按 route 精核，不能直接提交。

## 六、回归与已知边界

- M330 改变的是"切出更多真实入口"，不是放宽判据；所有新增单元仍 0 True
  （mall4j / springboot-demo / xxl-job 的 authz/deserial 均为 0）。
- M329 只豁免"容器层物理阻断"的单段 @PathVariable；带 `URLDecoder.decode`、
  通配、RequestParam、RequestBody 的路径保持原判。
- 已知未修：shelly-manager 的 CLI 误报来自通用 sqli 判据把装饰器/参数当
  SQL 链，下一轮可单独收口，不影响本轮门禁。
- oinone 的源码缺陷仍建议上游修 canonical path；本轮只做定级收口。

## 七、下一步

1. 人工提交 metasfresh CNA-LR；表单 6 项用你右侧文档第 2 节，提交前再跑一次
   `gh issue view 27079` 确认仍无回复。
2. x-springboot 走私密 Advisory；若作者已改 `GenUtils.java:152` 则转
   PATCHED_UPSTREAM。
3. 下一轮扩量优先精核 27 条 B 中的 Home Assistant/IoT authz，重点看
   `@login_required`/中间件覆盖与对象归属，不要直接按 scanner 判 True 提交。
