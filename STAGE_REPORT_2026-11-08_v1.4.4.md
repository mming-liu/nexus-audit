# STAGE REPORT · v1.4.4（M341–M344：第 4 单封箱、星标提纯、全噪退还）

> 日期：2026-11-08 ｜ 基线：v1.4.3 + 定时巡检（b0042c5 → 7e91c2d）
> 结论：WorkFlow-Engine SQLi 完成证据封箱与鉴权定级（PR:L / 8.8）；
> 星标与本地插件过滤收紧；全噪仓退还实扫名额。高星标巡猎唯一新扫仓的
> 5 条 A 全是 MyBatis-Plus 参数化/类型化反序列化假阳，本轮真实新 A = 0。

## 一、M341：第 4 单 WorkFlow-Engine 封箱

### 1.1 提交对齐

当前 main 历史：

    b0042c5 M340（M337-M340，smoke 1,911）
    7e91c2d M323/M324 续（MiniMax 标量 find + funchole :name 绑定，smoke 1,914）

7e91c2d 是 b0042c5 的直接后继，两边的改动都在 main 上，无分叉。
工作树在 v1.4.4 开始前干净。

### 1.2 /vue/* Filter 定级

application.yml：protectedUrlPatterns: /vue/*。

Digital-Infrastructure 的 Y9Oauth2ResourceConfiguration.java：

    FilterRegistrationBean<Y9Oauth2ResourceFilter> filterBean = ...
    filterBean.setUrlPatterns(y9Oauth2ResourceProperties.getProtectedUrlPatterns());

这是 Servlet URL pattern，/vue/* 是前缀映射，覆盖
/vue/doing/doingList4All 等嵌套路径；不是 Filter 内部的单段
AntPathMatcher。Y9Oauth2ResourceFilter.doFilter 在无 access_token 时
直接 401，introspection 失败/过期也 401。

因此定级：PR:L / CVSS 3.1 8.8 High（已登录普通用户可注入），
不是 PR:N / 9.8。@FlowableLog(... ADMIN) 只是审计日志，不是权限注解。

### 1.3 本地拼接复现

benchmarks/results/daily_hunt_packs/WorkFlow-Engine_sqli_doingList4All/sqli_repro.py
复刻 Y9TableServiceImpl.handleLikeCondition 的字符串操作：

    PAYLOAD=' OR 1=1 -- 
    WHERE= AND T.NAME LIKE '%' OR 1=1 -- %'
    SQL=... AND T.SYSTEMNAME = ? AND T.NAME LIKE '%' OR 1=1 -- %' ...
    PREDICATE_BREAKOUT=True

LOCAL_REPRO.md 留证。三条路由共用同一根因，已合并进同一份
SUBMISSION_PLAYBOOK.md：一个 CVE、三条 affected endpoints，不拆单。

### 1.4 披露状态

- 同仓历史：CVE-2026-102616、CVE-2026-110118。
- 本根因 dedup：前两条 ZERO_RECORD_FRESH，第三条外部源失败为 UNKNOWN。
- 私密渠道：GitHub /security/advisories/new；维护者
  shidaobang <shidaobang@risesoft.net>（2026-11-06 commit）。
- 尚未提交任何外部 CVE/Advisory。

## 二、M342：星标与本地插件/练习仓

target_scout.py：

- scout_daily() 默认 min_stars 150 → 300；
- NEW_GEN_STARS 80 → 150 下限（新生代仍保留 150..5000）；
- TRADITIONAL_STAR_BUCKETS → (300,1000) / (1001,5000)；
- _TOOL_LIB_RE 增加 comfyui|sd-webui|stable-diffusion|gradio|
  streamlit|jupyter|notebook|mcp-server（Home Assistant 之前已有）；
- _GLUED_STUDY_RE 覆盖 -study / _study / -learn / _learn；
- 保留既有边界：case-study 是业务仓，不判练习仓。

验证：Java-Agent-Study、foo_learn 判教学仓；ComfyUI/Gradio 判工具库；
case-study 不误杀；默认查询 star 下限 300，新生代 150。

## 三、M343：全噪仓退还实扫名额

daily_hunt.py 新增：

- 若 fresh_total == 0 且本次所有根因的 noise_code 全是
  LOCAL_LOOPBACK_ONLY / DEMO_CONTROLLER：
  - 写 state 账本（防重复克隆）；
  - ledger 记 SKIPPED / all_local_or_demo；
  - 不递增 scanned_slots，继续下一个候选。
- 出现任何 FRESH 根因（包括 A）时不退还，避免把真洞一起跳过。

验证：20 路由全 LOCAL 的仓被跳过，后续真仓拿到 1 个实扫名额。

## 四、M344：门禁与高星标巡猎

- smoke_test_chains.py：PASS，1,924 项
- triage_fallbacks.py --check-floor：16/16
- cli.py doctor：PASS（12 段全绿）

命令：

    python cli.py daily-hunt --languages java,python --days 21 --limit 8       --min-stars 500 --max-roots 5 --cooldown-days 7 --evict-cache       --repo-timeout 300

结果：候选 22 / 实扫 1 / 跳过 19 / 失败 2 / 根因 6 / 机器 A 5 / B 1；
recent_90d_roots=5。18 个候选在 7 天冷却期内免克隆，导致实扫只有 1 个
新仓；这是冷却策略的正常结果，不是名额算法故障。

### 唯一新扫仓的 5 条 A：全部 DEMOTE

EnterpriseAgentFramework（HEAD 5203cf7）：

| 入口 | 结论 |
| --- | --- |
| InternalAgentSkillCatalogController.resolveExecution deserial | 先 requireRuntime 验签；ObjectMapper 无 default typing；类型化 record，无 gadget |
| PlatformEmbedPublicController.submitPageActionResult sqli | MyBatis-Plus eq 参数化；limit 是 safeLimit 夹过的整数 |
| PlatformEmbedPublicController.claimPageAction sqli | 同上；findPageActionEvent 参数化 |
| PlatformRunCenterConversationController.detail sqli | eq 参数化；last("limit 1") 常量 |
| PlatformRunCenterConversationController.list sqli | like/eq 参数化；last("limit " + 常量) |

因此本轮新增真实 A = 0。v1.4.3 的 WorkFlow-Engine SQLi 仍是唯一
待披露的新根因（1 根因 / 3 路由）。

## 五、结论与下一步

1. 第 4 单证据链已封箱，鉴权为 PR:L/8.8；先走私密 Advisory/邮件，
   不要按 9.8 报，也不要在公开 Issue 贴 payload。
2. 星标 300/500 与 ComfyUI/Gradio/study 过滤生效；高星标池当前大部分在
   7 天冷却期，下一轮可等冷却或换 --cooldown-days 0 做补充，不要
   把“实扫 1”误读成名额算法坏了。
3. 全噪仓退还有效，但 EnterpriseAgentFramework 这类有 5 条 A 的仓仍会
   占名额；它的 A 全是参数化假阳，说明 M343 只该退“全噪”，不能退
   “有 A 但全假阳”的仓。
4. 第 2/3 单（metasfresh / x-springboot）状态不变，仍待你本人提交。
