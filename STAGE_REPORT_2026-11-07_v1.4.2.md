# STAGE REPORT · v1.4.2（M333–M336：裸路由收益、装饰器净化、新猎场扩量）

> 日期：2026-11-07 ｜ 基线：v1.4.1（7063b9a）
> 结论：M330 的 5 条 mall4j“新命中”中 3 条已被公开 CVE 覆盖，其余是
> admin/AuthFilter 或登录后业务入口；扩量 8 仓的 4 条机器 A 经人工精核
> **全部降级**，本轮真实可交单 A = **0**。路由误提与 HA/CLI 噪声已修。

## 一、M333：mall4j 9 条命中（4 → 9）

### 1.1 新增 5 条的去向

| 入口 | 结论 |
| --- | --- |
| DeliveryController.checkDelivery | **CVE-2026-102363**（未授权物流轨迹泄露，已公开） |
| FileController.uploadElementFile | **CVE-2026-102366**（admin 任意文件上传 XSS，已公开） |
| FileController.uploadTinymceEditorImages | **CVE-2026-102366**（同根因） |
| SysMenuController.listChildrenMenu | yami-shop-sys + yami-shop-security-admin；AuthFilter 路径 /*，仅排除登录/swagger，需 admin token |
| HotSearchController.info | yami-shop-admin；同上，需 admin token |
| UserAddrController.getUserAddrPage | yami-shop-admin；同上，admin 读取地址，属于后台权限面 |
| UserAddrController.getById | 同上；admin 读取任意地址，非未授权 |

其余两条旧的 review 项：

- AreaController.listByPid：/p/area/listByPid 在 API 适配器的 /p/* 登录过滤内，
  返回地区字典，不是敏感数据。
- UserCollectionController.addOrCancel：/p/user/collection/addOrCancel 在
  /p/* 登录过滤内；返回 Void，无 HTML 回显，xss 为假阳。

### 1.2 查重种子收紧

原 known_public_cves.json 对 mall4j 的两条 CVE 用 unit:"" 覆盖整仓，会把上述
任何入口都一律判 DUPLICATE_CVE，反而遮蔽其余真实入口。已收紧为：

- CVE-2026-102363 → DeliveryController.checkDelivery
- CVE-2026-102366 → FileController.uploadElementFile /
  FileController.uploadTinymceEditorImages

实测：这 3 个入口命中对应 CVE；SysMenuController.listChildrenMenu /
UserAddrController.getById 不再被整仓种子遮蔽（离线为 UNKNOWN）。

### 1.3 B 板 27 条快筛

- 27 条全部为 UNKNOWN，集中在 Home Assistant/IoT 的 authz；没有 FRESH。
- vedetta 的 api_export_job cmdi 是假阳：该路由只调用
  export_jobs.snapshot()，没有 subprocess/os.system。
- iotsploit 的 log_injection 属于低价值；local_roborock 等 admin authz
  未见未授权链。
- 结论：没有需要立刻升级为 A 的高危真洞。

## 二、M334：装饰器末段精确匹配

文件：core/slicer/web_treesitter.py。

旧实现 any(k in d.lower() for k in route_kw) 会把：

- @device_targeting_options 的 tar[get]ing 当成 GET；
- @method_decorator(..., name="dispatch") 的 dis[patch] 当成 PATCH；
- @expose(..., methods=("POST",)) 的参数字面量当成 POST；
- @post_dump 当成 POST；
- @converts("...postgresql...") 当成 POST。

改为解析装饰器末段标识符精确匹配，并排除 @click.* / @typer.*。白名单含
route/get/post/put/patch/delete/head/options/api_view/api_route/mapping/
websocket/require_http_methods/detail_route/list_route/expose/method_decorator。

这带来必须同步的真实基线变化（不是判据放宽）：

| 靶场 | 旧 → 新 | 原因 |
| --- | --- | --- |
| flask-realworld | 26 → **18** | 去掉 8 个 marshmallow @post_dump，真实路由 18 |
| django-oauth-toolkit | 18 → **19** | @method_decorator CBV 保留，URL 视图补全 |
| flask-admin | 15 → **25** | @expose 真路由补回；@action 菜单动作/@converts 不再混入 |
| sanic | 15 → **14** | 只保留真实路由 |
| litestar | 33 → **34** | 同上 |

benchmarks/results/SCOREBOARD.md 已按当前 results/*.json 重建；
benchmark_flask_rw.py 的 MIN_UNITS 更新为 18。

### shelly-manager 的 sqli=True 成因

- 旧切片把 @device_targeting_options 当 GET 路由，list_devices 进入规则层。
- 源码里 scan_use_case.execute(request) 命中 Python 的裸 .execute( SQL sink；
  request 由 targets 参数构造，于是被当成“外部输入进入 SQL 执行”。
- 修复：M334 后该 CLI 文件切出 0 个 Web 单元；另在 python_sqli_verdict 中
  排除 *use_case/*usecase.execute(...)，避免业务用例调用再被当 SQL。

## 三、M335：Python 新生代词绑 Web 框架 + HA 过滤

文件：core/context/target_scout.py。

- Python 新生代词改为 fastapi/django/flask + 业务词（rag/agent/mcp/workflow/
  text2sql/chatbi/knowledge-base/lowcode/wms/mes/his/iot/report/bi/erp）。
- Java 短词全部搭配 "spring-boot" 或 mybatis-plus。
- _TOOL_LIB_RE 增加 home[-_]?assistant|hacs|custom_components|esphome。
- 增加框架 only 回退：当“框架+业务词”全为 0 时，退到 fastapi/django/flask
  （或 "spring-boot"/mybatis-plus）+ created/pushed/stars 窗口，避免 8 个
  名额无候选。

实拉：净化后候选从 1 恢复到 **43**，Home Assistant 插件不再进入实扫队列。

## 四、M336：门禁与扩量巡猎

- 新增 [313]（装饰器精确匹配 + use_case sqli）与 [314]（HA 过滤 + 框架组合词）。
- smoke_test_chains.py：**PASS，1,892 项**。
- triage_fallbacks.py --check-floor：**16/16 达标**。
- cli.py doctor：**PASS（12 段全绿）**。

扩量命令：

~~~text
python cli.py daily-hunt --languages java,python --days 21 --limit 8 \
  --max-roots 5 --cooldown-days 7 --evict-cache --repo-timeout 300
~~~

结果：**候选 43 / 实扫 8 / 跳过 1 / 失败 1 / 根因 52 / 机器 A 4 / B 48**；
recent_90d_roots=11。

### 4 条机器 A 的人工精核（全部 DEMOTE）

| 候选 | 源码事实 | 结论 |
| --- | --- | --- |
| JavaClaw OnboardingController.postStep redir | 固定前缀 redirect:/onboarding/；nextId 来自服务端步骤表 | 非开放重定向，假阳 |
| creatorhub del_account arbitrary_file_delete | 删 DB 账号；profile 清理强制 relative_to(profiles_dir)；LocalAccessMiddleware 仅 loopback+Host+同源 | 本地单用户工作台，不可远程，假阳 |
| creatorhub publish_upload unrestricted_upload | UUID 文件名，固定 ./data/uploads，无路径穿越；仅本地可访问 | 本地功能，假阳 |
| higher-kinded-j updateEmailAsync xss | 返回 User 对象，无 HTML/模板回显；example 模块 | 假阳 |

证据文件在各 pack 的 REVIEW.md。因此本轮真实可交单 A = **0**。

## 五、结论与下一步

1. mall4j 的 5 条新增命中没有未公开真洞；3 条已有 CVE，其余 admin/登录后入口。
2. shelly-manager 的 CLI 误提和 .execute 假阳已修；HA/HACS/ESPHome 不再进入候选。
3. 扩量后的 4 条 A 全是本地/示例/固定前缀假阳，说明新猎场仍需按“远程可达 +
   真实敏感操作”人工收口，不能直接按 scanner A 板提交。
4. 第 2/3 单状态不变：metasfresh 仍等人工 CNA 提交；x-springboot 私密通道
   仍待联系/提交。
