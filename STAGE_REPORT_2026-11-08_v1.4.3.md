# STAGE REPORT · v1.4.3（M337–M340：判据收口、模块净化、高密度巡猎）

> 日期：2026-11-08 ｜ 基线：v1.4.2（43f92c5）
> 结论：M337/M338 把 4 条机器 A 假阳的底层判据全部收口；M339 的
> 业务词回退 + min_units 门槛让 8 个实扫名额首次全部落到中大型 Web 业务仓。
> 本轮 5 条机器 A 中 **3 条是真实 SQLi（同一根因）**，2 条 gaia 假阳被降级；
> 没有向外部提交任何 CVE/Advisory。

## 一、M337：redir / 文件删除 / 上传

### 1.1 Java 同源固定前缀

REDIR_CONST_TARGET_RE 新增：

- return "redirect:/<segment>/..." + var
- sendRedirect("/<segment>/..." + var)
- RedirectView("/<segment>/..." + var)

JavaClaw OnboardingController.postStep 的
return "redirect:/onboarding/" + nextId; 由 **True → False**；
而 return "redirect:/" + url;（第二字符可构造 //evil.com）仍为 **True**。
验证通过。

### 1.2 任意文件删除

- _FILE_DELETE_SAFE_RE 与 PATH_SAFE_RE 增加
  \.(is_)?relative_to\(。
- arbitrary_file_delete_verdict 不再把任意裸局部变量判 True：
  形参直接命中 → True；局部变量必须由入口形参/request 赋值（含一跳别名）
  → True，否则 None；mkstemp 临时文件仍 False。

验证：

| 样本 | 结果 |
| --- | --- |
| creatorhub del_account（candidate.relative_to(ROOT)） | **False** |
| def rm(path): os.remove(path) | True |
| target = path; os.remove(target) | True |
| target = "/tmp/x"; os.remove(target) | None |
| mkstemp 临时文件 | False |

### 1.3 上传与 loopback（对蓝图的一处修正）

蓝图建议“UUID 生成文件名就判 False”。实际 creatorhub 的代码是：

    ext = Path(filename).suffix
    name = f"{uuid.uuid4().hex}{ext}"

UUID 只换了**主干**，后缀仍由上传者决定（.html/.svg）。按定义这仍然是
unrestricted upload，**不能**放宽 _UPLOAD_GENERATED_RE 把原始后缀洗白；
否则会制造一个真实的漏报。

正确收口是攻击面：wild_noise.py 新增 LOCAL_LOOPBACK_ONLY，识别
LocalAccessMiddleware 或同时出现 loopback 字面量 + 客户端地址校验的单机
工作台。creatorhub 的上传 verdict 仍为 True，但 classify 返回
LOCAL_LOOPBACK_ONLY，压进 B 板，不占 A 板交单席位。

## 二、M338：example 模块与 JSON 实体 XSS

### 2.1 示例子模块过滤

java_servlet.py 的 IGNORE_DIRS 增加 example/examples/demo/demos/
sample/samples/docs，并用相对路径段匹配 *-example/*-demo/*-sample/
*-test/*-benchmark。关键边界：

- 扫描根目录本身叫 demo/test 时**不**被误杀；
- src/main/java/demo 里的 demo 是 **Java 包名**，不是模块，必须保留。

higher-kinded-j 的 hkj-spring/example 因此切出 **0 个入口**；
src/main/java/demo 的迷你控制器仍能切出 XssController.echo。

### 2.2 XSS JSON 实体

- _DB_WRAPPED_ECHO_RE 加入 ServerResponseEntity；
- _json_wrapper 加入 serverresponseentity/serverresponse；
- ModelAndView/ModelMap/View 明确排除在 JSON 类型之外；
- 仅在真实 DB 写路径（_db_writer_takes_value / _repo_write_in_evidence）
  且 _rest_json 成立时判 False。

结果：mall4j UserCollectionController.addOrCancel（返回
ServerResponseEntity<Void>）→ **False**；
higher-kinded-j updateEmailAsync（返回 CompletableFuture<User>）→ **False**；
M323 的 Service.createExportTask 仍保持 **None**，没有把“无 DB 链”误判成安全。

### 2.3 基线漂移（真实变化，不是判据放宽）

| 项 | 旧 → 新 | 原因 |
| --- | --- | --- |
| mall4j 人工复核面 | 9 → **8** | UserCollectionController.addOrCancel 的 xss 假阳被收口 |
| xxl-job 入口 | 41 → **37** | xxl-job-executor-samples 等 example/sample 模块被正确排除 |
| matrix 覆盖缺口 | 68 → **69** | example-only 探针被移除，缺口只增 1 且已更新上界 |

REVIEW_NEEDED=8、M170 37 入口、M139 ≤69 已同步；
SCOREBOARD.md 已重建。

## 三、M339：业务词回退 + min_units 不占名额

### 3.1 target_scout

M335 的“框架 only”回退（fastapi / "spring-boot"）会把函数式库和桌面包装器
捞回来。本版改为 NEW_GEN_FALLBACK_WORDS：

    admin, cms, erp, crm, mall, oa, rbac, portal, workflow,
    knowledge, rag, lowcode, mes, wms, iot

回退窗口 created:>2024-01-01、stars:60..5000，不再与框架名硬 AND。
实测候选从 1 恢复到 **34**，且不再出现纯框架裸搜。

### 3.2 daily_hunt min_units

新增 --min-units（默认 8）。0 < total_units < 8 且没有
ZERO_RECORD_FRESH 根因的仓记 SKIPPED low_units_N，**不递增
scanned_slots**；出现 A 根因时放行。实测低密度仓 3 被跳过、后续 12 路由仓
拿到名额。

## 四、M340：门禁与高密度巡猎

- smoke_test_chains.py：**PASS，1,911 项**
- triage_fallbacks.py --check-floor：**16/16 达标**
- cli.py doctor：**PASS（12 段全绿）**

扩量结果：

    candidates 34 / scanned 8 / skipped 9 / failed 0
    new roots 60 / board A 5 / B 55
    recent_90d_roots 18 / evicted 16 / min_units 8

### 5 条机器 A 的人工精核

| 候选 | 结论 |
| --- | --- |
| WorkFlow-Engine doingList4All sqli | **CONFIRM**，真实 SQLi |
| WorkFlow-Engine doingList4Dept sqli | **CONFIRM**，同一根因 |
| WorkFlow-Engine doingList4DuBan sqli | **CONFIRM**，同一根因 |
| gaia setSessionModel sqli | **DEMOTE**：MyBatis-Plus eq 参数化，last("LIMIT 1") 常量 |
| gaia asServiceSession deserial | **DEMOTE**：反序列化远端 AgentScope 响应，非请求体，未开 default typing |

因此真实 A = **1 个根因 / 3 条路由**，其余 2 条假阳。

### WorkFlow-Engine SQLi 证据链

- DoingRestController.java:51-55/66-70/81-85：三个方法接收
  @RequestParam(required=false) String searchMapStr，原样下传。
- WorkListServiceImpl.java:649-656/673-687/704-708：转交
  itemDoingApi.searchBySystemName(..., searchMapStr, ...)。
- ItemDoingApiImpl.java:69-80：Y9JsonUtil.readHashMap(searchMapStr) →
  y9TableService.getSql(searchMap)。
- Y9TableServiceImpl.java:310-314：LIKE '%" + value + "%'；
  327-336：='" + value + "'；345-358：日期范围直接拼接。
- 只有 systemName 用 ? 绑定（ItemDoingApiImpl.java:238-240），
  searchMapStr 的值没有任何绑定。
- 首两个入口 dedup = ZERO_RECORD_FRESH；第三个因外部源失败为 UNKNOWN。
- 鉴权：application.yml 的 protectedUrlPatterns: /vue/*；
  @FlowableLog(... ADMIN) 只是审计日志。若该 starter 按单段 Ant 匹配，
  /vue/doing/... 是否被覆盖需部署验证；至少在登录后可达（PR:L）。
  **未向 GitHub/MITRE 提交。**

## 五、结论与下一步

1. JavaClaw / creatorhub / higher-kinded-j 的 4 条假阳全部有机制级修复，
   不再依赖人工记忆。
2. 上传类目的正确修法是“本地 loopback 降噪”，不是把 UUID + 原始后缀
   判安全；后者会制造真实漏报。
3. WorkFlow-Engine 的 SQLi 是 v1.4.3 首个可确认的新根因；下一步先在
   部署环境验证 /vue/doing/* 的实际鉴权覆盖，再决定走私密 Advisory /
   邮件；不要直接把 scanner 的 5 条 A 当成 5 个 CVE。
4. 第 2/3 单（metasfresh / x-springboot）状态不变，仍待你本人提交。
