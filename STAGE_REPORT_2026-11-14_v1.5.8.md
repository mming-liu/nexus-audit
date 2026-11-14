# STAGE REPORT · v1.5.8（M379–M382：2-Hop 上传守卫 + 候选供给 + 满额巡猎）

> 日期：2026-11-14 ｜ 基线：v1.5.7（81edcb0 之前为 023a5cf）
> 结论：`RAG_LearnLittleCode` 的 `upload_chat_file` 由 2-Hop 守卫拦入 B；
> 候选供给从 3 恢复到 **8**（实扫 2）；满额巡猎产出 5 条 A，逐条精核后
> 4 条为"服务端构造跳转 URL"假阳、1 条为弱真实（Referer 开放重定向）。

## 一、M379：跨文件 2-Hop 上传守卫

`wild_noise` 新增：

| 函数 | 作用 |
|---|---|
| `upload_guard_scope(repo_root, src, unit)` | 入口函数体 → Hop1（service）→ Hop2（校验/存储 helper），拼成证据面 |
| `_py_called_names()` | 提取被调函数名（**允许点号前缀**，`svc.save_upload(` 取 `save_upload`） |
| `_repo_def_bodies()` / `_py_function_blocks()` | 跨文件、有界（400 文件）找函数定义体 |

判定：证据面命中「防穿越（`basename`/`re.sub`/…）」**或**「扩展名白名单 + UUID 固定命名」，
且仓内无上传目录的静态挂载 → `UPLOAD_SERVING_ONLY` / `NON_EXECUTABLE_UPLOAD`。

**顺手修掉两个真 Bug**：

1. `_py_function_blocks()` / `_ws_handler_block()` 用 `tail[1:]` 找"下一个 def"，
   对**缩进函数**会把同一个 def 行再匹配一次，函数体被截成 1 个字符（实测
   `save_upload` 体长 1）；改为从当前行末尾之后搜索；
2. `_py_called_names()` 的 `(?<![\w.])` 会把 `service.save_upload(` 整条漏掉，
   2-Hop 永远拼不起来。

验证：`RAG_LearnLittleCode` `upload_chat_file` → `NON_EXECUTABLE_UPLOAD`（A 板 1 → 0）。

## 二、M380：候选供给修复

- `scout_daily()` 新增**补拉**：有效候选 < `limit` 且未撞 403 时，用下一组轮换业务词
  再查最多 2 轮（`topup_round` 标记进 `query_specs`）；
- 新生代轨星标下限确认独立于 `min_stars`（`NEW_GEN_STARS=150..5000`，不随 300 抬高）；
- 实测候选数 **3 → 8**。

## 三、M381：门禁

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS 1,638 项**（+6：`[331]`） |
| `triage_fallbacks.py --check-floor` | **16/16** |
| `cli.py doctor` | PASS |
| `.githooks/pre-push` | exit 0 |

`[331]`：2-Hop 白名单+UUID → 拦；2-Hop 无白名单/无防穿越 → 不拦；StaticFiles 挂载 → 不拦；
new_gen 星标不随 min_stars 抬高；传统轨下限 ≥ min_stars；点号调用名可提取。

## 四、M382：满额巡猎

```
daily-hunt --languages java,python --days 21 --limit 8 --min-stars 300 \
  --max-roots 5 --cooldown-days 7 --evict-cache --repo-timeout 300
```

| 项 | 值 |
|---|---|
| 候选 / 实扫 / 跳过 / 失败 | **8** / 2 / 6 / 0 |
| 根因 | 137（A=5，B=132） |
| 实扫仓 | `continew-org/continew-admin`（10）、`itwanger/paicoding`（127） |

### 5 条 A 候选精核（全部 `redir`，均来自 paicoding）

| # | 入口 | 判定 | 依据 |
|---|---|---|---|
| 1 | `LoginRestController.logOut:82` | **弱真实** | `sendRedirect(request.getHeader("Referer"))`，Referer 可由站外链接带入 → CWE-601；需登录，危害低 |
| 2 | `LoginRestController.redirectToZsxq:102` | **假阳** | `zsxqHelper.buildZsxqLoginUrl("login")` → `zsxqProperties.getApi() + "?签名参数"`，固定外部域名 |
| 3 | `UserTransferController.transferByZsxq:50` | **假阳** | 同上，extra 是常量 `EXTRA_TAG_USER_TRANSFER` |
| 4 | `ZsxqLoginController.autoBindZsxqUser:51` | **假阳** | `buildZsxqLoginUrl("" + useXqName)`，`useXqName` 是 Boolean（只会拼成 true/false），目标域固定 |
| 5 | `ShortLinkController.getOriginalLink:53` | **假阳（设计如此）** | 短链服务核心功能：`sendRedirect(shortLinkService.getOriginalLink(code).getOriginalUrl())`，originalUrl 由创建者写入；这是短链的预期行为，不是缺陷 |

**根因**：`redir_verdict` 把 `sendRedirect(<helper 调用>)` 当可控跳转，未识别
"helper 返回固定域名 + 签名参数"的服务端构造形态。

**建议 M383**：`wild_noise` 增加 `SERVER_BUILT_REDIRECT` —— 跳转目标是
`build*Url/loginUrl/oauth*Url/sso*Url` 且实参不是自由文本（布尔/常量/枚举）时压 B；
同时把 `Referer` 型开放重定向单列为低危（`REFERER_OPEN_REDIRECT`），避免占 A 板席位。

## 五、提交

- `81edcb0` — v1.5.8 代码（M379–M381）
- 后续 docs 提交 — 本报告 + 11-14 巡猎报告（第二次）
