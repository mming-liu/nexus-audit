# STAGE REPORT · v1.3.5（M304 → M306）

> 日期：2026-10-31 ｜ 基线：v1.3.4（fc5524e）
> 结论：查重顺序反置已修（本地降噪 → 优先级 → 截断 → 联网），
> `ApiResult` 包装假阳与 log_injection 噪音各归其位。

## 一、M304：把"先截断后降噪"倒过来

旧顺序（v1.3.4 及以前）：

```
scan roots → roots[:max_roots] → run_one(联网查重) → wild_noise.classify
```

问题：前 5 条若是 `UNVERIFIED_WILD_AUTHZ` / `log_injection`，第 6 条真 sqli 直接被丢掉；
这 5 条噪音还各烧一次 GitHub API，最后全进板块 B，仓库再进 7 天冷却期。

新顺序（本版）：

```
scan roots
  → 排除 exported_roots（已导出的不再查重、不占名额）
  → wild_noise.classify（blocked 直接进 B，0 网络）
  → wild_noise.promote（authz HIGH 参与排序）
  → 按交单价值稳定排序（第一梯队 12 类 + HIGH authz）
  → 截取 max_roots
  → run_one / cve_dedup 联网查重
```

## 二、M305：两个降噪口子

| 项 | 修法 |
| --- | --- |
| `ApiResult.success(...)` 被判存储型 XSS | `_DB_WRAPPED_ECHO_RE` 从穷举类名改为命名机制：`R / ResponseEntity / \w*Result / \w*Response / \w*Resp` + `.ok/.success/.error/.fail/.data/.of`。统一 JSON 包装 → `_db_echo` False、`_db_render_points` 丢弃 |
| `log_injection` 占板块 A | `wild_noise` 新增 `LOW_SEVERITY_LOG_INJECTION`：CWE-117 低危，直接进 B（保留证据，不占交单席位） |

## 三、验证

| 项 | 结果 |
| --- | --- |
| 冒烟 [291] | 5 条 log_injection 噪音 + 第 6 条 hardcoded_secret + 第 7 条 sqli，`max_roots=2` 时送查重的是 `[sqli, hardcoded_secret]`，噪音 0 次 API、5 条直接进 B |
| 冒烟 [292] | `ApiResult/R/ResponseEntity/CommonResult/ApiResp` 五种包装全部识别；直出仓储仍判回显；log_injection 进 B |
| `smoke_test_chains.py` | PASS ✔ **1,744 项** |
| `cli.py doctor` | PASS（12 段全绿） |
| 实盘重跑（15:34–15:50） | 候选 24 / 实扫 10 / 跳过 3 / 失败 0；新增 **144**（A **7** / B 137）；即扫即焚 10 |
| 旧版被截断的仓 | 11 个（13:27–13:37 那批）在账本里解除 SHA/冷却锁定后重扫；`exported_roots` 在截断前生效，sz-boot-parent 3 条 xss 已导出 → 本轮 0 条重复 |
| 新增 A 行类目 | `cmdi` 1（codex-lb）、`pathtraver` 2（dramaclaw）、`arbitrary_file_delete` 2 与 `unrestricted_upload` 2（xianyu）—— 全是旧顺序下会被前 5 条噪音挤掉的高危类目 |

### 抽查结论（A 行不等于已确认）

- `codex-lb` **cmdi** `run_cache_isolation_probe`：端点要求 `OPS_WRITE` 权限，且
  `app/modules/cache_isolation_probe/` 全部 .py 里没有任何 `subprocess/Popen/os.system`
  → **规则层假阳**，不交单；
- `xianyu-auto-reply` **unrestricted_upload** `upload_qrcode`：管理员限定 +
  `content-type: image/*` + 2MB 上限 + 扩展名白名单（非法后缀回落 `.png`）+
  落盘文件名固定 `{prefix}-group{ext}`（不用原始文件名）→ **假阳**；
- 其余 5 条（pathtraver ×2、arbitrary_file_delete ×2、unrestricted_upload ×1）
  需人工读调用链后才能定性，`ZERO_RECORD_FRESH` 只代表"全网查过 0 命中"。

**结论**：这轮证明 M304 的顺序修复确实把以前被截断的高危候选放回了 A，
但"放回 A"不等于"真洞"——规则层对 `cmdi/unrestricted_upload` 仍会误报，
下一批应优先做这两个类目的"权限/白名单已就位"反向判据。

## 四、遗留

1. `NO_SQL_SINK` / `LOW_SEVERITY_LOG_INJECTION` 都是"宁可 B 不漏 A"的保守判据，B 板块会变长，需要人工复核捞回。
2. `exported_roots` 现在在截断前生效：已导出的根因不再占用每天的查重名额（顺带提升吞吐）。
