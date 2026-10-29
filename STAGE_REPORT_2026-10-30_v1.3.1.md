# STAGE REPORT · v1.3.1（M293 → M296）

> 日期：2026-10-30 ｜ 基线：v1.3.0（aa75fa6 / 93315b4 / e2b263f）
> 结论：**冒烟 PASS（1668 项断言）**、`doctor` exit 0、首轮"真出网"巡猎跑通。

## 一、首轮实盘暴露的问题 → 本版根治

| 问题 | 根因 | 动作 |
| --- | --- | --- |
| 抓回 10 仓有 8 仓扫出 0 | 裸搜 `language+pushed` 抓回驱动/插件/CLI/评测框架 | M293：按语言轮询业务限定词（Java ```spring-boot/admin/cms/erp/crm/mall``` 等）+ 工具库剔除 + 纯库 `ZERO_ENTRY_LIB` 不占名额 |
| `inspect_ai` 6 条 Unix Socket 接口漏进 A | `wild_noise` 不认识本地 IPC 控制面 | M294：`AF_UNIX` + `SO_PEERCRED`/`LOCAL_PEERCRED`/`socket_path` → `LOCAL_UNIX_SOCKET_SERVER` 进 B |
| Python 裸 authz 刷屏 | 兄弟守卫只认 Java 注解 | M294：`Depends(get_current_*)` / `Security(...)` / ```login_required` / `IsAuthenticated` 同权；无 HIGH 反差且非 `/admin` → `UNVERIFIED_WILD_AUTHZ` 进 B |
| 失败仓残留 52MB | 清理不在 `finally` | M295：`finally` 焚毁 + `--repo-timeout` 单仓软超时 |

## 二、性能：单根因 25s → 3s

首轮实盘发现每条根因查重约 25s：NVD 在本网络 TLS 被阻断，每次白等 10s+；CIRCL / advisories 是**仓库级**结果却被逐条重查。

- NVD 连续失败 2 次即熔断（本进程内不再发起）；
- CIRCL / GitHub advisories 进程内按 repo 记忆化。

实测：第 1 条 22.9s，第 2 条 10.9s，第 3 条起 2.8s。

## 三、首轮"真出网"巡猎结果（v1.3.1 代码）

```
[daily-hunt] 候选 24 ｜ 实扫 10 ｜ 跳过 0 ｜ 失败 2
[daily-hunt] 新增根因 19 ｜ 板块 A 11 ｜ 拦截进 B 8 ｜ 即扫即焚 11 个
```

- 抓回的是业务后台而非工具库：OpenLegislation（政府法案 API）、fastapi-best-architecture、metasfresh（ERP）、rebuild（CMS）、backend.ai、CordysCRM、mealie 等。
- 8 条裸 authz 被 `UNVERIFIED_WILD_AUTHZ` 压进 B（M294 生效）。
- 2 仓失败：commcare-hq、mealie（下轮重试；失败也焚缓存）。

## 四、验证

| 项目 | 结果 |
| --- | --- |
| `python benchmarks/smoke_test_chains.py` | PASS ✔ 1668 项（新增 [281]–[284]） |
| `python cli.py doctor` | exit 0 |
| `export_disputes.py --check` | 4 条证据对上源码 |
| 实盘 daily-hunt | 24 候选 → 10 实扫 → 19 根因（A 11 / B 8） |

## 五、已知边界

- 未配 `GITHUB_TOKEN` 时 GitHub core 限制 60 次/小时：建议 `--max-roots 5`（已写入 README 与 harness 定时任务）。
- 巨型仓（metasfresh 444MB）单仓扫描接近 `--repo-timeout 900s`；超时会记 FAILED 并焚缓存。
- 板块 A 仅代表"四个来源都查过且 0 命中"，仍需人工源码复核；本轮 `rebuild` 的 redir / pathtraver 与 `OpenLegislation` 的 xss 已初步判为弱信号或误报。
