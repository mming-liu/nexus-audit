# STAGE REPORT · v1.3.15（M318 → M319）

> 日期：2026-11-02 ｜ 基线：v1.3.14（6bfaca6）
> 结论：板块 B 的两座"富矿"实测均有守卫，**不是第 3 单**；
> 顺手收口超管专属入口降噪与 Hop 段路径守卫。

## 一、B 板块两条复核

### novel-plus AiAssistantController（FP）

- 每个方法先调 `checkAuthor(request)`：JWT → `authorService.queryAuthor`，
  未登录/作者状态异常直接 401/403；
- 服务层按 `authorId` 隔离：`loadOwnedPlan(authorId, planId)`、
  `taskMapper.selectByIdAndAuthor(taskId, authorId)`；
- 没有 Shiro 注解是因为它走的是**作者 JWT 身份**，不是后台权限体系。
  → B 判定正确，不是漏网真洞。

### ujcms CommentController.remove / ContributeController.remove（FP）

- `api/CommentController.remove`：`bean.getUserId().equals(user.getId())` 否则 404；
- `api/ContributeController.remove` → `service.delete` → `requireOwn(site, user, id)`
  否则 404；`isEditable` 再挡状态。
- → 两者都有归属校验，IDOR/越权不成立。

## 二、规则收口（M318）

| 项 | 修法 |
| --- | --- |
| 超管专属入口 | `wild_noise.SUPERADMIN_ONLY`：文件含 `haveSuperAdminAuth(` 或路径带 `/superadmin/`，authz/pathtraver/file_delete/upload 类进 B |
| Hop 段守卫 | `pathtraver_verdict` 对 `sink_in`（跨文件辅助段）也跑 `PATH_SAFE_RE`，`DbBackupService.safeResolve` 这类 Hop 里的 `getCanonicalPath().startsWith` 直接判 False |

## 三、种子库（M319）

新增 10 条：novel-plus（CVE-2026-90939/90941/90940、CVE-2025-4015/4017）、
ujcms（CVE-2026-93961/78140/2954）、wangmarket（CVE-2025-15415/15416），总计 42 条。

## 四、#27079 追评修正

- 原追评误带类名/路径，已删除并按"零细节"重发：
  https://github.com/metasfresh/metasfresh/issues/27079#issuecomment-6578455241
- 注意：删除前的评论可能已被 GitHub 通知/第三方镜像缓存，不能保证完全回收。

## 五、门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔ **1,821 项**（新增 [303] 5 项） |
| cli.py doctor | PASS（12 段全绿） |
