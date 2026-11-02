# STAGE REPORT · v1.3.14（FlyCms / wangmarket 复核 + metasfresh 72h 节点）

> 日期：2026-11-02 ｜ 基线：v1.3.13（638e4eb）
> 结论：FlyCms 候选**有防护，不是穿越**；wangmarket 两条是**超管专属**路径拼接，
> 价值不足以立项；metasfresh #27079 **仍无回复**。

## 一、FlyCms ApiToolsController.download（FP）

- 路由：`GET /api/system/tools/db/download?name=...`（`ApiToolsController.java:78`）
- 鉴权：`requirePermission("/api/system/tools/db/download")`（登录 + 权限节点）
- 路径：`DbBackupService.resolveForDownload(name)` → `safeResolve()`：

~~~java
private static final Pattern SAFE_NAME =
        Pattern.compile("^flycms_[A-Za-z0-9_\\-]+\\.sql$");

private Path safeResolve(String name) {
    if (name == null || !SAFE_NAME.matcher(name).matches()) {
        throw new IllegalArgumentException("非法的备份文件名");
    }
    Path target = BACKUP_DIR.resolve(name).normalize();
    if (!target.startsWith(BACKUP_DIR.toAbsolutePath().normalize())
            && !BACKUP_DIR.isAbsolute()) {
        throw new IllegalArgumentException("非法的备份文件名");
    }
    return target;
}
~~~

`../` 与绝对路径都被白名单正则挡死 → **不是路径穿越**。已把 FlyCms 的
CVE-2026-112294 / 112295 / 112296（GHSA-6phq-6cxr-q574）补进
`known_public_cves.json`，查重现在会直接把该仓标 DUPLICATE_CVE。

## 二、wangmarket PluginManageController（超管专属，低价值）

- `exportPlugin`（:1210）：`haveSuperAdminAuth()` 先检查；`pluginId` 只做
  `trim()`，随后拼进 `getPluginPath(...) + pluginId` 的目录路径并 `copyDir`。
  `../` 理论可越出插件目录，但**只有超级管理员**可达。
- `uploadPluginZip`（:831）：同样超管专属；`pluginId` 来自压缩包内
  `ROOT/system.txt`，未校验即拼进 `realPath + "myPlugin/" + pluginId + ".zip"`，
  `../` 可写出目录（写文件），但仍需超管。
- 结论：CWE-22 成立但 `PR:H` + 超管信任边界，按厂商惯例通常按"管理员本就有
  全部权限"关闭，**不构成第 3 单**。

## 三、metasfresh #27079（72h 节点）

- 状态：`open`，**0 条评论**，最后更新 2026-10-30T14:03:29Z；
- 维护者未开私密通道、未回复；
- 已在 #27079 发布零细节追问（2026-11-02T13:31:24Z；原评论误带类名/路径已删除）：
  https://github.com/metasfresh/metasfresh/issues/27079#issuecomment-6578455241
- 后续：若 11-06 前仍无回应，凭该公开记录转投 MITRE CNA-LR。

## 四、门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔ **1,816 项** |
| cli.py doctor | PASS（12 段全绿） |
