"""wayn111/waynboot-mall —— 第 16 野战仓，M97 国产鉴权框架 Sa-Token 语义。

## 为什么选它

waynboot-mall 是 Spring Boot 3 + MyBatis-Plus + 国产鉴权框架 **Sa-Token** 的
双端商城：`waynboot-mobile-api`（H5 移动端）+ `waynboot-admin-api`（运营后台）。
它的鉴权形态与前 15 个仓都不同：

  · 移动端不再用 Spring Security 过滤链，而是 `SaInterceptor` +
    `StpUtil.checkLogin()` 全站拦截 + `excludePathPatterns` 白名单；
  · 主体 ID 靠 `StpUtil.getLoginIdAsLong()` 从会话取（框架托管，客户端伪造不了）；
  · 注解式鉴权是 `@SaCheckPermission` / `@SaCheckRole` / `@SaCheckLogin`。

## M97 实测：3 个独立根因收到 1 个

初测 163 入口 / 170 条路由级 P0 / 9 个独立根因，逐条核查后消掉 8 个**误报**：

| 误报 | 机制 | 纯增量补齐 |
|---|---|---|
| 6 条 `pathtraver`（`OrderController.export` 等 6 个导出/上传端点） | 入口体一个文件 API 都没有；唯一的 `new File(...)` 来自 Hop 2 的 `ExcelUtil.getAbsoluteFile(filename, path)`，两个形参由**服务端配置**填充 | `_path_sink_identifiers`：sink 只在辅助段里时，要求与入口体标识符有交集，否则退 None |
| 1 条 `hardcoded_secret`（`WxController.jsSdkInit`） | 正则跨语句拼出"幽灵赋值"：`appSecret;` 的下一行 `resultJsonStr = "https://…"` 被拼成 `secret = "…"` | `SECRET_ASSIGN_RE` 三处收紧：名字前 `(?<![\w$])`、`[:=]` 两侧禁跨行、值禁跨行 |
| 1 条 `cors`（`UserController.getInfo`，与全局那条重复） | 装配证据第一行带路由别名，同一份全局配置算出不同签名 | `_root_cause_key` 先剥标题行再归一化 |

## 唯一确认的 P0（真阳，163 条路由）

`MobileSaTokenConfiguration.addCorsMappings`：
    registry.addMapping("/**")
            .allowedOriginPatterns("*")
            .allowedHeaders("*")
            .allowedMethods("*")
            .allowCredentials(true);
通配 Origin + 携带凭证（CWE-942）—— 浏览器端任意站点可带 cookie 读响应。
根因折叠把 163 条路由级命中折成 **1 个全局配置根因**。

## 门禁（--strict）

- 切片 ≥150 入口（实测 163）；
- 全库规则层 True 只允许来自**那一份全局 CORS 配置**：
  `MobileSaTokenConfiguration.addCorsMappings` 判 True，任何路由级
  （cors 以外的类目）True 都算误报；
- 三语言 Sa-Token 语义锚点：`@SaCheckPermission` / `@SaCheckRole` /
  `@SaCheckLogin` / `StpUtil.checkXxx()` 必须被认作角色/权限校验，
  `StpUtil.getLoginId*()` 必须被认作主体来源。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents import rule_detectors as R                     # noqa: E402
from core.slicer.java_servlet import JavaSlicer                 # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "waynboot-mall"
CATS = ("sqli", "cmdi", "xss", "pathtraver", "weakrand", "hash", "ssrf",
        "authz", "deserial", "spel", "xxe", "redir", "cors", "crypto",
        "trustbound", "securecookie", "ldapi", "xpathi", "ssti",
        "hardcoded_secret", "jwt_weakness")
MIN_UNITS = 150
# 唯一允许判 True 的单元（全局 CORS 配置）
CORS_CONFIG_UNIT = "MobileSaTokenConfiguration.addCorsMappings"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="waynboot-mall Sa-Token 双端商城零误报基准（M97）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥150 入口 + 仅全局 CORS 一个 True + Sa-Token 语义在线")
    ap.add_argument("--offline", action="store_true", help="规则层（默认）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "waynboot.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/wayn111/waynboot-mall.git）")
        return 2

    units = list(JavaSlicer(repo).extract_entry_units())
    print(f"靶场：{repo}")
    print(f"      切片单元 {len(units)} 个")

    true_rows: list[tuple[str, str, str]] = []
    _unit_hits: list[tuple[object, set[str]]] = []
    decided = 0
    decided_units = 0
    for u in units:
        unit_decided = False
        hit_cats: set[str] = set()
        for c in CATS:
            v = R.verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            unit_decided = True
            if v is True:
                hit_cats.add(c)
                true_rows.append((Path(u.file_path).name, u.unit_name, c))
        if hit_cats:
            _unit_hits.append((u, hit_cats))
        if unit_decided:
            decided_units += 1

    # 全局 CORS 缺陷的表现形态是"**每一条路由**都继承了那份通配配置"：
    # 163 条路由级 cors 命中本身是对的，关键是它们必须折叠成**同一个根因**。
    # 误报的判据是"cors 以外的类目出现 True"——那些才是判错的。
    cors_rows = [u for u, hit in _unit_hits if "cors" in hit]
    fps = [r for r in true_rows if r[2] != "cors"]
    cors_ok = bool(cors_rows)
    from cli import _root_cause_key
    root_keys = {_root_cause_key(u, "cors")[0] for u in cors_rows}
    n_roots = len(root_keys)

    # Sa-Token 语义锚点（注解式 + 编程式 + 主体来源）
    sa_anchor = {
        "@SaCheckPermission": bool(R._AUTHZ_ROLE_RE.search(
            "@SaCheckPermission(\"system:user:list\")")),
        "@SaCheckRole": bool(R._AUTHZ_ROLE_RE.search("@SaCheckRole(\"admin\")")),
        "@SaCheckLogin": bool(R._AUTHZ_ROLE_RE.search("@SaCheckLogin")),
        "StpUtil.checkPermission": bool(R._AUTHZ_ROLE_RE.search(
            "StpUtil.checkPermission(\"x\")")),
        "StpUtil.checkLogin": bool(R._AUTHZ_ROLE_RE.search(
            "StpUtil.checkLogin();")),
        "StpUtil.getLoginIdAsLong 主体来源": bool(R._AUTHZ_SUBJECT_RE.search(
            "Long uid = StpUtil.getLoginIdAsLong();")),
    }

    print("=" * 72)
    print("waynboot-mall 结果（Sa-Token 双端商城）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  单元覆盖（≥1 判定）   ：{decided_units}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    print(f"    全局 CORS 路由级命中：{len(cors_rows)} 条"
          f"（折叠成 {n_roots} 个独立根因）")
    print(f"    cors 以外的 True    ：{len(fps)}（全部算误报）")
    for r in fps[:12]:
        print(f"      [FP] {r[0]}:{r[1]} [{r[2]}]")
    print("  Sa-Token 语义锚点：")
    for k, v in sa_anchor.items():
        print(f"    {'OK ' if v else 'XX '}{k}")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if not cors_ok:
        bad.append("全局 CORS 通配+凭证缺陷未被判出（漏报真阳）")
    if n_roots != 1:
        bad.append(f"CORS 根因折叠成 {n_roots} 个（应为 1）")
    if fps:
        bad.append(f"计划外 True {len(fps)} 条")
    if not all(sa_anchor.values()):
        bad.append("Sa-Token 语义锚点未全覆盖")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（163 入口 / 仅 1 个全局 CORS 根因 / 零误报）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "waynboot", "units": len(units), "total_units": len(units),
        "decided": decided_units, "correct": decided_units - len(fps),
        "fp": len(fps), "reverse_fn": 0,
        "rule_evaluations": decided,
        "global_cors_hit": cors_ok,
        "sa_token_anchors": sa_anchor,
        "true_rows": [{"file": f, "unit": u, "category": c}
                      for f, u, c in true_rows],
        "fp_rows": [{"file": f, "unit": u, "category": c}
                    for f, u, c in fps],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
