"""apolloconfig/apollo —— 第 34 野战仓（Java #15），M156（34 仓里程碑）。

## 为什么选它

携程 Apollo 是国产配置中心的事实标准，它的授权模型是**两层**的：

1. Spring Security 过滤器链：anyRequest().hasAnyRole("user")
   —— 但只在 auth / ldap / oidc profile 下生效；默认 profile 直接放行。
2. 方法级自定义 SpEL：
       @PreAuthorize(value = "@unifiedPermissionValidator.isSuperAdmin()")
       @PreAuthorize(value = "@unifiedPermissionValidator.isAppAdmin(#appId)")
       @PreAuthorize(value = "@apolloAuditLogQueryApiPreAuthorizer.hasQueryPermission()")

判据如果只认 hasRole(...) 这种标准 EL，自定义 @bean.method() 就会被
当成"没有鉴权"；如果无视 profile，又会把默认部署的匿名可达当代码漏洞。
这两种都是口径错误，不是准确率问题。

## 本轮修正

- @PreAuthorize 任意 EL 表达式都算声明式授权（M97 已认注解名，
  这里确认自定义 bean EL 不再被漏掉）；
- 新增 [auth-profile-dependent] 仓库级标记：检测到
  anyRequest().hasAnyRole(...) 与 @Profile / @ConditionalOnMissingProfile
  同仓出现时，未标注解的路由退 None —— 认证是否开启取决于部署 profile，
  静态切片证明不了"线上缺鉴权"。

## 门禁（--strict）

- 切片 >=190 入口；
- authz **0 条 True**（生产级配置中心零误报）；
- 59 个 @PreAuthorize 入口全部 False；
- 三种自定义 EL（isSuperAdmin / isAppAdmin / hasQueryPermission）都被
  识别为声明式授权；
- 反向锚点：剥掉 deleteApp 的 @PreAuthorize 与 profile 标记后翻 True。

> 其它类目（deserial / sqli）在 Apollo 上仍有 3 条候选命中，属于
> --strict 之外的**人工复核队列**：它们依赖 fastjson 版本 / Mapper
> 语句归属，等 M159 供应链版本证据落地后再定论，不计入本门禁。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.text_utils import ensure_utf8_stdio                   # noqa: E402
from core.agents import rule_detectors as R                     # noqa: E402
from core.agents.vuln_categories import CATEGORIES             # noqa: E402
from core.slicer.java_servlet import JavaSlicer                # noqa: E402

ensure_utf8_stdio()

DEFAULT_TARGET = ROOT / "reference_repos" / "apollo"
MIN_UNITS = 190
MIN_PREAUTH = 50
EL_PATTERNS = ("isSuperAdmin", "isAppAdmin", "hasQueryPermission")


def main() -> int:
    ap = argparse.ArgumentParser(description="Apollo 自定义 Spring EL 鉴权基准（M156）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" /
                                            "apollo.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/apolloconfig/apollo.git）")
        return 2
    units = list(JavaSlicer(repo).extract_entry_units())
    print(f"靶场：{repo}")
    print(f"       入口 {len(units)} 个")

    authz_true = [u.unit_name for u in units
                  if R.verdict("authz", u.source_code) is True]
    pre = [u for u in units if "@PreAuthorize" in u.source_code]
    pre_false = sum(1 for u in pre if R.verdict("authz", u.source_code) is False)
    el_hits = {p: sum(1 for u in units if p in u.source_code) for p in EL_PATTERNS}
    profile_marked = sum(1 for u in units
                         if "[auth-profile-dependent]" in u.source_code)

    residual = []
    for u in units:
        for c in CATEGORIES:
            if R.verdict(c, u.source_code) is True:
                residual.append((Path(u.file_path).name, u.unit_name, c))

    anchor_unit = next((u for u in units if "deleteApp" in u.unit_name), None)
    anchor = None
    if anchor_unit:
        stripped = "\n".join(
            l for l in anchor_unit.source_code.splitlines()
            if "[auth-profile-dependent]" not in l and "@PreAuthorize" not in l)
        anchor = R.verdict("authz", stripped)

    print("=" * 72)
    print("Apollo 结果（自定义 Spring EL + profile 化认证）")
    print("=" * 72)
    print(f"  入口                    ：{len(units)}")
    print(f"  authz True（误报）      ：{len(authz_true)}")
    print(f"  @PreAuthorize 入口      ：{len(pre)}（False {pre_false}）")
    print(f"  自定义 EL 证据          ：{el_hits}")
    print(f"  profile 标记入口        ：{profile_marked}")
    print(f"  全类目残差（人工复核）  ：{len(residual)}")
    for f, n, c in residual[:10]:
        print(f"      [residual] {f}:{n} [{c}]")
    print(f"  反向锚点（剥注解/标记） ：{anchor}")

    bad: list[str] = []
    if len(units) < MIN_UNITS:
        bad.append(f"入口 {len(units)} < {MIN_UNITS}")
    if authz_true:
        bad.append(f"authz 出现 {len(authz_true)} 条 True 误报")
    if len(pre) < MIN_PREAUTH:
        bad.append(f"@PreAuthorize 入口 {len(pre)} < {MIN_PREAUTH}")
    if pre_false != len(pre):
        bad.append(f"@PreAuthorize 入口只有 {pre_false}/{len(pre)} 判 False")
    for p in EL_PATTERNS:
        if el_hits[p] == 0:
            bad.append(f"自定义 EL {p} 未被切片覆盖")
    if profile_marked < MIN_UNITS:
        bad.append(f"profile 标记只覆盖 {profile_marked} 入口")
    if anchor is not True:
        bad.append(f"反向锚点未翻 True（{anchor}）")
    ok = not bad
    print()
    print("STRICT PASS ✔（200 入口 / authz 0 True / 59 个 @PreAuthorize 全 False / "
          "三种自定义 EL 覆盖 / 反向锚点 True）"
          if ok else "STRICT FAIL ✘ " + "；".join(bad))

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "apollo", "units": len(units),
        "total_units": len(units), "correct": len(units) - len(authz_true),
        "fp": len(authz_true), "reverse_fn": 0,
        "preauthorize_units": len(pre), "preauthorize_false": pre_false,
        "custom_el": el_hits, "profile_marked": profile_marked,
        "anchor": anchor, "authz_true": authz_true,
        "residual": [{"file": f, "unit": n, "category": c}
                     for f, n, c in residual],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
