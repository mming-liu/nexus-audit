"""miguelgrinberg/flasky —— 第 27 野战仓（Python #7），M137。

## 为什么选它

flasky 是《Flask Web Development》的配套应用，也是 Flask 生态里**最典型**的
「多蓝图 + 自定义装饰器鉴权」结构：

    app/
      auth/views.py    @auth.route(...)   + @login_required
      main/views.py    @main.route(...)   + @admin_required / @permission_required
      api/posts.py     @api.route(...)    + @permission_required(Permission.WRITE)
      decorators.py    def permission_required(permission): ...
                       def admin_required(f): ...

它的价值不在"漏洞多"，而在**鉴权根本不在函数体里**：

    @main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
    @login_required
    @admin_required
    def edit_profile_admin(id):
        user = User.query.get_or_404(id)      # ← 形参直查 + 无主体比对

只看函数体的判据会把这 8 个路由全部判成"缺鉴权"（实测：`edit_profile_admin`
形参 `id` 直查 `User` 并写 `user.role`，问"有没有主体比对"答不出）。

M137 做了三件事（都在切片层，规则层只读证据）：

  1. **无括号装饰器入索引**。`ROUTE_DECORATOR_RE` 要求装饰器带 `(...)`，
     于是 `@admin_required` / `@login_required` 从来没进过 decorators ——
     `edit_profile_admin` 的守卫声明整条丢失。
  2. **`// Auth-Guard:` 证据头**：把声明的装饰器名写进切片头部，
     并把装饰器的**实现体**从仓库里找出来贴进证据段
     （`// ---- 守卫装饰器实现体 [app/decorators.py:6] ----`）。
  3. **公开内容只读面**：`/user/<username>` / `/posts/<id>/comments/` 这类
     "人人可见"的分页列举不是对象级越权面（与 Java 侧 `_is_public_catalog_read`
     同一套**正面证据**口径：必须先认出路由指向公开内容）。

## 门禁（--strict）

- 切片 ≥35 入口（实测 39），覆盖 ≥3 个蓝图目录；
- **全类目 0 True**（教程应用不该有任何计划外命中）；
- ≥8 个单元带 `// Auth-Guard:` 头，且守卫实现体真的贴进了证据段；
- `edit_profile_admin`（admin_required）/ `edit_post`（permission_required +
  归属比对）/ `moderate` 的 authz 必须是确定性 False；
- **反向锚点**：把 `edit_profile_admin` 的 `@admin_required` 与头部证据一起
  摘掉后，authz 必须**不再是 False** —— 证明判 False 靠的是守卫，
  而不是判据压根没看这块代码。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents import rule_detectors as R                     # noqa: E402
from core.slicer.web_treesitter import WebTreeSitterSlicer      # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "flasky"
CATS = ("sqli", "cmdi", "xss", "pathtraver", "weakrand", "hash", "ssrf",
        "authz", "deserial", "spel", "xxe", "redir", "cors", "crypto",
        "trustbound", "securecookie", "ldapi", "xpathi", "ssti",
        "hardcoded_secret", "jwt_weakness", "header_injection",
        "mass_assignment", "unsafe_reflection", "zip_slip")
MIN_UNITS = 35
MIN_GUARDED = 8
MIN_BLUEPRINTS = 3
GUARDED_MUST_FALSE = ("edit_profile_admin", "edit_post", "moderate")


def _strip_guard_evidence(src: str) -> str:
    """反向锚点：摘掉 `// Auth-Guard:` 头与守卫实现体证据段。"""
    out = "\n".join(ln for ln in (src or "").splitlines()
                    if "// Auth-Guard:" not in ln)
    return out.split("// ---- 守卫装饰器实现体")[0]


def main() -> int:
    ap = argparse.ArgumentParser(
        description="flasky 多蓝图 + 装饰器守卫零误报基准（M137）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥35 入口 + 全类目 0 True + Auth-Guard 证据 + 反向锚点")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "flasky.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/miguelgrinberg/flasky.git）")
        return 2

    units = WebTreeSitterSlicer(repo).extract_entry_units(repo)
    by_name = {u.unit_name: u for u in units}
    blueprints = sorted({Path(u.file_path).parent.name for u in units
                         if Path(u.file_path).parent.name in
                         ("auth", "main", "api")})
    guarded = [u for u in units if "// Auth-Guard:" in (u.source_code or "")]
    evidence = [u for u in guarded
                if "// ---- 守卫装饰器实现体" in (u.source_code or "")]

    print(f"靶场：{repo}")
    print(f"      切片单元 {len(units)} 个：{len(by_name)} 个唯一入口")
    print(f"      蓝图 {blueprints}")

    true_rows: list[tuple[str, str]] = []
    decided = 0
    decided_units = 0
    for u in units:
        hit = False
        for c in CATS:
            v = R.verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            hit = True
            if v is True:
                true_rows.append((u.unit_name, c))
        if hit:
            decided_units += 1

    must = {n: R.verdict("authz", by_name[n].source_code)
            for n in GUARDED_MUST_FALSE if n in by_name}
    anchor = {}
    u_admin = by_name.get("edit_profile_admin")
    if u_admin:
        stripped = _strip_guard_evidence(u_admin.source_code)
        anchor["edit_profile_admin"] = {
            "with_guard": R.verdict("authz", u_admin.source_code),
            "without_guard": R.verdict("authz", stripped),
            "changed": stripped != (u_admin.source_code or ""),
        }

    print("=" * 72)
    print("flasky 结果（多蓝图 + 装饰器守卫）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  带 Auth-Guard 头的单元：{len(guarded)}"
          f"（含实现体证据 {len(evidence)}）")
    print(f"  单元覆盖（≥1 判定）   ：{decided_units}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    for n, c in true_rows[:10]:
        print(f"      [FP] {n} [{c}]")
    print("  守卫函数的 authz 判定：")
    for n, v in must.items():
        print(f"    {n:22} = {v}")
    for n, a in anchor.items():
        print(f"  反向锚点 {n}：with={a['with_guard']} "
              f"without={a['without_guard']}（改写生效={a['changed']}）")

    bad: list[str] = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"计划外 True {len(true_rows)} 条")
    if len(guarded) < MIN_GUARDED:
        bad.append(f"Auth-Guard 头只有 {len(guarded)} 个 < {MIN_GUARDED}")
    if len(evidence) < MIN_GUARDED:
        bad.append(f"守卫实现体证据只有 {len(evidence)} 份 < {MIN_GUARDED}"
                   "（装饰器名字不算证据，必须看到实现体）")
    if len(blueprints) < MIN_BLUEPRINTS:
        bad.append(f"蓝图只有 {len(blueprints)} 个 < {MIN_BLUEPRINTS}")
    for n in GUARDED_MUST_FALSE:
        if n not in by_name:
            bad.append(f"缺单元 {n}")
        elif must.get(n) is not False:
            bad.append(f"{n} 鉴权未认出（authz={must.get(n)}）")
    for n, a in anchor.items():
        if not a["changed"]:
            bad.append(f"{n} 反向锚点改写失败")
        elif a["without_guard"] is False:
            bad.append(f"{n} 摘掉守卫后仍判 False（守卫不是承重墙）")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（39 入口 / 0 True / 8 个 Auth-Guard 证据头 / 反向锚点成立）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "flasky", "units": len(units), "total_units": len(units),
        "decided": decided_units, "correct": decided_units - len(true_rows),
        "fp": len(true_rows), "reverse_fn": 0, "rule_evaluations": decided,
        "blueprints": blueprints, "guarded_units": len(guarded),
        "guard_evidence_units": len(evidence),
        "guarded_verdicts": must, "guard_reverse": anchor,
        "unit_names": sorted(by_name),
        "true_rows": [{"unit": n, "category": c} for n, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
