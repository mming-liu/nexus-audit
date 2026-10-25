"""pallets/flask 官方教程应用 flaskr —— 第 18 野战仓，M107 Python 切片器淬火。

## 为什么选它

flaskr 是 Flask 官方文档手把手带读者写的**教程应用**（`examples/tutorial/flaskr`，
4 个模块 + schema）。它的价值不在"漏洞多"，而在**写法最规范**：

    @bp.route("/<int:id>/update", methods=("GET", "POST"))
    @login_required
    def update(id):
        post = get_post(id)            # ← 归属检查在**另一个函数**里

    def get_post(id, check_author=True):
        ...
        if check_author and post["author_id"] != g.user["id"]:
            abort(403, f"Post id {id} doesn't belong to user {g.user['id']}.")

官方自己把这叫 "the check_author argument is defined so that the function can be
used to get a post without checking the author" —— 教科书级的"跨函数归属校验"
形态，而且是**默认开启**的。

## M107 实测暴露的两个切片器缺陷（都已修）

1. **堆叠装饰器整条路由消失**。`@bp.route(...)` 与 `def` 之间隔了一个
   `@login_required`，而 `@login_required` 没有括号、装饰器正则匹配不上 ——
   旧逻辑只认"紧邻 def 上一行"，于是 `@bp.route` 被丢弃，`create/update/delete`
   三条路由**根本不在切片里**（实测 5 个单元而非 8 个）。
   修法：先算出 `def` 上方**连续装饰器块**的起始行，块内全部装饰器都收。

2. **DjanGoat 的路由通道指标口径错**（连带发现）。修好 ① 之后 DjanGoat 的
   视图先被 `@require_http_methods(...)` 装饰器通道收走，`_django_entries`
   按 (file, start_line) 去重就不再追加 `django:` 标记 —— 单元数 13 → 36
   （覆盖变好），而"带标记的单元数"指标掉成 0。指标改成直接问
   `_django_routes()` 解析器（35 条）。

## 门禁（--strict）

- 切片 ≥8 入口（实测 8：register/login/logout/index/create/update/delete/hello）；
- **全类目 0 True**（官方教程应用不该有任何 P0）；
- 跨函数归属校验**被认出**：`update` / `delete` 的 authz 必须是确定性 False
  （不是 None —— None 说明规则没看懂 `get_post` 里的 `author_id != g.user['id']`）；
- Hop 1 展开生效：`update` 的切片里必须出现 `get_post` 的函数体。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents import rule_detectors as R                     # noqa: E402
from core.slicer.web_treesitter import WebTreeSitterSlicer      # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "flaskr"
CATS = ("sqli", "cmdi", "xss", "pathtraver", "weakrand", "hash", "ssrf",
        "authz", "deserial", "spel", "xxe", "redir", "cors", "crypto",
        "trustbound", "securecookie", "ldapi", "xpathi", "ssti",
        "hardcoded_secret", "jwt_weakness", "header_injection")
MIN_UNITS = 8
OWNERSHIP_UNITS = ("update", "delete")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="flaskr 官方教程应用零误报 + 跨函数归属校验基准（M107）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥8 入口 + 全类目 0 True + update/delete 归属校验判 False")
    ap.add_argument("--offline", action="store_true", help="规则层（默认）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "flaskr.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}\n"
              "  flaskr 在 flask 仓的 examples/tutorial/flaskr —— 而 `examples`\n"
              "  在 IGNORE_DIRS 里，所以本基准用**拷贝出来的** reference_repos/flaskr\n"
              "  （来源 pallets/flask @ examples/tutorial/flaskr，M107）。")
        return 2

    units = WebTreeSitterSlicer(repo).extract_entry_units(repo)
    by_name = {u.unit_name: u for u in units}
    print(f"靶场：{repo}")
    print(f"      切片单元 {len(units)} 个：{sorted(by_name)}")

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

    own = {n: R.verdict("authz", by_name[n].source_code)
           for n in OWNERSHIP_UNITS if n in by_name}
    # Hop 1 展开：update 的切片里必须能看到 get_post 的函数体
    upd = by_name.get("update")
    hop1 = bool(upd and "def get_post" in (upd.source_code or ""))
    check_author = bool(upd and "check_author" in (upd.source_code or ""))

    print("=" * 72)
    print("flaskr 结果（官方教程应用 / 跨函数归属校验）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  单元覆盖（≥1 判定）   ：{decided_units}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    for n, c in true_rows[:10]:
        print(f"      [FP] {n} [{c}]")
    print("  跨函数归属校验（get_post 里的 author_id != g.user['id']）：")
    for n, v in own.items():
        print(f"    {n:8} authz = {v}")
    print(f"  Hop 1 展开（update 切片含 get_post 体）：{'✔' if hop1 else '✘'}")
    print(f"  check_author 机制在切片内：{'✔' if check_author else '✘'}")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}（堆叠装饰器没修？）")
    if true_rows:
        bad.append(f"计划外 True {len(true_rows)} 条")
    for n in OWNERSHIP_UNITS:
        if n not in by_name:
            bad.append(f"缺单元 {n}")
        elif own.get(n) is not False:
            bad.append(f"{n} 归属校验未认出（authz={own.get(n)}）")
    if not hop1:
        bad.append("Hop 1 未展开 get_post")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（8 入口 / 0 True / 跨函数归属校验判 False）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "flaskr", "units": len(units), "total_units": len(units),
        "decided": decided_units, "correct": decided_units - len(true_rows),
        "fp": len(true_rows), "reverse_fn": 0,
        "rule_evaluations": decided,
        "unit_names": sorted(by_name),
        "ownership_verdicts": {k: v for k, v in own.items()},
        "hop1_expanded": hop1,
        "check_author_in_slice": check_author,
        "true_rows": [{"unit": n, "category": c} for n, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
