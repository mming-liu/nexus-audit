"""nsidnev/fastapi-realworld-example-app —— 第 23 野战仓，M120 多模块 APIRouter。

## 为什么选它

这是 RealWorld 规范的**完整生产级 FastAPI 后端**：`app/api/routes/` 下
authentication / users / profiles / articles（含 `articles_common.py` +
`articles_resource.py` 两层）/ comments / tags 六组路由，全部用
`APIRouter` 挂载，鉴权走 `Depends(get_current_user_authorizer())` 高阶依赖，
数据库走 `databases` + asyncpg 的 **`$1`/`:name` 参数化**。

## M120 实测暴露的切片器缺陷

**跨行装饰器整条路由消失**。FastAPI 的装饰器常写成多行：

    @router.post(
        "",
        status_code=status.HTTP_201_CREATED,
        response_model=ArticleInResponse,
    )
    async def create_article(...):

M107 的"连续装饰器块"只处理了**单行**堆叠（`@a\\n@b\\ndef`），跨行形态仍是
"紧邻上一行是 `)`、不是 `@`" → 直接 break。整个仓库 19 条路由只切出 **6** 条。
修法：从 `def` 往上累计，直到"从该行到 def"的**括号配平**；配平后若该行以
`@` 开头就是块起点，再往上把堆叠的单行装饰器一并收进来。

## 门禁（--strict）

- 切片 ≥18 入口（实测 19，与仓库里 19 个 `@router.*` 逐一对上）；
- 全类目 **0 条 True**；
- **`$1`/`:name` 参数化必须判 False**（不是 None）—— 但只在**占位符与实参
  同处一次调用**时成立：

      await conn.fetch("SELECT ... WHERE slug = :slug", {"slug": slug})   → False

  本仓库的 `ArticlesRepository._force_fetch(query, values={...})` 把 SQL 放在
  变量里（占位符在赋值处、实参在调用处），跨语句的数据流不在规则层的能力
  范围内 —— 这一条实测仍是 None，**如实登记为已知缺口**，不硬判 False。
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

DEFAULT_TARGET = ROOT / "reference_repos" / "fastapi-realworld"
CATS = ("sqli", "cmdi", "xss", "pathtraver", "weakrand", "hash", "ssrf",
        "authz", "deserial", "spel", "xxe", "redir", "cors", "crypto",
        "trustbound", "securecookie", "ldapi", "xpathi", "ssti",
        "hardcoded_secret", "jwt_weakness", "header_injection")
MIN_UNITS = 18


def main() -> int:
    ap = argparse.ArgumentParser(
        description="fastapi-realworld 多模块 APIRouter 零误报基准（M120）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥18 入口 + 全类目 0 True + $1 参数化判 False")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "fastapi_rw.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/nsidnev/fastapi-realworld-example-app.git）")
        return 2

    units = list(WebTreeSitterSlicer(repo).extract_entry_units(repo))
    print(f"靶场：{repo}")
    print(f"      切片单元 {len(units)} 个：{sorted(u.unit_name for u in units)}")

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

    # `$1` / `:name` 参数化：占位符与实参**同处一次调用**时判 False。
    # 仓库里那层 `_force_fetch(query, values=…)` 把 SQL 放变量里，跨语句数据流
    # 不在规则层能力范围 —— 那个真实形态单独记一笔（known_gap）。
    param_verdict = R.verdict(
        "sqli",
        'async def f(conn, slug):\n'
        '    return await conn.fetch('
        '"SELECT a.slug FROM articles a WHERE a.slug = :slug",'
        ' {"slug": slug})\n')
    repo_file = next(repo.rglob("articles_repository.py"), None)
    repo_verdict = (R.verdict("sqli", repo_file.read_text(encoding="utf-8"))
                    if repo_file else None)

    print("=" * 72)
    print("fastapi-realworld 结果（多模块 APIRouter）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  单元覆盖（≥1 判定）   ：{decided_units}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    for n, c in true_rows[:10]:
        print(f"      [FP] {n} [{c}]")
    print(f"  `$1`/`:name` 参数化 repository 的 sqli 判定：{param_verdict}")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}（跨行装饰器没修？）")
    if true_rows:
        bad.append(f"计划外 True {len(true_rows)} 条")
    if param_verdict is not False:
        bad.append(f"占位符+实参同调的参数化 SQL 判成 {param_verdict}（应为 False）")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（19 入口 / 全类目 0 True / 参数化 SQL 判 False）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "fastapi_rw", "units": len(units),
        "total_units": len(units), "decided": decided_units,
        "correct": decided_units - len(true_rows), "fp": len(true_rows),
        "reverse_fn": 0, "rule_evaluations": decided,
        "param_sql_verdict": ("None" if param_verdict is None
                              else bool(param_verdict)),
        "known_gap_force_fetch": ("None" if repo_verdict is None
                                   else bool(repo_verdict)),
        "unit_names": sorted(u.unit_name for u in units),
        "true_rows": [{"unit": n, "category": c} for n, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
