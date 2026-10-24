"""FastAPI + SQLAlchemy 2.0 真实模板仓 — 第 28 个靶场，M80 Python 异步栈。

## 为什么选它

Jonatha-Varjao/fast-api-sql-template 是真实的分层 FastAPI 模板：
`async def` 路由、`APIRouter`、`Depends(require_superuser)`、SQLAlchemy 2.0
`session.execute(select(...))`、OAuth2 中间件。它专门用来压测：

  · `async def` / `@router.get` / `APIRouter` 能否被 Web 切片器识别；
  · `Depends(require_superuser)` 是否等价于方法级授权声明 → authz False；
  · `session.execute(select(Model).where(...))` 是否被误判 SQLi → sqli False。

## 门禁（--strict）

- ≥8 个异步入口；
- 5 个 users 管理端入口 authz False（有 require_superuser 依赖）；
- 全部入口 sqli False（SQLAlchemy 2.0 表达式绑定参数）；
- 全类目 0 条 True（零误报）。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict   # noqa: E402
from core.slicer.web_treesitter import WebTreeSitterSlicer       # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "fastapi-sql-template"
CATS = ("sqli", "cmdi", "xss", "pathtraver", "weakrand", "hash", "ssrf",
        "authz", "deserial", "spel", "xxe", "redir", "cors", "crypto",
        "trustbound", "securecookie", "ldapi", "xpathi", "jwt_weakness")
USER_ENDPOINTS = ("list_users_endpoint", "get_user_endpoint",
                  "create_user_endpoint", "update_user_endpoint",
                  "delete_user_endpoint")


def main() -> int:
    ap = argparse.ArgumentParser(description="FastAPI 真实模板仓基准")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥8 异步入口 + users 全 authz False + 0 True")
    ap.add_argument("--offline", action="store_true", help="规则层（默认）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "fastapi_wild.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/Jonatha-Varjao/fast-api-sql-template.git）")
        return 2

    units = WebTreeSitterSlicer(repo).extract_entry_units(repo)
    print(f"靶场：{repo}")
    print(f"      异步入口 {len(units)} 个")

    true_rows, decided_units = [], 0
    authz, sqli = {}, {}
    for u in units:
        one = False
        for c in CATS:
            v = rule_verdict(c, u.source_code)
            if v is None:
                continue
            one = True
            if v is True:
                true_rows.append((Path(u.file_path).name, u.unit_name, c))
        decided_units += 1 if one else 0
        name = u.unit_name.split("#")[0]
        authz[name] = rule_verdict("authz", u.source_code)
        sqli[name] = rule_verdict("sqli", u.source_code)

    print("=" * 72)
    print("FastAPI 结果（async + Depends + SQLAlchemy 2.0）")
    print("=" * 72)
    print(f"  异步入口              ：{len(units)}")
    print(f"  单元覆盖（≥1 判定）   ：{decided_units}")
    print(f"  规则层 True（误报）   ：{len(true_rows)}")
    print(f"  users authz           ："
          f"{ {k: authz.get(k) for k in USER_ENDPOINTS} }")
    print(f"  users sqli            ："
          f"{ {k: sqli.get(k) for k in USER_ENDPOINTS} }")

    bad = []
    if len(units) < 8:
        bad.append(f"异步入口 {len(units)} < 8")
    if true_rows:
        bad.append(f"规则层 True {len(true_rows)} 条")
    if any(authz.get(k) is not False for k in USER_ENDPOINTS):
        bad.append("users 入口 authz 未全部 False")
    if any(sqli.get(k) is True for k in USER_ENDPOINTS):
        bad.append("users 入口 sqli 出现 True")
    # delete 是空实现（pass），没有 SQL sink，合理为 None；其余四个必须
    # 被 SQLAlchemy 2.0 表达式判 False。
    if any(sqli.get(k) is not False for k in USER_ENDPOINTS[:4]):
        bad.append("users 查询/写入入口 sqli 未全部 False")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（async ' + str(len(units)) + ' 入口 / 0 True / Depends 授权在线）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "fastapi_wild", "units": len(units),
        "total_units": len(units), "decided": decided_units,
        "correct": decided_units - len(true_rows),
        "fp": len(true_rows), "reverse_fn": 0,
        "authz": {k: authz.get(k) for k in USER_ENDPOINTS},
        "sqli": {k: sqli.get(k) for k in USER_ENDPOINTS},
        "true_rows": [{"file": f, "unit": u, "category": c}
                      for f, u, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
