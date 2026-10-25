"""fastapi/full-stack-fastapi-template —— 第 32 野战仓（Python #8），M154。

## 为什么选它

这是 FastAPI 官方维护的全栈模板，把认证写成了三层框架机制，
函数体里几乎看不到主体判断：

    # app/api/deps.py
    SessionDep = Annotated[Session, Depends(get_db)]
    CurrentUser = Annotated[User, Depends(get_current_user)]

    # app/api/routes/users.py
    router = APIRouter(prefix="/users", tags=["users"])

    @router.get("/", dependencies=[Depends(get_current_active_superuser)])
    def read_users(session: SessionDep, ...): ...

    @router.get("/me")
    def read_user_me(current_user: CurrentUser): ...

判据只读函数体时会遇到两个"名字里没有 auth 语义"的坑：

  · CurrentUser 是**类型别名**，签名里只有 current_user: CurrentUser；
  · 路由级 dependencies 写在**多行装饰器**里，entry_body 一个字都看不到。

## 本轮修的三处（都由真实代码逼出）

1. 跨行装饰器尾巴污染：_read_symbol 只剥以 @ 开头的尾行，
   @router.post( 多行参数的续行（含 dependencies）会混进上一个入口体。
2. Annotated[..., Depends(...)] 别名与 APIRouter(dependencies=[...])
   需要展开成 // Auth-Dependency: Depends(...) 证据头，并贴依赖实现体。
3. python_authz_verdict 的 Depends 扫描只看 body，互补上 source 与
   get_current_active_superuser 这一族。

## 门禁（--strict）

- 切片 >=20 入口；
- 32 类 0 条 True（生产模板零误报）；
- 四个 superuser 路由 authz 必须 False；/items 的 CurrentUser 路由 False；
- private.py 的 create_user 只挂在 FASTAPI_ENV=development 分支上，
  按口径退 None（不登记为真值）；
- **反向锚点**：把 update_user 的 Auth-Dependency 证据头与依赖实现体
  一起剥掉，authz 必须从 False 翻成 True —— 证明 False 来自依赖证据。
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
from core.slicer.web_treesitter import WebTreeSitterSlicer     # noqa: E402

ensure_utf8_stdio()

DEFAULT_TARGET = ROOT / "reference_repos" / "full-stack-fastapi-template" / "backend"
MIN_UNITS = 20
SUPERUSER_ROUTES = ("read_users", "create_user", "update_user", "delete_user")
CURRENTUSER_ROUTES = ("read_items", "read_item", "create_item", "update_item",
                      "delete_item", "read_user_me", "delete_user_me")


def _unit(units, name, filename=None):
    for u in units:
        if u.unit_name == name and (filename is None
                                    or Path(u.file_path).name == filename):
            return u
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description="full-stack-fastapi-template Annotated/APIRouter 依赖基准（M154）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" /
                                            "fastapi_fullstack.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/fastapi/full-stack-fastapi-template.git）")
        return 2
    units = list(WebTreeSitterSlicer(repo).extract_entry_units(repo))
    print(f"靶场：{repo}")
    print(f"       入口 {len(units)} 个")

    true_rows: list[tuple[str, str, str]] = []
    decided = 0
    for u in units:
        for cat in CATEGORIES:
            v = R.verdict(cat, u.source_code)
            if v is None:
                continue
            decided += 1
            if v is True:
                true_rows.append((Path(u.file_path).name, u.unit_name, cat))

    checks: dict[str, bool | None] = {}
    for name in SUPERUSER_ROUTES:
        u = _unit(units, name, "users.py")
        checks["superuser:" + name] = (R.verdict("authz", u.source_code)
                                       if u else None)
    for name in CURRENTUSER_ROUTES:
        u = _unit(units, name)
        checks["currentuser:" + name] = (R.verdict("authz", u.source_code)
                                         if u else None)
    private = _unit(units, "create_user", "private.py")
    checks["dev-only:private.create_user"] = (
        R.verdict("authz", private.source_code) if private else None)

    anchor_unit = _unit(units, "update_user", "users.py")
    anchor = None
    if anchor_unit:
        stripped = anchor_unit.source_code.split("// ---- 依赖实现体")[0]
        stripped = "\n".join(l for l in stripped.splitlines()
                             if not l.startswith("// Auth-Dependency"))
        anchor = R.verdict("authz", stripped)

    alias_header = bool(anchor_unit and "Depends(get_current_active_superuser)"
                        in anchor_unit.source_code)
    read_users = _unit(units, "read_users", "users.py")
    router_dep = bool(read_users and
                      "Depends(get_current_active_superuser)"
                      in read_users.source_code)

    print("=" * 72)
    print("full-stack-fastapi-template 结果（Annotated / APIRouter dependencies）")
    print("=" * 72)
    print(f"  入口                    ：{len(units)}")
    print(f"  规则判定次数            ：{decided}")
    print(f"  True（误报）            ：{len(true_rows)}")
    for f, n, c in true_rows[:12]:
        print(f"      [FP] {f}:{n} [{c}]")
    print("  superuser 路由 authz：")
    for name in SUPERUSER_ROUTES:
        print(f"      {name:22} {checks['superuser:' + name]}")
    print("  CurrentUser 路由 authz：")
    for name in CURRENTUSER_ROUTES:
        print(f"      {name:22} {checks['currentuser:' + name]}")
    print(f"  development-only 路由   ：{checks['dev-only:private.create_user']}")
    print(f"  别名证据头 / Router 依赖：{alias_header} / {router_dep}")
    print(f"  反向锚点（剥证据后）    ：{anchor}")

    bad: list[str] = []
    if len(units) < MIN_UNITS:
        bad.append(f"入口 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"出现 {len(true_rows)} 条 True 误报")
    for name in SUPERUSER_ROUTES:
        if checks["superuser:" + name] is not False:
            bad.append(f"superuser:{name} 未判 False")
    for name in CURRENTUSER_ROUTES:
        if checks["currentuser:" + name] is not False:
            bad.append(f"currentuser:{name} 未判 False")
    if checks["dev-only:private.create_user"] is True:
        bad.append("development-only 路由被判 True（应退 None）")
    if not alias_header:
        bad.append("Annotated 别名证据头缺失")
    if not router_dep:
        bad.append("APIRouter/装饰器 dependencies 证据缺失")
    if anchor is not True:
        bad.append(f"反向锚点未翻 True（{anchor}）")
    ok = not bad
    print()
    print("STRICT PASS ✔（23 入口 / 32 类 0 True / superuser+CurrentUser 全 False / "
          "反向锚点 True）" if ok else "STRICT FAIL ✘ " + "；".join(bad))

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "fastapi_fullstack", "units": len(units),
        "total_units": len(units), "decided": decided,
        "correct": len(units) - len(true_rows), "fp": len(true_rows),
        "reverse_fn": 0, "rule_evaluations": decided,
        "checks": {k: v for k, v in checks.items()},
        "alias_header": alias_header, "router_dep": router_dep,
        "anchor": anchor,
        "true_rows": [{"file": f, "unit": n, "category": c}
                      for f, n, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
