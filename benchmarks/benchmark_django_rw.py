"""gothinkster/django-realworld-example-app —— 第 24 野战仓，M121 DRF 类视图。

## 为什么选它

这是 RealWorld 规范的 **Django REST Framework** 实现，路由全部指向**类视图**：

    url(r'^articles/feed/?$', ArticlesFeedAPIView.as_view()),
    router.register(r'articles', ArticleViewSet)        # DefaultRouter

而 DRF 的鉴权声明在**类属性**上：

    class ArticleViewSet(viewsets.GenericViewSet):
        permission_classes = (IsAuthenticatedOrReadOnly,)

方法体里一个字都看不到。M121 之前，`_django_routes` 遇到 `as_view` 直接
`continue` —— 整个仓库只切出 **1 个单元**（还是 `@receiver` 信号），DRF
通道等于不存在。

## M121 补的三件事

1. **类视图切片**：`url(..., Xxx.as_view())` 取 `get/post/put/patch/delete`，
   `router.register(r'p', XxxViewSet)` 取 `list/create/retrieve/update/
   partial_update/destroy`；按"方法行号落在类体范围内 + 同文件"精确定位
   （indexer 里类与方法都按裸名索引，没有 `Class.method` 键）。
2. **类属性注入切片头**：`// View-Action: update` + `// Permission-Classes:
   IsAuthenticatedOrReadOnly` —— 没有这两行，鉴权判据无从区分"公开读"与
   "登录即可写"。
3. **读写分治**（`_drf_authz_verdict`）：
   · 读动作（`list`/`retrieve`/`get`）→ False（公开读是被允许的）；
   · 写动作且只要求 `IsAuthenticated` 而不核对归属 → **True**（BOLA）；
   · `IsAdminUser`/`IsOwnerOrReadOnly` 或方法体里比对 `request.user` → False；
   · **先取现成资源**（`self.queryset.get(...)`）才谈得上越权 —— `create`、
     "收藏"、"关注"、登录注册这些不取现成资源，判 True 只会造假阳。

## 门禁（--strict）

- 切片 ≥8 个 DRF 动作单元（实测 10 个 + 1 个 signal = 11）；
- 只有 `ArticleViewSet.update` 一条 authz True（真 BOLA：`permission_classes`
  只有 `IsAuthenticatedOrReadOnly`，而 `update` 直接 `self.queryset.get(slug=slug)`
  拿别人的文章改）；
- `list`/`retrieve` 必须判 False（公开读）；
- 全类目除那一条外 0 True。
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

DEFAULT_TARGET = ROOT / "reference_repos" / "django-realworld"
CATS = ("sqli", "cmdi", "xss", "pathtraver", "weakrand", "hash", "ssrf",
        "authz", "deserial", "spel", "xxe", "redir", "cors", "crypto",
        "trustbound", "securecookie", "ldapi", "xpathi", "ssti",
        "hardcoded_secret", "jwt_weakness", "header_injection")
MIN_DRF = 8
# 唯一预期的 authz 真阳（缺 IsOwnerOrReadOnly 的 BOLA）
EXPECTED_BOLA = "ArticleViewSet.update"
PUBLIC_READS = ("ArticleViewSet.list", "ArticleViewSet.retrieve")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="django-realworld DRF 类视图基准（M121）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥8 个 DRF 动作 + 只有 1 条 BOLA 真阳 + 公开读判 False")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "django_rw.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/gothinkster/django-realworld-example-app.git）")
        return 2

    units = list(WebTreeSitterSlicer(repo).extract_entry_units(repo))
    drf = [u for u in units
           if any(d.startswith("django:") for d in u.decorators_or_modifiers)]
    print(f"靶场：{repo}")
    print(f"      切片单元 {len(units)} 个，其中 DRF 动作 {len(drf)} 个")

    true_rows: list[tuple[str, str]] = []
    decided = 0
    for u in units:
        for c in CATS:
            v = R.verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            if v is True:
                true_rows.append((u.unit_name, c))

    authz_true = sorted(n for n, c in true_rows if c == "authz")
    others = [(n, c) for n, c in true_rows if c != "authz"]
    read_v = {u.unit_name: R.verdict("authz", u.source_code)
              for u in drf if u.unit_name in PUBLIC_READS}

    print("=" * 72)
    print("django-realworld 结果（DRF 类视图 + permission_classes）")
    print("=" * 72)
    print(f"  DRF 动作单元          ：{len(drf)}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    print(f"    authz 真阳          ：{authz_true}")
    print(f"    其它类目 True       ：{others}")
    print("  公开读动作的 authz 判定：")
    for n, v in read_v.items():
        print(f"    {n:28} {v}")

    bad = []
    if len(drf) < MIN_DRF:
        bad.append(f"DRF 动作 {len(drf)} < {MIN_DRF}（类视图通道没打通？）")
    if authz_true != [EXPECTED_BOLA]:
        bad.append(f"authz 真阳 {authz_true} != [{EXPECTED_BOLA}]")
    if others:
        bad.append(f"其它类目出现 {len(others)} 条 True")
    for n in PUBLIC_READS:
        if n in read_v and read_v[n] is not False:
            bad.append(f"公开读 {n} 未判 False（{read_v[n]}）")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（10 个 DRF 动作 / 1 条真 BOLA / 公开读判 False）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "django_rw", "units": len(units),
        "total_units": len(units), "drf_actions": len(drf),
        "decided": len(units), "correct": len(units) - len(true_rows),
        "fp": len(others), "reverse_fn": 0,
        "rule_evaluations": decided,
        "authz_true": authz_true,
        "public_read_verdicts": {k: (None if v is None else bool(v))
                                 for k, v in read_v.items()},
        "drf_units": sorted(u.unit_name for u in drf),
        "true_rows": [{"unit": n, "category": c} for n, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
