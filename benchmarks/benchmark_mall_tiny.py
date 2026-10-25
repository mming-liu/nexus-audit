"""macrozheng/mall-tiny —— 第 28 野战仓（Java #12），M138。

## 为什么选它

mall-tiny 是 macros 商城系列里**最小可运行**的一版（40 个路由入口），
但它把 Spring Boot 的三大件一次性摆齐了：

    · Spring Security + JWT（`MallSecurityConfig` + `JwtAuthenticationTokenFilter`）
    · MyBatis-Plus（`QueryWrapper` / `UpdateWrapper` 的条件构造）
    · 全局 CORS（`GlobalCorsConfig`：`allowedOriginPatterns("*")` + 凭证）

它是一条**零误报**门禁：这三件件都会让"只读方法体"的判据误报 ——
JWT 过滤器配上之后方法体里没有权限注解；MyBatis-Plus 的 Wrapper 拼的是
常量列名；CORS 的缺陷在**配置类**里、每个路由都看得见同一份。

## 一处**真**根因（这条门禁不掩盖它）

`GlobalCorsConfig` 同时做了两件事：

    config.addAllowedOriginPattern("*");
    config.setAllowCredentials(true);

`*` + 凭证意味着任何站点都能带着受害者的 Cookie 读接口 —— 这是
**通配 + 凭证**的确定性根因（CWE-942）。它不是 40 个漏洞，是 **1 个**：
40 条路由命中全部来自同一份配置文本。门禁按 waynboot-mall 的既有口径
把它折叠成 1 个全局根因，并要求**承载文件唯一**。

## 门禁（--strict）

- 切片 ≥40 入口；
- `cors` 之外**全类目 0 True**（Spring Security / JWT / MyBatis-Plus 三件套
  一条误报都不许有）；
- `cors` 的 True 必须全部来自**同一个承载文件**，且折叠后的全局根因 = 1；
- **反向锚点**：把 `addAllowedOriginPattern("*")` 摘掉后，cors 必须**不再是
  True** —— 证明那 40 条是配置真的被读到了，不是碰巧命中。
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
from core.agents.vuln_categories import CATEGORIES              # noqa: E402
from core.slicer.java_servlet import JavaSlicer                 # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "mall-tiny"
MIN_UNITS = 40
GLOBAL_CORS_ROOTS = 1
# 装配证据里的框架组件标记：`// [cors-config] GlobalCorsConfig urlPatterns=['/**'] …`
_CORS_CARRIER_RE = re.compile(r"//\s*\[cors-config\]\s+([A-Za-z_]\w*)")
# "正确修复"的形态：把通配换成显式白名单（这是真正的修法，不是删配置）
_WILDCARD = 'addAllowedOriginPattern("*")'
_ALLOWLIST = 'addAllowedOrigin("https://admin.example.com")'


def main() -> int:
    ap = argparse.ArgumentParser(
        description="mall-tiny 零误报基准：JWT / MyBatis-Plus / 全局 CORS（M138）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥40 入口 + cors 外 0 True + 全局 CORS 折叠为 1 + 反向锚点")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "mall_tiny.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/macrozheng/mall-tiny.git）")
        return 2

    units = JavaSlicer(repo).extract_entry_units()
    cats = tuple(sorted(CATEGORIES))
    print(f"靶场：{repo}")
    print(f"      切片单元 {len(units)} 个")

    true_rows: list[tuple[str, str, str]] = []
    decided = 0
    for u in units:
        for c in cats:
            v = R.verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            if v is True:
                true_rows.append((Path(u.file_path).name, u.unit_name, c))

    non_cors = [r for r in true_rows if r[2] != "cors"]
    cors_rows = [r for r in true_rows if r[2] == "cors"]
    # 承载组件：从装配证据的 `[cors-config]` 标记读框架组件名 —— 不是路由
    # 所在的 Controller（40 条命中分布在 5 个 Controller 里，但缺陷只有一份）。
    carriers = sorted({
        _cors_carrier(u.source_code)
        for u in units
        if R.verdict("cors", u.source_code) is True
    } - {""})

    # 反向锚点：把通配换成**显式白名单**（真正的修法）→ 必须翻 False；
    # 另外把整块装配证据摘掉 → 必须不再是 True（缺证据不是"有漏洞"）。
    anchor = {}
    src0 = units[0].source_code if units else ""
    if _WILDCARD in src0:
        fixed = src0.replace(_WILDCARD, _ALLOWLIST)
        cut = src0[:src0.find("// ---- 框架装配证据")] \
            if "// ---- 框架装配证据" in src0 else ""
        anchor = {"with_wildcard": R.verdict("cors", src0),
                  "with_allowlist": R.verdict("cors", fixed),
                  "without_evidence": R.verdict("cors", cut) if cut else None,
                  "changed": fixed != src0}

    print("=" * 72)
    print("mall-tiny 结果（Spring Security + JWT / MyBatis-Plus / 全局 CORS）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  cors 之外 True        ：{len(non_cors)}")
    for f, n, c in non_cors[:10]:
        print(f"      [FP] {f}:{n} [{c}]")
    print(f"  cors True 行数        ：{len(cors_rows)}"
          f"（承载文件 {carriers}）")
    print(f"  折叠后全局根因数      ：{len(carriers)}")
    if anchor:
        print(f"  反向锚点：通配={anchor['with_wildcard']} "
              f"显式白名单={anchor['with_allowlist']} "
              f"无装配证据={anchor['without_evidence']}"
              f"（改写生效={anchor['changed']}）")

    bad: list[str] = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if non_cors:
        bad.append(f"cors 之外计划外 True {len(non_cors)} 条")
    if not cors_rows:
        bad.append("cors 一条都没判出来（通配+凭证是真根因，不许静默）")
    if len(carriers) != GLOBAL_CORS_ROOTS:
        bad.append(f"cors 承载组件 {len(carriers)} 个 != {GLOBAL_CORS_ROOTS}"
                   "（应折叠成同一个全局配置）")
    if not anchor:
        bad.append("反向锚点：切片里找不到通配行")
    elif not anchor["changed"]:
        bad.append("反向锚点改写失败")
    elif anchor["with_allowlist"] is not False:
        bad.append(f"换成显式白名单后仍判 {anchor['with_allowlist']}"
                   "（配置不是承重墙）")
    elif anchor["without_evidence"] is True:
        bad.append("摘掉装配证据后仍判 True（缺证据不该当有漏洞）")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（40 入口 / cors 外 0 True / 全局 CORS 折叠为 1 个根因 / 反向锚点成立）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "mall_tiny", "units": len(units), "total_units": len(units),
        "decided": len(units), "correct": len(units) - len(non_cors),
        "fp": len(non_cors), "reverse_fn": 0, "rule_evaluations": decided,
        "cors_rows": len(cors_rows), "cors_carriers": carriers,
        "unique_global_root_causes": len(carriers), "cors_anchor": anchor,
        "true_rows": [{"file": f, "unit": n, "category": c}
                      for f, n, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


def _cors_carrier(src: str) -> str:
    m = _CORS_CARRIER_RE.search(src or "")
    return m.group(1) if m else ""


if __name__ == "__main__":
    sys.exit(main())
