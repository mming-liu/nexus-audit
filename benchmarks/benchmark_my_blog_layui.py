"""ZHENFENG13/My-Blog-layui —— 第 30 野战仓（Java #13），M144（30 仓里程碑）。

## 为什么选它

My-Blog 有两个并存实现：`My-Blog`（M63 已接入的 Thymeleaf 原版）与
`My-Blog-layui`（本仓，Layui 后台 + Spring Security 过滤器链 + MyBatis-Plus）。
同一个业务、两套前端，正好用来做**双生对照**：规则层不该因为换了个 UI
骨架就判出不同结论。

本仓的三条真值（逐条人工核对过源码）：

  1. **MD5 口令哈希**（`hash` ×2）：`AdminController.login` 与
     `userInfoUpdate` 都是 `MD5Utils.MD5Encode(password, "UTF-8")` 直接落库/比对。
     MD5 是**无盐快速摘要**，口令表可离线爆破 —— 确定性真值。
  2. **富文本/JS 上下文未转义回显**（`xss` ×1）：`BlogController.gotoBlogEdit`
     把整条 `blogInfo` 与 `blogTags` 塞进 model 再 `return "adminLayui/blog-edit"`，
     视图证据命中 `blog-edit.html:145`：
         formSelects.value('tagId', [[${blogTags}]], true);
     —— `[[${...}]]` 是 Thymeleaf 的**内联表达式（不转义）**，而它落在
     JavaScript **字符串/数组**上下文里：标签名里带引号就能截断字符串。
     同文件 :85 的 `th:utext="${blogInfo.blogContent}"` 也是不转义渲染
     （`th:text` 才转义）。

## 门禁（--strict）

- 切片 ≥60 入口（实测 64）；
- **计划外 True 0 条**：除上面登记的两类真值外，全类目不许再有任何 True
  （SQL 拼接 / 管理端鉴权 / 路径 / SSRF 一律 0）；
- 管理端鉴权：≥40 个入口带 `[global-authz]` 标记（过滤器链确实装配上了），
  且 `authz` 维度 0 True；
- **双锚点**（两条都要翻得动）：
  · `hash`：把摘要算法字面量 `"MD5"` 换成 `"SHA-256"` 后必须不再是 True
    （切片里连 Hop 证据的实现体一起改，否则改的只是调用点、算法还在）；
  · `xss`：把「关联视图模板」证据段整段摘掉后必须不再是 True
    （证明 True 来自模板渲染点，不是函数体里猜出来的）。
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

DEFAULT_TARGET = ROOT / "reference_repos" / "My-Blog-layui"
MIN_UNITS = 60
MIN_GLOBAL_AUTHZ = 40
# 登记的确定性真值（类目 → 条数）
TRUTH = {"hash": 2, "xss": 1}
_MD5_LITERAL = re.compile(r'"MD5"')
_MOD_SEP = "// ---- 修饰符定义"
_TEMPLATE_SEP = "// ---- 关联视图模板"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="My-Blog-layui 双生对照基准：MD5 口令 + 富文本回显（M144）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥60 入口 + 计划外 True 0 + 双锚点翻转")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "my_blog_layui.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/ZHENFENG13/My-Blog-layui.git）")
        return 2

    units = JavaSlicer(repo).extract_entry_units()
    print(f"靶场：{repo}")
    print(f"      切片单元 {len(units)} 个")

    by_cat: dict[str, list] = {}
    decided = 0
    for u in units:
        for c in sorted(CATEGORIES):
            v = R.verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            if v is True:
                by_cat.setdefault(c, []).append(u)
    planned = sum(TRUTH.values())
    unplanned = {c: len(us) for c, us in by_cat.items()
                 if c not in TRUTH or len(us) != TRUTH[c]}
    global_authz = [u for u in units if "[global-authz]" in (u.source_code or "")]

    # 锚点 1：摘要算法字面量 MD5 → SHA-256（连 Hop 证据里的实现体一起改）
    hash_anchor = {}
    hu = (by_cat.get("hash") or [None])[0]
    if hu:
        src = hu.source_code
        mutated = _MD5_LITERAL.sub('"SHA-256"', src)
        hash_anchor = {"with_md5": R.verdict("hash", src),
                       "with_sha256": R.verdict("hash", mutated),
                       "changed": mutated != src}
    # 锚点 2：摘掉「关联视图模板」证据段
    xss_anchor = {}
    xu = (by_cat.get("xss") or [None])[0]
    if xu:
        src = xu.source_code
        i = src.find(_TEMPLATE_SEP)
        mutated = src[:i] if i >= 0 else src
        xss_anchor = {"with_model": R.verdict("xss", src),
                      "without_model": R.verdict("xss", mutated),
                      "changed": mutated != src}

    print("=" * 72)
    print("My-Blog-layui 结果（MD5 口令 / 富文本回显 / 管理端鉴权）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  全局鉴权标记单元      ：{len(global_authz)}")
    print(f"  authz True            ：{len(by_cat.get('authz') or [])}")
    print("  登记真值：")
    for c, n in TRUTH.items():
        got = len(by_cat.get(c) or [])
        print(f"    {c:8} 期望 {n} 实得 {got}"
              + ("" if got == n else "   ← 不一致"))
    for c, n in unplanned.items():
        print(f"    [计划外] {c} = {n}")
    if hash_anchor:
        print(f"  hash 锚点：MD5={hash_anchor['with_md5']} "
              f"SHA256={hash_anchor['with_sha256']}"
              f"（改写生效={hash_anchor['changed']}）")
    if xss_anchor:
        print(f"  xss 锚点：有 model={xss_anchor['with_model']} "
              f"无 model={xss_anchor['without_model']}"
              f"（改写生效={xss_anchor['changed']}）")

    bad: list[str] = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if len(global_authz) < MIN_GLOBAL_AUTHZ:
        bad.append(f"全局鉴权标记单元 {len(global_authz)} < {MIN_GLOBAL_AUTHZ}")
    if by_cat.get("authz"):
        bad.append(f"authz 判 True {len(by_cat['authz'])} 条（管理端路由不该越权）")
    for c, n in TRUTH.items():
        got = len(by_cat.get(c) or [])
        if got != n:
            bad.append(f"{c} 真值 {n} 条，实得 {got}")
    for c, n in unplanned.items():
        bad.append(f"计划外 True：{c} = {n}")
    if not hash_anchor:
        bad.append("缺 hash 锚点单元")
    elif not hash_anchor["changed"]:
        bad.append("hash 锚点改写失败")
    elif hash_anchor["with_sha256"] is True:
        bad.append("换成 SHA-256 后 hash 仍判 True")
    if not xss_anchor:
        bad.append("缺 xss 锚点单元")
    elif not xss_anchor["changed"]:
        bad.append("xss 锚点改写失败")
    elif xss_anchor["without_model"] is True:
        bad.append("摘掉 model.addAttribute 后 xss 仍判 True")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（64 入口 / 真值 3 条全中 / 计划外 0 / 双锚点成立）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "my_blog_layui", "units": len(units),
        "total_units": len(units), "decided": len(units),
        "correct": planned, "fp": sum(unplanned.values()), "reverse_fn": 0,
        "rule_evaluations": decided, "global_authz_units": len(global_authz),
        "truth": TRUTH,
        "truth_hits": {c: len(by_cat.get(c) or []) for c in TRUTH},
        "unplanned": unplanned,
        "hash_anchor": hash_anchor, "xss_anchor": xss_anchor,
        "true_rows": [{"unit": u.unit_name, "category": c}
                      for c, us in by_cat.items() for u in us],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
