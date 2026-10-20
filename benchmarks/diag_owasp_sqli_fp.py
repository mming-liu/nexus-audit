"""OWASP sqli/pathtraver 规则层误报逐条归因（只跑规则层，不调模型）。

背景：`--per-category 30` 下 sqli FPR 5/15、pathtraver 4/15，但逐条看下来
根因并不相同。这个脚本把每条误报的**值来源证据**与**当前判定**打出来。

切片很慢（OWASP 2740 个文件），所以把入口单元缓存成 pickle，
第二次起秒开。缓存里只有切片文本，不含任何模型结果。

用法：
    python benchmarks/diag_owasp_sqli_fp.py            # 首次建缓存
    python benchmarks/diag_owasp_sqli_fp.py --refresh  # 强制重建
"""
from __future__ import annotations

import os
import pickle
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.slicer.java_servlet import JavaSlicer          # noqa: E402
from core.agents import rule_detectors as R              # noqa: E402

REPO = os.path.join(ROOT, "reference_repos", "BenchmarkJava-master")
CACHE = os.path.join(ROOT, "benchmarks", "results", ".owasp_units.pkl")

CASES = {
    "sqli": ["BenchmarkTest00330", "BenchmarkTest01468", "BenchmarkTest01807",
             "BenchmarkTest01884", "BenchmarkTest02183"],
    "pathtraver": ["BenchmarkTest00365", "BenchmarkTest00958", "BenchmarkTest02035"],
}

MARKERS = ["This_should_always_happen", "a_Value", "barbarians_at_the_gate",
           "bobs_your_uncle", "safe!"]


def _slicer_fingerprint() -> str:
    """切片器/证据解析器的源码指纹。

    为什么需要：缓存只按文件存在与否判断，**改了 slicer 仍会命中旧切片**，
    于是"零回归"变成一句假话 —— 2026-10-20 实测：改完 `DATA_CALL_RE` 后直接
    跑回归，3 秒"通过"，实际用的还是改动前的切片。凡是"重建缓存后一致"的结论，
    都必须能证明缓存真的重建了。
    """
    import hashlib
    h = hashlib.sha256()
    files = [os.path.join(ROOT, "core", "slicer", "java_servlet.py"),
             os.path.join(ROOT, "core", "context", "java_impl_resolver.py"),
             os.path.join(ROOT, "core", "context", "taint_chain.py"),
             # 装配证据也进切片：改 excludePathPatterns 的解析同样会让
             # 旧缓存失效。指纹漏一个"影响切片内容"的文件，就等于留一条
             # "改了但回归说你没改"的后门 —— 这次差点又漏掉它。
             os.path.join(ROOT, "core", "context", "framework_wiring.py"),
             # 依赖组件版本块也进切片：新增/改动它同样会让旧缓存失效。
             # 漏掉这一行的后果与上次一模一样 —— 回归"通过"用的还是旧切片。
             os.path.join(ROOT, "core", "context", "dependency_versions.py"),
             # 形参主体注解块也进切片：仓库里有没有 HandlerMethodArgumentResolver
             # 直接决定切片里多不多那几行注释。
             os.path.join(ROOT, "core", "context", "argument_resolvers.py"),
             # CodeUnit 的字段变了（route_path），切片文本随之变化
             os.path.join(ROOT, "core", "models.py"),
             os.path.join(ROOT, "core", "text_utils.py"),
             os.path.abspath(__file__)]
    for p in files:
        try:
            st = os.stat(p)
        except OSError:
            continue
        h.update(f"{p}:{st.st_mtime_ns}:{st.st_size}".encode())
    return h.hexdigest()[:16]


def pick_unit(units: dict[str, str], case: str) -> str:
    """按用例名取**唯一**入口切片，同名多入口时锁 doPost。

    OWASP 的 TestCode 每个类都有 doGet + doPost 两条入口，真值标注的是
    doPost 那条链路（doGet 通常只做转发或页面壳）。用 `hit[0]` 取第一个，
    结果取决于切片器的输出顺序 —— 顺序一变，"静默放行"就凭空多出 264 条。
    """
    hit = [k for k in units if case in k]
    post = [k for k in hit if k.endswith(".doPost")]
    return (post or hit or [""])[0]


def load_units(refresh: bool = False) -> dict[str, str]:
    fp = _slicer_fingerprint()
    stamp = CACHE + ".fp"
    if not refresh and os.path.exists(CACHE) and os.path.exists(stamp):
        with open(stamp, encoding="utf-8") as fh:
            if fh.read().strip() == fp:
                with open(CACHE, "rb") as fh:
                    return pickle.load(fh)
    slicer = JavaSlicer(REPO)
    units = {u.unit_name: u.source_code for u in slicer.extract_entry_units()}
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    with open(CACHE, "wb") as fh:
        pickle.dump(units, fh)
    with open(stamp, "w", encoding="utf-8") as fh:
        fh.write(fp)
    return units


def main() -> None:
    refresh = "--refresh" in sys.argv
    units = load_units(refresh)
    print(f"入口总数 {len(units)}（缓存 {'已重建' if refresh else CACHE}）\n")

    for cat, names in CASES.items():
        print(f"########## {cat} ##########")
        for name in names:
            key = pick_unit(units, name)
            if not key:
                print(f"{name}: 未找到入口")
                continue
            src = units[key]
            body = R.entry_body(src)
            sib = R._sibling_methods(src)
            print(f"\n--- {key}")
            print(f"   sqli={R.sqli_verdict(src)}  pathtraver={R.pathtraver_verdict(src)}")
            print(f"   sqli_all_const={R._sql_concat_all_constant(body, sib)}"
                  f"  path_all_const={R._path_concat_all_constant(body, sib)}")
            for line in body.splitlines():
                s = line.strip()
                if "bar =" in s and "==" not in s:
                    print(f"   bar: {s[:110]}")
            for mk in MARKERS:
                if mk in sib:
                    print(f"   证据常量 {mk!r} 在 sib")
        print()


if __name__ == "__main__":
    main()
