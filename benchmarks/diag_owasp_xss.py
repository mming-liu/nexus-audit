"""OWASP xss 类目的规则层错判诊断。

只跑规则层（不调模型），把错判样本的判定路径打印出来，方便逐条归因。
用法：
    python benchmarks/diag_owasp_xss.py --cases 00149,00288
    python benchmarks/diag_owasp_xss.py --stats     # 只统计 sink 形态分布
"""
from __future__ import annotations

import argparse
import collections
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TARGET = ROOT / "reference_repos/BenchmarkJava-master"
CODE = TARGET / "src/main/java/org/owasp/benchmark/testcode"

SINK_RE = re.compile(
    r"(?:\.\s*getWriter\s*\(\s*\)|\.\s*getOutputStream\s*\(\s*\))"
    r"\s*\.\s*(?P<verb>print|println|printf|write|format)\s*\((?P<args>[^;]*)\)\s*;")
LOCALE = r"(?:java\.util\.Locale\.US\s*,\s*)?"


def _kind(verb: str, args: str) -> str:
    a = re.sub(r"\s+", " ", args.strip())
    if a.startswith("bar.toCharArray"):
        return f"{verb}.toCharArray"
    if re.fullmatch(LOCALE + r"bar", a):
        return f"{verb}(bar)"
    if re.fullmatch(LOCALE + r"bar,\s*obj", a):
        return f"{verb}(bar, obj)  ← bar 当格式串"
    if re.fullmatch(LOCALE + r"\"[^\"]*\",\s*obj", a):
        return f"{verb}(字面量, obj)"
    if a.startswith('"') and "bar" not in a:
        return f"{verb}(纯字面量)"
    return f"{verb}(其它)"


def stats() -> None:
    from core.agents.rule_detectors import XSS_ENCODE_RE, entry_body
    agg: collections.Counter = collections.Counter()
    for f in sorted(CODE.glob("BenchmarkTest*.java")):
        src = f.read_text(encoding="utf-8", errors="ignore")
        if "/xss-" not in src:
            continue
        body = entry_body(src)
        enc = bool(XSS_ENCODE_RE.search(body))
        for m in SINK_RE.finditer(body):
            agg[(_kind(m.group("verb"), m.group("args")), enc)] += 1
    print(f"{'':>4} {'已编码':<6} sink 形态")
    for (k, enc), v in agg.most_common(30):
        print(f"{v:>4} {'是' if enc else '否':<6} {k}")


def diag(names: list[str]) -> None:
    from benchmarks.benchmark_owasp import load_expected
    from core.agents import rule_detectors as RD
    from core.models import base_unit_name
    from core.slicer.java_servlet import JavaSlicer

    expected = load_expected(TARGET)
    units = JavaSlicer(CODE).extract_entry_units()
    by_case = {}
    for u in units:
        cls, meth = base_unit_name(u.unit_name).split(".", 1)
        if meth == "doPost" and cls in expected:
            by_case[cls] = u

    if not names:
        names = sorted(n for n, c in expected.items()
                       if c.category == "xss" and n in by_case)
    else:
        names = [n if n.startswith("Benchmark") else f"BenchmarkTest{int(n):05d}"
                 for n in names]

    for name in names:
        case = expected.get(name)
        if case is None or name not in by_case:
            print(f"{name}: 缺失")
            continue
        src = by_case[name].source_code
        v = RD.verdict("xss", src)
        mark = "OK " if v == case.real_vuln else "ERR"
        body = RD.entry_body(src)
        print(f"\n{'='*70}\n{mark} {name} 真值={case.real_vuln} 规则={v}")
        print(f"    has_external_input = {RD.has_external_input(src)}")
        print(f"    ENCODE(body)       = {bool(RD.XSS_ENCODE_RE.search(body))}")
        print(f"    template_render    = {RD._template_render(src)}")
        print(f"    plain_chain        = {RD._has_plain_chain(src)}")
        for m in SINK_RE.finditer(body):
            print(f"    sink: {m.group(0).strip()[:120]}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="")
    ap.add_argument("--stats", action="store_true")
    args = ap.parse_args()
    if args.stats:
        stats()
        return
    only = [c.strip() for c in args.cases.split(",") if c.strip()]
    diag(only)


if __name__ == "__main__":
    main()
