"""M54：Top200 unchecked 误报的"返回值变量如何被消费"分类。"""
from __future__ import annotations
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents.rule_detectors import verdict as rule_verdict, _split_sol_sections
from core.slicer.web3_slither import SoliditySlicer
from benchmarks.slice_cache import cached_units

GP = ROOT / "reference_repos" / "GPTScan-Top200-dev"
units = cached_units(GP, "gptscan-top200", lambda: SoliditySlicer(GP).extract_entry_units(GP))

CALL = re.compile(r"\.\s*call\s*(?:\{|\.|\()|\.\s*send\s*\(")
cats = {}
for u in units:
    if rule_verdict("unchecked_low_level_calls", u.source_code) is not True:
        continue
    func_src, mod_ev, func_ev = _split_sol_sections(u.source_code)
    # 找赋值变量
    var = None
    for m in CALL.finditer(func_src):
        st = max(func_src.rfind(";", 0, m.start()), func_src.rfind("{", 0, m.start()),
                 func_src.rfind("}", 0, m.start())) + 1
        en = func_src.find(";", m.start())
        stmt = func_src[st: en + 1 if en >= 0 else len(func_src)]
        am = re.search(r"\(?\s*(?:bool|var)\s+(\w+)", stmt) or \
             re.search(r"\(\s*(?:bool|var)\s+(\w+)\s*(?:,[^)]*)?\)\s*=", stmt)
        if am:
            var = am.group(1)
            break
    if not var:
        cats.setdefault("裸调用(无赋值)", []).append(u.unit_name)
        continue
    rest = func_src[func_src.find(var, func_src.find(var) + 1):]  # 粗略
    where = []
    for mm in re.finditer(rf"\b{re.escape(var)}\b", func_src):
        line = func_src[mm.start():func_src.find("\n", mm.start())]
        where.append(line.strip())
    tail = where[1:] if len(where) > 1 else []
    kind = []
    if any(re.search(r"\b(?:require|assert|if|while)\b", w) for w in tail):
        kind.append("条件消费")
    if any(re.search(r"\breturn\b", w) for w in tail):
        kind.append("return透传")
    if any(re.search(r"\(", w) and not re.search(r"\b(?:require|assert|if|while|return)\b", w)
           for w in tail):
        kind.append("作为实参")
    if not kind:
        kind = ["丢弃(未被消费)"]
    cats.setdefault("+".join(kind), []).append("%s::%s var=%s tail=%s" % (
        Path(u.file_path).name, u.unit_name, var, tail[:3]))

for k, v in sorted(cats.items(), key=lambda x: -len(x[1])):
    print("%-30s n=%d" % (k, len(v)))
    for x in v[:3]:
        print("      ", x)
