"""M54：判反风险锚点 —— smartbugs unchecked 真阳单元里是否出现"新早退模式"。

新早退模式（拟加）：
  A) 低级调用返回值被**作为实参传给辅助函数**
  B) 低级调用返回值被**return 透传**
  C) 低级调用返回值被**赋给命名返回值**
真阳单元若出现 ⇒ 早退会造成判反。
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.slicer.web3_slither import SoliditySlicer
from core.agents.rule_detectors import _split_sol_sections

SB = ROOT / "reference_repos" / "smartbugs-curated-main"
meta = {Path(x["path"]).name: x
        for x in json.loads((SB / "vulnerabilities.json").read_text(encoding="utf-8"))}
slicer = SoliditySlicer(SB)
units = slicer.extract_entry_units(SB / "dataset" / "unchecked_low_level_calls")
CALL = re.compile(r"\.\s*call\s*(?:\{|\.|\()|\.\s*send\s*\(")
hits = {"A": [], "B": [], "C": []}
n_true = 0
for u in units:
    entry = meta.get(Path(u.file_path).name)
    if not entry:
        continue
    vul = {l for v in entry["vulnerabilities"]
           if v["category"] == "unchecked_low_level_calls" for l in v["lines"]}
    if not vul:
        continue
    truth = any(u.start_line <= l <= u.end_line for l in vul)
    if not truth:
        continue
    n_true += 1
    func_src, _m, _f = _split_sol_sections(u.source_code)
    if not CALL.search(func_src):
        continue
    # 取赋值变量
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
        continue
    tail = func_src[func_src.find(var) + len(var):]
    tag = "%s::%s var=%s" % (Path(u.file_path).name, u.unit_name, var)
    # A) 作为实参：var 后面紧跟 (, 或 , var)
    if re.search(rf"\b{re.escape(var)}\s*[,)]", tail) and re.search(
            rf"\w+\s*\([^;]*\b{re.escape(var)}\b", tail):
        hits["A"].append(tag)
    # B) return 透传
    if re.search(rf"\breturn\b[^;]*\b{re.escape(var)}\b", tail):
        hits["B"].append(tag)
    # C) 命名返回值：签名里有 returns (... var ...)
    if re.search(rf"returns\s*\([^)]*\b{re.escape(var)}\b[^)]*\)", func_src):
        hits["C"].append(tag)
print("真阳单元总数:", n_true)
for k in "ABC":
    print("  模式%s 命中 %d 条" % (k, len(hits[k])))
    for x in hits[k][:12]:
        print("      ", x)
