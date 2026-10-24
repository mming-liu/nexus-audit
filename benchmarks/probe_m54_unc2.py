"""M54 unchecked：62 条 functionCallWithValue 的证据段形态分类 + 其它 10 条形态。"""
from __future__ import annotations
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents.rule_detectors import verdict as rule_verdict
from core.slicer.web3_slither import SoliditySlicer
from benchmarks.slice_cache import cached_units

GP = ROOT / "reference_repos" / "GPTScan-Top200-dev"
units = cached_units(GP, "gptscan-top200", lambda: SoliditySlicer(GP).extract_entry_units(GP))

kinds = {}
detail = []
for u in units:
    rv = rule_verdict("unchecked_low_level_calls", u.source_code)
    if rv is not True:
        continue
    src = u.source_code
    fn = u.unit_name
    if fn == "functionCallWithValue":
        # 找证据段
        p = src.find("// ---- 同文件辅助函数证据")
        seg = src[p:] if p >= 0 else ""
        has_revert_kw = bool(re.search(r"\brevert\b", seg))
        has_revert_call = bool(re.search(r"\b_revert\s*\(", seg))
        helper = re.findall(r"// ---- 同文件辅助函数证据 \[([^\]]*)\]", src)
        kind = "direct_revert" if has_revert_kw else ("_revert_call" if has_revert_call else "NO_REVERT_EVID")
        kinds.setdefault(kind, []).append(
            "%s | helpers=%s" % (Path(u.file_path).name, helper))
        if kind != "direct_revert":
            detail.append("### %s (%s)\n%s\n" % (Path(u.file_path).name, kind,
                                                seg[:1200]))
    else:
        detail.append("### OTHER %s :: %s\n%s\n" % (Path(u.file_path).name, fn,
                                                   src[:1500]))
Path(ROOT / "benchmarks" / "results" / "m54_unc_forms.txt").write_text(
    "\n".join(detail), encoding="utf-8")
for k, v in sorted(kinds.items()):
    print("%-18s n=%d" % (k, len(v)))
print("--- samples ---")
for k, v in sorted(kinds.items()):
    for x in v[:3]:
        print("   ", k, x)
