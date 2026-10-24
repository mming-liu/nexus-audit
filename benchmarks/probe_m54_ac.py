"""M54 access_control 误报：按判据分支归因 + 打印命中行。"""
from __future__ import annotations
import re, sys
from collections import Counter
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents.rule_detectors import (
    verdict as rule_verdict, _split_sol_sections, _SOLIDITY_OWNERISH_RE,
    _SOL_ALLOWANCE_WRITE_RE, _SOLIDITY_SELFDESTRUCT_RE, _SOLIDITY_DRAIN_RE,
    _sol_allowance_scoped, _sol_self_scoped_safe, _sol_bilateral_conserving,
    _sol_implicit_view, _sol_indirect_identity_check)
from core.slicer.web3_slither import SoliditySlicer
from benchmarks.slice_cache import cached_units

GP = ROOT / "reference_repos" / "GPTScan-Top200-dev"
units = cached_units(GP, "gptscan-top200", lambda: SoliditySlicer(GP).extract_entry_units(GP))
out = []
br = Counter()
for u in units:
    if rule_verdict("access_control", u.source_code) is not True:
        continue
    src = u.source_code
    func_src, mod_ev, func_ev = _split_sol_sections(src)
    # 复现判据分支
    tags = []
    if _SOLIDITY_SELFDESTRUCT_RE.search(func_src):
        tags.append("danger")
    if _SOLIDITY_OWNERISH_RE.search(func_src) or re.search(r"\btransferOwnership\s*\(", func_src):
        tags.append("owner_write")
        mm = _SOLIDITY_OWNERISH_RE.search(func_src)
        if mm:
            s = max(0, mm.start() - 60); e = min(len(func_src), mm.end() + 40)
            tags.append("OWNERHIT=" + func_src[s:e].replace("\n", " | "))
    if _SOLIDITY_DRAIN_RE.search(func_src):
        tags.append("drain")
    if not _sol_allowance_scoped(func_src, mod_ev, func_ev):
        tags.append("BRANCH_anyfrom_scoped=False")
    if not _sol_self_scoped_safe(func_src):
        tags.append("BRANCH_self_scoped=False")
    if not _sol_bilateral_conserving(func_src):
        tags.append("BRANCH_bilateral=False")
    if not _sol_implicit_view(func_src):
        tags.append("BRANCH_implicit_view=False")
    if not _sol_indirect_identity_check(func_src, mod_ev, func_ev):
        tags.append("BRANCH_indirect_id=False")
    if re.search(r"(?:require|if)\s*\([^;]{0,120}?\btx\s*\.\s*origin\s*==", func_src):
        tags.append("BRANCH_txorigin")
    key = "+".join(t.split("=")[0] for t in tags)
    br[key] += 1
    out.append("### %s :: %s  [%s]" % (Path(u.file_path).name, u.unit_name, key))
    out.append("    " + "\n    ".join(tags))
    out.append("    --- func_src ---")
    out.append("    " + func_src[:900].replace("\n", "\n    "))
    out.append("")
Path(ROOT / "benchmarks" / "results" / "m54_ac_attr.txt").write_text("\n".join(out), encoding="utf-8")
for k, v in br.most_common():
    print("%-70s %d" % (k, v))
