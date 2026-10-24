"""M52 探针二：330 条 access_control 退回样本的**模式聚类**（只读）。

比探针一更宽：不预设判据形态，而是按函数体的客观特征聚类，
让"哪一类可确定性早退 False"从数据里长出来，而不是先有结论再找证据。

聚类特征（互相独立、可叠加）：
  · 有无外部资金转出（send/transfer/call.value）
  · 有无映射写（减/增）
  · 有无标量状态写
  · 减方键是否 msg.sender
  · 有无自有域余额校验（require balances[msg.sender] >= x）
  · 有无 view/pure/constant
  · 有无 modifier
  · 是否只在 emit/log

用法：python benchmarks/probe_m52_patterns.py
"""
from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "benchmarks"))

from core.agents.rule_detectors import verdict as rule_verdict  # noqa: E402
from core.agents.rule_detectors import _looks_solidity          # noqa: E402
from triage_fallbacks import BENCHES, iter_units                # noqa: E402


def strip(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


_LOCAL_DECL_RE = re.compile(
    r"\b(?:uint\d*|int\d*|address|bool|bytes\d*|bytes32|string|var|"
    r"mapping\s*\([^)]*\))\s+(\w+)\s*=\s*")
_WRITE_RE = re.compile(
    r"(?<![=!<>+\-*/%&|^])((?:[A-Za-z_]\w*(?:\s*\[\s*[^\]]*\s*\])*)|(?:[A-Za-z_]\w*))"
    r"\s*(\+=|-=|\*=|/=|=(?!=))\s*([^;]*);")
_MAP_WRITE_RE = re.compile(
    r"([A-Za-z_]\w*)\s*\[\s*([^\]]*?)\s*\]\s*(\+=|-=|\*=|/=|=(?!=))\s*([^;]*);")
_EXT_OUT_RE = re.compile(
    r"\.\s*(?:transfer|send)\s*\("
    r"|\.\s*call\s*\{\s*value\s*:"
    r"|\.\s*call\s*\.\s*value\s*\(")
_SELFBAL_RE = re.compile(
    r"\w+\s*\[\s*msg\s*\.\s*sender\s*\]\s*>=\s*"
    r"|\w+\s*<=\s*\w+\s*\[\s*msg\s*\.\s*sender\s*\]")
_SENDER_KEY_RE = re.compile(r"msg\s*\.\s*sender")
_ONLY_EMIT_RE = re.compile(r"\bemit\s+\w+\s*\(|\blog\s*\(")
_MODIFIER_RE = re.compile(r"\bmodifier\s+")
_FUNC_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)")
_VIEW_RE = re.compile(r"\b(?:view|pure|constant)\b")


def profile(src: str) -> dict:
    b = strip(src)
    b2 = _LOCAL_DECL_RE.sub("", b)
    writes = _WRITE_RE.findall(b2)
    map_minus, map_plus, map_eq = [], [], []
    for name, key, op, _rhs in _MAP_WRITE_RE.findall(b2):
        (map_minus if op == "-=" else map_plus if op == "+=" else map_eq).append(
            (name, key))
    scalar_writes = [lhs for lhs, _op, _rhs in writes if "[" not in lhs]
    m = _FUNC_RE.search(b)
    return {
        "fname": m.group(1) if m else "?",
        "ext_out": bool(_EXT_OUT_RE.search(b)),
        "map_minus": map_minus,
        "map_plus": map_plus,
        "map_eq": map_eq,
        "scalar_writes": scalar_writes,
        "sender_minus": any(_SENDER_KEY_RE.search(k) for _n, k in map_minus),
        "sender_plus": any(_SENDER_KEY_RE.search(k) for _n, k in map_plus),
        "selfbal": bool(_SELFBAL_RE.search(b)),
        "readonly": bool(_VIEW_RE.search(b)),
        "modifier": bool(_MODIFIER_RE.search(b)),
        "only_emit": bool(_ONLY_EMIT_RE.search(b)) and not writes,
        "priv_sink": bool(re.search(
            r"\bselfdestruct\s*\(|\bsuicide\s*\(|\bdelegatecall\s*\(|"
            r"\btransferOwnership\s*\(|"
            r"\b(?:owner|creator|admin|paused|frozen|locked)\b\s*=(?!=)", b, re.I)),
    }


def main() -> int:
    groups: dict[str, list] = defaultdict(list)
    total = 0
    for bench in BENCHES:
        kind, _ = BENCHES[bench]
        if kind != "solidity":
            continue
        for u in iter_units(bench):
            src = u.source_code or ""
            if not src or not _looks_solidity(src):
                continue
            if rule_verdict("access_control", src) is not None:
                continue
            total += 1
            p = profile(src)
            # 聚类键：客观特征组合
            key = []
            key.append("外转" if p["ext_out"] else "无外转")
            key.append("映射减" if p["map_minus"] else "无映射减")
            key.append("映射增" if p["map_plus"] else "无映射增")
            key.append("标量写" if p["scalar_writes"] else "无标量写")
            key.append("自有域减" if p["sender_minus"] else "非自有域减")
            key.append("余额校验" if p["selfbal"] else "无余额校验")
            if p["priv_sink"]:
                key.append("有特权Sink")
            if p["modifier"]:
                key.append("带modifier")
            groups["/".join(key)].append((bench, u, p))

    print("=" * 72)
    print(f"M52 模式聚类：access_control 退回 {total} 条")
    print("=" * 72)
    for k, v in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        print(f"\n### {len(v):4} 条  {k}")
        cnt = Counter(f"{b}/{Path(u.file_path).name}" for b, u, _p in v)
        for ck, cv in cnt.most_common(6):
            print(f"       {ck:60} {cv}")
        for b, u, p in v[:3]:
            print(f"       - {b} {Path(u.file_path).name}:{u.unit_name} "
                  f"fn={p['fname']} minus={p['map_minus']} plus={p['map_plus']} "
                  f"eq={p['map_eq']} scalar={p['scalar_writes']} selfbal={p['selfbal']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
