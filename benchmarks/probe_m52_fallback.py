"""M52 专项探针：解剖剩余 330 条 access_control 退回样本（只读）。

探针只读，不写任何判定。目标：
  1. 把 access_control 退回样本按"是否真的存在特权动作"重新聚类；
  2. 测量两类候选非特权模式的占比：
     ① 隐式只读函数（剥注释/局部声明后无任何状态写、无外部资金转出）
     ② 双边守恒代币流转（同一映射扣减方 + 增加方配对，无特权 Sink）
  3. 反查真值：候选命中的样本里有没有官方标注 vul 的（判反风险）。

用法：python benchmarks/probe_m52_fallback.py [--json PATH]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict  # noqa: E402
from core.agents.rule_detectors import _looks_solidity          # noqa: E402

sys.path.insert(0, str(ROOT / "benchmarks"))
from triage_fallbacks import BENCHES, classify, iter_units      # noqa: E402


# ---- 探针用的判据（与将来落地的实现同形，但这里只是"测量"） ----

_PRIV_SINK_RE = re.compile(
    r"\bselfdestruct\s*\(|\bsuicide\s*\(|\bdelegatecall\s*\(|"
    r"\btransferOwnership\s*\(|"
    r"\b(?:owner|creator|admin|paused|frozen|locked)\b\s*=(?!=)", re.I)
_DRAIN_RE = re.compile(
    r"\.\s*(?:transfer|send)\s*\([^;]*(?:address\s*\(\s*this\s*\)|\bthis)\s*\.\s*balance"
    r"|\.\s*call\s*\{[^}]*\}\s*\([^;]*(?:address\s*\(\s*this\s*\)|\bthis)\s*\.\s*balance",
    re.S)
_LOCAL_DECL_RE = re.compile(
    r"\b(?:uint\d*|int\d*|address|bool|bytes\d*|bytes32|string|var|"
    r"mapping\s*\([^)]*\))\s+(\w+)\s*=\s*")
# 状态写：lhs 含索引（映射写）或标量写
_WRITE_RE = re.compile(
    r"(?<![=!<>+\-*/%&|^])((?:[A-Za-z_]\w*(?:\s*\[\s*[^\]]*\s*\])*)|(?:[A-Za-z_]\w*))"
    r"\s*(\+=|-=|\*=|/=|=(?!=))\s*([^;]*);")
# 外部资金转出（send/transfer/call value）
_EXT_OUT_RE = re.compile(
    r"\.\s*(?:transfer|send)\s*\(([^;()]*)\)"
    r"|\.\s*call\s*\{\s*value\s*:\s*([^;{}]*)\}"
    r"|\.\s*call\s*\.\s*value\s*\(([^;()]*)\)")
# 映射写：name[key] op= ...
_MAP_WRITE_RE = re.compile(
    r"([A-Za-z_]\w*)\s*\[\s*([^\]]*?)\s*\]\s*(\+=|-=|\*=|/=|=(?!=))\s*([^;]*);")


def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def has_state_write(body: str) -> bool:
    """剥掉局部声明后，是否还有状态写（标量写 / 映射写 / 数组 length 写）。

    坑：只认映射写（lhs 带 `[`）会漏掉 `state = state + _input` 这种
    标量写 —— 那正是 smartbugs overflow_single_tx 的漏洞形态。
    """
    body = _LOCAL_DECL_RE.sub("", body)
    for lhs, _op, _rhs in _WRITE_RE.findall(body):
        return True          # 任何赋值都是写（局部声明已剥离）
    # 数组 length 写：`bonusCodes.length--`（arbitrary_location_write_simple）
    if re.search(r"\.\s*length\s*(?:\+\+|--|\+=|-=|=)", body):
        return True
    return False


def calls_internal(body: str) -> bool:
    """函数体里有没有对**同合约其它函数**的调用（可能写状态）。

    坑：initWallet（parity_wallet_bug_1 L223，官方标 vul）函数体自己
    只写 `initDaylimit(_daylimit)` 这种**调用**，状态写在被调函数里。
    只看入口体就判"无状态写"→ 判反。这是"入口体没 X 就判安全"陷阱。
    """
    body = _strip_comments(body)
    # 去掉 require/assert/if 等控制关键字与常见库调用
    body = re.sub(r"\b(?:require|assert|revert|throw|if|else|for|while|"
                  r"return|emit|keccak256|sha3|now|msg|block|tx)\b", " ", body)
    # `name(...)` 形态的调用（不是结构体取值）
    for m in re.finditer(r"(?<![\w.])([a-z_]\w*)\s*\(", body):
        name = m.group(1)
        if name in ("require", "assert", "revert", "keccak256", "sha3",
                    "now", "address", "uint256", "uint", "bytes32", "string"):
            continue
        return True
    return False


def is_implicit_view(body: str) -> bool:
    """隐式只读：剥注释与局部声明后，无特权 Sink、无外部资金转出、无状态写。

    且**不调用任何可能写状态的同合约函数**（initWallet 陷阱）。
    """
    body = _strip_comments(body)
    if _PRIV_SINK_RE.search(body) or _DRAIN_RE.search(body):
        return False
    if _EXT_OUT_RE.search(body):
        return False
    if calls_internal(body):
        return False
    return not has_state_write(body)


def map_write_pairs(body: str) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """抽出映射写：返回 (扣减列表, 增加列表)，元素为 (映射名, 键)。"""
    body = _strip_comments(body)
    body = _LOCAL_DECL_RE.sub("", body)
    minus, plus = [], []
    for name, key, op, _rhs in _MAP_WRITE_RE.findall(body):
        if op == "-=":
            minus.append((name, key))
        elif op in ("+=", "*=", "="):
            plus.append((name, key))
    return minus, plus


def is_bilateral_conserving(body: str) -> bool:
    """双边守恒：所有映射写都在同一映射上，一减一增配对，无特权 Sink。

    允许额度的形态：allowance[_from][msg.sender] -= v 与
    balances[_from] -= v 配 balances[_to] += v —— 这类"扣两增一"
    同样是守恒（ERC20 transferFrom 语义），键不同但映射归属一致。
    """
    body = _strip_comments(body)
    if _PRIV_SINK_RE.search(body) or _DRAIN_RE.search(body):
        return False
    minus, plus = map_write_pairs(body)
    if not minus or not plus:
        return False
    mnames = {n for n, _ in minus}
    pnames = {n for n, _ in plus}
    # 扣减侧映射必须都被增加侧覆盖（allowance 是附属额度映射，
    # 单独允许：它是"扣减方"的额度，不是资金槽位）
    core_minus = {n for n, _ in minus if n != "allowance"}
    core_plus = {n for n, _ in plus if n != "allowance"}
    if not core_minus or not core_plus:
        return False
    if not core_minus <= core_plus:
        return False
    # 增加侧的键不能是 msg.sender 之外的全局键（不能凭空铸币给固定地址）
    for _n, key in plus:
        if not re.search(r"\w", key):
            return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description="M52 退回桶专项探针（只读）")
    ap.add_argument("--json", default=str(ROOT / "benchmarks" / "results" /
                                          "probe_m52.json"))
    args = ap.parse_args()

    # 官方真值反查表：文件 basename → {(该类目下的 vul 行集合)}
    #
    # 铁律：真值按 **(file, start_line) + 类目** 精确匹配。同一个文件在
    # 不同类目下的真值互不相干 —— `integer_overflow_1.sol` 标的是
    # arithmetic 漏洞，在 access_control 维度上它**不是**官方漏洞样本，
    # 拿它当 access_control 判反红线是错的口径。
    truth: dict[str, set[int]] = {}
    sbrepo = ROOT / "reference_repos" / "smartbugs-curated-main"
    meta_file = sbrepo / "vulnerabilities.json"
    if meta_file.exists():
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        for entry in meta:
            fn = Path(entry["path"]).name
            lines = set()
            for v in entry["vulnerabilities"]:
                if v["category"] != "access_control":
                    continue
                lines |= set(v["lines"])
            if lines:
                truth[fn] = lines

    stats = Counter()
    by_bench = defaultdict(Counter)
    hits: list[dict] = []
    vul_hits: list[dict] = []

    for bench in BENCHES:
        kind, _repo = BENCHES[bench]
        if kind != "solidity":
            continue
        for u in iter_units(bench):
            src = u.source_code or ""
            if not src or not _looks_solidity(src):
                continue
            if rule_verdict("access_control", src) is not None:
                continue
            stats["access_control 退回"] += 1
            bucket = classify("access_control", src)
            stats[f"桶/{bucket}"] += 1
            by_bench[bench][bucket] += 1

            view = is_implicit_view(src)
            bilat = is_bilateral_conserving(src)
            if view:
                stats["候选①隐式只读"] += 1
            if bilat:
                stats["候选②双边守恒"] += 1
            if view or bilat:
                fn = Path(u.file_path).name
                rec = {"bench": bench, "file": fn, "unit": u.unit_name,
                       "view": view, "bilateral": bilat,
                       "start_line": u.start_line, "end_line": u.end_line}
                hits.append(rec)
                tl = truth.get(fn)
                if tl:
                    if any(u.start_line <= l <= u.end_line for l in tl):
                        rec["official_vul"] = True
                        vul_hits.append(rec)
                    else:
                        rec["official_vul"] = False

    print("=" * 72)
    print("M52 access_control 退回桶专项探针（只读）")
    print("=" * 72)
    for k, v in sorted(stats.items(), key=lambda kv: -kv[1]):
        print(f"  {k:32} {v}")
    print()
    for bench, c in by_bench.items():
        print(f"  {bench}: {dict(c)}")
    print()
    print(f"候选命中合计 {len(hits)} 条，其中带官方真值的 {len(hits) - len(vul_hits)} 条")
    if vul_hits:
        print("\n! 反查命中官方 vul 真值（判反风险，必须逐条人工看）：")
        for r in vul_hits:
            print(f"  {r['bench']}/{r['file']}:{r['unit']} "
                  f"L{r['start_line']}-{r['end_line']} "
                  f"view={r['view']} bilateral={r['bilateral']}")
    else:
        print("反查：候选命中里**没有**官方 vul 真值（判反风险 0）")

    # 命中样本明细（前 40）
    print("\n候选命中明细（前 40）：")
    for r in hits[:40]:
        print(f"  {r['bench']:12} {r['file']:42} {r['unit']:28} "
              f"view={int(r['view'])} bil={int(r['bilateral'])}"
              + (f" OFFICIAL_VUL" if r.get("official_vul") else ""))

    out = {"stats": dict(stats), "hits": hits, "vul_hits": vul_hits}
    Path(args.json).write_text(json.dumps(out, ensure_ascii=False, indent=1),
                               encoding="utf-8")
    print(f"\n写入 {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
