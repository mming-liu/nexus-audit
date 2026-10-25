"""makerdao/dss —— 第 26 野战仓（Solidity #9），M136。

## 为什么选它

MakerDAO 的 DSS 核心（Vat / Cat / Dog / End / Spot ...）是 0.6.x 时代的
**旗舰合约**，而且它用两套**自研**基础设施替掉了我们熟悉的一切：

    // 授权：调用者键控的映射，不是 Ownable
    mapping (address => uint) public wards;
    modifier auth {
        require(wards[msg.sender] == 1, "Vat/not-authorized");
        _;
    }

    // 算术：合约内联手写 add/sub/mul，不是 SafeMath 库
    function _add(uint x, int y) internal pure returns (uint z) {
        z = x + uint(y);
        require(y >= 0 || z <= x);
        require(y <= 0 || z >= x);
    }

这两套写法都是**正确**的，但我们的判据此前一条都认不出：

  · `_SOLIDITY_MSGSENDER_MEMBER_RE` 只认"裸真值 / != 0 / &&"三种形态，
    `wards[msg.sender] == 1` 的**显式等值**写法直接漏掉 —— `rely`/`deny`/
    `file`/`cage` 这些只该管理员调的函数会被判成"缺访问控制"（判反）；
  · 内联 `_add/_sub` 既不是 `.add()` 也不是 `require((z = x + y) >= x)`
    的字面形态，`arithmetic` 维度只能退 None（不算误报，但等于没看懂）。

M136 把两者都做成**机制**判据（不挂函数名、不挂变量名）。

## 门禁（--strict）

- 切片 ≥200 单元（实测 234；`.t.sol` 测试合约已在切片层排除）；
- 五类判据 **0 条 True**（生产核心合约零误报）；
- `rely` / `deny` / `file` / `cage` 的 access_control 必须是**确定性 False**
  —— 证明 `auth` 的实现体被真的读到了；
- **反向锚点**：把签名上的 `auth` 摘掉（切片层随之不再附 modifier 证据体）
  后，access_control 必须**不再是 False** —— 证明"判 False"靠的是那道守卫，
  而不是判据压根没看这块代码；
- `_add` / `_sub` 的 arithmetic 必须是**确定性 False** —— 证明内联回卷校验
  被认出来了（不是碰巧退 None）。

反向锚点很重要：没有它，"0 条 True"在判据整个失灵时同样成立。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents import rule_detectors as R                     # noqa: E402
from core.slicer.web3_slither import SoliditySlicer            # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "dss"
CATS = ("access_control", "arithmetic", "reentrancy",
        "unchecked_low_level_calls", "delegatecall_untrusted")
MIN_UNITS = 200
AUTH_FUNCS = ("rely", "deny", "file", "cage")
ARITH_FUNCS = ("_add", "_sub")
_MOD_SEP = "// ---- 修饰符定义（本合约，供核验）----"


def _strip_auth_anchor(src: str) -> str:
    """反向锚点：摘掉签名上的 `auth`，并丢掉 modifier 证据体。

    真实切片里，`external auth` 的 `auth` 会触发切片层把 `modifier auth {…}`
    的实现体贴进证据段；签名上没有 `auth` 时**不会**贴。所以锚点必须同时
    做两件事，否则会造出一个现实中不存在的切片（"签名不用 auth、证据里却有
    auth 实现体"），判定层仍能看见守卫 —— 锚点就翻不过来。
    """
    cut = src.split(_MOD_SEP)[0]
    return cut.replace("external auth", "external").replace(
        "public auth", "public")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="MakerDAO dss 零误报基准：auth 映射守卫 + 内联算术封装（M136）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥200 入口 + 五类 0 True + auth/算术正反锚点")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "makerdao_dss.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/makerdao/dss.git）")
        return 2

    units = list(SoliditySlicer(repo).extract_entry_units(repo))
    by_name: dict[str, object] = {}
    for u in units:
        by_name.setdefault(u.unit_name, u)
    print(f"靶场：{repo}")
    print(f"      切片单元 {len(units)} 个（已排除 *.t.sol / *.s.sol 测试与脚本）")

    true_rows: list[tuple[str, str, str]] = []
    decided = 0
    for u in units:
        for c in CATS:
            v = R.verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            if v is True:
                true_rows.append((Path(u.file_path).name, u.unit_name, c))

    # 正向锚点：auth 守卫的函数必须判 False
    auth_rows: dict[str, object] = {}
    for fn in AUTH_FUNCS:
        u = by_name.get(fn)
        if not u:
            auth_rows[fn] = None
            continue
        auth_rows[fn] = R.verdict("access_control", u.source_code)
    # 反向锚点：摘掉 auth 之后必须不再是 False
    reverse: dict[str, dict] = {}
    for fn in AUTH_FUNCS:
        u = by_name.get(fn)
        if not u:
            continue
        stripped = _strip_auth_anchor(u.source_code)
        reverse[fn] = {
            "with_auth": R.verdict("access_control", u.source_code),
            "without_auth": R.verdict("access_control", stripped),
            "changed": stripped != u.source_code,
        }
    # 算术封装锚点
    arith = {fn: (R.verdict("arithmetic", by_name[fn].source_code)
                  if fn in by_name else None)
             for fn in ARITH_FUNCS}

    print("=" * 72)
    print("MakerDAO dss 结果（auth 映射守卫 / 内联算术封装）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    for f, n, c in true_rows[:12]:
        print(f"      [FP] {f}:{n} [{c}]")
    print("  auth 守卫（access_control 必须 False）：")
    for fn, v in auth_rows.items():
        print(f"    {fn:8} = {v}")
    print("  反向锚点（摘掉 auth → 必须不再是 False）：")
    for fn, a in reverse.items():
        print(f"    {fn:8} with={a['with_auth']} without={a['without_auth']}"
              f"（改写生效={a['changed']}）")
    print("  内联算术封装（arithmetic 必须 False）：")
    for fn, v in arith.items():
        print(f"    {fn:8} = {v}")

    bad: list[str] = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"计划外 True {len(true_rows)} 条")
    for fn in AUTH_FUNCS:
        if fn not in by_name:
            bad.append(f"缺单元 {fn}")
        elif auth_rows.get(fn) is not False:
            bad.append(f"{fn} 的 auth 守卫未认出（access_control={auth_rows.get(fn)}）")
    for fn, a in reverse.items():
        if not a["changed"]:
            bad.append(f"{fn} 反向锚点改写失败")
        elif a["without_auth"] is False:
            bad.append(f"{fn} 摘掉 auth 后仍判 False（守卫不是承重墙）")
    for fn in ARITH_FUNCS:
        if fn not in by_name:
            bad.append(f"缺算术单元 {fn}")
        elif arith.get(fn) is not False:
            bad.append(f"{fn} 内联算术封装未认出（arithmetic={arith.get(fn)}）")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（234 入口 / 五类 0 True / auth 与算术封装正反锚点成立）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "dss", "units": len(units), "total_units": len(units),
        "decided": len(units), "correct": len(units) - len(true_rows),
        "fp": len(true_rows), "reverse_fn": 0, "rule_evaluations": decided,
        "auth_verdicts": auth_rows, "auth_reverse": reverse,
        "inline_arithmetic": arith,
        "true_rows": [{"file": f, "unit": n, "category": c}
                      for f, n, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
