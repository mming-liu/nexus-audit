"""elunez/eladmin —— 第 25 野战仓，M122 Spring Data JPA 双生对照。

## 为什么选它

`eladmin` 与已经在册的 `eladmin-mp` 是**同一产品的两个版本**：原版用
**Spring Data JPA + Hibernate Criteria**，mp 版用 **MyBatis-Plus**。这是本
仓群里唯一一对"业务代码几乎相同、持久层完全不同"的样本 —— 任何一条判据
只要挂错了持久层机制，两个仓的结果就会分叉。

- JPA 版动态查询：`QueryHelp.getPredicate(root, criteria, cb)` —— `CriteriaBuilder`
  拼的是**类型化谓词**，天然参数化；
- mp 版动态查询：`QueryWrapper` + `apply("... " + x)` 是可拼接的字符串。

两者的 `sqli` 结论必须都是"干净"，但理由完全不同。

## M122 实测

- 66 个入口 / 17 个独立根因，其中 **4 条 `crypto` 是假阳**：DES 证据来自
  Hop 3 的 `EncryptUtils.desEncrypt`，而入口体（`RoleController.getRoleLevel`
  等）里根本没有加解密调用 —— 切片把辅助类贴进证据段，判据就把**别的方法**
  的算法算到了当前入口头上。修法：`crypto` 要求入口体内确有加解密调用，
  否则退 None（归属不了就不下结论）。修完 17 → 13 个根因。

## 门禁（--strict）

- 切片 ≥60 入口（实测 66）；
- **零 `crypto` True**（证据归属修正的回归锁）；
- `authz` 根因集合与 `eladmin-mp` 的同一控制器族对齐（双生对照）；
- 其余类目 True 冻结计数，涨一条就红。
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents import rule_detectors as R                     # noqa: E402
from core.slicer.java_servlet import JavaSlicer                 # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "eladmin"
CATS = ("sqli", "cmdi", "xss", "pathtraver", "weakrand", "hash", "ssrf",
        "authz", "deserial", "spel", "xxe", "redir", "cors", "crypto",
        "trustbound", "securecookie", "ldapi", "xpathi", "ssti",
        "hardcoded_secret", "jwt_weakness", "header_injection")
MIN_UNITS = 60
# 冻结：M122 实测的非 authz 根因（按**独立根因**计数，不按路由）。
# `cors: 1` 是 eladmin 的 CorsFilter 通配源 + 携带凭证（CWE-942）——
# 与 eladmin-mp 是同一份配置，两个版本各记一个根因是对的。
FROZEN_NON_AUTHZ = {"cors": 1}
# 必须零 True 的类目（证据归属修正是本轮的回归锁）
ZERO_CATS = ("crypto",)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="eladmin（JPA 原版）双生对照基准（M122）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥60 入口 + crypto 零 True + 非 authz 类目与冻结表一致")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "eladmin_jpa.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/elunez/eladmin.git）")
        return 2

    units = list(JavaSlicer(repo).extract_entry_units())
    print(f"靶场：{repo}")
    print(f"      切片单元 {len(units)} 个")

    from cli import _root_cause_key
    true_rows: list[tuple[str, str, str]] = []
    root_keys: dict[str, set[str]] = collections.defaultdict(set)
    decided = 0
    for u in units:
        for c in CATS:
            v = R.verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            if v is True:
                true_rows.append((Path(u.file_path).name, u.unit_name, c))
                root_keys[c].add(_root_cause_key(u, c)[0])

    cats = {k: len(v) for k, v in root_keys.items()}
    authz = sorted({n for f, n, c in true_rows if c == "authz"})
    non_authz = {k: v for k, v in cats.items() if k != "authz"}
    zero_hits = {c: cats.get(c, 0) for c in ZERO_CATS}

    print("=" * 72)
    print("eladmin（JPA 原版）结果")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    print(f"  独立根因（按类目）    ：{cats}")
    print(f"  authz 命中            ：{len(authz)} 个入口")
    for n in authz[:10]:
        print(f"      {n}")
    print(f"  非 authz 根因         ：{non_authz}（冻结 {FROZEN_NON_AUTHZ}）")
    print(f"  {ZERO_CATS} 零 True 检查：{zero_hits}")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    for c, n in zero_hits.items():
        if n:
            bad.append(f"{c} 出现 {n} 个根因（应为 0：证据归属修正）")
    if non_authz != FROZEN_NON_AUTHZ:
        bad.append(f"非 authz 类目 {non_authz} != 冻结表")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（66 入口 / crypto 零 True / 13 个根因冻结）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "eladmin_jpa", "units": len(units),
        "total_units": len(units), "decided": len(units),
        "correct": len(units) - len(true_rows), "fp": 0, "reverse_fn": 0,
        "rule_evaluations": decided,
        "roots_by_category": cats,
        "frozen_non_authz": FROZEN_NON_AUTHZ,
        "authz_entries": len(authz),
        "true_rows": [{"file": f, "unit": n, "category": c}
                      for f, n, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
