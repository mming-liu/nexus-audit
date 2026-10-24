"""gz-yami/mall4j —— 第 17 野战仓，M98 主体链（`SecurityUtils.getUser()`）全覆盖检验。

## 为什么选它

mall4j 是 5.3k Star 的企业级多模块商城：`yami-shop-api`（C 端）+ `yami-shop-admin`
（后台）+ `yami-shop-sys`（系统）+ `yami-shop-service`（MyBatis 层）。它的 C 端
鉴权形态是本仓群里的新形态：

    String userId = SecurityUtils.getUser().getUserId();
    UserAddr userAddr = userAddrService.getUserAddrByUserId(addrId, userId);

主体 id 先落到局部变量，再**与其他资源键一起**传给 Service —— 归属被写死在
查询条件里（就是 authz 类目 property 的第 ③ 条"查询条件本身把归属写死"）。

## M98 实测：24 个独立根因收到 10 个（其中 1 个是全局 CORS）

| 误报 | 机制 | 纯增量补齐 |
|---|---|---|
| 14 条 authz（Addr/MyOrder/ShopCart/UserCollection/Pay 等） | 主体源 `SecurityUtils.getUser()` 不在可信主体表里，2g 判据整批落空 | `_AUTHZ_SUBJECT_RE` += `SecurityUtils.getUser(` / `getLoginIdAsLong(`；`_AUTHZ_SUBJECT_CHAIN_VAR_RE` += `SecurityUtils.` |
| 若干 authz（`MyOrderController.orderDetail` 等） | 归属比对写成 `if (!Objects.equals(order.getUserId(), userId)) throw` —— 条件是**裸主体变量**，不是 `subject.getXxxId()` | `_ownership_compared` 增收"主体已落局部变量"形态 |

## 唯一确认的 P0（真阳，139 条路由）

`AuthConfig.java` 的 CORS 配置：`addMapping("/**")` + 通配 Origin + 携带凭证
（CWE-942）。根因折叠成 1 个全局配置根因。

## 门禁（--strict）

- 切片 ≥130 入口（实测 139）；
- **主体链全覆盖**：`AddrController` / `MyOrderController` / `ShopCartController` /
  `UserCollectionController` / `PayController` 五个 C 端"我的资源"控制器里
  `authz` **零 True**（这是 M98 要证的核心命题）；
- 全局 CORS 缺陷必须判出并折叠成 1 个根因；
- 人工复核面（`REVIEW_NEEDED`）冻结成清单：这些是**公开资源查询**
  （商品/公告/配送费/验证码）与后台文件上传，按 authz 类目的定义
  （"访问**归属于某个主体的资源**"）它们不是本类目的判定对象，
  但规则层无法仅凭代码区分"公开目录"与"他人资源"。如实登记、计数冻结，
  涨一条就红 —— 不假装零误报。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents import rule_detectors as R                     # noqa: E402
from core.slicer.java_servlet import JavaSlicer                 # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "mall4j"
CATS = ("sqli", "cmdi", "xss", "pathtraver", "weakrand", "hash", "ssrf",
        "authz", "deserial", "spel", "xxe", "redir", "cors", "crypto",
        "trustbound", "securecookie", "ldapi", "xpathi", "ssti",
        "hardcoded_secret", "jwt_weakness")
MIN_UNITS = 130
# 主体链全覆盖的检验范围：五个 C 端"我的资源"控制器（文件名 → 中文名）
SUBJECT_CHAIN_CONTROLLERS = {
    "AddrController.java": "收货地址",
    "MyOrderController.java": "我的订单",
    "ShopCartController.java": "购物车",
    "UserCollectionController.java": "我的收藏",
    "PayController.java": "支付单",
}
# 人工复核面：公开资源查询 + 后台文件上传。按 authz 类目定义不是判定对象，
# 但规则层区分不了"公开目录"与"他人资源" —— 计数冻结，涨一条就红。
REVIEW_NEEDED = 9
CORS_CONFIG_FILE = "AuthConfig.java"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="mall4j 主体链全覆盖 + 全局 CORS 基准（M98）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥130 入口 + 主体链五控制器 authz 零 True + CORS 折叠成 1")
    ap.add_argument("--offline", action="store_true", help="规则层（默认）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "mall4j.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/gz-yami/mall4j.git）")
        return 2

    units = list(JavaSlicer(repo).extract_entry_units())
    print(f"靶场：{repo}")
    print(f"      切片单元 {len(units)} 个")

    true_rows: list[tuple[Path, str, str]] = []
    decided = 0
    decided_units = 0
    for u in units:
        unit_decided = False
        for c in CATS:
            v = R.verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            unit_decided = True
            if v is True:
                true_rows.append((Path(u.file_path), u.unit_name, c))
        if unit_decided:
            decided_units += 1

    # ① 主体链全覆盖：五个控制器里 authz 必须零 True
    chain_hits = [(p, n, c) for p, n, c in true_rows
                  if c == "authz" and p.name in SUBJECT_CHAIN_CONTROLLERS]
    chain_units = [u for u in units
                   if Path(u.file_path).name in SUBJECT_CHAIN_CONTROLLERS]
    # ② 全局 CORS：所有 cors 命中必须折叠成 1 个根因
    from cli import _root_cause_key
    cors_units = [u for u in units
                  if R.verdict("cors", u.source_code) is True]
    root_keys = {_root_cause_key(u, "cors")[0] for u in cors_units}
    cors_file = (_root_cause_key(cors_units[0], "cors")[2]
                 if cors_units else "")
    cors_file = Path(cors_file).name if cors_file else ""
    # ③ 人工复核面
    review = [(p, n, c) for p, n, c in true_rows if c != "cors"
              and not (c == "authz"
                       and p.name in SUBJECT_CHAIN_CONTROLLERS)]

    print("=" * 72)
    print("mall4j 结果（主体链 SecurityUtils.getUser() + 全局 CORS）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  单元覆盖（≥1 判定）   ：{decided_units}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    print(f"    全局 CORS 路由级命中：{len(cors_units)} 条"
          f"（{cors_file}，折叠成 {len(root_keys)} 个根因）")
    print(f"  主体链五控制器单元    ：{len(chain_units)} 个，"
          f"authz True {len(chain_hits)} 条")
    for p, n, c in chain_hits[:10]:
        print(f"      [FP] {p.name}:{n} [{c}]")
    print(f"  人工复核面（公开资源/后台上传）：{len(review)} 条（冻结 {REVIEW_NEEDED}）")
    for p, n, c in review[:12]:
        print(f"      [?] {p.name}:{n} [{c}]")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if chain_hits:
        bad.append(f"主体链控制器出现 authz True {len(chain_hits)} 条")
    if not cors_units:
        bad.append("全局 CORS 通配+凭证缺陷未被判出")
    elif len(root_keys) != 1:
        bad.append(f"CORS 根因折叠成 {len(root_keys)} 个（应为 1）")
    if len(review) > REVIEW_NEEDED:
        bad.append(f"人工复核面涨到 {len(review)} 条（冻结 {REVIEW_NEEDED}）")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（139 入口 / 主体链零 True / CORS 折叠成 1）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "mall4j", "units": len(units), "total_units": len(units),
        "decided": decided_units,
        "correct": decided_units - len(chain_hits),
        "fp": len(chain_hits), "reverse_fn": 0,
        "rule_evaluations": decided,
        "cors_route_hits": len(cors_units),
        "cors_root_causes": len(root_keys),
        "cors_config_file": cors_file,
        "subject_chain_units": len(chain_units),
        "subject_chain_authz_true": len(chain_hits),
        "review_needed": len(review),
        "review_frozen": REVIEW_NEEDED,
        "review_rows": [{"file": p.name, "unit": n, "category": c}
                        for p, n, c in review],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
