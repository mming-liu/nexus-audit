"""newbee-mall-api 回归基线（第 6 靶场，**前后端分离 API**）。

## 为什么要有这个靶场

第 5 靶场（newbee-mall）是服务端渲染的 Web 版：主体从 `HttpSession` 取，
方法体里看得见 `session.getAttribute(KEY)`。而这个仓库是同一套业务的
**前后端分离 API 版**，主体换了一种完全不同的注入方式：

    public Result orders(@TokenToMallUser MallUser loginMallUser, ...) {
        ... orderService.getMyOrders(p, loginMallUser.getUserId()) ...
    }

方法体里**一行取主体的代码都没有** —— 主体在签名上，由
`TokenToMallUserMethodArgumentResolver` 注入。对只看方法体的判据来说，
这类入口长得跟"完全不取主体"的越权入口**一模一样**。2026-10-20 零改动
探针实测：18 条判 True 里 17 条是这一个机制造成的误报（真正的越权
`/paySuccess` 是第 18 条）。

这个靶场的价值就在这：它是唯一能验证"主体识别 ≠ 方法体里找 session"的样本。

## 锁三件事（不出 Score：没有逐路由漏洞真值）

  ① 切片穿透基线   —— 62 入口 / 59 有 Service 调用 / 59 全带实现体 / 52 含 Mapper SQL
  ② 形参主体注解   —— 56 条切片的签名上有 `@TokenToXxx`，且必须在切片里可见
  ③ authz 真值表   —— 29 safe + 1 vul，逐条人工核对（见下）

外加 sqli 方向护栏：全仓库 Mapper XML 的 `${}` 出现 0 次
（`<include refid>` 只拼列名片段，不含变量），所以任何 sqli=True 都是误报。

## 真值是怎么来的（每条都能逐行核对）

不来自漏洞报告，来自三条代码事实：

  1. 主体从哪来：`@TokenToMallUser MallUser loginMallUser`（由 resolver 注入，
     不是客户端可传的 DTO）
  2. 主体是否参与资源定位：`getOrderDetailByOrderNo(orderNo, userId)` /
     `params.put("userId", userId)` / `item.setUserId(userId)` /
     `!userId.equals(addr.getUserId())` + 终止
  3. 公开资源（分类/首页/商品详情/搜索）与"只读自己"（`/user/info`）
     没有资源归属面

缺少第 1+2 条的用户侧写操作 = 水平越权，全仓库只有 `/paySuccess` 一条。

## 不登记的部分（口径，不是猜测）

- **认证入口**（login / register / adminUser/login）：本身在建立身份
- **管理端业务接口（30 条）**：管理员本来就能操作全部商品/订单/用户，
  真正的问题是"普通用户能否访问"，属垂直权限，不在本判据范围
  —— 按铁律不硬判 True

## 用法

    python benchmarks/benchmark_newbeemallapi.py            # 全离线
    python benchmarks/benchmark_newbeemallapi.py --list     # 逐条三元组
    python benchmarks/benchmark_newbeemallapi.py --strict   # pre-push 用

与其它 benchmark 同一条铁律：**不 import 规则常量、不改 rule_detectors**。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict      # noqa: E402
from core.models import base_unit_name                               # noqa: E402
from core.slicer.java_servlet import JavaSlicer                      # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "newbee-mall-api-master"

# ---------------- ① 切片穿透基线 ----------------
BASELINE = {
    "entries": 62,
    "service_entries": 59,      # 入口体里出现 XxxService.method( 的入口数
    "service_penetrated": 59,   # 其中切片里真的带进了跨文件实现体（全中）
    "impl_hops": 62,            # 切片里出现 `[Hop N]` 段的入口
    "mapper_xml": 52,           # 含 Mapper XML SQL 的入口
}

# ---------------- ② 形参主体注解 ----------------
# 有 `@TokenToMallUser` / `@TokenToAdminUser` 形参的入口数。少一条就说明
# `_signature` 又被注解参数里的字符串/中文括号截断了（实测踩过：
# `@ApiOperation(value = "购物车列表(网页移动端不分页)")` 让 `value = "…(`
# 长得像一个方法调用，签名被截成半句，同文件的三个入口静默丢块）。
SUBJECT_PARAM_EXPECTED = 56

# 必须由"显式归属比对"判出来的入口（2e 判据）。这些是"先查资源再比 userId"
# 的标准写法，曾经整条落在 2b/2b-2/2c 的缝里被判 None。
SUBJECT_CMP_REQUIRED = {
    "NewBeeMallUserAddressAPI.deleteAddress",
    "NewBeeMallUserAddressAPI.getMallUserAddress",
    "NewBeeMallUserAddressAPI.updateMallUserAddress",
    "NewBeeMallShoppingCartAPI.updateNewBeeMallShoppingCartItem#2",
}

# ---------------- ③ authz 真值表 ----------------
# 键：unit_name（重载带 `#N` 后缀，按原样登记 —— 裸名留给源码里第一个定义）
# 值：(真值, 依据 tag)
#   "subject-key"  主体值参与资源定位（作为实参 / 容器值 / setter 右式）
#   "subject-cmp"  先查资源，再显式比对主体与归属，不等则终止
#   "public"       公开资源，没有资源归属面
#   "no-arg"       不接受任何资源标识入参（只能读到自己）
#   "no-subject"   不取主体、不比对归属，标识符直接进 Service → 水平越权
AUTHZ_TRUTH: dict[str, tuple[bool, str]] = {
    # ---- 收货地址：主体作查询键 / 显式比对 ----
    "NewBeeMallUserAddressAPI.addressList": (False, "subject-key"),
    "NewBeeMallUserAddressAPI.saveUserAddress": (False, "subject-key"),
    "NewBeeMallUserAddressAPI.getDefaultMallUserAddress": (False, "subject-key"),
    "NewBeeMallUserAddressAPI.updateMallUserAddress": (False, "subject-cmp"),
    "NewBeeMallUserAddressAPI.deleteAddress": (False, "subject-cmp"),
    "NewBeeMallUserAddressAPI.getMallUserAddress": (False, "subject-cmp"),
    # ---- 公开资源 ----
    "NewBeeMallGoodsCategoryAPI.getCategories": (False, "public"),
    "NewBeeMallGoodsAPI.goodsDetail": (False, "public"),
    "NewBeeMallIndexAPI.indexInfo": (False, "public"),
    "NewBeeMallGoodsAPI.search": (False, "public"),
    # ---- 订单 ----
    "NewBeeMallOrderAPI.orderList": (False, "subject-key"),      # params.put("userId", …)
    "NewBeeMallOrderAPI.orderDetailPage": (False, "subject-key"),
    "NewBeeMallOrderAPI.cancelOrder": (False, "subject-key"),
    "NewBeeMallOrderAPI.finishOrder": (False, "subject-key"),
    "NewBeeMallOrderAPI.saveOrder": (False, "subject-cmp"),      # 收货地址归属校验
    # 全仓库唯一的真越权：orderNo 直接进 Service，无主体、无归属
    "NewBeeMallOrderAPI.paySuccess": (True, "no-subject"),
    # ---- 购物车 ----
    "NewBeeMallShoppingCartAPI.cartItemList": (False, "subject-key"),
    "NewBeeMallShoppingCartAPI.cartItemPageList": (False, "subject-key"),
    "NewBeeMallShoppingCartAPI.saveNewBeeMallShoppingCartItem": (False, "subject-key"),
    "NewBeeMallShoppingCartAPI.updateNewBeeMallShoppingCartItem": (False, "subject-key"),
    "NewBeeMallShoppingCartAPI.updateNewBeeMallShoppingCartItem#2": (False, "subject-cmp"),
    "NewBeeMallShoppingCartAPI.toSettle": (False, "subject-key"),
    # ---- 个人中心 ----
    "NewBeeMallPersonalAPI.getUserDetail": (False, "no-arg"),
    "NewBeeMallPersonalAPI.updateInfo": (False, "subject-key"),
    "NewBeeMallPersonalAPI.logout": (False, "subject-key"),
    # ---- 管理员自己的账号（主体作资源键，无资源标识入参） ----
    "NewBeeAdminManageUserAPI.nameUpdate": (False, "subject-key"),
    "NewBeeAdminManageUserAPI.passwordUpdate": (False, "subject-key"),
    "NewBeeAdminManageUserAPI.profile": (False, "subject-key"),
    # 旧口径被"认证入口"排除、判 None 的那条：logout 是使用身份而非建立身份，
    # `adminUserService.logout(adminUser.getAdminUserId())` 是标准 2b 形态。
    "NewBeeAdminManageUserAPI.logout": (False, "subject-key"),
}

SERVICE_CALL_RE = re.compile(r"\b([A-Za-z_]\w*[Ss]ervice)\s*\.\s*([A-Za-z_]\w*)\s*\(")
XML_SQL_RE = re.compile(r"<\s*(select|insert|update|delete)\b", re.I)
DOLLAR_RE = re.compile(r"\$\{")
SUBJECT_BLOCK_MARK = "形参主体注解"


def _load(repo: Path):
    return JavaSlicer(repo).extract_entry_units()


def _entry_part(src: str) -> str:
    """切片里「入口方法自身」那一段（到第一个 `// ----` 证据段为止）。

    不能用整份切片数 Service 调用：证据段里贴进来的 ServiceImpl / Mapper
    本身就含 `xxxService.foo(`，一数就是 61/62，等于在数"我贴了什么"
    而不是"入口调了什么"。这里与 `entry_body()` 同一切法，但 benchmark
    不许 import 规则模块，所以自己切一行。
    """
    return src.split("// ----", 1)[0]


def slice_stats(units) -> dict[str, int]:
    """切片穿透五个口径。`impl_hops` 数的是**切片里真出现了 `[Hop N]` 段**的
    入口，不是"入口调了 Service" —— 断链恰恰发生在两者之间。"""
    impl, xml, svc_units, svc_hit = 0, 0, 0, 0
    for u in units:
        src = u.source_code
        has_impl = ("接口实现类方法体" in src) or bool(re.search(r"\[Hop \d+\]", src))
        if has_impl:
            impl += 1
        if XML_SQL_RE.search(src):
            xml += 1
        if SERVICE_CALL_RE.search(_entry_part(src)):
            svc_units += 1
            if has_impl:
                svc_hit += 1
    return {"entries": len(units), "service_entries": svc_units,
            "service_penetrated": svc_hit, "impl_hops": impl, "mapper_xml": xml}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--dump", default="", help="打印名字含该串的入口切片")
    ap.add_argument("--list", action="store_true", help="打印全部判定三元组")
    ap.add_argument("--strict", action="store_true",
                    help="基线漂移 / 方向性错误时以非零码退出（供 pre-push 用）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" / "newbeemallapi.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 靶场不存在：{repo}")
        sys.exit(2)
    units = _load(repo)
    print(f"靶场：{repo}")
    print(f"[1/3] 切出入口 {len(units)} 个")

    if args.dump:
        for u in units:
            if args.dump.lower() in u.unit_name.lower():
                print("=" * 78)
                print(u.unit_name, "|", u.route_path)
                print("-" * 78)
                print(u.source_code)
        return

    # ---------- ① 切片穿透 ----------
    st = slice_stats(units)
    print("\n① 切片穿透基线（入口 → ServiceImpl → Mapper XML）")
    ok = True
    for k, label in (("entries", "入口数"),
                     ("service_entries", "含 Service 调用的入口"),
                     ("service_penetrated", "其中带进跨文件实现体"),
                     ("impl_hops", "含跨文件实现体"),
                     ("mapper_xml", "含 Mapper XML SQL")):
        cur, base = st[k], BASELINE[k]
        flag = "" if cur == base else f"  <-- 基线 {base}"
        ok = ok and cur == base
        print(f"   {label:<24}{cur:>4}{flag}")
    if not ok:
        print("   ! 与基线不一致：升级切片器就同步改 BASELINE，别让它悄悄漂移")

    # ---------- ② 形参主体注解 ----------
    with_block = [u for u in units if SUBJECT_BLOCK_MARK in u.source_code]
    print(f"\n② 形参主体注解：{len(with_block)} 条切片带 `@TokenToXxx` 证据块"
          f"（基线 {SUBJECT_PARAM_EXPECTED}）")
    if len(with_block) != SUBJECT_PARAM_EXPECTED:
        ok = False
        print("   ! 数量不符：大概率是签名提取被注解参数里的字符串/中文括号截断了")
    named = {u.unit_name for u in units}
    missing_cmp = []
    for n in sorted(SUBJECT_CMP_REQUIRED):
        u = next((x for x in units if x.unit_name == n), None)
        if u is None:
            missing_cmp.append(n)
            print(f"   ✘ {n} 未入切片")
            continue
        v = rule_verdict("authz", u.source_code)
        mark = "✔" if v is False else f"✘ 规则={v}（必须 False）"
        if v is not False:
            missing_cmp.append(n)
        print(f"   {mark} {n}")
    if missing_cmp:
        ok = False

    # ---------- ③ authz 真值 ----------
    rows, orphan = [], []
    for name, (real, tag) in AUTHZ_TRUTH.items():
        u = next((x for x in units if base_unit_name(x.unit_name) == base_unit_name(name)), None)
        if u is None:
            orphan.append(name)
            continue
        rows.append({"unit": u, "real_vuln": real, "src": tag})
    print(f"\n③ authz 真值表：命中 {len(rows)} 条"
          f"（vul {sum(1 for r in rows if r['real_vuln'])} / "
          f"safe {sum(1 for r in rows if not r['real_vuln'])}）"
          f"  表内共 {len(AUTHZ_TRUTH)} 条")
    for n in orphan:
        print(f"   ! 真值表里的 {n} 没匹配到任何入口")

    decided, fallback = [], []
    for r in rows:
        rv = rule_verdict("authz", r["unit"].source_code)
        (decided if rv is not None else fallback).append((r, rv))

    right = sum(1 for r, rv in decided if rv == r["real_vuln"])
    print(f"   规则直接给出结论：{len(decided)}/{len(rows)}"
          f"（覆盖 {len(decided) / max(len(rows), 1) * 100:.0f}%）")
    print(f"   规则判定正确    ：{right}/{len(decided)}"
          f" = {right / max(len(decided), 1) * 100:.1f}%")

    safe_j = [(r, rv) for r, rv in decided if not r["real_vuln"]]
    vul_j = [(r, rv) for r, rv in decided if r["real_vuln"]]
    fp = [r for r, rv in safe_j if rv is True]
    fn = [r for r, rv in vul_j if rv is False]
    print(f"   ├ safe {len(safe_j)} 条判对 {len(safe_j) - len(fp)}"
          f"（FPR = {len(fp) / max(len(safe_j), 1) * 100:.1f}%）")
    print(f"   └ vul  {len(vul_j)} 条判对 {len(vul_j) - len(fn)}"
          f"（漏报率 = {len(fn) / max(len(vul_j), 1) * 100:.1f}%）")
    if fp or fn:
        ok = False
        print("\n   ! 方向性错误（必须为 0）：")
        for r in fp:
            print(f"     FP {r['unit'].unit_name:<52} 真值=safe 规则=True")
        for r in fn:
            print(f"     FN {r['unit'].unit_name:<52} 真值=vul  规则=False")
    if fallback:
        print("\n   退回模型（真值仍成立，只是规则不表态）：")
        for r, _ in fallback:
            print(f"     {r['unit'].unit_name:<52} "
                  f"真值={'vul ' if r['real_vuln'] else 'safe'} [{r['src']}] "
                  f"{r['unit'].route_path}")

    if args.list:
        print("\n   判定三元组：")
        for r, rv in decided + fallback:
            print(f"     {r['unit'].unit_name:<52} {r['unit'].route_path:<36} "
                  f"真值={'vul ' if r['real_vuln'] else 'safe'} 规则={rv}")

    # ---------- ④ sqli 方向护栏 ----------
    dollar_files = [p for p in repo.rglob("*.xml")
                    if "mapper" in str(p).lower()
                    and DOLLAR_RE.search(p.read_text(encoding="utf-8", errors="ignore"))]
    sqli_t = [u.unit_name for u in units if rule_verdict("sqli", u.source_code) is True]
    sqli_f = sum(1 for u in units if rule_verdict("sqli", u.source_code) is False)
    print(f"\n④ sqli 方向护栏：Mapper XML 含 `${{}}` 的文件 {len(dollar_files)} 个")
    print(f"   规则判 True（= 误报）：{len(sqli_t)}"
          f"{'  <-- 必须为 0' if sqli_t else ''}")
    for n in sqli_t:
        print(f"     ! {n}")
    print(f"   规则判 False（判安全）  ：{sqli_f} / {len(units)}")

    # ---------- 判定分布快照 ----------
    print("\n判定分布快照（True / False / None）：")
    snap = {}
    for cat in ("authz", "sqli", "xss", "pathtraver", "cmdi", "ssrf", "deserial"):
        vs = [rule_verdict(cat, u.source_code) for u in units]
        t, f = sum(1 for v in vs if v is True), sum(1 for v in vs if v is False)
        snap[cat] = {"true": t, "false": f, "none": len(vs) - t - f}
        print(f"   {cat:<11} {t:>4} / {f:>4} / {len(vs) - t - f:>4}")

    out = {
        "target": str(repo),
        "slice": st,
        "slice_matches_baseline": ok,
        "subject_param_blocks": len(with_block),
        "subject_cmp_missing": missing_cmp,
        "authz": {
            "truth_n": len(rows),
            "decided": len(decided),
            "correct": right,
            "fp": [r["unit"].unit_name for r in fp],
            "fn": [r["unit"].unit_name for r in fn],
            "fallback": [r["unit"].unit_name for r, _ in fallback],
            "orphan": orphan,
        },
        "sqli_false_positive": sqli_t,
        "sqli_safe_decided": sqli_f,
        "distribution": snap,
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    print(f"\n结果写入 {args.output}")
    if args.strict and (not ok or sqli_t or fp or fn):
        print("! --strict：基线漂移 / 方向性错误 / sqli 误报 → 退出码 3")
        sys.exit(3)


if __name__ == "__main__":
    main()
