"""RuoYi（若依）—— 第 11 个靶场：企业级多模块 Java + MyBatis 动态数据权限。

## 为什么需要它

此前所有 Java 靶场都是"漏洞教学仓库"：Controller、Service、Mapper 同模块，
MyBatis 用法简单。真实企业系统是另一回事，本靶场锁两件此前只敢说"支持"
没敢说"验证过"的事：

1. **跨 Maven 子模块穿透**：Controller 在 `ruoyi-admin`，Service 实现在
   `ruoyi-system`，Shiro 工具在 `ruoyi-common`，切面在 `ruoyi-framework`。
   切片的 `[Hop 1]` / 跨文件证据段必须真的跨子模块拉到实现体——门禁里
   断言 ≥100 个单元带跨模块 Hop 证据（当前 174）。
2. **`${params.dataScope}` 动态数据权限不是 SQLi**：SysUser/SysDept/SysRole
   的 Mapper XML 在 WHERE 末尾拼 `${params.dataScope}`，但 DataScopeAspect
   第 37 行**先 `clearDataScope` 清掉客户端传的 params.dataScope**、再写入
   服务端按角色生成的 SQL 片段——`${}` 是服务端可控值。（老版本 RuoYi
   没有 clear 才是真实 CVE；本靶场版本有防护。）

## 真值口径

· **authz**：方法上带 `@RequiresPermissions("...")` 的入口 → False。
  注解是作者写在代码里的权限声明（159 条），不是我们猜的。
· **sqli（dataScope 五路）**：SysUserController.list/export、
  SysDeptController.list、SysRoleController.list/export → False，依据
  切面 clear+overwrite 的服务端生成事实。
· **无注解入口一律不进真值表**（20 条 authz 判 True 的 checkXxxUnique /
  markRead 等是"作者未标注"而非"作者声明安全"——硬收进去就是掺沙子）。
  它们在 --list 输出里单列供人工复核。
· GenController.create（sqli 判 True）：作者给了 @RequiresRoles("admin")
  + SqlUtil.filterKeyword，是**管理员专用的建表工具**——按设计功能处理，
  不进 sqli 真值表（记录在案，不静默）。

## 门禁（--strict）

1. 真值表零误报、零判反（sqli 的 dataScope 五路允许退 None——控制器侧
   没有 ${}，判 False 不来自规则层）；
2. 跨模块 Hop 证据 ≥100 单元（切片穿透退化立刻红）；
3. authz 注解行全部被规则判 False（一条漏掉都算退化）。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict  # noqa: E402
from core.slicer.java_servlet import JavaSlicer                  # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "RuoYi-master"

# dataScope 五路：(文件名, 单元名, 类目, 依据)
DATASCOPE_ROWS = [
    ("SysUserController.java", "SysUserController.list", "sqli",
     "selectUserList → @DataScope 切面先 clearDataScope 再写服务端生成的"
     "数据权限 SQL（DataScopeAspect.java:37/133），${params.dataScope} 非客户端可控"),
    ("SysUserController.java", "SysUserController.export", "sqli",
     "同 list：export 复用 selectUserList，同一 @DataScope 路径"),
    ("SysDeptController.java", "SysDeptController.list", "sqli",
     "selectDeptList → 同一 @DataScope 机制（SysDeptServiceImpl.java:40/53/68）"),
    ("SysRoleController.java", "SysRoleController.list", "sqli",
     "selectRoleList → 同一 @DataScope 机制（SysRoleServiceImpl.java:55）"),
    ("SysRoleController.java", "SysRoleController.export", "sqli",
     "同 list：export 复用 selectRoleList"),
]

MIN_CROSS_MODULE_HOPS = 100


def _file_name(u) -> str:
    return Path(u.file_path).name


def main() -> int:
    ap = argparse.ArgumentParser(description="RuoYi 企业级多模块基准")
    ap.add_argument("--target", default=str(DEFAULT_TARGET))
    ap.add_argument("--offline", action="store_true", help="只跑确定性规则（CI 门禁）")
    ap.add_argument("--strict", action="store_true",
                    help="真值表零误报 + 跨模块 Hop 断言（CI 门禁）")
    ap.add_argument("--list", action="store_true", help="打印逐条判定")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" / "ruoyi.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 靶场不存在：{repo}（安装：curl -sL -o x.zip "
              f"https://codeload.github.com/yangzongzhuan/RuoYi/zip/refs/heads/master）")
        return 2

    units = JavaSlicer(repo).extract_entry_units()
    print("RuoYi 结果（企业级多模块 + MyBatis 动态数据权限）")
    print("=" * 72)
    print(f"切出入口 {len(units)} 个")

    # ---- 跨模块 Hop 证据统计 ----
    cross = 0
    for u in units:
        src = u.source_code or ""
        i = src.find("[Hop 1]")
        if i >= 0 and "ruoyi-admin" not in src[i:i + 160]:
            cross += 1
    print(f"跨 Maven 子模块 Hop1 证据 {cross} 单元"
          f"（门禁 ≥{MIN_CROSS_MODULE_HOPS}）")

    # ---- authz 注解真值行 ----
    ann_rows, unannotated_true = [], []
    for u in units:
        src = u.source_code or ""
        if "@RequiresPermissions" not in src:
            if rule_verdict("authz", src) is True:
                unannotated_true.append(u)
            continue
        ann_rows.append({"unit": u, "category": "authz", "real_vuln": False,
                         "why": "方法级 @RequiresPermissions 是作者写明"
                                "的权限声明（垂直授权）"})
    # dataScope sqli 真值行（按单元名精确解析）
    by_name = {}
    for u in units:
        by_name.setdefault((_file_name(u), u.unit_name), []).append(u)
    ds_rows, missing = [], []
    for fname, uname, cat, why in DATASCOPE_ROWS:
        cands = by_name.get((fname, uname))
        if not cands:
            missing.append(f"{fname}:{uname}（真值表与源码不同步）")
            continue
        ds_rows.append({"unit": cands[0], "category": cat, "real_vuln": False,
                        "why": why})

    rows = ann_rows + ds_rows
    print(f"真值行 {len(rows)}（authz 注解 {len(ann_rows)} + sqli dataScope "
          f"{len(ds_rows)}），命中失败 {len(missing)}")

    # ---- 规则层 ----
    wrong, reverse_fn, fallback = [], [], []
    for r in rows:
        rv = rule_verdict(r["category"], r["unit"].source_code)
        r["rv"] = rv
        if rv is None:
            fallback.append(r)
        elif rv == r["real_vuln"]:
            pass
        else:
            (reverse_fn if rv is True else wrong).append(r)
    ann_false = sum(1 for r in ann_rows if r["rv"] is False)
    print(f"\n规则层：判对 {len(rows) - len(wrong) - len(reverse_fn) - len(fallback)}"
          f"  False 直判 {len(rows) - len(wrong) - len(reverse_fn) - len(fallback)}"
          f"  误报 {len(wrong)}  判反 {len(reverse_fn)}  退回 {len(fallback)}")
    print(f"authz 注解行 {len(ann_rows)} 条中被直接判 False {ann_false} 条")
    for r in wrong:
        print(f"    [误报] {_file_name(r['unit'])}:{r['unit'].unit_name}")
    for r in reverse_fn:
        print(f"    [判反] {_file_name(r['unit'])}:{r['unit'].unit_name}")
    if unannotated_true:
        print(f"\n无注解且判 True 的入口 {len(unannotated_true)} 条"
              f"（作者未标注，不进真值表，供人工复核）：")
        for u in unannotated_true:
            print(f"    {_file_name(u)}:{u.unit_name}")
    if args.list:
        print("\n  dataScope 五路逐条：")
        for r in ds_rows:
            print(f"    {_file_name(r['unit']):28} {r['unit'].unit_name:32} "
                  f"真值=safe 规则={r['rv']}")

    out = {
        "target": str(repo),
        "total_units": len(units),
        "cross_module_hop_units": cross,
        "truth_rows": len(rows),
        "authz_annotation_rows": len(ann_rows),
        "authz_annotated_false": ann_false,
        "datascope_rows": len(ds_rows),
        "missing": missing,
        "decided": len(rows) - len(fallback),
        "correct": len(rows) - len(wrong) - len(reverse_fn) - len(fallback),
        "fp": len(wrong),
        "reverse_fn": len(reverse_fn),
        "fallback": len(fallback),
        "unannotated_true": [f"{_file_name(u)}:{u.unit_name}" for u in unannotated_true],
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    print(f"\n结果写入 {args.output}")

    if args.strict:
        bad = []
        if missing:
            bad.append(f"真值表 {len(missing)} 条未命中")
        if wrong:
            bad.append(f"误报 {len(wrong)} 条")
        if reverse_fn:
            bad.append(f"判反 {len(reverse_fn)} 条")
        if cross < MIN_CROSS_MODULE_HOPS:
            bad.append(f"跨模块 Hop 证据仅 {cross}（<{MIN_CROSS_MODULE_HOPS}，穿透退化）")
        if ann_false != len(ann_rows):
            bad.append(f"authz 注解行仅 {ann_false}/{len(ann_rows)} 直判 False"
                       f"（注解语义退化）")
        if bad:
            print("STRICT FAIL ✘ " + "；".join(bad))
            return 1
        print("STRICT PASS ✔ （零误报 / 零判反 / 跨模块穿透在线 / 注解语义在线）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
