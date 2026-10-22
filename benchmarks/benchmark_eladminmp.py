"""eladmin-mp —— 第 15 个靶场：Spring Boot + MyBatis-Plus + Spring Security EL。

## 为什么需要它

RuoYi 锁的是 Shiro 注解 + 多模块穿透；eladmin-mp 补另外两块企业级空白：

1. **Spring Security 自定义 EL 权限**：`@PreAuthorize("@el.check('user:list')")`
   —— 注解里的 SpEL 调用自定义 Bean 做垂直授权，语义与 `@RequiresPermissions`
   相同：方法级权限注解 = 作者写明的授权声明。
2. **MyBatis-Plus 条件构造器**：查询出口从 XML `${}/#{}` 换成 Wrapper 链。
   `.apply/.last/.inSql` 是显式拼接出口，`.eq/.like/...` 由框架参数化。

## 真值口径

· **authz**：方法上带 `@PreAuthorize("@el.check('...')")` 的入口 → False
  （作者垂直授权声明，53 条）。
· **无注解入口一律不进真值表**：AliPay / Verify / Generator 的 9 条判 True
  是"作者未标注"而非"作者声明安全"——单列供人工复核（其中 GeneratorController
  generatorCode 另有 pathtraver=True：tableName 拼模板路径，同口径在案）。
· **MyBatis-Plus 判据在靶场内零命中**（探针实测 `.apply(`=0、`.last(`=0、
  wrapper 单元 0 落 None）——按探针纪律，True/False 机制由冒烟 [75] 夹具
  锁定，不凑靶场分母。

## 门禁（--strict）

1. @el.check 真值行零误报、零判反；
2. 注解行全部被规则直判 False（一条漏掉都算退化）；
3. 切入单元 ≥60（切片退化立刻红）。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict  # noqa: E402
from core.slicer.java_servlet import JavaSlicer                  # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "eladmin-mp-master"
MIN_UNITS = 60


def _file_name(u) -> str:
    return Path(u.file_path).name


def main() -> int:
    ap = argparse.ArgumentParser(description="eladmin-mp 基准（MyBatis-Plus + EL 权限）")
    ap.add_argument("--target", default=str(DEFAULT_TARGET))
    ap.add_argument("--offline", action="store_true", help="只跑确定性规则（CI 门禁）")
    ap.add_argument("--strict", action="store_true", help="真值表零误报 + 注解语义断言")
    ap.add_argument("--list", action="store_true", help="打印逐条判定")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" / "eladminmp.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 靶场不存在：{repo}（安装：curl -sL -o x.zip "
              f"https://codeload.github.com/elunez/eladmin-mp/zip/refs/heads/master）")
        return 2

    units = JavaSlicer(repo).extract_entry_units()
    print("eladmin-mp 结果（Spring Security EL + MyBatis-Plus）")
    print("=" * 72)
    print(f"切出入口 {len(units)} 个")

    ann_rows, unannotated_true = [], []
    for u in units:
        src = u.source_code or ""
        if "@el.check" not in src:
            if rule_verdict("authz", src) is True:
                unannotated_true.append(u)
            continue
        ann_rows.append({"unit": u, "category": "authz", "real_vuln": False,
                         "why": "方法级 @PreAuthorize(\"@el.check(...)\") 是作者写明"
                                "的权限声明（垂直授权）"})

    wrong, reverse_fn, fallback = [], [], []
    for r in ann_rows:
        rv = rule_verdict(r["category"], r["unit"].source_code)
        r["rv"] = rv
        if rv is None:
            fallback.append(r)
        elif rv == r["real_vuln"]:
            pass
        else:
            (reverse_fn if rv is True else wrong).append(r)
    correct = len(ann_rows) - len(wrong) - len(reverse_fn) - len(fallback)
    print(f"真值行 {len(ann_rows)}（@el.check 注解），判对 {correct}"
          f"  误报 {len(wrong)}  判反 {len(reverse_fn)}  退回 {len(fallback)}")
    for r in wrong:
        print(f"    [误报] {_file_name(r['unit'])}:{r['unit'].unit_name}")
    for r in reverse_fn:
        print(f"    [判反] {_file_name(r['unit'])}:{r['unit'].unit_name}")
    if unannotated_true:
        print(f"\n无注解且判 True 的入口 {len(unannotated_true)} 条"
              f"（作者未标注，不进真值表，供人工复核）：")
        for u in unannotated_true:
            print(f"    {_file_name(u)}:{u.unit_name}")

    out = {
        "target": str(repo),
        "total_units": len(units),
        "truth_rows": len(ann_rows),
        "decided": len(ann_rows) - len(fallback),
        "correct": correct,
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
        if len(units) < MIN_UNITS:
            bad.append(f"切片仅 {len(units)} 单元（<{MIN_UNITS}，切片退化）")
        if wrong:
            bad.append(f"误报 {len(wrong)} 条")
        if reverse_fn:
            bad.append(f"判反 {len(reverse_fn)} 条")
        ann_false = sum(1 for r in ann_rows if r["rv"] is False)
        if ann_false != len(ann_rows):
            bad.append(f"@el.check 注解行仅 {ann_false}/{len(ann_rows)} 直判 False"
                       f"（注解语义退化）")
        if bad:
            print("STRICT FAIL ✘ " + "；".join(bad))
            return 1
        print("STRICT PASS ✔ （零误报 / 零判反 / @el.check 注解语义在线）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
