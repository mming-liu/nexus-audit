"""xuxueli/xxl-job —— 第 38 仓（Java #17），M170。

xxl-job 的鉴权有两层：
  1. @XxlSso(role = Consts.ADMIN_ROLE) —— 管理员角色门；
  2. @XxlSso(login = false) —— 作者显式声明的匿名入口（登录页/回调）；
  3. JobGroupPermissionUtil.validJobGroupPermission(request, groupId)
     —— 按当前登录用户的 jobGroup 做资源组权限校验。

权限不在 controller 方法体里，只认方法级 @PreAuthorize 会把 160 个后台
接口全判成缺鉴权。本基准锁定 authz + deserial 两类（xss 属管理端模板
渲染面，另行人工复核，不在本门禁内）。

门禁（--strict）：36 入口 / authz 0 True / deserial 0 True /
管理员门 False / 匿名门 None / 反向锚点 True。
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
from core.text_utils import ensure_utf8_stdio                   # noqa: E402

ensure_utf8_stdio()
DEFAULT_TARGET = ROOT / "reference_repos" / "xxl-job"
CATS = ("authz", "deserial")
MIN_UNITS = 30
_ANCHOR = '''@RestController
public class A {
  @RequestMapping("/user")
  @ResponseBody
  public User get(@RequestParam Long id) {
    return userMapper.selectById(id);
  }
}'''


def main() -> int:
    ap = argparse.ArgumentParser(description="xxl-job 权限门基准（M170）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" /
                                            "xxl_job.json"))
    args = ap.parse_args()
    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}")
        return 2

    units = list(JavaSlicer(repo).extract_entry_units())
    true_rows = []
    decided = 0
    for u in units:
        for c in CATS:
            v = R.verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            if v is True:
                true_rows.append((u.unit_name, c))
    import re
    admin = [u for u in units
             if re.search(r"@XxlSso\s*\([^)]*role\s*=", u.source_code)]
    anon = [u for u in units
            if re.search(r"@XxlSso\s*\([^)]*login\s*=\s*false",
                         u.source_code)]
    admin_v = R.verdict("authz", admin[0].source_code) if admin else None
    anon_v = R.verdict("authz", anon[0].source_code) if anon else None
    anchor = R.verdict("authz", _ANCHOR)

    print("=" * 72)
    print("xxl-job 结果（@XxlSso 角色门 / 资源组权限 / 匿名入口）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    for n, c in true_rows[:10]:
        print(f"    [FP] {n} [{c}]")
    print(f"  管理员门（应 False）  ：{admin_v}（{len(admin)} 条）")
    print(f"  匿名门（应 None）     ：{anon_v}（{len(anon)} 条）")
    print(f"  反向锚点（无鉴权）    ：{anchor}")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"出现 {len(true_rows)} 条 True：{true_rows[:5]}")
    if admin_v is not False:
        bad.append(f"管理员门未判 False：{admin_v}")
    if anon_v is not None:
        bad.append(f"匿名门未退回 None：{anon_v}")
    if anchor is not True:
        bad.append(f"反向锚点失效：{anchor}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "target": str(repo), "total_units": len(units),
        "decided": decided, "true": len(true_rows),
        "admin_guard": admin_v, "anon_guard": anon_v,
        "anchor": anchor, "fp": len(true_rows), "reverse_fn": 0,
        "pass": not bad,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    if bad:
        print("\nSTRICT FAIL ✘ " + "；".join(bad))
        print(f"结果写入 {out}")
        return 1
    print(f"\nSTRICT PASS ✔（{len(units)} 入口 / authz+deserial 0 True / "
          f"管理员门 False / 匿名门 None / 反向锚点 True）")
    print(f"结果写入 {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
