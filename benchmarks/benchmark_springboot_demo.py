"""xkcoding/spring-boot-demo —— 第 35 仓（Java #16），M167。

该仓是 55+ 模块的 Spring Boot 示例集，很多模块**故意**演示不安全写法
（demo-upload 无白名单、demo-task-xxl-job 的 SSRF、demo-orm-jdbctemplate
无鉴权 CRUD）。本基准不把"示例故意留的坑"当误报，也不把整仓 CORS 配置
继承算成 74 个漏洞；它锁定的是**安全语义模块**：

    demo-rbac-security / demo-rbac-shiro / demo-swagger /
    demo-oauth / demo-actuator

这些模块的鉴权由 SecurityConfig 的 anyRequest().authenticated() +
access("@rbacAuthorityService.hasPermission(...)") 统一强制，controller
方法体里看不到 —— 切片器据此打 [global-authz] 标记，authz 退 None。

门禁（--strict）：19 入口 / 7 类目 0 True / 全局标记覆盖 19 / 反向锚点 True。
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
DEFAULT_TARGET = ROOT / "reference_repos" / "spring-boot-demo"
MODULES = ("demo-rbac-security", "demo-rbac-shiro", "demo-swagger",
           "demo-oauth", "demo-actuator")
CATS = ("authz", "unrestricted_upload", "log_injection", "xss",
        "ssrf", "redir", "deserial")
MIN_UNITS = 15
_ANCHOR = '''@RestController
public class A {
  @GetMapping("/user")
  public User get(@RequestParam Long id) {
    return userMapper.selectById(id);
  }
}'''


def main() -> int:
    ap = argparse.ArgumentParser(description="spring-boot-demo 安全模块基准（M167）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" /
                                            "springboot_demo.json"))
    args = ap.parse_args()
    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}")
        return 2

    units = [u for u in JavaSlicer(repo).extract_entry_units()
             if any(("/" + m + "/") in u.file_path.replace("\\", "/")
                    for m in MODULES)]
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
    marked = sum(1 for u in units if "[global-authz]" in u.source_code)
    anchor = R.verdict("authz", _ANCHOR)

    print("=" * 72)
    print("spring-boot-demo 安全模块（SecurityConfig 全量认证 + RBAC EL）")
    print("=" * 72)
    print(f"  安全模块入口          ：{len(units)}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    for n, c in true_rows[:10]:
        print(f"    [FP] {n} [{c}]")
    print(f"  [global-authz] 覆盖   ：{marked}/{len(units)}")
    print(f"  反向锚点（无全局配置） ：{anchor}")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"规则层出现 {len(true_rows)} 条 True：{true_rows[:5]}")
    if marked != len(units):
        bad.append(f"全局标记只覆盖 {marked}/{len(units)}")
    if anchor is not True:
        bad.append(f"反向锚点失效：{anchor}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "target": str(repo), "scope": list(MODULES),
        "total_units": len(units), "decided": decided,
        "true": len(true_rows), "global_authz_marked": marked,
        "anchor": anchor, "fp": len(true_rows), "reverse_fn": 0,
        "pass": not bad,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    if bad:
        print("\nSTRICT FAIL ✘ " + "；".join(bad))
        print(f"结果写入 {out}")
        return 1
    print(f"\nSTRICT PASS ✔（{len(units)} 入口 / 7 类目 0 True / "
          f"全局标记 {marked}/{len(units)} / 反向锚点 True）")
    print(f"结果写入 {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
