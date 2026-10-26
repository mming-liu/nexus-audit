"""YunaiV/ruoyi-vue-pro —— 第 41 仓（Java #18），M185。

整仓 3271 入口，管理端 @PreAuthorize("@ss.hasPermission(...)") 与 App 端
getLoginUserId() 自助接口占绝大多数。本基准锁定 system + infra 两个
基础模块（302 入口）：管理端声明式权限 + App 自助主体链，authz 0 True。
"""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents import rule_detectors as R
from core.slicer.java_servlet import JavaSlicer
from core.text_utils import ensure_utf8_stdio
ensure_utf8_stdio()
DEFAULT_TARGET = ROOT / "reference_repos" / "ruoyi-vue-pro"
MODULES = ("yudao-module-system", "yudao-module-infra")
CATS = ("authz", "sqli", "deserial")   # xss 属管理端模板面，另行人工复核
_ANCHOR = '''@RestController
public class A {
  @GetMapping("/user")
  public User get(@RequestParam Long id) { return userMapper.selectById(id); }
}'''

def main() -> int:
    ap = argparse.ArgumentParser(description="ruoyi-vue-pro 基础模块基准（M185）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" / "ruoyi_vue_pro.json"))
    a = ap.parse_args()
    repo = Path(a.target)
    if not repo.exists():
        print(f"! 找不到 {repo}"); return 2
    units = [u for u in JavaSlicer(repo).extract_entry_units()
             if any(("/" + m + "/") in u.file_path.replace("\\", "/") for m in MODULES)]
    true_rows = [(u.unit_name, c) for u in units for c in CATS
                 if R.verdict(c, u.source_code) is True]
    pre = next((u for u in units if "@PreAuthorize" in u.source_code), None)
    per = next((u for u in units if "@PermitAll" in u.source_code), None)
    pre_v = R.verdict("authz", pre.source_code) if pre else None
    per_v = R.verdict("authz", per.source_code) if per else None
    anchor = R.verdict("authz", _ANCHOR)
    print(f"切片 {len(units)} / True {len(true_rows)} / PreAuthorize {pre_v} / PermitAll {per_v} / 锚点 {anchor}")
    bad = []
    if len(units) < 250: bad.append(f"切片 {len(units)} < 250")
    if true_rows: bad.append(f"True: {true_rows[:5]}")
    if pre_v is not False: bad.append(f"PreAuthorize {pre_v}")
    if per_v is not None: bad.append(f"PermitAll {per_v}")
    if anchor is not True: bad.append(f"锚点 {anchor}")
    out = Path(a.output); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"total_units": len(units), "true": len(true_rows),
                               "preauthorize": pre_v, "permitall": per_v,
                               "anchor": anchor, "fp": len(true_rows),
                               "pass": not bad}, ensure_ascii=False, indent=2), encoding="utf-8")
    if bad: print("STRICT FAIL " + "；".join(bad)); return 1
    print(f"STRICT PASS ✔（{len(units)} 入口 / 0 True / PreAuthorize False / PermitAll None）")
    return 0

if __name__ == "__main__":
    sys.exit(main())
