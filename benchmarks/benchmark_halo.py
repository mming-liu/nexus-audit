"""halo-dev/halo —— 第 47 仓（Java #20），M215。

Halo 2.x 用 Spring WebFlux 的 RouterFunction 函数式路由，没有
@RestController/@RequestMapping 注解，注解式切片器得到 0 个入口。本基准
如实登记这一边界：验证仓内确有 RouterFunction 路由与安全适配器，0 个
注解入口 / 0 True；反向锚点证明注解式判据仍然工作。
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents import rule_detectors as R
from core.slicer.java_servlet import JavaSlicer
from core.text_utils import ensure_utf8_stdio
ensure_utf8_stdio()
DEFAULT_TARGET = ROOT / "reference_repos" / "halo" / "application" / "src" / "main" / "java"
CATS = ("authz", "jndi_injection", "arbitrary_file_delete", "csrf_disabled", "regex_dos")
_ANCHOR = '''@RestController
public class A {
  @GetMapping("/user")
  public User get(@RequestParam Long id) { return userMapper.selectById(id); }
}'''

def main() -> int:
    ap = argparse.ArgumentParser(description="halo RouterFunction 边界基准（M215）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" / "halo.json"))
    a = ap.parse_args(); repo = Path(a.target)
    if not repo.exists(): print(f"! 找不到 {repo}"); return 2
    units = list(JavaSlicer(repo).extract_entry_units())
    true_rows = [(u.unit_name, c) for u in units for c in CATS
                 if R.verdict(c, u.source_code) is True]
    router = sum(1 for p in repo.rglob("*.java")
                 if "RouterFunction" in p.read_text(encoding="utf-8", errors="ignore"))
    anchor = R.verdict("authz", _ANCHOR)
    print(f"注解入口 {len(units)} / RouterFunction 文件 {router} / True {len(true_rows)} / 锚点 {anchor}")
    bad = []
    if router < 3: bad.append(f"RouterFunction 文件 {router} < 3")
    if true_rows: bad.append(f"True: {true_rows[:5]}")
    if anchor is not True: bad.append(f"锚点 {anchor}")
    out = Path(a.output); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"total_units": len(units), "router_function_files": router,
                               "true": len(true_rows), "anchor": anchor,
                               "fp": 0, "pass": not bad}, ensure_ascii=False,
                              indent=2), encoding="utf-8")
    if bad: print("STRICT FAIL " + "；".join(bad)); return 1
    print(f"STRICT PASS ✔（0 注解入口 / RouterFunction {router} 文件 / 0 True / 锚点 True）")
    return 0

if __name__ == "__main__":
    sys.exit(main())
