"""第1周验收冒烟测试：路由提取 + 跨文件上下文索取循环。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.context.tool_handlers import run_context_loop
from core.slicer.web_treesitter import WebTreeSitterSlicer

REPO = Path(__file__).resolve().parents[0] / "fixtures" / "demo_flask"

slicer = WebTreeSitterSlicer(REPO)
units = slicer.extract_entry_units(REPO)
print(f"路由入口数: {len(units)}")
for u in units:
    print(f"  {u.unit_name} @ {Path(u.file_path).name}:{u.start_line} 装饰器={u.decorators_or_modifiers} 调用={u.called_symbols}")

assert units, "必须至少提取出一个路由入口"
assert any(u.unit_name == "delete_order" for u in units), "delete_order 必须被提取"

results = run_context_loop(units[:1], REPO)
r = results[0]
symbols = [b["symbol"] for b in r["context_blocks"]]
print(f"\n上下文循环轮数: {r['rounds']}，索取符号: {symbols}")

# get_item 是 svc.get_item 的跨文件调用，应被索取到（Service 在 api/service.py）
assert any("service" in str(b["source"]).lower() or b["symbol"] in ("get_item", "OrderService")
           for b in r["context_blocks"]), "跨文件符号索取失败"

print("\nSMOKE TEST PASS ✔")
