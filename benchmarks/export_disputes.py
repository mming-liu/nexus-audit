"""导出真值争议清单：`python benchmarks/export_disputes.py [--target X] [--json] [--check]`

用法
----

    # 终端看清单 + 核对证据（默认行为，含自校验）
    python benchmarks/export_disputes.py

    # 生成可贴进 GitHub issue 的 markdown
    python benchmarks/export_disputes.py --md > disputes.md

    # 机器可读
    python benchmarks/export_disputes.py --json

    # 只做证据核对，不打印清单（适合放进 CI / 冒烟）
    python benchmarks/export_disputes.py --check

为什么 `--check` 要能单独跑：证据行号写错是静默的 —— 报告照样生成、
格式照样正确，只是维护者点进去看到的是无关代码。把"逐字核对"做成
独立的一步，才能在前置流程里拦住它。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmarks.disputed_truth import (          # noqa: E402
    KIND_LABEL, all_disputes, dump_issues, dump_json, render_markdown,
    verify_evidence,
)


def main() -> int:
    ap = argparse.ArgumentParser(description="导出靶场真值争议清单")
    ap.add_argument("--target", action="append",
                    help="只导出指定靶场（可多次）。默认全部。")
    ap.add_argument("--md", action="store_true", help="输出 markdown 报告")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--out", help="写入文件（默认 stdout）")
    ap.add_argument("--check", action="store_true",
                    help="只核对证据能否逐字对上，不输出清单")
    ap.add_argument("--issues", metavar="DIR",
                    help="每个靶场生成一份 issue 草稿（写到 DIR）")
    ap.add_argument("--skip-check", action="store_true",
                    help="跳过证据核对（仅用于靶场未克隆的环境）")
    args = ap.parse_args()

    problems: list[str] = []
    if not args.skip_check:
        problems = verify_evidence(ROOT)

    if args.check:
        if problems:
            print(f"✘ 证据核对未通过（{len(problems)} 处）：")
            for p in problems:
                print(f"  - {p}")
            return 1
        n = len(all_disputes())
        print(f"✔ 证据核对通过：{n} 条争议，全部能逐字对上源码")
        return 0

    if args.issues:
        written = dump_issues(args.issues)
        for p in written:
            print(f"已写入 {p}", file=sys.stderr)
        if problems:
            print(f"\n⚠ 证据核对有 {len(problems)} 处问题：", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            return 1
        return 0

    if args.json:
        if args.out:
            dump_json(args.out, args.target)
            print(f"已写入 {args.out}", file=sys.stderr)
        else:
            import json
            from dataclasses import asdict
            items = all_disputes()
            if args.target:
                items = [d for d in items if d.target in args.target]
            print(json.dumps([asdict(d) for d in items],
                             ensure_ascii=False, indent=2))
    elif args.md:
        text = render_markdown(args.target)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"已写入 {args.out}", file=sys.stderr)
        else:
            print(text)
    else:
        items = all_disputes()
        if args.target:
            items = [d for d in items if d.target in args.target]
        if not items:
            print("（无争议样本）")
            return 0
        print(f"真值争议清单（{len(items)} 条）")
        print("=" * 78)
        for d in items:
            print(d.one_line())
            print(f"    结论：{d.summary}")
            for e in d.evidence:
                loc = f"{e.file}:{e.line}" if e.line else e.file
                print(f"    证据：{loc}")
                print(f"          {e.text.strip()}")
            print()
        print("=" * 78)
        print("分歧类型分布：")
        by: dict[str, int] = {}
        for d in items:
            by[d.kind] = by.get(d.kind, 0) + 1
        for k, v in sorted(by.items(), key=lambda x: -x[1]):
            print(f"  {KIND_LABEL[k]}: {v}")
        print("\n提示：--md 生成可贴进 issue 的报告，--check 只核对证据。")

    if problems:
        print(f"\n⚠ 证据核对有 {len(problems)} 处问题：", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
