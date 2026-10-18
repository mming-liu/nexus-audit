"""nexus-audit CLI：命令行入口与 GitHub Action CI/CD 触发入口。

用法：
  python cli.py scan <repo_path>            # 全量扫描
  python cli.py pr-scan --base origin/main  # GitHub PR 增量扫描（仅解析 git diff 影响的调用链）
TODO(第4周)：PR 增量模式与自动生成 PR 修复评论。
"""
import argparse


def main():
    parser = argparse.ArgumentParser(prog="nexus-audit", description="AI 自动化漏洞挖掘审计框架")
    sub = parser.add_subparsers(dest="command", required=True)
    p_scan = sub.add_parser("scan", help="全量扫描目标仓库")
    p_scan.add_argument("repo_path")
    p_pr = sub.add_parser("pr-scan", help="PR 增量扫描（仅 git diff 影响的调用链）")
    p_pr.add_argument("--base", default="origin/main")
    args = parser.parse_args()
    print(f"nexus-audit: {args.command} 模式尚未实现，请参考 README 开发路线图")


if __name__ == "__main__":
    main()
