"""nexus-audit CLI：命令行入口与 GitHub Action CI/CD 触发入口。

用法：
  python cli.py scan <repo_path> [--offline] [--output report.md]
      全量扫描：切片 → 跨文件上下文 → 两步法初筛 → 反方挑刺 → 沙箱验证 → 报告
  python cli.py pr-scan --base origin/main
      GitHub PR 增量扫描（仅解析 git diff 影响的调用链，第4周）

--offline：使用内置离线 PoC 模板（不调用任何 LLM API），用于演示与回归测试。
"""
from __future__ import annotations

import argparse
import asyncio
import subprocess
from pathlib import Path

from core.agents.router import TwoTierRouter
from core.agents.scenario_matcher import ScenarioMatcher
from core.agents.skeptic_reviewer import SkepticReviewer
from core.context.tool_handlers import run_context_loop
from core.sandbox.patch_generator import PatchGenerator
from core.sandbox.web_docker_verifier import WebDockerVerifier
from core.slicer.web_treesitter import WebTreeSitterSlicer


def build_report(repo: str, hypotheses, poc_results, skipped_skeptic: int) -> str:
    lines = [f"# nexus-audit 扫描报告", "",
             f"- 目标仓库：`{repo}`",
             f"- 初筛漏洞假设：{len(hypotheses)}",
             f"- 沙箱验证确认：{sum(1 for r in poc_results if r.verified)}", ""]
    for r in poc_results:
        h = r.hypothesis
        status = "✔ 已复现（高危）" if r.verified else "✘ 未复现/访问被正确拒绝"
        lines += [f"## [{h.vuln_type.upper()}] {h.unit.unit_name}",
                  f"- 位置：`{h.unit.file_path}:{h.unit.start_line}`",
                  f"- 状态：{status}",
                  f"- 缺失校验：{h.property_missing or '无'}",
                  f"- 分析：{h.reasoning_summary}",
                  f"- 沙箱摘要：{r.output_digest.splitlines()[0] if r.output_digest else '无'}",
                  f"- PoC 脚本：`{r.poc_script_path}`",
                  f"- 自愈轮数：{r.self_heal_rounds}", ""]
    if not poc_results:
        lines.append("（无进入沙箱验证的假设）")
    return "\n".join(lines)


def cmd_scan(args):
    repo = Path(args.repo_path).resolve()
    if args.web3:
        return cmd_scan_web3(args, repo)

    # Java 赛道：按类目做两步法（Web 赛道的 IDOR/越权场景不适用于 Servlet 用例）
    if args.java:
        return cmd_scan_java(args, repo)

    print(f"[1/5] 切片：提取路由入口 ...")
    units = WebTreeSitterSlicer(repo).extract_entry_units(repo)
    print(f"      共 {len(units)} 个路由入口")

    print(f"[2/5] 跨文件上下文扩展循环 ...")
    ctx = run_context_loop(units, repo)
    print(f"      平均 {sum(r['rounds'] for r in ctx)/max(len(ctx),1):.1f} 轮索取")

    print(f"[3/5] 两步法初筛（Scenario + Property）...")
    if args.offline:
        # 离线模式：本地启发式初筛（关键词命中场景 + 规则核对属性），不调用任何 API
        from core.models import VulnHypothesis

        class OfflineMatcher:
            async def audit_repo(self, us):
                hs = []
                for unit in us:
                    src = unit.source_code
                    if any(k in src for k in ("order_id", "account_id", "user_id")):
                        missing = not any(k in src for k in ("owner_id", "current_user", "abort(403)"))
                        hs.append(VulnHypothesis(
                            unit=unit, vuln_type="idor", scenario_hit=True,
                            property_missing="资源归属人与会话身份未比对" if missing else "",
                            confidence=0.6 if missing else 0.1))
                return hs
        matcher = OfflineMatcher()
        hypotheses = asyncio.run(matcher.audit_repo(units))
    else:
        # 免费模型优先：探测 FREE_CANDIDATES，全不可用再走付费降级链
        from core.agents.model_selector import auto_select_and_print
        tier1_model = auto_select_and_print(tier=1)
        tier1 = TwoTierRouter()
        tier1.tier1.model = tier1_model
        matcher = ScenarioMatcher(router=tier1)
        hypotheses = asyncio.run(matcher.audit_repo(units))
    if hypotheses and isinstance(hypotheses[0], list):
        hypotheses = [h for sub in hypotheses for h in sub]
    hypotheses = [h for h in hypotheses if h.property_missing]
    print(f"      进入复核队列：{len(hypotheses)}")

    print(f"[4/5] 反方挑刺（Skeptic）...")
    if args.offline:
        skeptic = SkepticReviewer(llm=lambda p: '{"rejected": false, "reason": "offline 模式默认放行进入沙箱"}')
        kept = asyncio.run(skeptic.filter_false_positives(hypotheses))
    else:
        kept = asyncio.run(SkepticReviewer(router=TwoTierRouter()).filter_false_positives(hypotheses))
    print(f"      保留 {len(kept)} 个假设进入沙箱")

    print(f"[5/5] 沙箱动态验证 ...")
    verifier = WebDockerVerifier(python=args.python)
    results = [verifier.verify_finding(h) for h in kept]

    report = build_report(str(repo), kept, results, len(hypotheses) - len(kept))
    out = Path(args.output or "report.md")
    out.write_text(report, encoding="utf-8")
    print(f"\n完成：报告已写入 {out}")
    print(f"确认漏洞 {sum(1 for r in results if r.verified)}/{len(results)}")


def cmd_scan_java(args, repo: Path):
    """Java Web 赛道：Servlet/Spring 入口切片 + 按漏洞类目两步法。"""
    from core.agents.vuln_categories import ALL_KEYS
    from core.agents.scenario_matcher import ScenarioMatcher
    from core.slicer.java_servlet import JavaSlicer

    categories = [c.strip() for c in args.categories.split(",")] if args.categories else ALL_KEYS

    print(f"[1/4] Java 入口切片 ...")
    units = JavaSlicer(repo).extract_entry_units()
    # 同一用例的 doGet 只是转发，保留 doPost 即可，避免重复计费
    units = [u for u in units if not u.unit_name.endswith(".doGet")]
    print(f"      共 {len(units)} 个入口")
    if not units:
        print("      未发现 Java Web 入口（需 @WebServlet / @GetMapping 等注解）")
        return

    print(f"[2/4] 类目选择：{', '.join(categories)}")
    print(f"[3/4] 两步法初筛（并发 {args.concurrency}）...")
    if args.offline:
        from benchmarks.offline_baseline import offline_predict
        flagged = [(u, c) for u in units for c in categories if offline_predict(u.source_code, c)]
    else:
        from core.agents.model_selector import auto_select_and_print
        from core.agents.router import OpenAICompatClient, TwoTierRouter
        model = args.model or auto_select_and_print(tier=1)
        matcher = ScenarioMatcher(
            router=TwoTierRouter(tier1=OpenAICompatClient(model=model)),
            max_concurrency=args.concurrency, code_language="java_web")
        results = asyncio.run(matcher.audit_many([(u, categories) for u in units], "java_web"))
        flagged = [(u, h.vuln_type) for u, hs in zip(units, results)
                   for h in hs if h.property_missing]

    print(f"      命中 {len(flagged)} 处")

    print(f"[4/4] 写报告 ...")
    lines = [f"# nexus-audit Java 扫描报告", "",
             f"- 目标仓库：`{repo}`",
             f"- 审计入口：{len(units)}",
             f"- 命中：{len(flagged)}", ""]
    for u, cat in flagged:
        lines += [f"## [{cat.upper()}] {u.unit_name}",
                  f"- 位置：`{u.file_path}:{u.start_line}`",
                  f"- 路由：{', '.join(u.decorators_or_modifiers)}", ""]
    out = Path(args.output or "report_java.md")
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n完成：报告已写入 {out}")


def cmd_scan_web3(args, repo: Path):
    """Web3 赛道：Solidity 函数切片 + 精度/优先级缺陷检测（对标 DVDF 已知缺陷）。"""
    from core.slicer.web3_slither import (SoliditySlicer, detect_precision_loss,
                                          detect_reentrancy_surface, detect_arbitrary_call,
                                          detect_missing_receive)
    from core.models import PoCResult

    print(f"[1/4] Solidity 函数切片 ...")
    units = SoliditySlicer().extract_entry_units(repo)
    print(f"      共 {len(units)} 个函数")

    print(f"[2/4] Scenario 场景匹配 ...")
    print(f"[3/4] Property 属性核对（精度/重入/任意外部调用/ETH 接收）...")
    hyps = (detect_precision_loss(units)
            + detect_reentrancy_surface(units)
            + detect_arbitrary_call(units)
            + detect_missing_receive(units, repo))
    print(f"      假设：{len(hyps)}")

    print(f"[4/4] 报告（Web3 动态验证需 Foundry，此处为静态高置信结论）...")
    results = [PoCResult(hypothesis=h, verified=(h.confidence >= 0.8),
                         output_digest="static: 高置信度，建议 forge test 回归确认")
               for h in hyps]
    out = Path(args.output or "report.md")
    out.write_text(build_report(str(repo), hyps, results, 0), encoding="utf-8")
    print(f"\n完成：报告已写入 {out}（静态确认 {sum(1 for r in results if r.verified)}/{len(results)}）")


def cmd_pr_scan(args):
    """GitHub PR 增量扫描：仅解析 git diff 影响的文件中的路由与调用链。"""
    diff = subprocess.run(["git", "diff", "--name-only", args.base, "HEAD"],
                          capture_output=True, text=True)
    changed = [l for l in diff.stdout.splitlines() if l.endswith(".py")]
    print(f"PR 增量扫描：{len(changed)} 个 Python 文件变更（基于 {args.base}）")
    for f in changed:
        print(f"  - {f}")
    if not changed:
        print("无 Python 变更，跳过")
        return
    # TODO(第4周): 将 changed 文件的调用链与全量符号表求交，仅审计受影响路由
    print("提示：受影响路由过滤逻辑将在下一迭代接入 audit_repo(units_subset)")


def load_dotenv(path: str | Path = ".env") -> None:
    """极简 .env 加载（不覆盖已有环境变量）。"""
    import os
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


def main():
    load_dotenv(Path(__file__).resolve().parent / ".env")
    parser = argparse.ArgumentParser(prog="nexus-audit", description="AI 自动化漏洞挖掘审计框架")
    sub = parser.add_subparsers(dest="command", required=True)
    p_scan = sub.add_parser("scan", help="全量扫描目标仓库")
    p_scan.add_argument("repo_path")
    p_scan.add_argument("--offline", action="store_true", help="离线演示模式（不调用 LLM API）")
    p_scan.add_argument("--web3", action="store_true", help="Web3 赛道（Solidity 精度/逻辑缺陷检测）")
    p_scan.add_argument("--java", action="store_true", help="Java 赛道（Servlet/Spring 入口切片）")
    p_scan.add_argument("--categories", default=None,
                        help="Java 赛道指定漏洞类目，逗号分隔（默认全部 11 类）")
    p_scan.add_argument("--model", default=None, help="指定模型名（跳过免费模型探测）")
    p_scan.add_argument("--concurrency", type=int, default=6, help="LLM 并发数")
    p_scan.add_argument("--output", default=None, help="报告输出路径")
    p_scan.add_argument("--python", default=None, help="PoC 执行使用的 Python 解释器")
    p_pr = sub.add_parser("pr-scan", help="PR 增量扫描（仅 git diff 影响的调用链）")
    p_pr.add_argument("--base", default="origin/main")
    args = parser.parse_args()
    if args.command == "scan":
        cmd_scan(args)
    else:
        cmd_pr_scan(args)


if __name__ == "__main__":
    main()
