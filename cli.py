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
import os
import re
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
    ran = sum(1 for r in poc_results if r.sandbox_ran)
    confirmed = sum(1 for r in poc_results if r.sandbox_ran and r.verified)
    static_only = sum(1 for r in poc_results if not r.sandbox_ran and r.verified)
    lines = [f"# nexus-audit 扫描报告", "",
             f"- 目标仓库：`{repo}`",
             f"- 初筛漏洞假设：{len(hypotheses)}",
             f"- 沙箱验证确认：{confirmed}",
             # 没跑沙箱的高置信假设必须单独列出。混进"确认"是冒充验证结果，
             # 完全不计又是漏报 —— 两者都会让读者对"到底验证过没有"产生误判。
             f"- 静态高危候选（未跑沙箱）：{static_only}"
             + ("（本赛道未执行 make test / forge test，需人工或 CI 复核）"
                if static_only else ""), ""]
    for r in poc_results:
        h = r.hypothesis
        # 状态必须区分"跑过沙箱"和"没跑过沙箱"。
        #
        # 早期版本只有两档（verified / 未verified），而 Web3 赛道根本不跑
        # Foundry，`verified` 是由静态置信度推出来的。结果报告里出现
        # "✔ 已复现（高危）"—— 从未执行过任何 PoC 的静态猜测被冒充成
        # 验证过的漏洞，比漏报更危险。现在把三种状态分开写。
        if not r.sandbox_ran:
            status = ("⚠ 静态高危候选（待 forge 验证）" if r.verified
                      else "⚠ 静态低置信度候选（未验证）")
        else:
            status = "✔ 已复现（沙箱确认）" if r.verified else "✘ 未复现（沙箱已执行）"
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
    # 把展开到的跨文件实现**写回切片**，否则下一步的 audit_repo 拿到的还是
    # 未展开的原切片 —— 模型看不到被调用方法的内部实现，只能靠猜。
    # run_context_loop 只负责返回 context_blocks，回写是调用方的责任。
    by_name = {u.unit_name: u for u in units}
    expanded = 0
    for rec in ctx:
        u = by_name.get(rec["unit"])
        if not u:
            continue
        blocks = [b for b in rec.get("context_blocks", [])
                  if b.get("role") == "expansion" and "未找到符号" not in (b.get("source") or "")]
        if not blocks:
            continue
        extra = ["", "// ---- 跨文件上下文（按需展开） ----"]
        for b in blocks:
            extra.append(f"// [{b['symbol']}]")
            extra.extend("//   " + ln for ln in (b["source"] or "").splitlines())
        u.source_code += "\n".join(extra)
        expanded += 1
    print(f"      已回写 {expanded} 个入口的跨文件实现")

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


def emit_github_annotations(flagged, failed, repo: Path) -> int:
    """向 stdout 输出 GitHub Actions 行级 annotation，返回输出条数。

    格式：`::warning file={path},line={n},title={cat}::{msg}`
    GitHub 会把这条挂到 PR 的 Files Changed 里对应代码行下方 —— 这是审阅者
    真正会看到的位置，比让人去翻 CI 日志有效得多。

    只在 `GITHUB_ACTIONS` 环境下输出：本地跑时一堆 `::` 行会淹没正常输出。
    路径必须转成相对仓库根，否则 GitHub 对不上文件（它按仓库相对路径索引）。
    """
    if not os.environ.get("GITHUB_ACTIONS"):
        return 0
    n = 0
    for u, cat in flagged:
        try:
            rel = Path(u.file_path).resolve().relative_to(repo.resolve()).as_posix()
        except ValueError:
            rel = Path(u.file_path).as_posix()
        # annotation 的消息体不能有裸换行（会截断），逗号和冒号要转义
        msg = f"可能存在 {cat.upper()}；入口 {u.unit_name}".replace("\n", " ")
        msg = msg.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::warning file={rel},line={u.start_line},title={cat.upper()}::{msg}")
        n += 1
    for u, cat in failed:
        try:
            rel = Path(u.file_path).resolve().relative_to(repo.resolve()).as_posix()
        except ValueError:
            rel = Path(u.file_path).as_posix()
        print(f"::error file={rel},line={u.start_line},title=判定失败::"
              f"{cat.upper()} 判定失败（限流/超时），需重跑，不是无漏洞")
        n += 1
    return n


def emit_step_summary(report_path: Path) -> bool:
    """把 Markdown 报告追加到 `$GITHUB_STEP_SUMMARY` 指向的文件。

    这是 GitHub Actions 的原生能力：往那个文件写 Markdown，PR 页面就会多出
    一张渲染好的看板，**不需要任何 Token 权限**。比"把报告塞进 artifact
    让人下载"体验好得多，也比调 GitHub API 发评论少一层授权麻烦。

    注意是**追加**：同一个 job 里多个步骤都可以往里写，各自成一段。
    """
    p = os.environ.get("GITHUB_STEP_SUMMARY")
    if not p:
        return False
    try:
        body = Path(report_path).read_text(encoding="utf-8")
    except OSError:
        return False
    with open(p, "a", encoding="utf-8") as f:
        f.write("\n\n---\n\n" + body + "\n")
    return True


def cmd_scan_java(args, repo: Path):
    """Java Web 赛道：Servlet/Spring 入口切片 + 按漏洞类目两步法。"""
    from core.agents.vuln_categories import OWASP_KEYS
    from core.agents.scenario_matcher import ScenarioMatcher
    from core.slicer.java_servlet import JavaSlicer

    # 默认只跑 OWASP 的 11 类，避免对每个入口 × 全部类目做 N×M 次模型调用；
    # 真实项目需覆盖 SSRF/XXE/表达式注入等，用 --categories 显式指定。
    categories = [c.strip() for c in args.categories.split(",")] if args.categories else OWASP_KEYS

    print(f"[1/4] Java 入口切片 ...")
    preset = getattr(args, "_units", None)
    if preset is not None:
        units = preset
        print(f"      使用 PR 增量受影响子集，共 {len(units)} 个入口")
    else:
        units = JavaSlicer(repo).extract_entry_units()
        # 同一用例的 doGet 只是转发，保留 doPost 即可，避免重复计费
        units = [u for u in units if not u.unit_name.endswith(".doGet")]
        print(f"      共 {len(units)} 个入口")
    if not units:
        print("      未发现 Java Web 入口（需 @WebServlet / @GetMapping 等注解）")
        return

    print(f"[2/4] 类目选择：{', '.join(categories)}")
    print(f"[3/4] 两步法初筛（规则前置 + 并发 {args.concurrency}）...")

    from core.agents.rule_detectors import verdict as rule_verdict

    # --- 规则前置 ---------------------------------------------------------
    # 凡客观可判定的（用了哪个算法 / 哪个 Context / ACAO 取值 / 反序列化白名单），
    # 先由确定性规则给结论，模型只处理剩余部分。
    # 理由见 core/agents/rule_detectors.py 顶部：模型在这些"事实题"上会摇摆，
    # 而摇摆无法靠补充上下文纠正。
    decided: dict[tuple[str, str], bool] = {}     # (unit_name, cat) -> bool
    pending: list[tuple] = []
    for u in units:
        for c in categories:
            v = rule_verdict(c, u.source_code)
            if v is None:
                pending.append((u, c))
            else:
                decided[(u.unit_name, c)] = v
    print(f"      规则直接判定 {len(decided)} 项，余 {len(pending)} 项交模型")

    failed: list[tuple] = []          # 调用失败，必须与"判为无漏洞"区分
    model_flagged: list[tuple] = []
    if pending and args.offline:
        from benchmarks.offline_baseline import offline_predict
        model_flagged = [(u, c) for u, c in pending if offline_predict(u.source_code, c)]
    elif pending:
        from core.agents.model_selector import auto_select_and_print
        from core.agents.router import OpenAICompatClient, TwoTierRouter
        model = args.model or auto_select_and_print(tier=1)
        matcher = ScenarioMatcher(
            router=TwoTierRouter(tier1=OpenAICompatClient(model=model)),
            max_concurrency=args.concurrency, code_language="java_web")
        # 按入口聚合待判类目，避免同一入口被拆成多次调用
        by_unit: dict[str, tuple] = {}
        for u, c in pending:
            prev = by_unit.get(u.unit_name)
            by_unit[u.unit_name] = (u, [c]) if prev is None else (u, prev[1] + [c])
        batch = list(by_unit.values())
        results = asyncio.run(matcher.audit_many(batch, "java_web"))
        pairs = {u.unit_name: (u, cs) for u, cs in batch}
        for (u, cs), hs in zip(batch, results):
            if not hs:
                # 空结果 = 该入口所有类目都没走完，视为调用失败而非"无漏洞"
                failed += [(u, c) for c in cs]
                continue
            got = {h.vuln_type for h in hs if h.property_missing}
            model_flagged += [(u, c) for c in cs if c in got]

    flagged = [(u, c) for (name, c), v in decided.items() if v
               for u in units if u.unit_name == name] + model_flagged

    # --- 反方挑刺（Skeptic）-----------------------------------------------
    # 只复核**模型判出来**的命中。规则命中的结论是逐行可核对的事实
    # （算法名、setSecure 调没调、${} vs #{}），让概率型质检员去推翻确定性
    # 结论，等于把规则已经消掉的不确定性重新引进来 —— 方向反了。
    # 这是记忆第 10 条的直接应用：能规则化的场合不要用抽样/复核去兜。
    skeptic_rejected: list[tuple] = []
    if model_flagged and not args.no_skeptic:
        from core.models import VulnHypothesis
        from core.agents.skeptic_reviewer import SkepticReviewer

        hyps = [VulnHypothesis(unit=u, vuln_type=c, scenario_hit=True,
                               property_missing="见扫描结论",
                               reasoning_summary=f"两步法初筛命中 {c}")
                for u, c in model_flagged]
        if args.offline:
            reviewer = SkepticReviewer(
                llm=lambda p: '{"rejected": false, "reason": "offline 模式默认放行"}')
        else:
            from core.agents.router import TwoTierRouter
            reviewer = SkepticReviewer(router=TwoTierRouter())
        kept_h = asyncio.run(reviewer.filter_false_positives(hyps))
        kept_pairs = {(h.unit.unit_name, h.vuln_type) for h in kept_h}
        skeptic_rejected = [(u, c) for u, c in model_flagged
                            if (u.unit_name, c) not in kept_pairs]
        # 被推翻的从命中里剔除，但**单独列出**：静默删掉会让"漏报"和
        # "被判定为误报"无法区分，事后无从审计复核质量。
        model_flagged = [(u, c) for u, c in model_flagged
                         if (u.unit_name, c) in kept_pairs]
        flagged = [(u, c) for (name, c), v in decided.items() if v
                   for u in units if u.unit_name == name] + model_flagged
        print(f"      反方挑刺：推翻 {len(skeptic_rejected)} 项，保留 {len(model_flagged)} 项")

    print(f"      命中 {len(flagged)} 处")
    if failed:
        print(f"      [警告] {len(failed)} 项判定失败（不计为无漏洞，需重跑）："
              f"{', '.join(f'{u.unit_name}:{c}' for u, c in failed[:5])}"
              f"{' ...' if len(failed) > 5 else ''}")

    print(f"[4/4] 写报告 ...")
    lines = [f"# nexus-audit Java 扫描报告", "",
             f"- 目标仓库：`{repo}`",
             f"- 审计入口：{len(units)}",
             f"- 规则直接判定：{len(decided)} 项（命中 {sum(decided.values())}）",
             f"- 交模型判定：{len(pending)} 项（命中 {len(model_flagged)}）",
             f"- 反方挑刺推翻：{len(skeptic_rejected)} 项"
             + ("（仅复核模型命中；规则命中为确定性事实，不经复核）"
                if skeptic_rejected else ""),
             f"- **判定失败：{len(failed)} 项**" if failed else "- 判定失败：0",
             f"- 命中：{len(flagged)}", ""]
    for u, cat in flagged:
        lines += [f"## [{cat.upper()}] {u.unit_name}",
                  f"- 位置：`{u.file_path}:{u.start_line}`",
                  f"- 路由：{', '.join(u.decorators_or_modifiers)}", ""]
    if failed:
        lines += ["## 判定失败（需重跑，不是无漏洞）", ""]
        for u, c in failed:
            lines.append(f"- `{u.unit_name}` / {c} @ `{u.file_path}:{u.start_line}`")
    out = Path(args.output or "report_java.md")
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n完成：报告已写入 {out}")

    # CI 集成：只在 GitHub Actions 里生效，本地跑是 no-op
    if getattr(args, "github_comment", False):
        n = emit_github_annotations(flagged, failed, repo)
        summed = emit_step_summary(out)
        if n:
            print(f"      已输出 {n} 条 GitHub 行级 annotation")
        if summed:
            print(f"      已追加到 $GITHUB_STEP_SUMMARY（PR 页面会渲染成看板）")
        if not n and not summed:
            print("      [提示] 未检测到 GITHUB_ACTIONS / GITHUB_STEP_SUMMARY，"
                  "GitHub 输出已跳过（本地运行时属正常）")


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
    # sandbox_ran=False：本赛道不跑 Foundry，verified 只是静态置信度的阈值化，
    # 不能当作"已复现"。报告侧据此渲染成"静态高危候选（待 forge 验证）"。
    results = [PoCResult(hypothesis=h, verified=(h.confidence >= 0.8),
                         sandbox_ran=False,
                         output_digest="static: 未执行 forge test，仅静态推断")
               for h in hyps]
    out = Path(args.output or "report.md")
    out.write_text(build_report(str(repo), hyps, results, 0), encoding="utf-8")
    print(f"\n完成：报告已写入 {out}（静态高危候选 {sum(1 for r in results if r.verified)}/{len(results)}，"
          f"均未执行 forge test）")


def cmd_pr_scan(args):
    """PR 增量扫描：只审计受 git diff 影响的路由。

    为什么不能只列文件名：一个 `SecurityUtil.checkURL()` 的改动会影响所有
    调用它的路由，而调用关系是**反向**的（改的是被调方，风险在调用方）。
    所以这里做三件事：
      1. 从 diff 取出变更文件与变更函数名
      2. 在全量切片里找"直接位于变更文件中的入口"（hot）
      3. 再找"调用了变更函数的入口"（dependent）—— 这是漏报最容易发生的地方

    注意：只扫 `.py` 是旧实现的遗留限制，Java 赛道同样要覆盖，否则改了
    Controller 却报"无变更，跳过"。
    """
    repo = Path(args.repo or ".").resolve()
    # git 命令必须在**被审计仓库**里执行。否则 `--repo /tmp/target`
    # 会读到当前工作目录（引擎自己）的 diff，把引擎改动当成目标仓库变更 ——
    # 实测就是这么误报的。
    diff = subprocess.run(["git", "-C", str(repo), "diff", "--name-only",
                           args.base, "HEAD"],
                          capture_output=True, text=True)
    if diff.returncode != 0:
        print(f"[!] git diff 失败：{diff.stderr.strip()[:200]}")
        print(f"    检查 `{repo}` 是否为 git 仓库、`{args.base}` 是否存在"
              f"（可用 --base HEAD~1 或具体 commit）")
        return
    changed = [l.strip() for l in diff.stdout.splitlines() if l.strip()]
    code_exts = (".py", ".java", ".kt", ".go", ".js", ".ts", ".sol")
    changed = [f for f in changed if f.endswith(code_exts)]
    print(f"PR 增量扫描：{len(changed)} 个代码文件变更（基于 {args.base}）")
    for f in changed:
        print(f"  - {f}")
    if not changed:
        print("无代码变更，跳过")
        return

    # 变更函数名：用 diff 里被改动的行反推所属方法，避免整文件当成变更面
    funcs = _changed_symbols(repo, args.base, changed)
    if funcs:
        print(f"  涉及的函数/方法：{', '.join(sorted(funcs)[:12])}"
              f"{' ...' if len(funcs) > 12 else ''}")

    repo = Path(args.repo or ".")
    units = _slice_for_pr(repo, args.language)
    if not units:
        print("未发现在支持的赛道上可切的入口，跳过")
        return
    # 防呆：如果切出来几千个入口，说明 repo 指到了引擎自己或巨型仓库，
    # 这时"受影响子集"的判定没有意义（引擎代码不是被审计目标）。
    if len(units) > 2000:
        print(f"[!] {repo} 切出 {len(units)} 个入口，疑似指向了引擎自身或过大的仓库。"
              f"请用 --repo 指定**被审计的业务仓库**。")
        return
    print(f"  全量入口 {len(units)} 个，开始求受影响子集 ...")

    hot, dependent = [], []
    changed_set = {str(Path(f).as_posix()) for f in changed}

    # 精确到"变更行落在哪个方法里"。只按文件判定会把同文件的所有路由
    # 都算成受影响 —— Cors.java 里改 vuls2 一行，9 个路由全被拉进来，
    # 增量扫描就退化成全量扫描了。
    changed_methods = _changed_methods_of(repo, args.base, changed)

    # 所有被改动的方法名（跨文件合并），供反向依赖使用。
    # 注意不能只用 _changed_symbols()：它从 diff 文本抓签名，改动内容是
    # `// patched` 这种注释时抓不到任何签名。_changed_methods_of() 是按
    # 行号反查所属方法，更可靠，两者取并集。
    changed_funcs: set[str] = set()
    for v in changed_methods.values():
        changed_funcs |= (v or set())
    changed_funcs |= funcs

    for u in units:
        up = str(u.file_path).replace("\\", "/")
        match_file = next((c for c in changed_set if up.endswith(c) or c.endswith(up)), None)
        if match_file:
            meths = changed_methods.get(match_file)
            if meths is None:
                hot.append(u)          # 拿不到方法级信息，退回文件级（宁多不漏）
                continue
            if u.unit_name.split(".")[-1] in meths:
                hot.append(u)
            continue
        # 2) 入口调用了变更函数 —— 反向依赖。
        #    这是增量扫描真正的价值所在：改一个 SecurityUtil.checkURL，
        #    所有调用它的路由都可能受影响，而改动文件本身一个入口都没有。
        called = set(getattr(u, "called_symbols", []) or [])
        if changed_funcs and called & changed_funcs:
            dependent.append(u)

    # 3) 装配级反向依赖：改动的函数被某个 Filter / Interceptor / CorsProcessor
    #    调用，而该组件作用于一批路由 —— 这些路由全部受影响。
    #    只做方法级调用链会漏掉这一层：改 SecurityUtil.checkURL，入口直接调它的
    #    只有 4 条，但 OriginFilter / ReferFilter / CustomCorsProcessor 都调它，
    #    它们保护的路由同样受影响，而这层关系只存在于框架装配里。
    wired = _wiring_dependents(repo, changed_funcs, units, {u.unit_name for u in hot + dependent})
    dependent += wired

    print(f"  直接变更的入口 {len(hot)} 个；反向依赖命中 {len(dependent)} 个")

    subset = hot + dependent
    if not subset:
        print("无受影响路由，本次 PR 无需审计")
        return

    if args.dry_run:
        lines = ["# PR 增量扫描：受影响路由（dry-run）", "",
                 f"- 基线：`{args.base}`",
                 f"- 变更文件：{len(changed)}",
                 f"- 受影响入口：{len(subset)}", ""]
        for u in hot:
            lines.append(f"- [变更文件] `{u.unit_name}` @ `{u.file_path}:{u.start_line}`")
        for u in dependent:
            lines.append(f"- [反向依赖] `{u.unit_name}` @ `{u.file_path}:{u.start_line}`")
        out = Path(args.output or "report_pr.md")
        out.write_text("\n".join(lines), encoding="utf-8")
        print(f"\n完成（dry-run）：受影响路由已写入 {out}")
        return

    # 真正进入审计：复用 scan 的规则前置 + 模型两步法
    ns = argparse.Namespace(
        repo_path=str(repo), offline=args.offline, web3=False, java=True,
        categories=args.categories, model=args.model, concurrency=args.concurrency,
        output=args.output or "report_pr.md", python=None, _units=subset,
        no_skeptic=getattr(args, "no_skeptic", False),
        github_comment=getattr(args, "github_comment", False))
    print("\n进入审计（仅上述受影响路由）...")
    cmd_scan_java(ns, repo)


def _changed_symbols(repo: Path, base: str, files: list[str]) -> set[str]:
    """从 diff 的新增/删除行里反推被改动的函数名。

    不做完整语法解析，只抓"变更行附近最近的方法签名"。够用于
    「这次改动影响了哪些方法」这种粗粒度判断；误报方向是多抓，
    宁可多审计一个入口也不要漏。"""
    funcs: set[str] = set()
    for f in files:
        r = subprocess.run(["git", "-C", str(repo), "diff", "-U15", base, "HEAD", "--", f],
                           capture_output=True, text=True)
        if r.returncode != 0:
            continue
        for ln in r.stdout.splitlines():
            if not ln.startswith(("+", "-")) or ln.startswith(("+++", "---")):
                continue
            s = ln[1:]
            for pat in (
                r"\bdef\s+(\w+)\s*\(",                        # python
                r"\b(?:public|private|protected)\s[\w<>\[\],\s]+\s+(\w+)\s*\(",  # java
                r"\bfunction\s+(\w+)\s*\(",                   # solidity/js
                r"\bfunc\s+(?:\([^)]*\)\s*)?(\w+)\s*\(",      # go
            ):
                for m in re.finditer(pat, s):
                    if m.group(1) not in {"if", "for", "while", "switch", "catch"}:
                        funcs.add(m.group(1))
    return funcs


_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", re.M)
_METHOD_SIG_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|abstract|synchronized|native)\s+)*"
    r"(?:[\w<>\[\],.?\s]+\s+)?(\w+)\s*\([^;{]*\)\s*(?:throws\s+[\w.,\s]+)?\{",
    re.M)


def _changed_methods_of(repo: Path, base: str, files: list[str]) -> dict[str, set[str] | None]:
    """返回 {变更文件相对路径: 受影响的函数名集合}；None 表示解析不出、退回文件级。

    做法：解析 unified diff 的 hunk 头拿到"变更起点在新文件中的行号"，
    再在**当前工作区文件**里查这一行落在哪个方法体内。
    之所以不靠 diff 的上下文行抓签名：`+int patched = 1;` 这种改动
    周围 3 行内可能一个签名都没有，抓不到就只能退回文件级，
    结果一个文件的全部路由都被当成受影响。
    """
    out: dict[str, set[str] | None] = {}
    for f in files:
        r = subprocess.run(["git", "-C", str(repo), "diff", "-U3", base, "HEAD", "--", f],
                           capture_output=True, text=True)
        if r.returncode != 0:
            out[f] = None
            continue
        starts = _added_line_numbers(r.stdout)
        if not starts:
            out[f] = None
            continue
        try:
            src = (repo / f).read_text(encoding="utf-8", errors="replace")
        except OSError:
            out[f] = None
            continue
        names: set[str] = set()
        ok = False
        for ln in starts:
            n = _method_at_line(src, ln)
            if n:
                names.add(n)
                ok = True
        out[f] = names if ok else None
    return out


def _method_at_line(src: str, line_no: int) -> str | None:
    """找出第 line_no 行（1-based）属于哪个方法。

    从该行**往前**扫，用花括号收支判断"什么时候走出了方法体"：
    向前看时，`}` 表示"我在这个块外面"（+1），`{` 表示"我进了这个块"（-1）。
    当收支回到 <=0 时遇到的第一个方法签名，就是所属方法。
    这个方向不能反：反过来会让上一行的方法（vuls1）把下一行抢走。
    """
    lines = src.splitlines()
    if not (1 <= line_no <= len(lines)):
        return None
    depth = 0
    for i in range(min(line_no, len(lines)) - 1, -1, -1):
        s = lines[i]
        # 先看签名（当前行就是签名行时 depth 才是 0），再更新收支
        m = _METHOD_SIG_RE.match(s)
        if m and depth <= 0:
            name = m.group(1)
            if name not in {"if", "for", "while", "switch", "catch",
                            "synchronized", "try", "else"}:
                return name
        depth += s.count("}") - s.count("{")
        if depth < -2:
            break
    return None


def _wiring_dependents(repo: Path, changed_funcs: set[str], units, already: set[str]) -> list:
    """找出受"被改动的全局组件"影响的入口。

    路径：变更函数 → 哪个 Filter/Processor 调了它 → 该组件作用于哪些 URL
         → 这些 URL 对应的入口。
    用 framework_wiring 的 URL→组件映射做反查，避免再造一套 Filter 解析。
    """
    if not changed_funcs:
        return []
    try:
        from core.context.framework_wiring import FrameworkWiringResolver
    except Exception:
        return []
    try:
        fw = FrameworkWiringResolver(repo)
        comps = fw.wiring
    except Exception:
        return []

    # 哪些组件的代码里调用了变更函数
    dirty = []
    for w in comps:
        body = getattr(w, "body", "") or ""
        if not body:
            continue
        if any(re.search(rf"\b{re.escape(f)}\s*\(", body) for f in changed_funcs):
            dirty.append(w)
    if not dirty:
        return []

    # 每个入口的路由 → 是否被 dirty 组件覆盖
    out = []
    # 把"作用于全部路由"的组件单独摘出来：它一旦命中，受影响的确实是全部路由，
    # 但那不是"精确增量"，而应提示走全量回归。同时**不能**因此丢弃
    # 其它精确组件的命中 —— 否则 CustomCorsProcessor 那一条就白算了。
    global_comps = [w.name for w in dirty
                    if any(p in ("/*", "/**", "*", "**") for p in (w.url_patterns or []))]
    precise = [w for w in dirty if w.name not in global_comps]

    for u in units:
        if u.unit_name in already:
            continue
        url = _route_of_unit(u)
        if not url:
            continue
        if any(_ant_match_simple(p, url) for w in precise for p in (w.url_patterns or [])):
            out.append(u)

    if global_comps:
        print(f"  [提示] 改动同时命中全局组件 {', '.join(sorted(set(global_comps)))}"
              f"（urlPatterns=/*），理论上影响全部路由；"
              f"上方只列出精确命中的 {len(out)} 条，建议对全局组件覆盖范围做全量回归。")
    return out


def _route_of_unit(u) -> str:
    """取出**完整**路由 = 类级 @RequestMapping 前缀 + 方法级路径。

    必须带类前缀：framework_wiring 里的 urlPatterns 是完整 URL
    （`/cors/sec/httpCors`），而切片里 annotations 只记方法级路径
    （`/sec/httpCors`）。不拼前缀就永远匹配不上，装配级反向依赖全部失效。
    """
    route = (u.decorators_or_modifiers[0] if getattr(u, "decorators_or_modifiers", None) else "")
    m = re.search(r'"([^"]*)"', route)
    method_path = m.group(1) if m else ""

    prefix = ""
    try:
        lines = Path(u.file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
        # 先定位**类声明行**，再往上找它的注解。
        # 直接向上扫 @RequestMapping 会拿到上一个方法的注解：
        # Cors.java 里 `@RequestMapping("/sec/corsFilter")` 就在相邻方法上，
        # 结果拼出 `/sec/corsFilter/sec/checkOrigin` 这种不存在的路由。
        cls_line = None
        for i in range(min(u.start_line - 1, len(lines)) - 1, -1, -1):
            if re.search(r"^\s*(?:public\s+|final\s+|abstract\s+)*(?:class|interface|enum)\s+\w+",
                         lines[i]):
                cls_line = i
                break
        if cls_line is not None:
            for i in range(cls_line, max(cls_line - 12, -1), -1):
                cm = re.search(r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?"([^"]*)"', lines[i])
                if cm:
                    prefix = cm.group(1)
                    break
    except (OSError, AttributeError):
        pass

    if not prefix:
        return method_path
    if not method_path:
        return prefix
    return prefix.rstrip("/") + "/" + method_path.lstrip("/")


def _ant_match_simple(pattern: str, url: str) -> bool:
    """轻量 ant 匹配，与 framework_wiring._ant_match 语义一致（宁多不少）。"""
    import fnmatch
    if pattern in ("/*", "/**", "*", "**"):
        return True
    if pattern == url:
        return True
    rx = re.escape(pattern).replace(r"\*\*", "\x00").replace(r"\*", "[^/]*")
    rx = rx.replace("\x00", ".*")
    return re.fullmatch(rx, url) is not None


def _added_line_numbers(diff_text: str) -> list[int]:
    """从 unified diff 里取出所有**新增/删除行**在新文件中的行号。

    必须逐行跟踪，不能只用 hunk 头。hunk 头 `@@ -32,6 +32,7 @@` 的 `+32`
    是**上下文起始行**，真正被改的那一行可能是 32+3=35。
    只听 hunk 头会落到上一个方法末尾的空白行上，方法定位直接失效 ——
    实测就是这样把 vuls2 的改动算到了 vuls1 头上。
    """
    out: list[int] = []
    cur, in_hunk = 0, False
    for ln in diff_text.splitlines():
        m = _HUNK_RE.match(ln)
        if m:
            cur, in_hunk = int(m.group(1)), True
            continue
        if not in_hunk or ln.startswith(("+++", "---")):
            continue
        if ln.startswith("+"):
            out.append(cur)
            cur += 1
        elif ln.startswith("-"):
            out.append(cur)          # 删除行在当前游标处生效
        elif ln[:1] in (" ", ""):
            cur += 1
        else:
            in_hunk = False
    return out


def _slice_for_pr(repo: Path, language: str):
    """按语言选切片器；auto 时先试 Java 再试 Python。"""
    lang = (language or "auto").lower()
    units = []
    if lang in ("auto", "java"):
        try:
            from core.slicer.java_servlet import JavaSlicer
            units = JavaSlicer(repo).extract_entry_units()
        except Exception:
            units = []
    if not units and lang in ("auto", "py", "python"):
        try:
            from core.slicer.flask_routes import FlaskRouteSlicer
            units = FlaskRouteSlicer().extract_entry_units(repo)
        except Exception:
            units = []
    return units


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
    p_scan.add_argument("--no-skeptic", action="store_true",
                        help="跳过反方挑刺复核（仅影响模型命中，规则命中不受影响）")
    p_scan.add_argument("--github-comment", dest="github_comment", action="store_true",
                        help="输出 GitHub Actions 行级 annotation + 写入 $GITHUB_STEP_SUMMARY")
    p_scan.add_argument("--output", default=None, help="报告输出路径")
    p_scan.add_argument("--python", default=None, help="PoC 执行使用的 Python 解释器")
    p_pr = sub.add_parser("pr-scan", help="PR 增量扫描（仅 git diff 影响的调用链）")
    p_pr.add_argument("--base", default="origin/main", help="diff 基线，如 origin/main 或 HEAD~1")
    p_pr.add_argument("--repo", default=".", help="仓库根目录（默认当前目录）")
    p_pr.add_argument("--language", default="auto", choices=["auto", "java", "python"],
                      help="目标语言；auto 时先试 Java 再试 Python")
    p_pr.add_argument("--categories", default=None,
                      help="漏洞类目，逗号分隔（默认 OWASP 11 类）")
    p_pr.add_argument("--model", default=None, help="指定模型名")
    p_pr.add_argument("--concurrency", type=int, default=4, help="LLM 并发数")
    p_pr.add_argument("--offline", action="store_true", help="离线模式（不调用 LLM）")
    p_pr.add_argument("--github-comment", dest="github_comment", action="store_true",
                      help="输出 GitHub Actions 行级 annotation + 写入 $GITHUB_STEP_SUMMARY")
    p_pr.add_argument("--dry-run", action="store_true",
                      help="只列出受影响路由，不做审计")
    p_pr.add_argument("--output", default=None, help="报告输出路径")
    args = parser.parse_args()
    if args.command == "scan":
        cmd_scan(args)
    else:
        cmd_pr_scan(args)


if __name__ == "__main__":
    main()
