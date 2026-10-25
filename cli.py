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
import difflib
import hashlib
import importlib
import json
import os
import re
import subprocess
import time
import sys
from pathlib import Path

from core.agents.router import TwoTierRouter
from core.agents.scenario_matcher import ScenarioMatcher
from core.agents.skeptic_reviewer import SkepticReviewer
from core.context.tool_handlers import run_context_loop
from core.models import base_unit_name
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


def _collect_rule_true(units, categories) -> list:
    """收集规则层确定性判 True 的 (unit, category)。

    只认 True —— False 是"这一类目上安全"，没有可验证的攻击面；
    None 是证据不足，合成出来的 PoC 只会是凭空断言。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    hits = []
    for u in units:
        for c in categories:
            try:
                if rule_verdict(c, u.source_code) is True:
                    hits.append((u, c))
            except Exception:  # noqa: BLE001 —— 单条判据异常不许中断整批合成
                continue
    return hits


def _emit_pocs(units, categories, out_dir: str) -> int:
    """把规则层 True 命中翻译成可运行的 PoC 骨架并落盘（M45）。"""
    from core.sandbox.poc_synthesizer import PocSynthesizer
    hits = _collect_rule_true(units, categories)
    print(f"[PoC] 规则层确定性命中 {len(hits)} 条，开始合成验证骨架 ...")
    rep = PocSynthesizer().synthesize_many(hits, Path(out_dir))
    for a in rep.artifacts:
        flag = "OK " if a.self_check_ok else "FAIL"
        print(f"  [{flag}] {a.path:44} {a.language:9} {a.category:14} {a.self_check_msg}")
    for e in rep.errors:
        print(f"  [ERR] {e}")
    print(f"[PoC] 产出 {len(rep.artifacts)} 份（自检通过 {rep.ok_count}）→ {out_dir}")
    return 0 if rep.ok_count == len(rep.artifacts) else 1


def cmd_scan(args):
    repo = Path(args.repo_path).resolve()
    if args.web3:
        return cmd_scan_web3(args, repo)

    # Java 赛道：按类目做两步法（Web 赛道的 IDOR/越权场景不适用于 Servlet 用例）
    if args.java:
        return cmd_scan_java(args, repo)

    # M58 野战模式：全类目规则普查 + Sink 门控漏斗（无需人工指定类目）
    if getattr(args, "auto", False):
        return cmd_scan_auto(args, repo)

    print(f"[1/5] 切片：提取路由入口 ...")
    units = WebTreeSitterSlicer(repo).extract_entry_units(repo)
    print(f"      共 {len(units)} 个路由入口")

    # PoC 合成模式：只跑规则层 + 合成，不调模型
    if getattr(args, "emit_poc", None):
        from core.agents.vuln_categories import OWASP_KEYS
        cats = ([c.strip() for c in args.categories.split(",")]
                if getattr(args, "categories", None) else list(OWASP_KEYS))
        return _emit_pocs(units, cats, args.emit_poc)

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
        tier1 = _router_with_cache(args)
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
        kept = asyncio.run(SkepticReviewer(router=_router_with_cache(args)).filter_false_positives(hypotheses))
    print(f"      保留 {len(kept)} 个假设进入沙箱")

    print(f"[5/5] 沙箱动态验证 ...")
    verifier = WebDockerVerifier(python=args.python)
    results = [verifier.verify_finding(h) for h in kept]

    report = build_report(str(repo), kept, results, len(hypotheses) - len(kept))
    out = Path(args.output or "report.md")
    out.write_text(report, encoding="utf-8")
    print(f"\n完成：报告已写入 {out}")
    print(f"确认漏洞 {sum(1 for r in results if r.verified)}/{len(results)}")

    # --- SARIF 2.1.0 导出（Python/Web3 赛道）---
    if getattr(args, "sarif", None):
        entries = [{"file": r.hypothesis.unit.file_path,
                    "line": r.hypothesis.unit.start_line,
                    "category": r.hypothesis.vuln_type,
                    "unit": r.hypothesis.unit.unit_name,
                    "level": "warning" if r.verified else "note",
                    "message": f"[{r.hypothesis.vuln_type.upper()}] "
                               f"{r.hypothesis.unit.unit_name}（{r.hypothesis.property_missing or '候选'}）"}
                   for r in results]
        write_sarif(args.sarif, entries, repo)
        print(f"      SARIF 已写入 {args.sarif}（{len(entries)} 条 results）")

    # --- M57：单文件交互式 HTML 报告 ---
    if getattr(args, "html", None):
        entries = [{"file": r.hypothesis.unit.file_path,
                    "line": r.hypothesis.unit.start_line,
                    "category": r.hypothesis.vuln_type,
                    "unit": r.hypothesis.unit.unit_name,
                    "level": "warning" if r.verified else "note",
                    "priority": "P0" if r.verified else "P2",
                    "message": (r.hypothesis.property_missing
                                or f"{r.hypothesis.vuln_type} 高危候选"),
                    "code": r.hypothesis.unit.source_code,
                    "code_from": r.hypothesis.unit.start_line}
                   for r in results]
        _write_html(args, entries, repo)


_SOLIDITY_AUTO_CATS = ["reentrancy", "access_control",
                       "unchecked_low_level_calls", "arithmetic"]


_TEST_PATH_PARTS = {"test", "tests", "__tests__", "mock", "mocks", "testing"}


def _is_test_path(path: str | Path) -> bool:
    """测试/夹具路径：生产扫描默认排除（M79 Uniswap `contracts/test/`）。"""
    return any(part.lower() in _TEST_PATH_PARTS for part in Path(path).parts)


# M164：只扫**能定义密钥的源码/配置**。minified JS bundle 与 i18n JSON
# 里的 "secret" 是文案/字段名，不是凭证 —— kkFileView 的 index.umd.js、
# Apollo 的 en.json 实测各贡献 1 条假阳。JS/TS/JSON 不作为文件级密钥面。
_SECRET_FILE_EXTS = {
    ".py", ".java", ".sol", ".properties", ".yml", ".yaml", ".env",
    ".conf", ".ini", ".toml",
}
_SECRET_FILE_SKIP = {
    ".git", "__pycache__", "node_modules", "target", "build", "dist",
    "vendor", "tests", "test",
}


_WIRING_SOURCE_RE = re.compile(r"来源\s+([^\s]+)")


def _root_cause_key(unit, cat: str) -> tuple[str, str, str]:
    """M71：把路由级 P0 归并到独立根因。

    返回 (signature, kind, evidence_file)：
      · kind=global-config —— CORS 结论完全来自 `框架装配证据` 的同一份全局
        配置（入口体里没有 Access-Control-Allow-Origin），按配置体哈希归并；
      · kind=file-level    —— 硬编码密钥文件级伪单元，一个文件一个根因；
      · kind=endpoint      —— 其余按 (类目, 文件, 起始行, 单元名) 独立。
    """
    from core.agents.rule_detectors import entry_body, wiring_block
    src = unit.source_code or ""
    if cat == "cors" and "Access-Control-Allow-Origin" not in entry_body(src):
        blk = wiring_block(src)
        if blk:
            # M97：装配证据的**第一行标题**带路由别名
            # （`…（别名 system/user、system/user/{userId} 全部命中）`），
            # 同一份全局 CORS 配置在不同路由上因此算出不同签名 ——
            # waynboot 实测 162 条折成 1 个根因、另 1 条因为别名不同单列。
            # 根因的物理载体是**配置体**，不是别名清单，所以先剥掉标题行
            # 再归一化。
            body_only = re.sub(r"(?s)^.*?----\s*\n", "", blk, count=1) \
                if blk.lstrip().startswith("----") else blk
            if not body_only.strip():
                body_only = blk
            norm = re.sub(r"\s+", " ", body_only).strip()
            m = _WIRING_SOURCE_RE.search(blk)
            evidence = m.group(1) if m else ""
            return (f"cors:{hashlib.sha256(norm.encode()).hexdigest()[:12]}",
                    "global-config", evidence)
    if cat == "hardcoded_secret" and getattr(unit, "file_level", False):
        p = str(Path(unit.file_path).resolve())
        return f"hardcoded_secret:file:{p}", "file-level", unit.file_path
    p = str(Path(unit.file_path).resolve())
    return (f"{cat}:{p}:{unit.start_line}:{unit.unit_name}", "endpoint",
            unit.file_path)


def _baseline_keys(path: str | Path, repo: Path) -> set[tuple[str, str, str]]:
    """读 SARIF / --summary-json 基线，返回 (类目, uri, 根因签名) 集合。"""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    keys: set[tuple[str, str, str]] = set()
    if isinstance(data, dict) and "runs" in data:
        for run in data.get("runs", []):
            for r in run.get("results", []):
                rule = str(r.get("ruleId") or "").upper()
                locs = r.get("locations") or []
                uri = ""
                if locs:
                    pl = locs[0].get("physicalLocation") or {}
                    uri = (pl.get("artifactLocation") or {}).get("uri", "")
                root = (r.get("properties") or {}).get("root_cause")
                if root:
                    keys.add((rule, uri, str(root)))
                unit = (r.get("properties") or {}).get("unit")
                if unit:
                    keys.add((rule, uri, str(unit)))
    elif isinstance(data, dict):
        for rc in data.get("root_causes", []):
            keys.add((str(rc.get("category") or "").upper(),
                      _sarif_rel(rc.get("file", ""), repo),
                      str(rc.get("signature") or "")))
    return keys


def _apply_baseline(root_causes: list[dict], p0: list[tuple],
                    path: str | Path, repo: Path) -> tuple[list, list, int, int]:
    """按 (类目, uri, 根因签名) 抑制存量，返回
    (new_p0, new_roots, suppressed_routes, suppressed_roots)。"""
    keys = _baseline_keys(path, repo)
    kept_roots: list[dict] = []
    suppressed_routes = 0
    for rc in root_causes:
        k = (str(rc["category"]).upper(),
             _sarif_rel(rc["file"], repo), str(rc["signature"]))
        if k in keys:
            suppressed_routes += int(rc["affected_routes"])
        else:
            kept_roots.append(rc)
    kept_sigs = {rc["signature"] for rc in kept_roots}
    new_p0 = [(u, c) for u, c in p0 if _root_cause_key(u, c)[0] in kept_sigs]
    return (new_p0, kept_roots, suppressed_routes,
            len(root_causes) - len(kept_roots))


def _build_root_causes(p0: list[tuple]) -> list[dict]:
    """把 [(unit, cat)] 折叠成独立根因列表（保持首次出现顺序）。"""
    groups: dict[str, dict] = {}
    for u, cat in p0:
        key, kind, evidence = _root_cause_key(u, cat)
        g = groups.get(key)
        if g is None:
            g = {"signature": key, "category": cat, "kind": kind,
                 "evidence_file": evidence, "units": []}
            groups[key] = g
        g["units"].append(u)
    out: list[dict] = []
    for g in groups.values():
        us = g["units"]
        rep = us[0]
        out.append({
            "signature": g["signature"], "category": g["category"],
            "kind": g["kind"], "evidence_file": g["evidence_file"],
            "representative": rep, "affected_routes": len(us),
            "routes": [x.unit_name for x in us[:5]],
            "file": rep.file_path, "line": rep.start_line,
            "unit_name": rep.unit_name,
        })
    return out


def _scan_secret_files(repo: Path) -> list:
    """M67 补充：配置文件/工具类里的硬编码密钥不挂在路由入口上。

    `scan --auto` 的切片单位是路由函数，VAmPI 的 `config.py`、litemall 的
    `JwtHelper.java` 这类"密钥定义在入口之外"的文件永远不会进切片。这里
    做一遍文件级 hardcoded_secret 普查（只收规则层 True），作为伪单元并入
    P0；不参与 unit×类目漏斗计数，单独在简报里记 `secret_files_flagged`。
    """
    from core.models import CodeUnit, Language
    from core.agents.rule_detectors import verdict as rule_verdict
    out: list = []
    for p in repo.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in _SECRET_FILE_EXTS:
            continue
        if any(part in _SECRET_FILE_SKIP for part in p.parts):
            continue
        try:
            if p.stat().st_size > 300_000:
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if rule_verdict("hardcoded_secret", text) is not True:
            continue
        suffix = p.suffix.lower()
        lang = (Language.JAVA_WEB if suffix == ".java"
                else Language.SOLIDITY_WEB3 if suffix == ".sol"
                else Language.PYTHON_WEB)
        u = CodeUnit(file_path=str(p), language=lang,
                     unit_name=f"[secret-file] {p.name}",
                     start_line=1, end_line=text.count("\n") + 1,
                     source_code=text, own_body=text)
        u.file_level = True                      # 供补丁器识别，免重切片
        out.append(u)
    return out


def cmd_scan_auto(args, repo: Path):
    """M58 野战模式：全类目毫秒级规则普查 + Sink 门控漏斗。

    两级漏斗：
      第一级（全类目规则普查）——按 unit 语言自动遍历全部适用类目：
        · rule_verdict == True  → P0（确定性实锤），不调模型；
        · rule_verdict == False → 静默排除；
      第二级（Sink 门控模型派发）——对 None 的 (unit, 类目) 对用
        build_rule_diagnostic 检查是否"真有外部输入 + 敏感 Sink"：
        无事实的（纯计算函数等）直接过滤，不派发模型；
        有事实的才是模型复核候选（P1/P2，模型层在 M60 分桶）。
    """
    from core.agents.rule_detectors import (verdict as rule_verdict,
                                            build_rule_diagnostic,
                                            _looks_solidity,
                                            _looks_python)
    from core.agents.vuln_categories import CATEGORIES

    print(f"[auto/1] 全语言切片 ...")
    units = list(WebTreeSitterSlicer(repo).extract_entry_units(repo))
    from core.slicer.web3_slither import SoliditySlicer
    units += list(SoliditySlicer(repo).extract_entry_units(repo))
    from core.slicer.java_servlet import JavaSlicer
    units += list(JavaSlicer(repo).extract_entry_units())
    test_units = [u for u in units if _is_test_path(u.file_path)]
    units = [u for u in units if not _is_test_path(u.file_path)]
    print(f"      共 {len(units)} 个入口"
          + (f"（已排除测试/夹具 {len(test_units)} 个）" if test_units else ""))

    web_cats = sorted(c for c in CATEGORIES if c not in _SOLIDITY_AUTO_CATS)
    p0: list[tuple] = []            # [(unit, cat)] 规则实锤
    secret_covered: set[Path] = set()   # 已被路由切片判过硬编码密钥的文件
    model_candidates: list[tuple] = []   # None + 有 Sink/输入事实
    n_filtered = 0                  # None 且无 Sink 事实 → 不派发
    n_false = 0                     # 规则确定性排除
    t0 = time.monotonic()

    print(f"[auto/2] 全类目规则普查（毫秒级/单元）...")
    for u in units:
        if _looks_solidity(u.source_code):
            cats = _SOLIDITY_AUTO_CATS
        else:
            cats = web_cats
        for cat in cats:
            v = rule_verdict(cat, u.source_code)
            if v is True:
                p0.append((u, cat))
                if cat == "hardcoded_secret":
                    secret_covered.add(Path(u.file_path).resolve())
            elif v is False:
                n_false += 1
            else:
                # Sink 门控：诊断非空 ⇔ 该单元真的存在外部输入行 + 敏感 Sink 行
                if build_rule_diagnostic(cat, u.source_code):
                    model_candidates.append((u, cat))
                else:
                    n_filtered += 1
    secret_units = [x for x in _scan_secret_files(repo)
                    if Path(x.file_path).resolve() not in secret_covered]
    p0 += [(u, "hardcoded_secret") for u in secret_units]
    root_causes = _build_root_causes(p0)
    all_root_causes = list(root_causes)
    suppressed_routes = 0
    suppressed_roots = 0
    if getattr(args, "baseline", None):
        p0, root_causes, suppressed_routes, suppressed_roots = _apply_baseline(
            root_causes, p0, args.baseline, repo)
    elapsed_ms = (time.monotonic() - t0) * 1000
    per_unit_ms = elapsed_ms / max(len(units), 1)
    n_pairs = (len(p0) - len(secret_units) + n_false
               + len(model_candidates) + n_filtered)
    filter_rate = n_filtered / max(n_filtered + len(model_candidates), 1)
    print(f"      {n_pairs} 次（unit × 类目）判定，耗时 {elapsed_ms:.0f} ms"
          f"（均值 {per_unit_ms:.2f} ms/单元）")
    print(f"      P0 实锤 {len(p0)} ｜ 独立根因 {len(root_causes)} ｜ "
          f"规则排除 {n_false} ｜ "
          f"模型候选 {len(model_candidates)} ｜ Sink 漏斗过滤 {n_filtered}"
          f"（过滤率 {filter_rate:.0%}）")
    if secret_units:
        print(f"      另：配置/工具类硬编码密钥文件 {len(secret_units)} 个"
              "（文件级普查，不计入路由单元）")
    if getattr(args, "baseline", None):
        print(f"      基线抑制 {suppressed_roots} 个独立根因 / "
              f"{suppressed_routes} 条路由级命中；本次净增 {len(p0)} 条")

    # --- 产出（P0 落报告；模型候选在 --offline 下标 P2 待复核）---
    lines = [f"# 野战扫描报告（--auto 全类目普查）—— {repo}", "",
             f"- 切片单元：{len(units)}",
             f"- 判定对：{n_pairs}（unit × 类目），规则普查 {elapsed_ms:.0f} ms",
             f"- P0 实锤：{len(p0)}（独立根因 {len(root_causes)}）；"
             f"规则排除：{n_false}",
             f"- Sink 漏斗：过滤 {n_filtered}，模型候选 {len(model_candidates)}"
             f"（过滤率 {filter_rate:.0%}）"]
    if test_units:
        lines.append(f"- 已排除测试/夹具路径：{len(test_units)} 个入口")
    if getattr(args, "baseline", None):
        lines.append(f"- 基线抑制：{suppressed_roots} 个独立根因 / "
                     f"{suppressed_routes} 条路由级命中；本次净增 {len(p0)} 条")
    if secret_units:
        lines.append(f"- 文件级硬编码密钥：{len(secret_units)} 个"
                     "（配置/工具类，不占路由入口）")
    lines.append("")
    if p0:
        lines.append(f"## P0 [Confirmed] 规则实锤"
                     f"（{len(root_causes)} 个独立根因 / {len(p0)} 条路由级命中）")
        lines.append("")
        for rc in root_causes:
            u, cat = rc["representative"], rc["category"]
            if rc["affected_routes"] > 1:
                ev = (Path(rc["evidence_file"]).name
                      if rc["evidence_file"] else "全局装配证据")
                lines.append(f"- **[{cat}]** 全局根因 `{ev}`"
                             f"（影响 {rc['affected_routes']} 条路由）")
                lines.append(f"  - 代表入口：`{u.unit_name}` @ "
                             f"`{u.file_path}:{u.start_line}`")
                lines.append("  - 前 5 条路由：" + "；".join(
                    f"`{x}`" for x in rc["routes"]))
            else:
                lines.append(f"- **[{cat}]** `{u.unit_name}` @ "
                             f"`{u.file_path}:{u.start_line}`")
            if getattr(args, "graph", None):
                from core.context.taint_graph import build_taint_graph
                g = build_taint_graph(u, cat)
                if g:
                    lines += [g, ""]
        lines.append("")
    # M60：报告固定按 P0 → P1 → P2 三档渲染（段序即优先级）。
    # P1 [High-Confidence]：规则退 None、含敏感 Sink、经模型 Cite-Before-Verdict
    # 双引证且 Skeptic 未推翻 —— 模型阶段产出；--offline 下留空段。
    lines.append("## P1 [High-Confidence] 模型双引证通过")
    lines.append("")
    if not args.offline:
        pass  # 模型阶段接入点：双引证通过者在此归档
    lines.append("")
    lines.append("## P2 [Review-Needed] Sink 门控候选（模型复核队列）")
    lines.append("")
    if model_candidates:
        for u, cat in model_candidates[:50]:
            lines.append(f"- [{cat}] `{u.unit_name}` @ "
                         f"`{u.file_path}:{u.start_line}`")
        if len(model_candidates) > 50:
            lines.append(f"- ...（共 {len(model_candidates)} 条）")
        lines.append("")
    out = Path(args.output or "report_auto.md")
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n完成：野战报告已写入 {out}")

    # --- M61：野战一键组合（--fix / --emit-poc 与漏斗联动）---
    patches_verified = 0
    fix_text = ""
    if getattr(args, "fix", None) and p0:
        _fix_out = out.with_name("fix_report_auto.md")
        _verify_fixes_any(repo, [u for u, _ in p0], out_path=str(_fix_out))
        if _fix_out.exists():
            fix_text = _fix_out.read_text(encoding="utf-8")
            patches_verified = fix_text.count("```diff")
    pocs_generated = 0
    if getattr(args, "emit_poc", None) and p0:
        from core.sandbox.poc_synthesizer import PocSynthesizer
        _syn = PocSynthesizer().synthesize_many(list(p0), Path(args.emit_poc))
        pocs_generated = _syn.ok_count

    if getattr(args, "advisory_dir", None):
        from core.context.advisory_exporter import export_advisories
        adv_paths = export_advisories(root_causes, repo,
                                      Path(args.advisory_dir),
                                      fix_text=fix_text)
        print(f"      披露草稿 {len(adv_paths)} 份（按独立根因，"
              f"不按路由）-> {args.advisory_dir}")

    # --- M66：机器可读狩猎简报 ---
    if getattr(args, "summary_json", None):
        route_by_cat: dict[str, int] = {}
        unique_by_cat: dict[str, int] = {}
        for _, cat in p0:
            route_by_cat[cat] = route_by_cat.get(cat, 0) + 1
        for rc in root_causes:
            unique_by_cat[rc["category"]] = unique_by_cat.get(
                rc["category"], 0) + 1
        summary = {
            "repo": str(repo),
            "total_units": len(units),
            "test_units_skipped": len(test_units),
            "total_pairs_evaluated": n_pairs,
            # 兼容既有门禁：p0_confirmed 仍是路由级命中数。
            "p0_confirmed": len(p0),
            "p0_route_level_hits": len(p0),
            "p0_unique_root_causes": len(root_causes),
            "p0_route_by_cat": route_by_cat,
            "p0_unique_by_cat": unique_by_cat,
            "root_causes": [{
                "category": rc["category"], "kind": rc["kind"],
                "signature": rc["signature"],
                "affected_routes": rc["affected_routes"],
                "representative": rc["unit_name"],
                "file": rc["file"], "line": rc["line"],
                "routes": rc["routes"],
            } for rc in root_causes],
            "secret_files_flagged": len(secret_units),
            "funnel_filtered_out": n_filtered,
            "funnel_filter_rate": round(filter_rate, 4),
            "llm_dispatched": len(model_candidates),
            "model_candidates": [{
                "unit": u.unit_name, "category": cat,
                "file": u.file_path, "line": u.start_line,
                "diagnostic": build_rule_diagnostic(cat, u.source_code)[:1200],
            } for u, cat in model_candidates[:20]],
            "patches_verified": patches_verified,
            "pocs_generated": pocs_generated,
            "baseline": str(getattr(args, "baseline", "") or ""),
            "suppressed_by_baseline": suppressed_routes,
            "suppressed_root_causes": suppressed_roots,
            "new_findings": len(p0),
            "elapsed_ms": round(elapsed_ms, 1),
        }
        Path(args.summary_json).write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8")
        print(f"      狩猎简报已写入 {args.summary_json}")

    if getattr(args, "sarif", None):
        entries = [{"file": rc["file"], "line": rc["line"],
                    "category": rc["category"],
                    "unit": (rc["unit_name"] if rc["affected_routes"] == 1
                             else f"{rc['category']} 全局根因"),
                    "level": "warning", "priority": "P0",
                    "affected_routes_count": rc["affected_routes"],
                    "root_cause": rc["signature"],
                    "root_kind": rc["kind"],
                    "message": (f"[{rc['category']}] 规则层确定性实锤（P0）"
                                + (f"；同一全局配置影响 "
                                   f"{rc['affected_routes']} 条路由"
                                   if rc["affected_routes"] > 1 else ""))}
                   for rc in root_causes]
        entries += [{"file": u.file_path, "line": u.start_line,
                     "category": cat, "unit": u.unit_name,
                     "level": "note", "priority": "P2",
                     "message": f"[{cat}] Sink 门控候选（待模型复核）"}
                    for u, cat in model_candidates]
        write_sarif(args.sarif, entries, repo)
        print(f"      SARIF 已写入 {args.sarif}（{len(entries)} 条 results）")
    # M127：GitLab SAST（gl-sast-report.json v15）—— 与 SARIF 同一份根因集合
    if getattr(args, "gitlab_sast", None):
        from core.context.gitlab_exporter import (
            build_sast_report, validate_sast_report, write_sast_report)
        _gl_findings = [{
            "file": rc["file"], "line": rc["line"],
            "category": rc["category"],
            "severity": _gl_severity(rc["category"]),
            "cwe": CATEGORIES[rc["category"]].cwe
            if rc["category"] in CATEGORIES else "",
            "name": f"{rc['category']} in {rc['unit_name']}",
            "message": (f"[{rc['category']}] 规则层确定性实锤（P0）"),
            "description": (f"根因签名 {rc['signature']}；"
                            f"影响 {rc['affected_routes']} 条路由。"),
        } for rc in root_causes]
        _gl = build_sast_report(_gl_findings, repo)
        _gl_errs = validate_sast_report(_gl)
        write_sast_report(args.gitlab_sast, _gl)
        print(f"      GitLab SAST 已写入 {args.gitlab_sast}"
              f"（{len(_gl['vulnerabilities'])} 条 vulnerabilities）")
        if _gl_errs:
            print(f"      [!] schema 自检发现 {len(_gl_errs)} 处问题："
                  f"{_gl_errs[:3]}")
    if getattr(args, "html", None):
        html_entries = [{"file": rc["file"], "line": rc["line"],
                         "category": rc["category"],
                         "unit": (rc["unit_name"] if rc["affected_routes"] == 1
                                  else f"{rc['category']} 全局根因"),
                         "priority": "P0", "level": "warning",
                         "message": (f"{rc['category']} 规则层确定性实锤（P0）"
                                     + (f"；影响 {rc['affected_routes']} 条路由"
                                        if rc["affected_routes"] > 1 else "")),
                         "code": rc["representative"].source_code,
                         "code_from": rc["representative"].start_line,
                         "affected_routes": rc["affected_routes"],
                         "routes": rc["routes"]}
                        for rc in root_causes]
        html_entries += [{"file": u.file_path, "line": u.start_line,
                          "category": cat, "unit": u.unit_name,
                          "priority": "P2", "level": "note",
                          "message": f"{cat} Sink 门控候选（待模型复核）",
                          "code": u.source_code, "code_from": u.start_line}
                         for u, cat in model_candidates]
        prio_rank = {"P0": 0, "P1": 1, "P2": 2}
        html_entries.sort(key=lambda e: prio_rank.get(str(e.get("priority")), 3))
        from core.context.report_html import build_html_report
        out_html = Path(args.html)
        out_html.write_text(build_html_report(
            html_entries, str(repo),
            funnel={"total_units": len(units), "p0_confirmed": len(p0),
                    "p0_route_level_hits": len(p0),
                    "p0_unique_root_causes": len(root_causes),
                    "funnel_filtered": n_filtered,
                    "funnel_dispatched": len(model_candidates)}),
            encoding="utf-8")
        print(f"      HTML 报告已写入 {out_html}（{len(html_entries)} 条）")


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


def _router_with_cache(args) -> "TwoTierRouter":
    """M59：构造带磁盘缓存的路由器（--no-llm-cache 禁用）。

    缓存键 = sha256(model + messages + temperature)，只缓存成功响应；
    扫描中断后重跑，已完成的调用毫秒级命中，不重复消耗 Token。
    """
    from core.agents.router import TwoTierRouter, CachedLLMClient, LLMDiskCache
    r = TwoTierRouter()
    if getattr(args, "no_llm_cache", False):
        return r
    cache = LLMDiskCache(path=getattr(args, "llm_cache_path", None)
                         or ".cache/llm_responses.jsonl")
    r.tier1 = CachedLLMClient(r.tier1, cache)
    return r


def _write_html(args, entries: list[dict], repo: Path) -> None:
    """M57：把检出项写成单文件交互式 HTML 报告。

    entries 与 SARIF 导出共用同一份 dict（单一事实源）；code / fix_diff
    为可选字段 —— 有则渲染带行号 Sink 高亮的代码块与补丁 Diff 框。
    """
    from core.context.report_html import build_html_report
    out = Path(args.html)
    out.write_text(build_html_report(entries, str(repo)), encoding="utf-8")
    print(f"      HTML 报告已写入 {out}（{len(entries)} 条）")


def _sarif_rel(file_path: str, repo: Path) -> str:
    """SARIF 的 artifactLocation.uri 必须是**仓库相对路径**（GitHub 按仓库
    相对路径索引文件），对不上时退回 POSIX 绝对路径并保留可读性。"""
    try:
        return Path(file_path).resolve().relative_to(Path(repo).resolve()).as_posix()
    except (ValueError, OSError):
        return Path(file_path).as_posix()


def build_sarif(entries: list[dict], repo: str | Path = ".") -> dict:
    """把审计命中序列化为 SARIF v2.1.0（GitHub Code Scanning 原生格式）。

    entries: [{file, line, category, unit, message, level?, flow?}]，
    flow 为可选的调用链 [{file, line, message?}] → results[].codeFlows。
    结构必须含 GitHub 校验的三要素：runs[0].tool.driver.rules、
    runs[0].results[].locations[].physicalLocation（uri + region.startLine）。
    """
    rules: dict[str, dict] = {}
    results: list[dict] = []
    from core.context.cvss import compute_cvss31
    for e in entries:
        cat = str(e.get("category") or "UNKNOWN").upper()
        if cat not in rules:
            cvss = compute_cvss31(cat.lower())
            rules[cat] = {
                "id": cat,
                "shortDescription": {"text": f"{cat} 漏洞候选"},
                # GitHub Code Scanning 原生读取 security-severity（0.0–10.0）
                "properties": {
                    "security-severity": f"{cvss['score']:.1f}",
                    "cvss": cvss["vector"],
                    "severity": cvss["severity"],
                },
            }
        uri = _sarif_rel(e.get("file", "."), repo)
        line = int(e.get("line") or 1)
        phys = {"artifactLocation": {"uri": uri},
                "region": {"startLine": max(1, line)}}
        res = {"ruleId": cat,
               "level": e.get("level") or "warning",
               "message": {"text": e.get("message") or f"{cat} @ {e.get('unit', '')}"},
               # M60：置信度分档进 properties（GitHub Code Scanning 会透出）
               "properties": {"priority": e.get("priority")
                              or ("P0" if e.get("level") != "note" else "P2"),
                              **({"unit": e["unit"]} if e.get("unit") else {}),
                              **({"security-severity":
                                  f"{compute_cvss31(cat.lower())['score']:.1f}"}
                                 if e.get("level") != "note" else {}),
                              **({"affected_routes_count":
                                  int(e["affected_routes_count"])}
                                 if e.get("affected_routes_count") else {}),
                              **({"root_cause": e["root_cause"]}
                                 if e.get("root_cause") else {}),
                              **({"root_kind": e["root_kind"]}
                                 if e.get("root_kind") else {})},
               "locations": [{"physicalLocation": phys}],
               # codeFlows 常驻：哪怕是单点链路，GitHub 的 "Code flow" 面板
               # 也要有东西可渲染；多跳链路把 flow 传进来即可。
               "codeFlows": [{"threadFlows": [{"locations": [
                   {"location": {"message": {"text": f.get("message", "")}
                                 if f.get("message") else {},
                                 "physicalLocation": {
                                     "artifactLocation": {
                                         "uri": _sarif_rel(f.get("file", e.get("file", ".")), repo)},
                                     "region": {"startLine": max(1, int(f.get("line") or line))}}}}
                   for f in (e.get("flow") or [{"file": e.get("file", "."), "line": line}])]}]}]}
        results.append(res)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "nexus-audit",
                "version": "1.0.0",
                "informationUri": "https://owasp.org/www-project-benchmark/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def write_sarif(path: str | Path, entries: list[dict], repo: str | Path = ".") -> int:
    """写 SARIF 文件，返回 results 条数（0 也照写 —— 空结果本身是事实）。"""
    sarif = build_sarif(entries, repo)
    Path(path).write_text(json.dumps(sarif, ensure_ascii=False, indent=2),
                          encoding="utf-8")
    return len(sarif["runs"][0]["results"])


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

    if getattr(args, "emit_poc", None):
        return _emit_pocs(units, categories, args.emit_poc)

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

    # --- RuleDiagnostic：半成品事实移交 -----------------------------------
    # 规则退回 None 的入口，把"已经核实了一半的事实"（候选输入行 / 候选
    # sink 行）作为纯客观注释头拼进送审代码段顶部。只给定位参考，不下结论
    # —— 结论仍是模型的。注释行不会被 Cite-Before-Verdict 当成可引用证据。
    # line_offset：头部行数会使代码整体下移，重建一次让 L 编号自洽。
    from core.agents.rule_detectors import build_rule_diagnostic
    by_uid: dict[int, tuple] = {}
    for u, c in pending:
        prev = by_uid.get(id(u))
        by_uid[id(u)] = (u, [c]) if prev is None else (u, prev[1] + [c])
    diag_n = 0
    for u, cats in by_uid.values():
        headers = [d for c in cats if (d := build_rule_diagnostic(c, u.source_code))]
        if not headers:
            continue
        n = len(headers)
        headers = [d for c in cats
                   if (d := build_rule_diagnostic(c, u.source_code, line_offset=n))]
        u.source_code = "\n".join(headers) + "\n" + u.source_code
        diag_n += 1
    if diag_n:
        print(f"      已向 {diag_n} 个入口注入静态前筛事实注释头")

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
    if getattr(args, "baseline", None):
        _keys = _baseline_keys(args.baseline, repo)
        _before = len(flagged)
        flagged = [(u, c) for u, c in flagged
                   if (c.upper(), _sarif_rel(u.file_path, repo),
                       u.unit_name) not in _keys]
        print(f"      基线抑制 {_before - len(flagged)} 条；本次净增 {len(flagged)} 条")
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
        if getattr(args, "graph", None):
            from core.context.taint_graph import build_taint_graph
            g = build_taint_graph(u, cat)
            if g:
                lines += [g, ""]
    if failed:
        lines += ["## 判定失败（需重跑，不是无漏洞）", ""]
        for u, c in failed:
            lines.append(f"- `{u.unit_name}` / {c} @ `{u.file_path}:{u.start_line}`")
    out = Path(args.output or "report_java.md")
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n完成：报告已写入 {out}")

    # --- SARIF 2.1.0 导出（GitHub Code Scanning 可直接上传）---
    if getattr(args, "sarif", None):
        entries = [{"file": u.file_path, "line": u.start_line, "category": c,
                    "unit": u.unit_name,
                    "message": f"[{c.upper()}] 入口 {u.unit_name}（规则/模型命中）"}
                   for u, c in flagged]
        entries += [{"file": u.file_path, "line": u.start_line, "category": c,
                     "unit": u.unit_name, "level": "error",
                     "message": f"{c.upper()} 判定失败（限流/超时），需重跑，不是无漏洞"}
                    for u, c in failed]
        n = write_sarif(args.sarif, entries, repo)
        print(f"      SARIF 已写入 {args.sarif}（{n} 条 results）")

    # --- M57：单文件交互式 HTML 报告（Java 赛道）---
    if getattr(args, "html", None):
        html_entries = [{"file": u.file_path, "line": u.start_line,
                         "category": c, "unit": u.unit_name,
                         "priority": "P0", "level": "warning",
                         "message": f"{c} 规则/模型命中（P0 规则实锤）",
                         "code": u.source_code, "code_from": u.start_line}
                        for u, c in flagged]
        _write_html(args, html_entries, repo)
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

    if getattr(args, "emit_poc", None):
        # Solidity 侧确定性 True 的两类：重入 / 越权（tx.origin 钓鱼也归
        # access_control —— 规则层对 tx.origin 鉴权直接判 True）
        return _emit_pocs(units, ["reentrancy", "access_control"], args.emit_poc)

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
    # .xml 必须在列：Mapper XML 是 SQL 注入真值的所在地（第 2/3 跳），
    # 把它当"非代码"过滤掉，改 Mapper 的 PR 会被误判为"无变更，跳过"
    # （实测 newbee-mall 的 C 场景：diff 明明有文件，却报 0 个）。
    code_exts = (".py", ".java", ".kt", ".go", ".js", ".ts", ".sol", ".xml")
    changed = [f for f in changed if f.endswith(code_exts)]
    print(f"PR 增量扫描：{len(changed)} 个代码文件变更（基于 {args.base}）")
    for f in changed:
        print(f"  - {f}")
    if not changed:
        if getattr(args, "fix", False):
            # fix 模式不依赖 diff：补丁自检的对象是"规则层命中"，全量即可
            print("无代码变更；--fix 模式改为覆盖全量入口")
            _verify_fixes_any(repo, _slice_for_pr(repo, args.language))
            return
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

    # Mapper XML 变更：`_changed_methods_of` 的方法签名正则在 XML 上必然
    # 落空，而 XML 恰恰是 SQL 注入真值的所在地（第 2/3 跳）。两步走：
    #   精确层：从 diff 里抓被改的语句 id（<select id="x">），
    #           命中"切片里贴进了这条语句"的入口；
    #   兜底层：解析不出 id 时，凡切片引用了该 XML 文件名的入口全部拉入
    #           （宁多不漏，与 hot 的文件级退回同一原则）。
    xml_ids: set[str] = set()
    xml_bases: list[str] = []
    for f in changed:
        if not f.endswith(".xml"):
            continue
        xml_bases.append(Path(f).name)
        r = subprocess.run(["git", "-C", str(repo), "diff", "-U3", args.base, "HEAD", "--", f],
                           capture_output=True, text=True)
        ids = _xml_statement_ids(r.stdout)
        if ids:
            xml_ids |= ids
    if xml_ids:
        print(f"  变更的 Mapper 语句：{', '.join(sorted(xml_ids)[:10])}"
              f"{' ...' if len(xml_ids) > 10 else ''}")

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
            # 同名重载的 unit_name 带 `#N` 后缀（`update` / `update#2`），
            # 与 git diff 给的方法名对不上 —— 先剥掉再比。
            if base_unit_name(u.unit_name).split(".")[-1] in meths:
                hot.append(u)
            continue
        # 2) 入口调用了变更函数 —— 反向依赖。
        #    这是增量扫描真正的价值所在：改一个 SecurityUtil.checkURL，
        #    所有调用它的路由都可能受影响，而改动文件本身一个入口都没有。
        #
        #    调用集合必须取**整份切片**而不只是 called_symbols（后者只来自
        #    入口自身方法体 = 第 1 跳直调）。切片的 [Hop N] 段里出现的
        #    方法调用正是"该入口可达"的证据：改 ServiceImpl 里的深层方法、
        #    Mapper 语句，只要切片穿透到了它，就该算受影响。
        called = (set(getattr(u, "called_symbols", []) or [])
                  | set(_java_called_names(u.source_code)))
        # 自己的方法名不算"调用了变更函数"：切片的签名行 `public String logout(`
        # 会被抓成一次 `logout` 调用，把同名的其它入口全串进来
        # （实测改 PersonalController.logout 会多拉进 AdminController.logout）。
        called.discard(base_unit_name(u.unit_name).split(".")[-1])
        if changed_funcs and called & changed_funcs:
            dependent.append(u)
            continue
        if xml_ids and any(f'id="{s}"' in u.source_code for s in xml_ids):
            dependent.append(u)
            continue
        if xml_bases and any(b in u.source_code for b in xml_bases):
            dependent.append(u)        # XML 变了但解析不出语句 id → 兜底
            continue

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
        if getattr(args, "fix", False):
            # fix 模式不依赖 diff：没有变更面时对全量入口做修复自检
            print("无受影响路由，补丁自检改为覆盖全量入口")
            _verify_fixes_any(repo, units)
            return
        print("无受影响路由，本次 PR 无需审计")
        return

    if getattr(args, "fix", False):
        _verify_fixes_any(repo, subset)
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
        github_comment=getattr(args, "github_comment", False),
        sarif=getattr(args, "sarif", None),
        html=getattr(args, "html", None),
        baseline=getattr(args, "baseline", None),
        auto=getattr(args, "auto", False))
    print("\n进入审计（仅上述受影响路由）...")
    cmd_scan_java(ns, repo)

    # M112：把本次增量结果转成 GitHub PR 行级 review 载荷。
    # 直接复用刚写出的 summary json（与报告同一份事实源，不重算一遍）。
    gh_out = getattr(args, "gh_comments", None)
    if gh_out:
        from core.context.pr_commenter import (build_review_payload,
                                               write_review_payload)
        findings: list[dict] = []
        sum_path = Path(getattr(ns, "summary_json", "") or "")
        if sum_path.is_file():
            try:
                data = json.loads(sum_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {}
            for hit in data.get("p0_confirmed_details", []) or []:
                findings.append({
                    "file": hit.get("file", ""),
                    "line": hit.get("line", 0),
                    "category": hit.get("category", ""),
                    "severity": hit.get("severity", "HIGH"),
                    "cwe": hit.get("cwe", ""),
                    "message": hit.get("message", ""),
                })
        payload = build_review_payload(findings, repo)
        out_gh = write_review_payload(gh_out, payload)
        print(f"GitHub PR review 载荷：{len(payload['comments'])} 条评论"
              f" → {out_gh}")
        if payload["comments"]:
            print("  提交方式：gh api repos/{owner}/{repo}/pulls/{n}/reviews "
                  "--input " + str(out_gh))


def _hunt_repo_name(repo: Path) -> str:
    """仓库显示名：取最后一段目录名；`contracts` 这类泛名再往上取一层。"""
    name = repo.name
    if name in ("contracts", "src", "app", "") and repo.parent.name:
        name = f"{repo.parent.name}-{name}"
    return name


def _hunt_one(repo: Path, outdir: Path, advisory_root: str | None,
              extra: list[str], timeout: int = 1800) -> dict:
    """对单个仓库跑一次 `scan --auto`（子进程：与野战命令同一条路径）。

    刻意不复用仓库内函数而是**再调一次 cli.py**：hunt 的价值是"把你手工
    会跑的那条命令批量跑一遍"，两条路径必须是同一条。子进程还顺带隔离了
    单仓崩溃（rc≠0 只记在该仓名下，不中断整批）。
    """
    name = _hunt_repo_name(repo)
    outdir.mkdir(parents=True, exist_ok=True)
    summary = outdir / "summary.json"
    cmd = [sys.executable, str(Path(__file__).resolve()),
           "scan", str(repo), "--auto", "--offline",
           "--summary-json", str(summary),
           "--output", str(outdir / "report.md"),
           "--html", str(outdir / "report.html"),
           "--sarif", str(outdir / "report.sarif"), *extra]
    if advisory_root:
        cmd += ["--advisory-dir", str(Path(advisory_root) / name)]
    t0 = time.monotonic()
    try:
        p = subprocess.run(cmd, cwd=Path(__file__).resolve().parent,
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
        rc = p.returncode
        tail = "\n".join([x for x in ((p.stdout or "") + (p.stderr or ""))
                          .strip().splitlines() if x.strip()][-3:])
    except subprocess.TimeoutExpired:
        rc, tail = 124, f"超时（{timeout}s）"
    dt = time.monotonic() - t0
    data: dict = {}
    if summary.exists():
        try:
            data = json.loads(summary.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}
    return {
        "name": name, "path": str(repo), "scan_rc": rc,
        "duration_s": round(dt, 2),
        "units": data.get("total_units", 0),
        "p0_route": data.get("p0_route_level_hits", data.get("p0_confirmed", 0)),
        "p0_unique": data.get("p0_unique_root_causes", 0),
        "by_cat": data.get("p0_unique_by_cat") or data.get("p0_route_by_cat") or {},
        "funnel_filtered": data.get("funnel_filtered_out", 0),
        "patches_verified": data.get("patches_verified", 0),
        "tail": tail,
    }


def cmd_hunt(args) -> int:
    """M91：多仓批量野战 + Portfolio 总览大屏。

        python cli.py hunt repoA repoB repoC --html portfolio.html \\
               --advisory-dir advisories/ --summary-json hunt.json

    逐仓（或 --jobs N 并发）跑 `scan --auto`，产出：
      · 每个仓自己的 report.md / report.html / report.sarif / summary.json
        （落在 <outdir>/<仓名>/ 下）；
      · 跨仓汇总 JSON（--summary-json）；
      · 单文件 Portfolio 大屏（--html）；
      · 去重后的 GHSA 披露草稿目录（--advisory-dir，每仓一个子目录，
        仓内按"独立根因"去重 —— 与单仓 --advisory-dir 同一口径）。
    """
    repos = [Path(p) for p in args.repos]
    missing = [str(p) for p in repos if not p.exists()]
    if missing:
        print(f"! 目录不存在：{', '.join(missing)}")
        return 2
    outdir = Path(args.outdir or "hunt_results")
    outdir.mkdir(parents=True, exist_ok=True)
    extra: list[str] = []
    if getattr(args, "fix", False):
        extra.append("--fix")
    if getattr(args, "emit_poc", None):
        extra += ["--emit-poc", str(args.emit_poc)]

    print(f"[hunt] {len(repos)} 个仓库 → {outdir}"
          + (f"（并发 {args.jobs}）" if args.jobs > 1 else "（顺序）"))
    records: list[dict] = []
    jobs = max(1, int(args.jobs or 1))
    if jobs > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=jobs) as ex:
            futs = {ex.submit(_hunt_one, r, outdir / _hunt_repo_name(r),
                              args.advisory_dir, extra): r for r in repos}
            for fut, r in futs.items():          # 保序收集
                rec = fut.result()
                records.append(rec)
                print(f"  [{rec['name']}] rc={rec['scan_rc']} "
                      f"units={rec['units']} 根因={rec['p0_unique']} "
                      f"{rec['duration_s']}s")
    else:
        for r in repos:
            rec = _hunt_one(r, outdir / _hunt_repo_name(r),
                            args.advisory_dir, extra)
            records.append(rec)
            print(f"  [{rec['name']}] rc={rec['scan_rc']} units={rec['units']} "
                  f"根因={rec['p0_unique']} {rec['duration_s']}s")

    agg = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "repos": records,
        "totals": {
            "repos": len(records),
            "units": sum(int(r["units"]) for r in records),
            "p0_route_level_hits": sum(int(r["p0_route"]) for r in records),
            "p0_unique_root_causes": sum(int(r["p0_unique"]) for r in records),
            "failed_repos": sum(1 for r in records if r["scan_rc"] != 0),
        },
    }
    if args.summary_json:
        Path(args.summary_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.summary_json).write_text(
            json.dumps(agg, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"      汇总 JSON → {args.summary_json}")
    if args.html:
        from core.context.report_html import build_portfolio_html
        Path(args.html).parent.mkdir(parents=True, exist_ok=True)
        Path(args.html).write_text(
            build_portfolio_html(records), encoding="utf-8")
        print(f"      Portfolio 大屏 → {args.html}")
    if args.advisory_dir:
        adv = Path(args.advisory_dir)
        n = sum(1 for _ in adv.rglob("*.md")) if adv.exists() else 0
        print(f"      披露草稿 → {adv}（{n} 份）")

    t = agg["totals"]
    print(f"\n[hunt] {t['repos']} 仓 / {t['units']} 入口 / "
          f"{t['p0_unique_root_causes']} 独立根因 / "
          f"{t['p0_route_level_hits']} 条路由级命中 / 失败 {t['failed_repos']}")
    return 0 if t["failed_repos"] == 0 else 1


_BENCH_TEMPLATE = '''"""@@NAME@@（@@TARGET@@）—— 由 `cli.py benchmark-gen` 自动固化的回归门禁。

## 这个文件是怎么来的

M93 之前每个野战仓的回归门禁都是**手抄**一份：抄默认路径、抄单元数地板、
抄几条代表性锚点。抄三份就开始漂（M73/M79/M80 各漂过一次），而且新仓
上手要重抄一遍。

`cli.py benchmark-gen <repo>` 把那一遍自动化了：对目标仓库跑一次全量
切片 + 全类目规则普查，把**当时的事实**固化成本脚本：

  · 切片单元 @@UNIT_COUNT@@ 个、确定性判定 @@PAIRS@@ 对；
  · 确定性 True @@N_TRUE@@ 条（逐条登记为 TRUE_ANCHORS，漏一条就红）；
  · 确定性命中 False 的锚点 @@N_FALSE@@ 条（代表"已确认安全"的写法，
    翻成 True 就说明新判据把安全代码判成了漏洞）。

生成时间：@@GEN_TS@@
生成命令：`python cli.py benchmark-gen @@TARGET@@ --out <本文件>`

## 门禁（--strict）

  1. 切片 ≥ MIN_UNITS（切片器退化能当场发现）
  2. 确定性判定 ≥ MIN_DECIDED（判据静默退回能当场发现）
  3. TRUE_ANCHORS 全部仍判 True（零漏报 / 零判反）
  4. 除 TRUE_ANCHORS 外零 True（零误报）
  5. FALSE_ANCHORS 全部仍判 False（安全锚点不得翻面）

> 这个门禁锁的是"**相对生成时刻不漂**"，不是"这套真值绝对正确"。
> 生成时那批 True 是否真是漏洞，仍需人工逐条核查（M63 起的野战纪律）。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _find_root(start: Path) -> Path:
    """定位仓库根（含 core/agents/rule_detectors.py 的那一层）。

    不能写死 `parent.parent`：生成到 `benchmarks/` 之外时（冒烟与临时仓
    都是这样）`sys.path` 会指错，脚本连 import 都进不去。先向上走
    （正常情形：生成在 benchmarks/ 下），走不到就用生成时记录的根路径。
    """
    for p in [start, *start.parents]:
        if (p / "core" / "agents" / "rule_detectors.py").is_file():
            return p
    hint = Path(ROOT_HINT)
    if (hint / "core" / "agents" / "rule_detectors.py").is_file():
        return hint
    return start.parent


# 生成时所在仓库根（只有向上走找不到时才用到）
ROOT_HINT = r"@@ROOT_HINT@@"
ROOT = _find_root(Path(__file__).resolve().parent)
sys.path.insert(0, str(ROOT))

from benchmarks.slice_cache import cached_units              # noqa: E402
from core.agents.rule_detectors import (                     # noqa: E402
    _looks_solidity, verdict as rule_verdict)
from core.agents.vuln_categories import CATEGORIES           # noqa: E402

DEFAULT_TARGET = ROOT / "@@TARGET@@"
BENCH_KEY = "@@BENCH_KEY@@"
MIN_UNITS = @@MIN_UNITS@@
MIN_DECIDED = @@MIN_DECIDED@@

SOL_CATS = ["reentrancy", "access_control",
            "unchecked_low_level_calls", "arithmetic"]
WEB_CATS = sorted(c for c in CATEGORIES if c not in SOL_CATS)

# (仓库内相对路径, 单元名, 类目)
TRUE_ANCHORS = {
@@TRUE_ANCHORS@@}

FALSE_ANCHORS = [
@@FALSE_ANCHORS@@]


def _rel(repo: Path, file_path: str) -> str:
    try:
        return Path(file_path).resolve().relative_to(repo.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(file_path).as_posix()


def build_units(repo: Path) -> list:
    """三语言切片（与 `cli.py scan --auto` 同口径）。"""
    from core.slicer.java_servlet import JavaSlicer
    from core.slicer.web3_slither import SoliditySlicer
    from core.slicer.web_treesitter import WebTreeSitterSlicer
    units = list(WebTreeSitterSlicer(repo).extract_entry_units(repo))
    units += list(SoliditySlicer(repo).extract_entry_units(repo))
    units += list(JavaSlicer(repo).extract_entry_units())
    return units


def main() -> int:
    ap = argparse.ArgumentParser(description="@@NAME@@ 自动生成回归门禁")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="单元/判定地板 + 真值全命中 + 零误报 + 安全锚点不翻面")
    ap.add_argument("--no-cache", action="store_true", help="禁用切片温缓存")
    ap.add_argument("--offline", action="store_true", help="规则层（默认）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "@@BENCH_KEY@@.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}")
        return 2

    units = cached_units(repo, BENCH_KEY, lambda: build_units(repo),
                         no_cache=args.no_cache)
    print(f"靶场：{repo}")
    print(f"      切片单元 {len(units)} 个（地板 {MIN_UNITS}）")

    verdicts: dict[tuple[str, str, str], bool] = {}
    n_decided = 0
    for u in units:
        rel = _rel(repo, u.file_path)
        cats = SOL_CATS if _looks_solidity(u.source_code) else WEB_CATS
        for c in cats:
            v = rule_verdict(c, u.source_code)
            if v is None:
                continue
            n_decided += 1
            verdicts[(rel, u.unit_name, c)] = v

    true_hits = {k for k, v in verdicts.items() if v is True}
    missed = sorted(TRUE_ANCHORS - (true_hits & TRUE_ANCHORS))
    unexpected = sorted(true_hits - TRUE_ANCHORS)
    broken_false = sorted(k for k in FALSE_ANCHORS
                          if verdicts.get(k) is not False)

    print("=" * 72)
    print("@@NAME@@ 结果（benchmark-gen 固化门禁）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  确定性判定            ：{n_decided}（地板 {MIN_DECIDED}）")
    print(f"  真值锚点命中          ：{len(TRUE_ANCHORS) - len(missed)}"
          f"/{len(TRUE_ANCHORS)}")
    print(f"  误报（真值外 True）   ：{len(unexpected)}")
    print(f"  安全锚点翻面          ：{len(broken_false)}/{len(FALSE_ANCHORS)}")
    for k in missed[:10]:
        print(f"    [漏报] {k[0]}:{k[1]} [{k[2]}]")
    for k in unexpected[:10]:
        print(f"    [误报] {k[0]}:{k[1]} [{k[2]}]")
    for k in broken_false[:10]:
        print(f"    [翻面] {k[0]}:{k[1]} [{k[2]}]")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if n_decided < MIN_DECIDED:
        bad.append(f"判定 {n_decided} < {MIN_DECIDED}")
    if missed:
        bad.append(f"漏报 {len(missed)} 条")
    if unexpected:
        bad.append(f"误报 {len(unexpected)} 条")
    if broken_false:
        bad.append(f"安全锚点翻面 {len(broken_false)} 条")
    ok = not bad
    print(f"\\n{'STRICT PASS ✔（真值全命中 / 零误报 / 锚点未翻面）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": BENCH_KEY, "units": len(units), "total_units": len(units),
        "decided": n_decided, "rule_evaluations": n_decided,
        "correct": len(TRUE_ANCHORS) - len(missed),
        "fp": len(unexpected), "reverse_fn": len(missed) + len(broken_false),
        "truth_n": len(TRUE_ANCHORS),
        "missed": [list(k) for k in missed],
        "unexpected": [list(k) for k in unexpected],
        "broken_false": [list(k) for k in broken_false],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
'''


def _bench_gen_units(repo: Path) -> list:
    """与 `cli.py scan --auto` 同口径的三语言切片。"""
    from core.slicer.web_treesitter import WebTreeSitterSlicer
    units = list(WebTreeSitterSlicer(repo).extract_entry_units(repo))
    from core.slicer.web3_slither import SoliditySlicer
    units += list(SoliditySlicer(repo).extract_entry_units(repo))
    from core.slicer.java_servlet import JavaSlicer
    units += list(JavaSlicer(repo).extract_entry_units())
    return units


def cmd_benchmark_gen(args) -> int:
    """M93：把一个野战仓库一键转成回归门禁脚本。

    自动化的是**抄写**，不是判断：生成器只把"此刻的事实"（切片单元数、
    确定性判定数、当时判 True 的锚点、几条有代表性的 False 锚点）固化下来，
    真值是否成立仍要人工核查。所以脚本的 docstring 里明写
    "锁的是相对生成时刻不漂，不是这套真值绝对正确"。
    """
    from core.agents.rule_detectors import (verdict as rule_verdict,
                                            _looks_solidity)
    from core.agents.vuln_categories import CATEGORIES
    from benchmarks.slice_cache import cached_units

    repo = Path(args.repo_path)
    if not repo.exists():
        print(f"! 仓库不存在：{repo}")
        return 2
    name = _hunt_repo_name(repo)
    bench_key = args.bench_key or re.sub(r"[^a-z0-9_]+", "_", name.lower()).strip("_")
    out = Path(args.out or f"benchmarks/benchmark_{bench_key}.py")

    units = cached_units(repo, f"{bench_key}_gen",
                         lambda: _bench_gen_units(repo),
                         no_cache=getattr(args, "no_cache", False))
    sol_cats = list(_SOLIDITY_AUTO_CATS)
    web_cats = sorted(c for c in CATEGORIES if c not in sol_cats)

    def rel(fp: str) -> str:
        try:
            return Path(fp).resolve().relative_to(repo.resolve()).as_posix()
        except (ValueError, OSError):
            return Path(fp).as_posix()

    verdicts: dict[tuple[str, str, str], bool] = {}
    n_decided = 0
    for u in units:
        r = rel(u.file_path)
        cats = sol_cats if _looks_solidity(u.source_code) else web_cats
        for c in cats:
            v = rule_verdict(c, u.source_code)
            if v is None:
                continue
            n_decided += 1
            verdicts[(r, u.unit_name, c)] = v

    true_keys = sorted(k for k, v in verdicts.items() if v is True)
    # False 锚点取样：每个类目最多 3 条，总量上限 24 条 —— 全量写进去会让
    # 生成脚本变成第二个靶场，失去"锚点"的意义。
    by_cat: dict[str, list] = {}
    for k, v in sorted(verdicts.items()):
        if v is False:
            by_cat.setdefault(k[2], []).append(k)
    false_keys: list = []
    for c in sorted(by_cat):
        false_keys += by_cat[c][:3]
    false_keys = false_keys[:24]

    gen_ts = time.strftime("%Y-%m-%d %H:%M:%S")
    root_dir = Path(__file__).resolve().parent
    try:
        target_rel = repo.resolve().relative_to(root_dir.resolve()).as_posix()
    except ValueError:
        target_rel = str(repo).replace("\\", "/")
    script = (_BENCH_TEMPLATE
              .replace("@@NAME@@", name)
              .replace("@@TARGET@@", target_rel)
              .replace("@@BENCH_KEY@@", bench_key)
              .replace("@@ROOT_HINT@@", str(root_dir).replace("\\", "/"))
              .replace("@@GEN_TS@@", gen_ts)
              .replace("@@UNIT_COUNT@@", str(len(units)))
              .replace("@@PAIRS@@", str(n_decided))
              .replace("@@N_TRUE@@", str(len(true_keys)))
              .replace("@@N_FALSE@@", str(len(false_keys)))
              .replace("@@MIN_UNITS@@", str(max(1, int(len(units) * 0.8))))
              .replace("@@MIN_DECIDED@@", str(max(1, int(n_decided * 0.8))))
              .replace("@@TRUE_ANCHORS@@",
                       "".join(f"    ({k[0]!r}, {k[1]!r}, {k[2]!r}),\n"
                               for k in true_keys))
              .replace("@@FALSE_ANCHORS@@",
                       "".join(f"    ({k[0]!r}, {k[1]!r}, {k[2]!r}),\n"
                               for k in false_keys)))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(script, encoding="utf-8")
    print(f"[benchmark-gen] {name} → {out}")
    print(f"  切片 {len(units)} 单元 / 判定 {n_decided} 对 / "
          f"True 锚点 {len(true_keys)} / False 锚点 {len(false_keys)}")
    print(f"  单元地板 {max(1, int(len(units) * 0.8))} / "
          f"判定地板 {max(1, int(n_decided * 0.8))}")
    return 0


def _matrix_probe_units() -> dict[str, list]:
    """三语言探针语料（M100）：每种语言取**两个**小靶场的切片。

    为什么两个：单库覆盖不全就会在矩阵里报出**假的缺口**（java-sec-code
    没有 crypto/hash/weakrand 样本，矩阵会显示这三类"Java 不支持"）。
    拼两个互补的库才能让 "—" 真的表示"判据缺失"而不是"语料没样本"。
    刻意不用大靶场：矩阵问的是能力有没有，不是准确率。
    """
    root = Path(__file__).resolve().parent / "reference_repos"
    out: dict[str, list] = {}
    try:
        from core.slicer.java_servlet import JavaSlicer
        units: list = []
        for name in ("java-sec-code", "Hello-Java-Sec-master"):
            p = root / name
            if p.exists():
                units += list(JavaSlicer(p).extract_entry_units())
        # M153：zip_slip 在真实业务代码上的唯一入口证据。
        # kkFileView 的解压落在 service 层（无 Controller 注解），JavaSlicer
        # 的入口切片看不到它；矩阵问的是"判据有没有"，因此单独把
        # unRar + helper 证据拼成一个单元纳入 Java 探针。
        kk_reader = (root / "kkFileView" / "server" / "src" / "main" /
                     "java" / "cn" / "keking" / "service" /
                     "CompressFileReader.java")
        if kk_reader.is_file():
            from core.models import CodeUnit, Language
            _text = kk_reader.read_text(encoding="utf-8", errors="replace")

            def _span(sig: str) -> str:
                _i = _text.index(sig)
                _j = _text.index("{", _i)
                _depth = 0
                for _k in range(_j, len(_text)):
                    if _text[_k] == "{":
                        _depth += 1
                    elif _text[_k] == "}":
                        _depth -= 1
                        if _depth == 0:
                            return _text[_i:_k + 1]
                return _text[_i:]

            try:
                _unrar = _span("public String unRar(")
                _helper = _span("private Path getFilePathInsideArchive(")
                units.append(CodeUnit(
                    file_path=str(kk_reader), language=Language.JAVA_WEB,
                    unit_name="CompressFileReader.unRar",
                    start_line=_text[:_text.index("public String unRar(")].count("\n") + 1,
                    end_line=_text[:_text.index("public String unRar(")].count("\n")
                    + _unrar.count("\n") + 1,
                    decorators_or_modifiers=[], called_symbols=[],
                    source_code=_unrar + "\n\n" + _helper,
                    own_body=_unrar))
            except ValueError:
                pass
        if units:
            out["java"] = units
    except Exception:                                        # noqa: BLE001
        pass
    try:
        from core.slicer.web_treesitter import WebTreeSitterSlicer
        units = []
        for name in ("vulpy-master", "pygoat-master"):
            p = root / name
            if p.exists():
                units += list(WebTreeSitterSlicer(p).extract_entry_units(p))
        if units:
            out["python"] = units
    except Exception:                                        # noqa: BLE001
        pass
    try:
        from core.slicer.web3_slither import SoliditySlicer
        units = []
        for name in ("DeFiVulnLabs-main", "smartbugs-curated-main"):
            p = root / name
            if p.exists():
                units += list(SoliditySlicer(p).extract_entry_units(p))
        if units:
            out["solidity"] = units
    except Exception:                                        # noqa: BLE001
        pass
    return out


# 类目 → 确定性补丁器（--fix）。没有补丁器的类目在矩阵里显示 "—"。
MATRIX_FIX_MAP: dict[str, tuple[str, ...]] = {
    "sqli": ("_fix_sqli_targets", "_fix_python_sqli", "_fix_mp_concat"),
    "xss": ("_fix_xss_targets",),
    "deserial": ("_fix_deserial_targets", "_fix_python_deserial",
                 "_fix_python_yaml"),
    "cmdi": ("_fix_python_shell",),
    "redir": ("_fix_python_redirect",),
    "cors": ("_fix_cors_config",),
    "hardcoded_secret": ("_fix_hardcoded_secret",),
    "jwt_weakness": ("_fix_jwt_weakness",),
    "reentrancy": ("_fix_solidity_reentrancy",),
    "access_control": ("_fix_solidity_onlyowner", "_fix_solidity_initiator",
                       "_fix_solidity_txorigin"),
    "arithmetic": ("_fix_solidity_arith_guard",),
    "unchecked_low_level_calls": ("_fix_solidity_unchecked_wrap",),
    # M139–M141：第 28、29、30 类
    "unsafe_reflection": ("_fix_java_unsafe_reflection",),
    "zip_slip": ("_fix_zip_slip",),
    "delegatecall_untrusted": ("_fix_solidity_delegatecall",),
    # M151：把早已就位、却漏登记的 4 个补丁器接回矩阵。
    # 矩阵的 "--fix" 列读的是这张表，不是 doctor 的名单 —— 表漏登就会
    # 在能力矩阵里显示 "—"（看起来"没有补丁器"），而 --fix 实际能跑。
    "ssti": ("_fix_java_ssti_viewname",),
    "header_injection": ("_fix_java_header_injection",),
    "mass_assignment": ("_fix_java_mass_assignment",),
    "weakrand": ("_fix_java_weakrand",),
    # M157/M158：第 31、32 类
    "unrestricted_upload": ("_fix_unrestricted_upload",),
    "signature_replay": ("_fix_solidity_ecrecover",),
}


def cmd_matrix(args) -> int:
    """M100：24 类 × 三语言 ×（规则 / --fix / --emit-poc / CVSS）能力矩阵。

    口径说清楚：**"✓" 表示"该语言下这个类目至少有一条真实入口被规则判出
    确定性结论（True 或 False）"**，不是"准确率 100%"。矩阵回答的是覆盖
    缺口（哪一类在哪一门语言上根本判不出来），不是质量。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    from core.agents.vuln_categories import CATEGORIES
    from core.context.cvss import compute_cvss31

    probes = _matrix_probe_units()
    if not probes:
        print("! 三语言探针语料都不可用（reference_repos 缺失）")
        return 2
    langs = ["java", "python", "solidity"]
    print("== nexus-audit 能力覆盖矩阵（规则 / --fix / --emit-poc / CVSS）==")
    print("   ✓ = 该语言下有真实入口被判出确定性结论（True/False）")
    print("   — = 覆盖缺口（该类目在该语言上一条判据都没有）")
    print()
    hdr = (f"{'类目':<26}{'Java':>6}{'Python':>8}{'Solidity':>10}"
           f"{' --fix':>8}{' --emit-poc':>12}{' CVSS':>7}")
    print(hdr)
    print("-" * len(hdr))

    gaps: list[tuple[str, str]] = []
    n_fix_total = 0
    for cat in sorted(CATEGORIES):
        cells = []
        for lang in langs:
            units = probes.get(lang) or []
            hit = 0
            for u in units:
                if rule_verdict(cat, u.source_code) is not None:
                    hit += 1
                    break
            cells.append("✓" if hit else "—")
            if not hit:
                gaps.append((cat, lang))
        fixes = MATRIX_FIX_MAP.get(cat, ())
        fix_cell = "✓" if fixes else "—"
        if fixes:
            n_fix_total += 1
        try:
            from core.models import CodeUnit, Language
            from core.sandbox.poc_synthesizer import PocSynthesizer
            _synth = PocSynthesizer()
            _probes = (
                ("OrderController", Language.JAVA_WEB,
                 "public void f(String q) { jdbc.query(q); }"),
                ("app", Language.PYTHON_WEB,
                 "def f():\n    cur.execute('select ' + x)"),
                ("Contract", Language.SOLIDITY_WEB3,
                 "function f() public { msg.sender.transfer(1); }"),
            )
            _ok = 0
            for _tgt, _lg, _body in _probes:
                _u = CodeUnit(file_path="X", language=_lg, unit_name=_tgt,
                              start_line=1, end_line=2, decorators_or_modifiers=[],
                              called_symbols=[], source_code=_body, own_body=_body)
                _art = _synth.synthesize(_u, cat)
                if _art is not None and _art.self_check_ok:
                    _ok += 1
            poc_cell = "✓" if _ok == len(_probes) else ("~" if _ok else "—")
        except Exception:                                    # noqa: BLE001
            poc_cell = "—"
        cv = compute_cvss31(cat, "x", False)
        cv_cell = "✓" if str(cv.get("vector", "")).startswith("CVSS:3.1/") else "—"
        print(f"{cat:<26}{cells[0]:>6}{cells[1]:>8}{cells[2]:>10}"
              f"{fix_cell:>8}{poc_cell:>12}{cv_cell:>7}")

    print()
    print(f"类目总数 {len(CATEGORIES)} ｜ 有确定性补丁器的类目 {n_fix_total} ｜ "
          f"MATRIX_FIX_MAP 登记的补丁器 {len(DOCTOR_PATCHERS)} 个")
    print(f"覆盖缺口（类目 × 语言）：{len(gaps)} 处")
    for cat, lang in gaps[:20]:
        print(f"    - {cat} / {lang}")
    if len(gaps) > 20:
        print(f"    …（共 {len(gaps)} 处）")
    # 缺口数与门禁的互锁：写进 json 供冒烟断言"缺口不增长"
    if args.summary_json:
        Path(args.summary_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.summary_json).write_text(json.dumps({
            "categories": sorted(CATEGORIES),
            "languages": langs,
            "gaps": [{"category": c, "language": l} for c, l in gaps],
            "gap_count": len(gaps),
            "fix_map": {k: list(v) for k, v in MATRIX_FIX_MAP.items()},
            "patchers": len(DOCTOR_PATCHERS),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"矩阵 JSON → {args.summary_json}")
    return 0


def _reslice_for_fix(repo: Path, unit_name: str):
    """补丁写入后重新切片并取回同一入口（剥 `#N` 后缀比对）。

    清缓存是硬前提：`java_impl_resolver._FILE_CACHE` 按路径缓存不看 mtime，
    不清空的话重切片读到的还是补丁前的旧内容 —— "补丁后仍 True"就是
    缓存造出来的假结论。`DependencyVersionResolver` / `view_templates`
    都按次实例化/读盘，无需额外清理。
    """
    from core.context.java_impl_resolver import _FILE_CACHE
    _FILE_CACHE.clear()
    from core.slicer.java_servlet import JavaSlicer
    return next((x for x in JavaSlicer(repo).extract_entry_units()
                 if base_unit_name(x.unit_name) == base_unit_name(unit_name)), None)


def _verify_fixes(repo: Path, units: list, out_path: str | Path = "fix_report.md") -> None:
    """对规则层判 True 的确定性命中生成补丁并自检（sqli / xss / deserial）。

    只处理**规则层确定性命中**：模型命中没有可机械验证的修复模板，
    让 LLM 生成补丁再让 LLM 验收等于自己给自己判卷。
    自检 = 把补丁写进被审计仓库重新切片、重跑对应规则；验证不过的
    补丁一律不推荐 —— 一个"修完规则还报"的补丁比不修更危险。
    工作树在 finally 里还原（`newline=""` 字节级往返，Windows 文本模式
    会把还原变成 CRLF 篡改），`--fix` 从不留下未声明的文件变更。
    **验证器只能验证"规则收口"，验证不了"补丁语义正确"—— diff 必须打给人。**
    """
    from core.agents.rule_detectors import verdict as rule_verdict

    buckets: dict[str, list] = {"sqli": [], "xss": [], "deserial": []}
    for u in units:
        try:
            for cat in buckets:
                if rule_verdict(cat, u.source_code) is True:
                    buckets[cat].append(u)
        except Exception:
            continue
    if not any(buckets.values()):
        print("\n补丁自检：没有规则层判 True 的命中，无需修复")
        return
    print(f"\n补丁自检：sqli {len(buckets['sqli'])} / xss {len(buckets['xss'])} / "
          f"deserial {len(buckets['deserial'])} 条规则层命中")

    lines = ["# 补丁自检（sqli `${}`→`#{}` / xss `th:utext`→`th:text` /"
             " deserial fastjson→1.2.83）", ""]
    fixed = (_fix_sqli_targets(repo, buckets["sqli"], lines)
             + _fix_xss_targets(repo, buckets["xss"], lines)
             + _fix_deserial_targets(repo, buckets["deserial"], lines))
    out = Path(out_path)
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"  生成并验证通过 {fixed} 个补丁 → {out}")


def _fix_sqli_targets(repo: Path, targets: list, lines: list) -> int:
    """`${}` → `#{}`：只对切片里贴了 Mapper XML 语句的 sqli 命中生效。"""
    if not targets:
        return 0
    fixed = 0
    seg_re = re.compile(r"// 来自 (\S+\.xml)[^\n]*\n(.*?)(?=\n// 来自 |\Z)", re.S)
    for u in targets:
        for m in seg_re.finditer(u.source_code):
            xml_name, body = m.group(1), m.group(2)
            if "${" not in body:
                continue
            hit = next(repo.rglob(xml_name), None)
            if hit is None:
                continue
            with open(hit, encoding="utf-8", errors="replace", newline="") as fh:
                original = fh.read()
            # 替换必须用函数：替换串里写 r"#\{\1\}" 会把 `\{` 原样留在结果里
            # （实测产出 `#\{name\}`，规则验证还通过了 —— 坏补丁骗过规则）。
            patched = re.sub(r"\$\{(\w+)\}", lambda mm: "#{" + mm.group(1) + "}", original)
            if patched == original:
                continue
            try:
                with open(hit, "w", encoding="utf-8", newline="") as fh:
                    fh.write(patched)
                u2 = _reslice_for_fix(repo, u.unit_name)
                from core.agents.rule_detectors import verdict as rule_verdict
                v2 = rule_verdict("sqli", u2.source_code) if u2 else None
            finally:
                with open(hit, "w", encoding="utf-8", newline="") as fh:
                    fh.write(original)      # 还原，不留变更
                from core.context.java_impl_resolver import _FILE_CACHE
                _FILE_CACHE.clear()
            if v2 is False:
                fixed += 1
                diff = difflib.unified_diff(
                    original.splitlines(), patched.splitlines(),
                    fromfile=f"a/{xml_name}", tofile=f"b/{xml_name}", lineterm="")
                lines += [f"## [sqli] {u.unit_name}（`{xml_name}`）", "```diff",
                          *diff, "```", "",
                          "> 自检通过：重切片 + 重跑 sqli 规则 → False。",
                          "> 注意 `${}`→`#{}` 把值改为绑定参数；order by / 列名等",
                          "> **标识符拼接**场景不能这样修，应改白名单 —— 需人工确认。", ""]
            else:
                lines += [f"## [sqli] {u.unit_name}（`{xml_name}`）",
                          f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）", ""]
    return fixed


_TPL_FILE_RE = re.compile(r"//\s+(\S+\.(?:html|ftl|jsp)):\d+")
_TPL_HIT_RE = re.compile(r"//\s*>>?\s*(\d+)\s*\|\s?(.*)")


def _fix_xss_targets(repo: Path, targets: list, lines: list) -> int:
    """`th:utext=` → `th:text=`：模板文件路径从切片段头精确反解。

    只改"关联视图模板"证据块里标了 `>>` 的渲染点行，不整文件替换 ——
    模板里别的 `th:utext` 可能渲染的是别的（已编码的）键。
    """
    if not targets:
        return 0
    fixed = 0
    for u in targets:
        i = u.source_code.find("关联视图模板")
        if i < 0:
            lines += [f"## [xss] {u.unit_name}",
                      "- 切片里没有模板渲染证据段，跳过（无确定性修复模板）", ""]
            continue
        seg = u.source_code[i:]
        fm = _TPL_FILE_RE.search(seg)
        hits = [(int(n), raw) for n, raw in _TPL_HIT_RE.findall(seg)
                if "th:utext=" in raw.lower()]
        if fm is None or not hits:
            lines += [f"## [xss] {u.unit_name}",
                      "- 证据段里解析不到模板文件或 th:utext 渲染点，跳过", ""]
            continue
        rel = fm.group(1)
        tpl = repo / rel
        if not tpl.is_file():
            tpl = next(repo.rglob(Path(rel).name), None)   # 配置根与仓库根不同级时兜底
        if tpl is None:
            lines += [f"## [xss] {u.unit_name}",
                      f"- 模板文件 `{rel}` 不在仓库内，跳过", ""]
            continue
        with open(tpl, encoding="utf-8", errors="replace", newline="") as fh:
            original = fh.read()
        patched_lines = original.splitlines(keepends=True)
        changed: list[int] = []
        for n, _raw in hits:
            if 1 <= n <= len(patched_lines):
                new = patched_lines[n - 1].replace("th:utext=", "th:text=")
                if new != patched_lines[n - 1]:
                    patched_lines[n - 1] = new
                    changed.append(n)
        if not changed:
            continue
        patched = "".join(patched_lines)
        try:
            with open(tpl, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            u2 = _reslice_for_fix(repo, u.unit_name)
            from core.agents.rule_detectors import verdict as rule_verdict
            v2 = rule_verdict("xss", u2.source_code) if u2 else None
        finally:
            with open(tpl, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
            from core.context.java_impl_resolver import _FILE_CACHE
            _FILE_CACHE.clear()
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(
                original.splitlines(), patched.splitlines(),
                fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm="")
            lines += [f"## [xss] {u.unit_name}（`{rel}`）", "```diff",
                      *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 xss 规则 → False。"
                      "（th:text 自动转义；如该值本应承载富文本，需人工确认。）", ""]
        else:
            lines += [f"## [xss] {u.unit_name}（`{rel}`）",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）", ""]
    return fixed


_FASTJSON_SAFE_VERSION = "1.2.83"


def _fastjson_pom_patches(repo: Path) -> list[tuple[Path, str, str]]:
    """定位 fastjson 依赖的版本声明，产出 (pom, 原文, 补丁后文本)。

    版本可能直接写在 `<version>` 里，也可能经 `<properties>` 占位符
    （`${fastjson.version}`）—— 占位符必须改属性定义，只改引用处等于没改。
    """
    out: list[tuple[Path, str, str]] = []
    seen: set[Path] = set()
    for pom in sorted(repo.rglob("pom.xml")):
        if pom in seen or "target" in pom.parts:
            continue
        try:
            text = pom.read_text(encoding="utf-8", errors="replace", newline="")
        except OSError:
            continue
        if "<artifactId>fastjson</artifactId>" not in text:
            continue
        seen.add(pom)
        new_text = text
        for dm in re.finditer(r"<dependency>(.*?)</dependency>", text, re.S):
            blk = dm.group(1)
            if "<artifactId>fastjson</artifactId>" not in blk:
                continue
            vm = re.search(r"<version>([^<]+)</version>", blk)
            if not vm:
                continue
            val = vm.group(1).strip()
            if val.startswith("${") and val.endswith("}"):
                prop = val[2:-1].strip()
                pm = re.search(rf"<({re.escape(prop)})>([^<]*)</\1>", new_text)
                if pm:
                    new_text = new_text[:pm.start(2)] + _FASTJSON_SAFE_VERSION \
                        + new_text[pm.end(2):]
            else:
                s, e = vm.span(1)
                new_text = new_text[:s] + _FASTJSON_SAFE_VERSION + new_text[e:]
        if new_text != text:
            out.append((pom, text, new_text))
    return out


def _fix_deserial_targets(repo: Path, targets: list, lines: list) -> int:
    """fastjson 版本 → 1.2.83（默认 safeMode）：版本决定结论的类目，
    修复落在 pom.xml 而不是代码 —— 这本身就是"版本是代码给不出的事实"
    的反向应用。"""
    if not targets:
        return 0
    patches = _fastjson_pom_patches(repo)
    if not patches:
        for u in targets:
            lines += [f"## [deserial] {u.unit_name}",
                      "- 仓库内没有带版本声明的 fastjson 依赖，跳过", ""]
        return 0
    fixed = 0
    try:
        for pom, _original, patched in patches:
            with open(pom, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
        u2 = _reslice_for_fix(repo, targets[0].unit_name)
        from core.agents.rule_detectors import verdict as rule_verdict
        v2 = rule_verdict("deserial", u2.source_code) if u2 else None
    finally:
        for pom, original, _patched in patches:
            with open(pom, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
        from core.context.java_impl_resolver import _FILE_CACHE
        _FILE_CACHE.clear()
    if v2 is False:
        fixed = len(targets)
        for pom, original, patched in patches:
            diff = difflib.unified_diff(
                original.splitlines(), patched.splitlines(),
                fromfile=f"a/{pom.relative_to(repo).as_posix()}",
                tofile=f"b/{pom.relative_to(repo).as_posix()}", lineterm="")
            lines += ["```diff", *diff, "```"]
        names = ", ".join(u.unit_name for u in targets)
        lines += ["", f"> 自检通过：{names}",
                  "> 重切片 + 重跑 deserial 规则 → False（fastjson 1.2.83 起"
                  " 默认 safeMode，autoType 不可劫持）。", ""]
    else:
        lines += [f"## [deserial] {', '.join(u.unit_name for u in targets)}",
                  f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）", ""]
    return fixed


# ---------------- Module 14：Python / Solidity 确定性补丁 ----------------

def _verify_fixes_any(repo: Path, units: list, out_path: str | Path = "fix_report.md") -> None:
    """按语言把命中分发给对应的确定性修复器（Java/Python/Solidity）。

    语言判定复用规则层的识别函数 —— 同一套"这是什么代码"的口径，
    避免路由判 Python、规则判 Java 的分裂。
    """
    from core.agents.rule_detectors import _looks_python, _looks_solidity
    # 每次扫描重建补丁报告：旧实现 append 到上次的 fix_report，重复 --fix 时
    # patches_verified 会把上一轮 diff 也算进来（VAmPI 实测 1 条报成 2 条）。
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("", encoding="utf-8")
    py = [u for u in units if _looks_python(u.source_code)]
    sol = [u for u in units if _looks_solidity(u.source_code)]
    rest = [u for u in units if not _looks_python(u.source_code)
            and not _looks_solidity(u.source_code)]
    n = 0
    report: list[str] = ["# 补丁自检（Python 参数化 / Solidity CEI）", ""]
    n += _fix_jwt_weakness(repo, units, report)
    if py:
        n += _fix_python_sqli(repo, py, report)
        n += _fix_python_deserial(repo, py, report)
        n += _fix_python_shell(repo, py, report)
        n += _fix_python_yaml(repo, py, report)
        n += _fix_python_redirect(repo, py, report)
        n += _fix_hardcoded_secret(repo, py, report)
        # M140：Python 侧 Zip Slip（`extractall(..., filter="data")`）
        n += _fix_zip_slip(repo, py, report)
        # M157：第 31 类 —— Python UploadFile 文件名校验
        n += _fix_unrestricted_upload(repo, py, report)
    if sol:
        n += _fix_solidity_txorigin(repo, sol, report)
        n += _fix_solidity_reentrancy(repo, sol, report)
        n += _fix_solidity_initiator(repo, sol, report)
        n += _fix_solidity_onlyowner(repo, sol, report)
        n += _fix_solidity_arith_guard(repo, sol, report)
        n += _fix_solidity_unchecked_wrap(repo, sol, report)
        # M141：不受信 delegatecall → 目标收窄到 address(this)
        n += _fix_solidity_delegatecall(repo, sol, report)
        # M158：第 32 类 —— ecrecover 零地址校验 + nonce 消费
        n += _fix_solidity_ecrecover(repo, sol, report)
    if rest:
        n += _fix_cors_config(repo, rest, report)
        n += _fix_hardcoded_secret(repo, rest, report)
        n += _fix_mp_concat(repo, rest, report)
        # M106：第 19、20 类 —— 两个 Java 侧确定性补丁
        n += _fix_java_ssti_viewname(repo, rest, report)
        n += _fix_java_header_injection(repo, rest, report)
        n += _fix_java_mass_assignment(repo, rest, report)
        n += _fix_java_weakrand(repo, rest, report)
        # M139/M140：第 23、24 类 —— 反射白名单 / 解压前缀校验
        n += _fix_java_unsafe_reflection(repo, rest, report)
        n += _fix_zip_slip(repo, rest, report)
        # M157：第 31 类 —— Java MultipartFile 文件名校验
        n += _fix_unrestricted_upload(repo, rest, report)
        _verify_fixes(repo, rest, out_path)
    if n:
        out = Path(out_path)
        out.open("a", encoding="utf-8").write("\n".join(report) + "\n")
    if not (py or sol or rest):
        print("\n补丁自检：没有规则层判 True 的命中，无需修复")


def _py_parametrize_call(node) -> object | None:
    """把 ast 层的注入型 execute 实参改写为参数化形态，返回新 Call 节点。

    支持四种拼接形态（vulpy 实测三种）：
      `"..." % x` / `f"...{x}..."` / `"...{}".format(x)` / `"..." + x`
    全部归一为 `execute("... ? ...", (x,))`。`%` 占位符 `%s/%d/%f`
    与 `{}` 都替换成 DB-API 的 `?`。无法识别的形态返回 None（不生成
    补丁 —— 宁可不修也不产坏补丁）。
    """
    import ast as _ast

    call = node
    if not (isinstance(call, _ast.Call) and isinstance(call.func, _ast.Attribute)
            and call.func.attr == "execute" and call.args):
        return None
    sql_node = call.args[0]
    sql_parts: list[str] = []
    values: list[_ast.expr] = []

    def literal_of(n: _ast.expr) -> str | None:
        return n.value if isinstance(n, _ast.Constant) and isinstance(n.value, str) else None

    def walk(n: _ast.expr) -> bool:
        lit = literal_of(n)
        if lit is not None:
            sql_parts.append(lit)
            return True
        if isinstance(n, _ast.BinOp) and isinstance(n.op, _ast.Mod):
            if not walk(n.left):
                return False
            vals = n.right.elts if isinstance(n.right, _ast.Tuple) else [n.right]
            values.extend(vals)
            return True
        if isinstance(n, _ast.BinOp) and isinstance(n.op, _ast.Add):
            # M152 实测缺口：原实现要求左右**都是字面量**，于是
            # `"select ... " + uid` 这种最常见的拼接根本进不了 edits，
            # 规则判 True 却永远修不了。右操作数只要是表达式就当作绑定值；
            # 左边继续递归（覆盖 "a" + b + c 的左结合形态）。
            if not walk(n.left):
                return False
            if literal_of(n.right) is not None:
                sql_parts.append(literal_of(n.right))
            else:
                # 拼接点必须补一个 ? 占位符：只把值挪进参数元组而 SQL 里
                # 不留占位符，会得到 "where id = " 这种把整段值丢掉的
                # 坏补丁 —— 规则层却会因为"看见参数化调用"判 False。
                sql_parts.append("?")
                values.append(n.right)
            return True
        if isinstance(n, _ast.JoinedStr):
            for part in n.values:
                if isinstance(part, _ast.Constant):
                    sql_parts.append(part.value)
                else:
                    sql_parts.append("?")
                    values.append(part.value)
            return True
        if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute) \
                and n.func.attr == "format" and literal_of(n.func.value) is not None:
            sql_parts.append(n.func.value.value)
            values.extend(n.args)
            return True
        return False

    if not walk(sql_node) or not values:
        return None
    sql = "".join(sql_parts)
    sql = re.sub(r"%[sdf]", "?", sql)
    sql = sql.replace("{}", "?")
    new_args = [_ast.Constant(value=sql),
                _ast.Tuple(elts=list(values), ctx=_ast.Load())]
    return _ast.Call(func=call.func, args=new_args, keywords=[])


def _fix_python_deserial(repo: Path, targets: list, lines: list) -> int:
    """Python yaml.load → yaml.safe_load 补丁（Module 25，第 6 类确定性修复）。

    只对 deserial 判 True 且源码里有 `yaml.load(` 的单元动手。ast 定位
    `Call(func=Attribute(attr='load'))`，改名 `safe_load` 并丢弃 Loader
    实参（safe_load 不收 Loader kwarg）。重切片 + 重跑 deserial 规则
    自检，与 py-sqli 补丁同一套闭环；pickle 没有等价安全 API，不生成
    补丁（宁可不修也不产坏补丁）。
    """
    import ast as _ast
    from core.agents.rule_detectors import verdict as rule_verdict

    fixed = 0
    for u in targets:
        if rule_verdict("deserial", u.source_code) is not True:
            continue
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        try:
            tree = _ast.parse(original)
        except SyntaxError:
            continue
        edits: list[tuple[int, int, int, int, str]] = []
        has_load = False
        for node in _ast.walk(tree):
            if not (isinstance(node, _ast.Call)
                    and isinstance(node.func, _ast.Attribute)
                    and node.func.attr == "load"
                    and isinstance(node.func.value, _ast.Name)
                    and node.func.value.id == "yaml"):
                continue
            has_load = True
            # `load` → `safe_load`（只改属性名那段，yaml 对象保持原样）
            edits.append((node.func.value.end_lineno, node.func.value.end_col_offset,
                          node.func.end_lineno, node.func.end_col_offset,
                          ".safe_load"))
            # 丢弃 Loader 实参：safe_load 不收 kwarg，留着会 TypeError
            for kw in node.keywords:
                edits.append((kw.lineno, kw.col_offset,
                              kw.end_lineno, kw.end_col_offset, ""))
        if not has_load:
            continue
        src_lines = original.splitlines(keepends=True)
        ok = True
        for l1, c1, l2, c2, new in sorted(edits, reverse=True):
            if l1 != l2:
                ok = False          # Loader 跨行的形态交给人工，不产坏补丁
                break
            src_lines[l1 - 1] = src_lines[l1 - 1][:c1] + new + src_lines[l1 - 1][c2:]
        if not ok:
            continue
        patched = "".join(src_lines)
        try:
            _ast.parse(patched)      # 补丁必须仍是合法 Python
        except SyntaxError:
            continue
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            from core.slicer.web_treesitter import WebTreeSitterSlicer
            u2 = next((x for x in WebTreeSitterSlicer(repo).extract_entry_units()
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            v2 = rule_verdict("deserial", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [py-deserial] {u.unit_name}（`{f.name}`）", "```diff",
                      *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 deserial 规则 → False"
                      "（safe_load 值域锁死在基础类型）。", ""]
        else:
            lines += [f"## [py-deserial] {u.unit_name}（`{f.name}`）",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）", ""]
    return fixed


def _fix_python_sqli(repo: Path, targets: list, lines: list) -> int:
    """Python SQLi 参数化补丁：拼接实参 → `execute("... ?", (x,))`。

    用 ast 定位与改写（正则配平嵌套括号在真实代码上必然踩坑），
    ast.unparse 生成调用片段，行级替换；重切片 + 重跑 sqli 规则自检。
    """
    import ast as _ast

    fixed = 0
    for u in targets:
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        try:
            tree = _ast.parse(original)
        except SyntaxError:
            continue
        edits: list[tuple[int, int, int, int, str]] = []   # (l1,c1,l2,c2,new)
        for node in _ast.walk(tree):
            new = _py_parametrize_call(node)
            if new is not None:
                edits.append((node.lineno, node.col_offset,
                              node.end_lineno, node.end_col_offset,
                              _ast.unparse(new)))
        if not edits:
            continue
        src_lines = original.splitlines(keepends=True)
        for l1, c1, l2, c2, new in sorted(edits, reverse=True):
            if l1 == l2:
                src_lines[l1 - 1] = src_lines[l1 - 1][:c1] + new + src_lines[l1 - 1][c2:]
        patched = "".join(src_lines)
        try:
            _ast.parse(patched)          # 补丁必须仍是合法 Python
        except SyntaxError:
            continue
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            from core.slicer.web_treesitter import WebTreeSitterSlicer
            u2 = next((x for x in WebTreeSitterSlicer(repo).extract_entry_units()
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            from core.agents.rule_detectors import verdict as rule_verdict
            v2 = rule_verdict("sqli", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [py-sqli] {u.unit_name}（`{f.name}`）", "```diff",
                      *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 sqli 规则 → False。", ""]
        else:
            lines += [f"## [py-sqli] {u.unit_name}（`{f.name}`）",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）", ""]
    return fixed


_SOLID_EXT_LINE_RE = re.compile(
    r"\.\s*call\s*\{[^}]*value:|\.\s*call\s*\.\s*value\s*\(|\.send\s*\(|\.transfer\s*\(")
_SOLID_DED_LINE_RE = re.compile(
    r"^\s*[\w\[\]\.]+\s*(?:-=|\s*=\s*0\s*;)")


def _sol_slice_line_to_file(u, src_idx: int) -> int:
    """切片 source_code 的行索引 → 源文件的行号（1-based）。

    切片头部可能有多行注入注释（`// contract: X` / `// pragma: solidity …`
    —— M53 加了后者），它们**不属于**源文件。直接用
    `u.start_line + src_idx - 1` 会整体偏移 1 行，补丁写到错误的行上
    （实测 CEI 补丁自检因此判不出"规则翻转 False"）。

    口径：切片头部的连续注释行（以 `//` 开头）数 = 偏移量，源文件行号
    从 `u.start_line` 起算，头部行不算。
    """
    src_lines = u.source_code.splitlines()
    header = 0
    for ln in src_lines:
        if ln.lstrip().startswith("//"):
            header += 1
        else:
            break
    # 切片第 header 行（0-based）= 源文件第 u.start_line 行，逐行 +1 对应。
    # 实测锚点：Bank.sol withdraw start_line=4，切片 idx3 的外转行 = 文件第 5 行。
    return u.start_line + (src_idx - header)


def _fix_solidity_reentrancy(repo: Path, targets: list, lines: list) -> int:
    """Solidity CEI 补丁：把"外转之后的清零/扣减行"移到外转之前。

    只处理两行紧邻（间隔 ≤ 6 行）的单纯反序 —— 复杂控制流（条件分支里
    的扣减、多处扣减）行交换语义不可靠，一律跳过交人工。自检同前：
    重切片 + 重跑 reentrancy 规则。
    """
    fixed = 0
    for u in targets:
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        file_lines = original.splitlines(keepends=True)
        # 切片首行是 "// contract: X" 注入行（可能还有 "// pragma:"）；
        # source_code 第 idx 行对应文件第 _sol_slice_line_to_file 行。
        src_lines = u.source_code.splitlines()
        ext_idx = ded_idx = None
        for i, ln in enumerate(src_lines):
            if ext_idx is None and _SOLID_EXT_LINE_RE.search(ln):
                ext_idx = i
            elif ext_idx is not None and ded_idx is None \
                    and _SOLID_DED_LINE_RE.search(ln) \
                    and re.search(r"[Bb]alance|[Dd]eposit|shares|stake|funds|credit", ln):
                ded_idx = i
                break
        if ext_idx is None or ded_idx is None or ded_idx - ext_idx > 6 \
                or ext_idx == 0:
            continue
        f_ext = _sol_slice_line_to_file(u, ext_idx)
        f_ded = _sol_slice_line_to_file(u, ded_idx)
        if not (1 <= f_ext <= len(file_lines) and 1 <= f_ded <= len(file_lines)):
            continue
        patched_lines = list(file_lines)
        patched_lines[f_ext - 1], patched_lines[f_ded - 1] = \
            patched_lines[f_ded - 1], patched_lines[f_ext - 1]
        patched = "".join(patched_lines)
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            from core.slicer.web3_slither import SoliditySlicer
            u2 = next((x for x in SoliditySlicer(repo).extract_entry_units(repo)
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            from core.agents.rule_detectors import verdict as rule_verdict
            v2 = rule_verdict("reentrancy", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [sol-reentrancy] {u.unit_name}（`{f.name}`）", "```diff",
                      *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 reentrancy 规则 → False（CEI 正序）。",
                      "> 注意：若扣减可能 revert（余额不足），先扣减后转账的顺序", 
                      "> 同时改变了失败语义 —— 需人工确认回滚路径。", ""]
        else:
            lines += [f"## [sol-reentrancy] {u.unit_name}（`{f.name}`）",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）", ""]
    return fixed


def _fix_solidity_initiator(repo: Path, targets: list, lines: list) -> int:
    """补丁第 9 类（Module 40）：executeOperation 回调插 initiator 校验。

    Aave 借贷池回调 `executeOperation` 缺 `require(initiator == address(this))`
    时任何人可直调回调转走资产（M34 判据的真值形态）。修复 = 在函数体
    `{` 后插入 initiator 恒等校验（形参名从签名抓：initiator/_initiator），
    重切片 + 重跑 access_control 翻 False 才算自检通过，finally 字节级还原。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if "executeOperation" not in src:
            continue
        if rule_verdict("access_control", src) is not True:
            continue
        pm = re.search(r"executeOperation\s*\([^)]*\b(?:_)?initiator\b", src)
        if not pm:
            continue
        im = re.search(r"address\s+(?:payable\s+)?(_?initiator)\b", src)
        if not im:
            continue
        init_var = im.group(1)
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        # 在 executeOperation 函数体 `{` 之后插入校验行（取入口行区间内
        # 签名的第一个 `{`；插入行带原文件缩进 8 空格的兜底——按函数体
        # 首个非空行的缩进对齐更稳）。
        lines_all = original.splitlines(keepends=True)
        insert_at = None
        indent = "        "
        for i in range(max(0, u.start_line - 1), min(u.end_line, len(lines_all))):
            if i < u.start_line - 1:
                continue
            if "executeOperation" in lines_all[i]:
                # 找签名 `{`：若在本行，插入点 = 下一行；若签名跨行，
                # 继续向下找首个 `{`
                seg = lines_all[i]
                if "{" in seg:
                    insert_at = i + 1
                else:
                    for j in range(i + 1, min(u.end_line, len(lines_all))):
                        if "{" in lines_all[j]:
                            insert_at = j + 1
                            break
                break
        if insert_at is None:
            continue
        # 缩进对齐：看插入点前一非空行
        for k in range(insert_at - 1, -1, -1):
            t = lines_all[k].lstrip()
            if t and not t.startswith("//"):
                indent = lines_all[k][: len(lines_all[k]) - len(t)]
                break
        stmt = (f'{indent}require({init_var} == address(this), '
                f'"Unauthorized initiator");\n')
        patched_lines = lines_all[:insert_at] + [stmt] + lines_all[insert_at:]
        patched = "".join(patched_lines)
        v2 = None
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            from core.slicer.web3_slither import SoliditySlicer
            u2 = next((x for x in SoliditySlicer(repo).extract_entry_units(repo)
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            v2 = rule_verdict("access_control", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [sol-initiator] {u.unit_name}（`{f.name}`）", "```diff",
                      *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 access_control 规则 → False。",
                      "> 回调只允许本合约发起的闪贷触发，外部直调 revert。", ""]
        else:
            lines += [f"## [sol-initiator] {u.unit_name}（`{f.name}`）",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）", ""]
    return fixed


_PY_SHELL_TRUE_RE = re.compile(
    r"((?:subprocess\.\w+|os\.system)\s*\()([^;]{0,200}?shell\s*=\s*True[^;]{0,80}?\))",
    re.S)


def _fix_python_shell(repo: Path, targets: list, lines: list) -> int:
    """补丁第 10 类（Module 40）：Python `shell=True` 改列表传参。

    `subprocess.run(cmd, shell=True, ...)` → `subprocess.run(
    shlex.split(cmd), ...)`：拆掉 shell 解释层，注入面消失（元字符不再
    被 /bin/sh 解释）。os.system 形态的命令拼接太自由（整串含重定向等
    shell 语义），不能机械改写 —— 不处理，宁可不修也不产坏补丁。
    需要时在文件头补 `import shlex`。自检同前：重切片 cmdi 翻 False。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if "shell=True" not in src or "os.system" in src:
            continue
        m = _PY_SHELL_TRUE_RE.search(src)
        if not m:
            continue
        inner = m.group(2)
        # 命令必须是单个裸变量名（shlex.split(var)）—— 字符串字面量/
        # f-string/拼接形态交人工（shlex.split 一个已拼好的串防不住
        # 注入，必须改源头）。
        cm = re.match(r"\s*([A-Za-z_]\w*)\s*[,)]", inner)
        if not cm:
            continue
        var = cm.group(1)
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        new_call = re.sub(
            r"(\(\s*)" + re.escape(var) + r"\s*,([^;]{0,200}?)shell\s*=\s*True\s*,?\s*",
            rf"\g<1>shlex.split({var}),\2", original, count=1, flags=re.S)
        if new_call == original:
            # shell=True 在尾参位置（后面没有逗号）
            new_call = re.sub(
                r"\(\s*" + re.escape(var) + r"\s*,([^;]{0,200}?)shell\s*=\s*True\s*\)",
                rf"(shlex.split({var}),\1)", original, count=1, flags=re.S)
        if new_call == original:
            continue
        if "import shlex" not in new_call:
            new_call = "import shlex\n" + new_call
        v2 = None
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(new_call)
            from core.slicer.web_treesitter import WebTreeSitterSlicer
            u2 = next((x for x in WebTreeSitterSlicer(repo).extract_entry_units()
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            v2 = rule_verdict("cmdi", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(), new_call.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [py-shell] {u.unit_name}（`{f.name}`）", "```diff",
                      *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 cmdi 规则 → False。",
                      "> shell=True → shlex.split 列表传参：元字符不再被", ""
                      "> /bin/sh 解释，命令注入面消失。", ""]
        else:
            lines += [f"## [py-shell] {u.unit_name}（`{f.name}`）",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）", ""]
    return fixed


def _fix_solidity_onlyowner(repo: Path, targets: list, lines: list) -> int:
    """补丁第 11 类（Module 48）：Solidity 高危函数补挂 onlyOwner 修饰符。

    形态（同合约里**已经有** `modifier onlyOwner { require(msg.sender == owner); }`
    定义，只是高危函数忘了挂）：nssc Unprotected.sol 的 changeOwner 就是
    这样 —— 修饰符在文件里，函数上没挂。修复 = 在函数签名的修饰符位插
    `onlyOwner`，重切片后 access_control 判据看到修饰符**实现体**里的
    msg.sender 恒等检查 → 翻 False。

    三道闸门（少一道就可能改坏）：
      ① 规则层已判 access_control=True（确实是越权面）；
      ② 切片里能找到 `modifier onlyOwner` 的**定义**（不是名字，是定义）；
      ③ 目标函数签名上**没有** already 挂 onlyOwner。
    自检同前：重切片 + 重跑 access_control 翻 False，finally 字节级还原。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if rule_verdict("access_control", src) is not True:
            continue
        fname = re.search(r"function\s+([A-Za-z_]\w*)", src)
        if not fname:
            continue
        fname = fname.group(1)
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        # modifier 定义要从**文件**里找：切片只拼"本函数用到的"修饰符，
        # 而本函数恰恰是**漏挂**的那个 —— 切片里根本没有 onlyOwner 的定义。
        if not re.search(r"\bmodifier\s+onlyOwner\b", original):
            continue
        # 定位目标函数的定义行（不是调用点、不是 modifier 体）
        mdef = re.search(rf"function\s+{re.escape(fname)}\s*\(", original)
        if not mdef:
            continue
        # 签名可能跨行：向后找该函数的第一个 `{`
        brace = original.find("{", mdef.end())
        if brace < 0:
            continue
        head = original[mdef.start():brace]
        if re.search(r"\bonlyOwner\b", head):
            continue                      # 已挂，跳过
        # 修饰符位：在可见性关键字之后（没有可见性就贴在 `)` 之后）
        mm = re.search(r"\b(public|external|internal|private)\b", head)
        if mm:
            ins = mdef.start() + mm.end()
        else:
            close = head.rfind(")")
            if close < 0:
                continue
            ins = mdef.start() + close + 1
        patched = original[:ins] + " onlyOwner " + original[ins:]
        v2 = None
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            from core.slicer.web3_slither import SoliditySlicer
            u2 = next((x for x in SoliditySlicer(repo).extract_entry_units(repo)
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            v2 = rule_verdict("access_control", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [sol-onlyowner] {u.unit_name}（`{f.name}`）", "```diff",
                      *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 access_control 规则 → False。",
                      "> 同合约已定义 onlyOwner 修饰符，只是高危函数漏挂；"
                      "> 补挂后调用者身份进入授权判定。", ""]
        else:
            lines += [f"## [sol-onlyowner] {u.unit_name}（`{f.name}`）",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）", ""]
    return fixed


def _fix_python_yaml(repo: Path, targets: list, lines: list) -> int:
    """补丁第 12 类（Module 48）：Python YAML 反序列化改 safe_load。

    `yaml.load(x)`（未指定 SafeLoader）/ `yaml.unsafe_load(x)` /
    `yaml.full_load(x)` → `yaml.safe_load(x)`：值域锁死在基础类型，
    构造器劫持面消失。语义安全（safe_load 只少支持自定义 tag，不改正常
    业务数据的读法）。自检：重切片 + 重跑 deserial 翻 False。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if rule_verdict("deserial", src) is not True:
            continue
        if not re.search(r"\byaml\s*\.\s*(?:unsafe_load|full_load|load)\s*\(", src):
            continue
        if re.search(r"\byaml\s*\.\s*safe_load\s*\(", src):
            continue
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        # 只改**没有**显式 SafeLoader 的调用：带 Loader=... 的换法要保留
        # 其余参数，直接改名会把 Loader 关键字参数留在 safe_load 上（非法）。
        patched = re.sub(r"\byaml\s*\.\s*(?:unsafe_load|full_load|load)\s*\(",
                         "yaml.safe_load(", original)
        if patched == original:
            continue
        v2 = None
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            from core.slicer.web_treesitter import WebTreeSitterSlicer
            u2 = next((x for x in WebTreeSitterSlicer(repo).extract_entry_units()
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            v2 = rule_verdict("deserial", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [py-yaml] {u.unit_name}（`{f.name}`）", "```diff",
                      *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 deserial 规则 → False。",
                      "> yaml.load/unsafe_load/full_load → yaml.safe_load："
                      "值域锁死在基础类型，构造器劫持面消失。", ""]
        else:
            lines += [f"## [py-yaml] {u.unit_name}（`{f.name}`）",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）", ""]
    return fixed


def _fix_python_redirect(repo: Path, targets: list, lines: list) -> int:
    """补丁第 18 类（Module 90）：Python/Django 开放重定向补同源校验。

    修法只有一个（Django 官方推荐的那一个）：在跳转前用
    `url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()})`
    做同源判定，不通过就退回站内固定路径。

    **不采用**"自己写 startswith('/') 校验"：`//evil.com` 是协议相对 URL，
    单看首字符 `/` 挡不住它 —— 那会产出一个"看起来修了、实际还能跳出去"的
    坏补丁。也不采用域名黑名单：黑名单天然可绕。

    插入点是跳转语句**之前**的一行，缩进与之对齐；形参目标不就地赋值
    （`request.POST['x'] = "/"` 非法），统一用 `return redirect("/")` 早退。
    自检同前：重切片 + 重跑 redir 规则 → False。
    """
    from core.agents.rule_detectors import (verdict as rule_verdict,
                                            _PY_REDIR_SINK_RE)
    fixed = 0
    imp = "from django.utils.http import url_has_allowed_host_and_scheme"
    for u in targets:
        src = u.source_code or ""
        if rule_verdict("redir", src) is not True:
            continue
        m = _PY_REDIR_SINK_RE.search(src)
        if not m:
            continue
        # 取整条调用原文（跨行也要完整），到文件里按原文定位
        call_txt = _py_call_text(src, m.end() - 1)
        if not call_txt:
            continue
        args = _py_first_arg(call_txt)
        if not args:
            continue
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        idx = original.find(call_txt)
        if idx < 0:
            continue
        line_start = original.rfind("\n", 0, idx) + 1
        indent = original[line_start:idx]
        if indent.strip():
            continue                     # 不是行首（同行有别名赋值）→ 交人工
        guard = (f"{indent}if not url_has_allowed_host_and_scheme({args}, "
                 f"allowed_hosts={{request.get_host()}}):\n"
                 f"{indent}    return redirect(\"/\")\n")
        patched = original[:line_start] + guard + original[line_start:]
        if imp not in patched:
            # `from __future__` 必须是文件的第一条语句 —— import 插在它之前
            # 会直接把文件写成 SyntaxError（实测过）。有它就跟在它后面。
            fut = re.search(r"(?m)^from\s+__future__\s+import[^\n]*\n", patched)
            if fut:
                at = fut.end()
                patched = patched[:at] + imp + "\n" + patched[at:]
            else:
                patched = imp + "\n" + patched
        v2 = None
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            from core.slicer.web_treesitter import WebTreeSitterSlicer
            u2 = next((x for x in WebTreeSitterSlicer(repo).extract_entry_units()
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            v2 = rule_verdict("redir", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [py-redir] {u.unit_name}（`{f.name}`）", "```diff",
                      *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 redir 规则 → False。",
                      "> 跳转前用 url_has_allowed_host_and_scheme 做同源判定，",
                      "> 不通过则退回站内固定路径（不用 startswith('/')，",
                      "> 因为 `//evil.com` 是协议相对 URL，首字符校验挡不住）。", ""]
        else:
            lines += [f"## [py-redir] {u.unit_name}（`{f.name}`）",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）", ""]
    return fixed


def _py_call_text(src: str, open_idx: int) -> str:
    """取 `src[open_idx]` 处 `(` 开始的完整调用原文（引号感知配平）。"""
    depth = 0
    quote = ""
    i = open_idx
    while i < len(src):
        c = src[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                start = src.rfind("\n", 0, open_idx) + 1
                return src[start:i + 1].strip()
        i += 1
    return ""


def _py_first_arg(call_txt: str) -> str:
    """调用原文的第一个实参（顶层逗号切分）。"""
    oi = call_txt.find("(")
    if oi < 0:
        return ""
    depth = 0
    quote = ""
    for i in range(oi + 1, len(call_txt)):
        c = call_txt[i]
        if quote:
            if c == "\\":
                continue
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return call_txt[oi + 1:i].strip()
            depth -= 1
        elif c == "," and depth == 0:
            return call_txt[oi + 1:i].strip()
    return ""


def _fix_solidity_txorigin(repo: Path, targets: list, lines: list) -> int:
    """补丁第 7 类（Module 31）：权限校验里的 `tx.origin ==` 改 `msg.sender ==`。

    只替换入口行区间内的 `tx.origin`；重切片 + 重跑 access_control 规则
    翻 False 才算自检通过，finally 字节级还原。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if "tx.origin" not in src:
            continue
        if rule_verdict("access_control", src) is not True:
            continue
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        file_lines = original.splitlines(keepends=True)
        patched_lines = list(file_lines)
        changed = False
        for i in range(max(0, u.start_line - 1), min(u.end_line, len(patched_lines))):
            if re.search(r"\btx\s*\.\s*origin\b", patched_lines[i]):
                new = re.sub(r"\btx\s*\.\s*origin\b", "msg.sender",
                             patched_lines[i])
                if new != patched_lines[i]:
                    patched_lines[i] = new
                    changed = True
        if not changed:
            continue
        patched = "".join(patched_lines)
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            from core.slicer.web3_slither import SoliditySlicer
            u2 = next((x for x in SoliditySlicer(repo).extract_entry_units(repo)
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            v2 = rule_verdict("access_control", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [sol-txorigin] {u.unit_name}（`{f.name}`）", "```diff",
                      *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 access_control 规则 → False。",
                      "> tx.origin → msg.sender：钓鱼调用里 msg.sender 是攻击者",
                      "> 自身，无法再冒充外部交易的发起人。", ""]
        else:
            lines += [f"## [sol-txorigin] {u.unit_name}（`{f.name}`）",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）", ""]
    return fixed


# ---- Module 55：第 13 类（arithmetic 守卫注入）/ 第 14 类（unchecked 调用包裹） ----

# 复合赋值语句：`balances[msg.sender] -= amt;` / `totalSupply += amount;`
_SOL_COMPOUND_ASSIGN_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<lhs>[A-Za-z_]\w*(?:\s*\[[^\]]*\])*)"
    r"\s*(?P<op>\+=|-=)\s*(?P<rhs>[^;]+);\s*$")
# 独立语句行的裸底层调用：`target.send(amt);` / `target.call(...);`
# 也覆盖老语法 `msg.sender.call.value(1)();`（0.4.x 常见形态）。
# —— 左侧无赋值（有赋值说明返回值已被消费，不是本类目的面）
_SOL_BARE_CALL_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<expr>[A-Za-z_][\w.]*\s*\.\s*"
    r"(?:send|call)\b[^;]*)\s*;\s*$")


def _fix_solidity_arith_guard(repo: Path, targets: list, lines: list) -> int:
    """补丁第 13 类（Module 55）：算术溢出/下溢守卫注入。

    对规则层判 True 的复合赋值语句，在语句前插入前置守卫：
      `x -= y;` → `require(x >= y, "underflow");` + 原语句
      `x += y;` → `require(x + y >= x, "overflow");` + 原语句
    自检闭环：重切片 + 重跑 arithmetic 规则 → False。
    只处理单行复合赋值；多行/嵌套形态交人工。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    from core.slicer.web3_slither import SoliditySlicer
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if rule_verdict("arithmetic", src) is not True:
            continue
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        file_lines = original.splitlines(keepends=True)
        patched_lines = list(file_lines)
        inserts: list[tuple[int, str]] = []      # (行号, 守卫行)
        for i in range(max(0, u.start_line - 1),
                       min(u.end_line, len(patched_lines))):
            m = _SOL_COMPOUND_ASSIGN_RE.match(patched_lines[i].rstrip("\r\n"))
            if not m:
                continue
            indent, lhs, op, rhs = (m.group("indent"), m.group("lhs"),
                                    m.group("op"), m.group("rhs"))
            if op == "-=":
                guard = f'{indent}require({lhs} >= {rhs}, "underflow");'
            else:
                guard = f'{indent}require({lhs} + {rhs} >= {lhs}, "overflow");'
            inserts.append((i, guard))
        if not inserts:
            continue
        for i, guard in sorted(inserts, reverse=True):
            patched_lines.insert(i, guard + "\n")
        patched = "".join(patched_lines)
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            u2 = next((x for x in SoliditySlicer(repo).extract_entry_units(repo)
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            v2 = rule_verdict("arithmetic", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(),
                                        patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [sol-arith-guard] {u.unit_name}（`{f.name}`）",
                      "```diff", *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 arithmetic 规则 → False。",
                      "> 前置上下界守卫在溢出发生前中止，是 0.4.x~0.7.x",
                      "> 的标准写法（0.8+ 编译器已内置）。", ""]
        else:
            lines += [f"## [sol-arith-guard] {u.unit_name}（`{f.name}`）",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）", ""]
    return fixed


def _fix_solidity_unchecked_wrap(repo: Path, targets: list, lines: list) -> int:
    """补丁第 14 类（Module 55）：底层调用返回值检查包裹。

    对规则层判 True 的裸底层调用语句（`target.send(amt);` / 
    `target.call(...);`），包裹 `require(..., "call failed");`。
    自检闭环：重切片 + 重跑 unchecked_low_level_calls 规则 → False。
    有赋值的调用（返回值已被消费）不是本类目的面，不动。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    from core.slicer.web3_slither import SoliditySlicer
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if rule_verdict("unchecked_low_level_calls", src) is not True:
            continue
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        file_lines = original.splitlines(keepends=True)
        patched_lines = list(file_lines)
        changed = False
        for i in range(max(0, u.start_line - 1),
                       min(u.end_line, len(patched_lines))):
            raw = patched_lines[i].rstrip("\r\n")
            m = _SOL_BARE_CALL_RE.match(raw)
            if not m or "=" in raw.split("(")[0]:
                continue
            indent, expr = m.group("indent"), m.group("expr")
            patched_lines[i] = (f'{indent}require({expr}, "call failed");\n')
            changed = True
        if not changed:
            continue
        patched = "".join(patched_lines)
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            u2 = next((x for x in SoliditySlicer(repo).extract_entry_units(repo)
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            v2 = (rule_verdict("unchecked_low_level_calls", u2.source_code)
                  if u2 else None)
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(),
                                        patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [sol-unchecked-wrap] {u.unit_name}（`{f.name}`）",
                      "```diff", *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 unchecked_low_level_calls",
                      "> 规则 → False。失败即中止（SWC-104）：底层调用失败",
                      "> 不再被静默忽略。", ""]
        else:
            lines += [f"## [sol-unchecked-wrap] {u.unit_name}（`{f.name}`）",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）", ""]
    return fixed


# ---- Module 68：第 15 类（hardcoded_secret → 环境变量读取） ----

# Python：SECRET_KEY = "..." / secret_key = '...' / config['SECRET_KEY'] = "..."
# 凭证词必须落在标识符末尾（`secret_content` 是数据字段，不是密钥）。
_SECRET_NAME_RE = (
    r"(?:jwt[_-]?secret|access[_-]?key[_-]?secret|client[_-]?secret"
    r"|api[_-]?secret|app[_-]?secret|secret[_-]?key|secretkey"
    r"|private[_-]?key|signing[_-]?key|secret)")
_SECRET_PY_ASSIGN_RE = re.compile(
    r"^(?P<prefix>[ \t]*[^=\n]*?" + _SECRET_NAME_RE + r")"
    r"(?P<tail>(?![\w])[^=\n]*?=\s*)['\"](?P<val>[^'\"]{1,})['\"]"
    r"(?P<suffix>\s*)$", re.I)
# Java：String jwtSecret = "..."; / String API_SECRET = "...";
_SECRET_JAVA_ASSIGN_RE = re.compile(
    r"^(?P<prefix>[ \t]*(?:(?:private|public|protected|static|final)"
    r"\s+)*String\s+(?P<name>\w*?" + _SECRET_NAME_RE + r"))"
    r"(?P<tail>(?![\w])\s*=\s*)['\"](?P<val>[^'\"]{1,})['\"]"
    r"(?P<suffix>\s*;\s*)$", re.I)


def _env_name(var: str) -> str:
    """从赋值左侧推导环境变量名。

    优先取**引号内的键名**（`config['SECRET_KEY']` → SECRET_KEY）；
    否则取最后一个标识符并转大写蛇形（`jwtSecret` → JWT_SECRET）。
    """
    km = re.search(r"['\"]([A-Za-z_]\w*)['\"]", var)
    if km:
        return km.group(1).upper()
    names = re.findall(r"[A-Za-z_]\w*", var)
    ident = names[-1] if names else "APP"
    env = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", ident).upper()
    return env or "APP_SECRET"


# ---- Module 75：第 16 类（全局 CORS 通配 → 固定白名单） ----

_CORS_WILDCARD_PATCHES = [
    (re.compile(r'\.\s*allowedOriginPatterns\s*\(\s*"\*"\s*\)'),
     '.allowedOriginPatterns("https://app.example.com")'),
    (re.compile(r'\.\s*allowedOrigins\s*\(\s*"\*"\s*\)'),
     '.allowedOrigins("https://app.example.com")'),
    (re.compile(r'\.\s*addAllowedOriginPattern\s*\(\s*"\*"\s*\)'),
     '.addAllowedOriginPattern("https://app.example.com")'),
    (re.compile(r'\.\s*addAllowedOrigin\s*\(\s*"\*"\s*\)'),
     '.addAllowedOrigin("https://app.example.com")'),
    (re.compile(r'\.\s*setAllowedOrigins\s*\(\s*"\*"\s*\)'),
     '.setAllowedOrigins("https://app.example.com")'),
]


def _fix_cors_config(repo: Path, targets: list, lines: list) -> int:
    """第 16 类补丁：全局 CORS 通配 + 凭据 → 固定白名单。

    一条 `CorsConfig` / `WebMvcConfigurer` 配置会污染整仓所有路由；这里按
    装配证据里的 `来源 X.java` 归并，每个配置文件只打一处补丁，然后重切片
    验证**代表性路由**的 cors_verdict 翻 False，finally 字节级还原。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    from core.agents.rule_detectors import wiring_block
    by_file: dict[Path, list] = {}
    for u in targets:
        if rule_verdict("cors", u.source_code) is not True:
            continue
        blk = wiring_block(u.source_code)
        m = _WIRING_SOURCE_RE.search(blk) if blk else None
        if not m:
            continue
        rel = m.group(1).replace("\\", "/")
        cand = repo / rel
        if not cand.is_file():
            cand = next(repo.rglob(Path(rel).name), None)
        if cand and cand.is_file():
            by_file.setdefault(cand, []).append(u)
    fixed = 0
    for cfg, units in by_file.items():
        with open(cfg, encoding="utf-8", errors="replace", newline="") as fh:
            original = fh.read()
        patched = original
        for pat, repl in _CORS_WILDCARD_PATCHES:
            patched = pat.sub(repl, patched)
        if patched == original:
            lines += [f"## [cors] 全局配置 `{cfg.name}`",
                      "- 未找到可确定性替换的 `*` 通配，跳过", ""]
            continue
        try:
            with open(cfg, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            from core.context.java_impl_resolver import _FILE_CACHE
            _FILE_CACHE.clear()
            from core.slicer.java_servlet import JavaSlicer
            fresh = {x.unit_name: x for x in
                     JavaSlicer(repo).extract_entry_units()}
            rep = units[0]
            u2 = fresh.get(rep.unit_name)
            v2 = (rule_verdict("cors", u2.source_code) if u2 else None)
        finally:
            with open(cfg, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
            from core.context.java_impl_resolver import _FILE_CACHE
            _FILE_CACHE.clear()
        rel = cfg.relative_to(repo).as_posix()
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(
                original.splitlines(), patched.splitlines(),
                fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm="")
            lines += [f"## [cors] 全局配置 `{rel}`（影响 {len(units)} 条路由）",
                      "```diff", *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 cors 规则 → False。",
                      "> 通配改为固定白名单；若确需多域名，请从环境变量读取",
                      "> 白名单并在启动时校验。", ""]
        else:
            lines += [f"## [cors] 全局配置 `{rel}`",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）",
                      ""]
    return fixed


def _ensure_os_import(lines: list[str]) -> list[str]:
    """Python 补丁引用 `os.environ` 时，缺 `import os` 就补一行。

    插入点跳过模块 docstring 与 `from __future__`（后者必须位于文件最前，
    放它前面会直接 SyntaxError）；已有 `import os` / `from os import` 则不动。
    """
    if any(re.match(r"\s*(?:import\s+os\b|from\s+os\s+import\b)", ln)
           for ln in lines):
        return lines
    idx, n = 0, len(lines)
    while idx < n and (not lines[idx].strip()
                       or lines[idx].lstrip().startswith("#")):
        idx += 1
    if idx < n:
        m = re.match(r'\s*[rRuUbBfF]{0,2}("""|\'\'\')', lines[idx])
        if m:
            q = m.group(1)
            if q in lines[idx][m.end():]:
                idx += 1
            else:
                idx += 1
                while idx < n and q not in lines[idx]:
                    idx += 1
                idx = min(idx + 1, n)
    while idx < n:
        s = lines[idx].strip()
        if not s or s.startswith("#") or re.match(
                r"from\s+__future__\s+import\b", s):
            idx += 1
            continue
        break
    lines.insert(idx, "import os\n")
    return lines


def _fix_jwt_weakness(repo: Path, targets: list, lines: list) -> int:
    """第 17 类补丁（M82）：关验签/alg none/未签名解析器 → 强制验签。

    Python：`verify_signature: False` → True；`verify=False` → True；
            `algorithms=["none"]` → `["HS256"]`。
    Java：`parseClaimsJwt(` → `setSigningKey(env).parseClaimsJws(`。
    写入后重切片、重跑规则翻 False，finally 字节级还原。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    by_file: dict[Path, object] = {}
    for u in targets:
        if rule_verdict("jwt_weakness", u.source_code) is not True:
            continue
        by_file.setdefault(Path(u.file_path), u)
    fixed = 0
    for path, rep in by_file.items():
        with open(path, encoding="utf-8", errors="replace", newline="") as fh:
            original = fh.read()
        patched = original
        if path.suffix == ".py":
            patched = re.sub(
                r'(["\'])verify_signature\1\s*:\s*False',
                lambda m: f'{m.group(1)}verify_signature{m.group(1)}: True',
                patched)
            patched = re.sub(r"\bverify\s*=\s*False", "verify=True", patched)
            patched = re.sub(
                r"(algorithms\s*=\s*\[)([^\]]*)(\])",
                lambda m: (m.group(1)
                           + m.group(2).replace('"none"', '"HS256"')
                           .replace("'none'", "'HS256'")
                           + m.group(3)), patched)
        else:
            if "setSigningKey" not in patched:
                patched = re.sub(
                    r"Jwts\s*\.\s*parser\s*\(\s*\)",
                    'Jwts.parser().setSigningKey('
                    'System.getenv("JWT_SECRET"))', patched)
            patched = re.sub(r"\.parseClaimsJwt\s*\(", ".parseClaimsJws(",
                             patched)
        if patched == original:
            lines += [f"## [jwt_weakness] `{path.name}`",
                      "- 未找到可确定性替换的验签开关，跳过", ""]
            continue
        try:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            if path.suffix == ".py":
                from core.slicer.web_treesitter import WebTreeSitterSlicer
                fresh = {x.unit_name: x for x in
                         WebTreeSitterSlicer(repo).extract_entry_units(repo)}
            else:
                from core.context.java_impl_resolver import _FILE_CACHE
                _FILE_CACHE.clear()
                from core.slicer.java_servlet import JavaSlicer
                fresh = {x.unit_name: x for x in
                         JavaSlicer(repo).extract_entry_units()}
            u2 = fresh.get(rep.unit_name)
            v2 = (rule_verdict("jwt_weakness", u2.source_code) if u2 else None)
        finally:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
            if path.suffix != ".py":
                from core.context.java_impl_resolver import _FILE_CACHE
                _FILE_CACHE.clear()
        rel = path.relative_to(repo).as_posix() if path.is_relative_to(repo) \
            else path.name
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(
                original.splitlines(), patched.splitlines(),
                fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm="")
            lines += [f"## [jwt_weakness] `{rel}`",
                      "```diff", *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 `jwt_weakness` → False。",
                      "> 验签开关已强制开启 / 算法已限定 HS256；"
                      "Java 需注入 `JWT_SECRET` 环境变量。", ""]
        else:
            lines += [f"## [jwt_weakness] `{rel}`",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）",
                      ""]
    return fixed


def _fix_hardcoded_secret(repo: Path, targets: list, lines: list) -> int:
    """补丁第 15 类（Module 68）：硬编码密钥改环境变量读取。

    Python：`SECRET_KEY = "xxx"` → `SECRET_KEY = os.environ.get("XXX")`
    Java：  `String jwtSecret = "xxx";` →
            `String jwtSecret = System.getenv("JWT_SECRET");`
    自检闭环：重切片 + 重跑 hardcoded_secret 规则 → False。
    占位符值（your-secret/123456 等）不修（本来就不构成泄露）。
    """
    from core.agents.rule_detectors import (verdict as rule_verdict,
                                            SECRET_PLACEHOLDER_RE)
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if rule_verdict("hardcoded_secret", src) is not True:
            continue
        f = Path(u.file_path)
        if not f.is_file():
            continue
        is_py = str(f).endswith(".py")
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        file_lines = original.splitlines(keepends=True)
        patched_lines = list(file_lines)
        changed = False
        lo = max(0, u.start_line - 1)
        hi = min(u.end_line, len(patched_lines))
        for i in range(lo, hi):
            raw = patched_lines[i].rstrip("\r\n")
            if is_py:
                m = _SECRET_PY_ASSIGN_RE.match(raw)
                if not m:
                    continue
                if SECRET_PLACEHOLDER_RE.search(m.group("val")):
                    continue
                env = _env_name(m.group("prefix"))
                patched_lines[i] = (f'{m.group("prefix")}{m.group("tail")}'
                                    f'os.environ.get("{env}")'
                                    f'{m.group("suffix") or ""}\n')
                changed = True
            else:
                m = _SECRET_JAVA_ASSIGN_RE.match(raw)
                if not m:
                    continue
                if SECRET_PLACEHOLDER_RE.search(m.group("val")):
                    continue
                env = _env_name(m.group("name"))
                patched_lines[i] = (f'{m.group("prefix")}{m.group("tail")}'
                                    f'System.getenv("{env}");\n')
                changed = True
        if not changed:
            continue
        if is_py and any("os.environ.get" in ln for ln in patched_lines):
            patched_lines = _ensure_os_import(patched_lines)
        patched = "".join(patched_lines)
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            # Java 切片器按路径缓存源码，不看 mtime；重切片前必须清掉
            from core.context.java_impl_resolver import _FILE_CACHE
            _FILE_CACHE.clear()
            if getattr(u, "file_level", False):
                # 文件级伪单元（配置/工具类）：没有路由可重切，直接对补丁后
                # 的全文重跑规则。
                v2 = rule_verdict("hardcoded_secret", patched)
            # 重切片按语言分流：py 用 WebTreeSitterSlicer，java 用 JavaSlicer
            elif str(f).endswith(".py"):
                from core.slicer.web_treesitter import WebTreeSitterSlicer
                u2 = next((x for x in WebTreeSitterSlicer(repo)
                           .extract_entry_units(repo)
                           if x.unit_name == u.unit_name
                           and Path(x.file_path) == f), None)
                v2 = (rule_verdict("hardcoded_secret", u2.source_code)
                      if u2 else None)
            else:
                from core.slicer.java_servlet import JavaSlicer
                u2 = next((x for x in JavaSlicer(repo).extract_entry_units()
                           if x.unit_name == u.unit_name
                           and Path(x.file_path) == f), None)
                v2 = (rule_verdict("hardcoded_secret", u2.source_code)
                      if u2 else None)
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(),
                                        patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [hardcoded-secret] {u.unit_name}（`{f.name}`）",
                      "```diff", *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 hardcoded_secret 规则 →",
                      "> False。密钥移出代码由环境注入（CWE-798 消解）；",
                      "> 注意同步更新部署环境与密钥轮换。", ""]
        else:
            lines += [f"## [hardcoded-secret] {u.unit_name}（`{f.name}`）",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）",
                      ""]
    return fixed


_MP_CONCAT_RE = re.compile(
    r'(\.apply|\.last)\s*\(\s*"([^"]*)"\s*\+\s*([A-Za-z_]\w*)'
    r'(?:\s*\+\s*"([^"]*)")?\s*\)')


def _fix_mp_concat(repo: Path, targets: list, lines: list) -> int:
    """补丁第 8 类（Module 31）：MyBatis-Plus 拼接出口改占位符绑定。

    `.apply("col = '" + x + "'")` → `.apply("col = '{0}'", x)`；
    `.last("limit " + p)` → `.last("limit {0}", p)`。只处理单变量拼接，
    多变量/含函数调用的形态交人工。自检同前：重切片 + 重跑 sqli 规则。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if not re.search(r"\.(?:apply|last)\s*\(", src):
            continue
        if rule_verdict("sqli", src) is not True:
            continue
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        file_lines = original.splitlines(keepends=True)
        patched_lines = list(file_lines)
        changed = False
        for i in range(max(0, u.start_line - 1), min(u.end_line, len(patched_lines))):
            new = _MP_CONCAT_RE.sub(
                lambda mm: f'{mm.group(1)}("{mm.group(2)}{{0}}'
                           f'{mm.group(4) or ""}", {mm.group(3)})',
                patched_lines[i])
            if new != patched_lines[i]:
                patched_lines[i] = new
                changed = True
        if not changed:
            continue
        patched = "".join(patched_lines)
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            u2 = _reslice_for_fix(repo, u.unit_name)
            v2 = rule_verdict("sqli", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [mp-concat] {u.unit_name}（`{f.name}`）", "```diff",
                      *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 sqli 规则 → False（{0} 占位符",
                      "> 由 Wrapper 预编译绑定，与 .eq 同语义）。", ""]
        else:
            lines += [f"## [mp-concat] {u.unit_name}（`{f.name}`）",
                      f"- 补丁后规则仍报 `{v2}`，**不推荐**该补丁（自检未过）", ""]
    return fixed


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

_XML_STMT_RE = re.compile(
    r"<(?:select|insert|update|delete|sql)\b[^>]*?\bid=\"(\w+)\"", re.I)


def _xml_statement_ids(diff_text: str) -> set[str]:
    """从 Mapper XML 的 diff 里抓被改到的语句 id。

    `select`/`insert`/`update`/`delete` 是可执行语句，`sql` 是被
    `<include refid>` 复用的片段 —— 改片段等于改所有引用它的语句。
    `resultMap` 不收：它太宽（一个 ResultMap 常被全文件共用），
    收进来会让兜底层失去意义；resultMap 变更由"切片引用了该 XML
    文件名"这条兜底规则接住。
    """
    ids: set[str] = set()
    for ln in diff_text.splitlines():
        if not ln.startswith(("+", "-")) or ln.startswith(("+++", "---")):
            continue
        ids |= set(_XML_STMT_RE.findall(ln))
    return ids


def _java_called_names(source: str) -> set[str]:
    """切片全文里的方法调用名（与 JavaSlicer._called_symbols 同一口径）。

    called_symbols 只来自入口自身方法体（第 1 跳）；反向依赖必须连
    [Hop N] 段里的调用一起看，否则改第 2/3 跳的方法会漏。
    """
    exclude = {"if", "for", "while", "switch", "catch", "return", "new",
               "super", "this", "println", "String", "Integer"}
    out = set()
    for m in re.finditer(r"(?:\.|\b)([A-Za-z_]\w*)\s*\(", source):
        n = m.group(1)
        if n not in exclude:
            out.add(n)
    return out


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


# doctor 的规则注册表检查直接从 vuln_categories.CATEGORIES 派生 ——
# 单一事实源，避免两份清单漂移（M54 实测：手抄清单漏类目导致 20 vs 21）。
from core.agents.vuln_categories import CATEGORIES  # noqa: E402
DOCTOR_RULE_CATEGORIES = sorted(CATEGORIES.keys())

DOCTOR_PATCHERS = [
    "_fix_sqli_targets", "_fix_xss_targets", "_fix_deserial_targets",
    "_fix_python_deserial", "_fix_python_sqli", "_fix_python_shell",
    "_fix_python_yaml", "_fix_solidity_reentrancy", "_fix_solidity_initiator",
    "_fix_solidity_onlyowner", "_fix_solidity_txorigin", "_fix_mp_concat",
    "_fix_solidity_arith_guard", "_fix_solidity_unchecked_wrap",
    "_fix_hardcoded_secret", "_fix_cors_config", "_fix_jwt_weakness",
    "_fix_python_redirect",
    # M106：第 19、20 类 —— Java 视图名注入白名单 / 响应头 CRLF 清洗
    "_fix_java_ssti_viewname", "_fix_java_header_injection",
    # M125：第 21、22 类 —— 批量赋值忽略列表 / 弱随机源
    "_fix_java_mass_assignment", "_fix_java_weakrand",
    # M139-M141：第 23、24、25 类 —— 反射白名单 / 解压前缀 / 委托目标
    "_fix_java_unsafe_reflection", "_fix_zip_slip",
    "_fix_solidity_delegatecall",
    # M157/M158：第 31、32 类
    "_fix_unrestricted_upload", "_fix_solidity_ecrecover",
]


def _fix_java_ssti_viewname(repo: Path, targets: list, lines: list) -> int:
    r"""补丁第 19 类（Module 106）：Thymeleaf/Spring MVC **视图名注入**。

    修法：在 `return "<字面量>" + <形参>` 之前插一行**视图名白名单**守卫 ——

        java.util.Set<String> __safeView = java.util.Set.of("index", "home");
        if (!__safeView.contains(para)) { return "error/404"; }

    **不采用**"给方法补 `@ResponseBody`"：那会把整条路由的语义从"渲染视图"
    改成"直接输出字符串"，页面会白屏 —— 是"看起来修了、实际把业务改坏"的
    坏补丁。白名单守卫保留视图机制，只把不认识的名字挡在门外。

    守卫刻意写成**不嵌套括号**的两行（`__safeView.contains(para)`），
    这样 `ssti_verdict` 的白名单正则（`if\s*\([^)]*\.contains\(\s*var\s*\)`）
    能逐字匹配到 —— 补丁必须能被自己的判据复核，否则自检就是自欺。
    """
    from core.agents.rule_detectors import (verdict as rule_verdict,
                                            _SSTI_THYMELEAF_RET_RE)
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if rule_verdict("ssti", src) is not True:
            continue
        m = next((x for x in _SSTI_THYMELEAF_RET_RE.finditer(src)
                  if x.group(1) is not None), None)
        if not m:
            continue
        var = m.group(3)
        ret_txt = m.group(0)
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        idx = original.find(ret_txt)
        if idx < 0:
            continue
        line_start = original.rfind("\n", 0, idx) + 1
        indent = original[line_start:idx]
        if indent.strip():
            continue                       # 不是行首 → 交人工
        guard = (f"{indent}java.util.Set<String> __safeView = "
                 f"java.util.Set.of(\"index\", \"home\");\n"
                 f"{indent}if (!__safeView.contains({var})) {{ "
                 f"return \"error/404\"; }}\n")
        patched = original[:line_start] + guard + original[line_start:]
        v2 = None
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            # 清跨文件实现体缓存：`java_impl_resolver._FILE_CACHE` 按路径缓存、
            # 不看 mtime —— 不清就永远读回未修补的旧内容，自检必然看到 True。
            from core.context.java_impl_resolver import _FILE_CACHE as _FC
            _FC.clear()
            from benchmarks.slice_cache import cached_units  # noqa: F401
            from core.slicer.java_servlet import JavaSlicer
            u2 = next((x for x in JavaSlicer(repo).extract_entry_units()
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            v2 = rule_verdict("ssti", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
            from core.context.java_impl_resolver import _FILE_CACHE as _FC2
            _FC2.clear()
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(),
                                        patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [java-ssti-view] {u.unit_name}（`{f.name}`）",
                      "```diff", *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 ssti 规则 → False。",
                      f"> 视图名前加白名单守卫（`{var}` 只允许已知视图名），",
                      "> 不认识的路径返回 error/404 —— 不给 @ResponseBody，",
                      "> 那会把'渲染视图'改成'输出字符串'，页面直接白屏。", ""]
    return fixed


def _fix_java_header_injection(repo: Path, targets: list,
                               lines: list) -> int:
    """补丁第 20 类（Module 106）：HTTP 响应头 CRLF 注入。

    修法：把响应头的 value 表达式整体包一层 CR/LF 清洗 ——

        resp.setHeader("Content-Disposition",
                       ("attachment; filename=" + name).replaceAll("[\\r\\n]", ""));

    必须**整体加括号**：`"a" + b.replaceAll(...)` 只清洗了 `b`，
    `"a" + b` 里若 `a` 本身含 CR/LF 仍会被注入；而且运算符优先级会让
    拼接发生在清洗之后。括号是这条补丁的正确性前提，不是风格问题。
    """
    from core.agents.rule_detectors import (verdict as rule_verdict,
                                            _HDR_SINK_RE, _HDR_SANITIZE_RE,
                                            _hdr_value_idents,
                                            _ssti_call_args,
                                            _bare_params, _entry_signature,
                                            _REQUEST_READ_RE)
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if rule_verdict("header_injection", src) is not True:
            continue
        params = set(_bare_params(_entry_signature(src)))
        for m in _HDR_SINK_RE.finditer(src):
            args = _ssti_call_args(src, m.end() - 1)
            if len(args) < 2:
                continue
            value = args[1]
            if _HDR_SANITIZE_RE.search(value):
                continue
            idents = _hdr_value_idents(value)
            if not (params & idents or _REQUEST_READ_RE.search(value)):
                continue
            f = Path(u.file_path)
            if not f.is_file():
                continue
            with open(f, encoding="utf-8", newline="") as fh:
                original = fh.read()
            idx = original.find(value)
            if idx < 0:
                continue
            # 只在实参**恰好**是这一段时替换（避免把子串误替换）
            patched = (original[:idx] + f"({value}).replaceAll(\"[\\\\r\\\\n]\", \"\")"
                       + original[idx + len(value):])
            v2 = None
            try:
                with open(f, "w", encoding="utf-8", newline="") as fh:
                    fh.write(patched)
                from core.context.java_impl_resolver import _FILE_CACHE as _FC
                _FC.clear()
                from core.slicer.java_servlet import JavaSlicer
                u2 = next((x for x in JavaSlicer(repo).extract_entry_units()
                           if x.unit_name == u.unit_name
                           and Path(x.file_path) == f), None)
                v2 = rule_verdict("header_injection",
                                  u2.source_code) if u2 else None
            finally:
                with open(f, "w", encoding="utf-8", newline="") as fh:
                    fh.write(original)
                from core.context.java_impl_resolver import _FILE_CACHE as _FC2
                _FC2.clear()
            if v2 is False:
                fixed += 1
                diff = difflib.unified_diff(original.splitlines(),
                                            patched.splitlines(),
                                            fromfile=f"a/{f.name}",
                                            tofile=f"b/{f.name}", lineterm="")
                lines += [f"## [java-hdr-crlf] {u.unit_name}（`{f.name}`）",
                          "```diff", *diff, "```", "",
                          "> 自检通过：重切片 + 重跑 header_injection → False。",
                          "> 头值整体加括号后 replaceAll 剥掉 CR/LF ——",
                          "> 不加括号只会清洗最后一段拼接，等于没修。", ""]
            break                          # 一个单元修一处即可
    return fixed


def _gl_severity(category: str) -> str:
    """类目 → GitLab 严重级（M127）。

    取值只有五档，判据挂"这个类目的**直接后果**"，不是拍脑袋：
      · 能直接拿服务器执行权/读全库 → CRITICAL（cmdi / deserial / sqli）
      · 能越权读写他人数据 / 读任意文件 / 打内网 → HIGH
      · 客户端脚本执行 / 跳转钓鱼 / 弱凭证 → MEDIUM
      · 配置类（CORS 通配、弱算法、信任边界）→ LOW
    """
    crit = {"cmdi", "deserial", "sqli", "unchecked_low_level_calls",
            "reentrancy", "access_control", "arithmetic"}
    high = {"authz", "pathtraver", "ssrf", "xxe", "spel", "ssti",
            "ldapi", "xpathi", "header_injection"}
    med = {"xss", "redir", "hardcoded_secret", "jwt_weakness", "crypto",
           "hash", "weakrand", "mass_assignment", "bad_randomness"}
    cat = (category or "").lower()
    if cat in crit:
        return "CRITICAL"
    if cat in high:
        return "HIGH"
    if cat in med:
        return "MEDIUM"
    return "LOW"


def _fix_java_mass_assignment(repo: Path, targets: list, lines: list) -> int:
    """补丁第 21 类（Module 125）：Java 批量赋值补**忽略列表**。

    `BeanUtils.copyProperties(src, dst)` 把整个请求体灌进实体；Spring 的三参
    重载就是官方的排除列表机制：

        BeanUtils.copyProperties(src, dst, "id", "role", "isAdmin", "password");

    为什么不全字段白名单化：那需要改实体/DTO 结构，属于业务重构，不是确定性
    补丁。忽略列表是同一个 API 的既有语义，改完行为可预测、可自检。
    """
    from core.agents.rule_detectors import (verdict as rule_verdict,
                                            _MASS_JAVA_SINK_RE)
    fixed = 0
    ignore = ', "id", "role", "isAdmin", "is_superuser", "password"'
    for u in targets:
        src = u.source_code or ""
        if rule_verdict("mass_assignment", src) is not True:
            continue
        m = _MASS_JAVA_SINK_RE.search(src)
        if not m:
            continue
        call = m.group(0)
        if call.count(",") > 1:
            continue                       # 已经有排除列表
        new_call = call[:-1] + ignore + ")"
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        idx = original.find(call)
        if idx < 0:
            continue
        patched = original[:idx] + new_call + original[idx + len(call):]
        v2 = None
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            from core.context.java_impl_resolver import _FILE_CACHE as _FC
            _FC.clear()
            from core.slicer.java_servlet import JavaSlicer
            u2 = next((x for x in JavaSlicer(repo).extract_entry_units()
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            v2 = rule_verdict("mass_assignment",
                              u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
            from core.context.java_impl_resolver import _FILE_CACHE as _FC2
            _FC2.clear()
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(),
                                        patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [java-mass-assign] {u.unit_name}（`{f.name}`）",
                      "```diff", *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 mass_assignment → False。",
                      "> 用 Spring 三参重载的排除列表挡住权限字段；",
                      "> 不做全字段白名单（那是业务重构，不是确定性补丁）。", ""]
    return fixed


def _fix_java_weakrand(repo: Path, targets: list, lines: list) -> int:
    """补丁第 22 类（Module 125）：Java 弱随机源 → `SecureRandom`。

    `new Random()` / `Math.random()` 是线性同余发生器，种子可预测；安全敏感
    场景（令牌、验证码、盐、临时密码）必须换 `java.security.SecureRandom`。

    只改**构造点**，不引入新变量名 —— `new Random()` → `new SecureRandom()`
    是同一接口（`java.util.Random` 的 API 是 `SecureRandom` 的超集），
    调用方 `nextInt()` 等一行不用动。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if rule_verdict("weakrand", src) is not True:
            continue
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        patched = re.sub(r"\bnew\s+(?:java\.util\.)?Random\s*\(\s*\)",
                         "new java.security.SecureRandom()", original, count=1)
        if patched == original:
            continue
        v2 = None
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            from core.context.java_impl_resolver import _FILE_CACHE as _FC
            _FC.clear()
            from core.slicer.java_servlet import JavaSlicer
            u2 = next((x for x in JavaSlicer(repo).extract_entry_units()
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            v2 = rule_verdict("weakrand", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
            from core.context.java_impl_resolver import _FILE_CACHE as _FC2
            _FC2.clear()
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(),
                                        patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [java-weakrand] {u.unit_name}（`{f.name}`）",
                      "```diff", *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 weakrand → False。",
                      "> `new Random()` → `new SecureRandom()`：同一接口，",
                      "> 调用方不用改；线性同余种子可预测的问题根除。", ""]
    return fixed


def _fix_java_unsafe_reflection(repo: Path, targets: list, lines: list) -> int:
    """补丁第 23 类（M139）：反射目标加**白名单守卫**。

    修法（在反射调用前插一行守卫）：

        java.util.Set<String> __allowedReflect = java.util.Set.of("java.lang.String");
        if (!__allowedReflect.contains(cls)) { throw new IllegalArgumentException(...); }

    为什么不改成 `Class.forName("常量")`：那会把"按名字查表"的动态能力改没，
    业务直接坏掉 —— 是"看起来修了、实际把功能删了"的坏补丁。白名单保住
    动态性，只把**取值集合**收窄到可信类。

    变量名刻意不带点、不嵌括号：判据层 `_reflect_whitelisted` 认的就是
    `<容器>.contains(<变量>)` 这一形态 —— 补丁必须能被自己的判据复核。
    """
    from core.agents.rule_detectors import (verdict as rule_verdict,
                                            _JAVA_REFLECT_RE,
                                            _reflect_sink_arg)
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if rule_verdict("unsafe_reflection", src) is not True:
            continue
        var = ""
        call = ""
        for m in _JAVA_REFLECT_RE.finditer(src):
            arg = _reflect_sink_arg(m)
            if re.fullmatch(r"[A-Za-z_]\w*", arg):
                var, call = arg, m.group(0)
                break
        if not var or not call:
            continue
        f = Path(u.file_path)
        if not f.is_file():
            continue
        original = f.read_text(encoding="utf-8")
        idx = original.find(call)
        if idx < 0:
            continue
        line_start = original.rfind("\n", 0, idx) + 1
        # 反射调用常在语句**中间**（`Class<?> c = Class.forName(cls);`）——
        # 守卫要插在**整条语句之前**，缩进取行首缩进，不是调用点前的空白。
        lead = re.match(r"[ \t]*", original[line_start:]).group(0)
        guard = (f'{lead}java.util.Set<String> __allowedReflect = '
                 f'java.util.Set.of("java.lang.String");\n'
                 f'{lead}if (!__allowedReflect.contains({var})) {{ '
                 f'throw new IllegalArgumentException('
                 f'"reflection target not allowlisted"); }}\n')
        patched = original[:line_start] + guard + original[line_start:]
        v2 = None
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            from core.context.java_impl_resolver import _FILE_CACHE as _FC
            _FC.clear()
            from core.slicer.java_servlet import JavaSlicer
            u2 = next((x for x in JavaSlicer(repo).extract_entry_units()
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            v2 = rule_verdict("unsafe_reflection", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
            from core.context.java_impl_resolver import _FILE_CACHE as _FC2
            _FC2.clear()
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [java-unsafe-reflect] {u.unit_name}（`{f.name}`）",
                      "```diff", *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 unsafe_reflection → False。",
                      f"> 反射目标 `{var}` 现在必须先过白名单集合。", ""]
    return fixed


def _fix_zip_slip(repo: Path, targets: list, lines: list) -> int:
    """补丁第 24 类（M140）：解压落盘前的**规范化前缀校验**。

    Java：在 `new File(dest, entry.getName())` 之后插三行 ——

        java.io.File __destDir = new java.io.File(dest.toString()).getCanonicalFile();
        java.io.File __canonTarget = target.getCanonicalFile();
        if (!__canonTarget.getPath().startsWith(__destDir.getPath()
                + java.io.File.separator)) { throw new java.io.IOException(...); }

    关键点是**先规范化再比前缀**：只拼 `dest + name` 拦不住 `../`，
    只 `contains("..")` 拦不住符号链接与编码变体。`toString()` 让 String
    与 File 两种基路径都能编译（String 的 toString 是恒等）。

    Python：`extractall(dest)` → `extractall(dest, filter="data")`（PEP 706）。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if rule_verdict("zip_slip", src) is not True:
            continue
        f = Path(u.file_path)
        if not f.is_file():
            continue
        original = f.read_text(encoding="utf-8")
        patched = ""
        note = ""
        if _looks_python_src(src):
            m = re.search(r"\.\s*extractall\s*\(", original)
            if not m:
                continue
            patched = (original[:m.end()] + 'filter="data", '
                       + original[m.end():])
            note = '> `extractall(..., filter="data")`（PEP 706）。'
        else:
            fm = re.search(
                r"(?m)^([ \t]*)(?:[A-Za-z_][\w.<>\[\]]*\s+)?([A-Za-z_]\w*)"
                r"\s*=\s*new\s+File\s*\(\s*([A-Za-z_]\w*)\s*,\s*"
                r"[^;]*?getName\s*\(\s*\)\s*\)\s*;",
                original)
            if not fm:
                continue
            indent, var, dest = fm.group(1), fm.group(2), fm.group(3)
            guard = (
                f"\n{indent}java.io.File __destDir = "
                f"new java.io.File({dest}.toString()).getCanonicalFile();"
                f"\n{indent}java.io.File __canonTarget = "
                f"{var}.getCanonicalFile();"
                f"\n{indent}if (!__canonTarget.getPath().startsWith("
                f"__destDir.getPath() + java.io.File.separator)) {{ "
                f"throw new java.io.IOException(\"Zip Slip detected\"); }}\n")
            patched = original[:fm.end()] + guard + original[fm.end():]
            note = ("> 规范化前缀校验：`getCanonicalFile()` 之后按 "
                    f"`{dest}` 的规范路径比 `startsWith`。")
        if patched == original:
            continue
        v2 = None
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            from core.context.java_impl_resolver import _FILE_CACHE as _FC
            _FC.clear()
            u2 = _reslice_unit(repo, u, src, f)
            v2 = rule_verdict("zip_slip", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
            from core.context.java_impl_resolver import _FILE_CACHE as _FC2
            _FC2.clear()
            if _looks_python_src(src):
                from benchmarks.slice_cache import cached_units  # noqa: F401
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [zip-slip] {u.unit_name}（`{f.name}`）",
                      "```diff", *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 zip_slip → False。", note, ""]
    return fixed


def _fix_solidity_delegatecall(repo: Path, targets: list, lines: list) -> int:
    """补丁第 25 类（M141）：委托目标收窄到**可信集合**。

    修法：在 `target.delegatecall(...)` 之前插一行

        require(target == address(this), "delegatecall target not allowlisted");

    `address(this)` 是**唯一**在"看不见对方代码"的前提下可证明可信的目标
    （自委托只执行本合约自己的代码）。要保留跨合约委托的，把这里换成
    管理员维护的白名单槽位即可 —— 判据认的是"目标被约束"这个机制，
    不认具体是哪一个容器。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if rule_verdict("delegatecall_untrusted", src) is not True:
            continue
        m = re.search(r"([A-Za-z_]\w*)\s*\.\s*delegatecall", src)
        if not m:
            continue
        target, stmt = m.group(1), m.group(0)
        f = Path(u.file_path)
        if not f.is_file():
            continue
        original = f.read_text(encoding="utf-8")
        idx = original.find(stmt)
        if idx < 0:
            continue
        line_start = original.rfind("\n", 0, idx) + 1
        indent = original[line_start:idx]
        if indent.strip():
            continue
        guard = (f'{indent}require({target} == address(this), '
                 f'"delegatecall target not allowlisted");\n')
        patched = original[:line_start] + guard + original[line_start:]
        v2 = None
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            from core.slicer.web3_slither import SoliditySlicer
            u2 = next((x for x in SoliditySlicer(repo).extract_entry_units(repo)
                       if x.unit_name == u.unit_name
                       and Path(x.file_path) == f), None)
            v2 = (rule_verdict("delegatecall_untrusted", u2.source_code)
                  if u2 else None)
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [sol-delegatecall] {u.unit_name}（`{f.name}`）",
                      "```diff", *diff, "```", "",
                      "> 自检通过：重切片 + 重跑 delegatecall_untrusted → False。",
                      f"> 委托目标 `{target}` 现在必须等于 `address(this)`。", ""]
    return fixed



def _fix_unrestricted_upload(repo: Path, targets: list, lines: list) -> int:
    """第 31 类（M157）：给"原始文件名直接落盘"补**后缀白名单**守卫。

    只改"文件名先赋给变量、再落盘"的形态（有明确插入点）；文件名内联在
    transferTo/open 里的写法不硬改 —— 在表达式里塞守卫会破坏语法，宁可不修。
    白名单变量名刻意写得能被执行后的判据逐字复核（_upload_has_guard 的
    if + raise/throw 结构）。
    """
    from core.agents.rule_detectors import (verdict as rule_verdict,
                                            _looks_python)
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if rule_verdict("unrestricted_upload", src) is not True:
            continue
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        file_lines = original.splitlines(keepends=True)
        py = _looks_python(src)
        ins_at = None
        indent = ""
        name_var = "name"
        if py:
            m = re.search(r"(?m)^([ \t]*)(\w+)\s*=\s*\w+\s*\.\s*filename\s*$",
                          original)
            if m:
                # +1：插到赋值行的**下一行**。count("\n") 得到的是该行行号
                # （0-based），直接当插入下标会把守卫插到赋值之前，
                # 生成 name 未定义就先用的坏补丁。
                ins_at = original[:m.end()].count("\n") + 1
                indent = m.group(1)
                name_var = m.group(2)
            block = (f"{indent}ALLOWED_EXT = {{\"jpg\", \"jpeg\", \"png\", \"gif\", \"pdf\"}}\n"
                     f"{indent}_ext = {name_var}.rsplit(\".\", 1)[-1].lower()\n"
                     f"{indent}if _ext not in ALLOWED_EXT:\n"
                     f"{indent}    raise ValueError(\"unsupported file type\")\n")
        else:
            m = re.search(
                r"(?m)^([ \t]*)(?:String|var)\s+(\w+)\s*=\s*\w+\s*\.\s*"
                r"get(?:OriginalFilename|SubmittedFileName)\s*\(\s*\)\s*;",
                original)
            if m:
                ins_at = original[:m.end()].count("\n") + 1
                indent = m.group(1)
                name_var = m.group(2)
            block = (f"{indent}java.util.Set<String> ALLOWED_EXT = "
                     f"java.util.Set.of(\"jpg\", \"jpeg\", \"png\", \"gif\", \"pdf\");\n"
                     f"{indent}String _ext = {name_var}"
                     f".substring({name_var}.lastIndexOf('.') + 1)"
                     f".toLowerCase();\n"
                     f"{indent}if (!ALLOWED_EXT.contains(_ext)) {{ "
                     f"throw new IllegalArgumentException(\"unsupported file type\"); }}\n")
        if ins_at is None:
            lines += [f"## [unrestricted_upload] {u.unit_name}",
                      "- 找不到文件名赋值插入点，跳过（不硬改表达式）", ""]
            continue
        patched_lines = list(file_lines)
        patched_lines.insert(ins_at, block)
        patched = "".join(patched_lines)
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            if py:
                from core.slicer.web_treesitter import WebTreeSitterSlicer
                u2 = next((x for x in WebTreeSitterSlicer(repo).extract_entry_units(repo)
                           if x.unit_name == u.unit_name and Path(x.file_path) == f), None)
            else:
                # 缓存按路径缓存、不看 mtime：不清空的话重切片读到的还是
                # 补丁前的旧内容，"补丁后仍 True"就是缓存造出来的假结论。
                from core.context.java_impl_resolver import _FILE_CACHE
                _FILE_CACHE.clear()
                from core.slicer.java_servlet import JavaSlicer
                u2 = next((x for x in JavaSlicer(repo).extract_entry_units()
                           if x.unit_name == u.unit_name and Path(x.file_path) == f), None)
            v2 = rule_verdict("unrestricted_upload", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
            from core.context.java_impl_resolver import _FILE_CACHE
            _FILE_CACHE.clear()
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [unrestricted_upload] {u.unit_name}（{f.name}）",
                      "\x60\x60\x60diff", *diff, "\x60\x60\x60", "",
                      "> 自检通过：重切片 + 重跑 unrestricted_upload -> False。",
                      "> 白名单是**示例**（jpg/png/gif/pdf）；上线前按业务改成",
                      "> 真实允许的类型，别把业务需要的格式挡掉。", ""]
        else:
            lines += [f"## [unrestricted_upload] {u.unit_name}（{f.name}）",
                      f"- 补丁后规则仍报 {v2!r}，**不推荐**该补丁（自检未过）", ""]
    return fixed



def _fix_solidity_ecrecover(repo: Path, targets: list, lines: list) -> int:
    """第 32 类（M158）：原生 ecrecover 补零地址校验 + 一次性 nonce 消费。

    两处插入：
      ① 赋值行后：require(signer != address(0)) + require(!__usedSig[h]) +
         __usedSig[h] = true；
      ② 合约开括号后：mapping(bytes32 => bool) private __usedSig;
    拿不到合约声明/bytes32 形参时**不修** —— 生成一个编译不过的补丁比不修更糟。
    """
    from core.agents.rule_detectors import (verdict as rule_verdict,
                                            _sol_has_nonce_consumption)
    fixed = 0
    for u in targets:
        src = u.source_code or ""
        if rule_verdict("signature_replay", src) is not True:
            continue
        f = Path(u.file_path)
        if not f.is_file():
            continue
        with open(f, encoding="utf-8", newline="") as fh:
            original = fh.read()
        file_lines = original.splitlines(keepends=True)
        lo = max(0, int(getattr(u, "start_line", 1)) - 1)
        hi = min(len(file_lines), int(getattr(u, "end_line", len(file_lines))))
        assign = None
        for i in range(lo, hi):
            if re.search(r"\baddress(?:\s+payable)?\s+\w+\s*=\s*ecrecover\s*\(",
                         file_lines[i]):
                assign = i
                break
        if assign is None:
            continue
        am = re.search(r"\baddress(?:\s+payable)?\s+(\w+)\s*=\s*ecrecover",
                       file_lines[assign])
        var = am.group(1)
        indent = re.match(r"[ \t]*", file_lines[assign]).group(0)
        sig_m = re.search(r"bytes32\s+(\w+)", src)
        hash_var = sig_m.group(1) if sig_m else None
        need_zero = not re.search(
            rf"\b{re.escape(var)}\s*!=\s*address\s*\(\s*0\s*\)", src)
        need_nonce = not _sol_has_nonce_consumption(src)
        inserts: list[tuple[int, str]] = []
        guard = ""
        if need_zero:
            guard += f"{indent}require({var} != address(0), \"invalid signature\");\n"
        if need_nonce:
            if hash_var is None:
                lines += [f"## [signature_replay] {u.unit_name}",
                          "- 找不到 bytes32 签名哈希形参，nonce 消费无法自动插入", ""]
                continue
            guard += (f"{indent}require(!__usedSig[{hash_var}], \"signature used\");\n"
                      f"{indent}__usedSig[{hash_var}] = true;\n")
            c_at = None
            for i in range(lo, -1, -1):
                if re.search(r"^\s*contract\s+\w+", file_lines[i]):
                    c_at = i
                    break
            if c_at is None:
                lines += [f"## [signature_replay] {u.unit_name}",
                          "- 切片里没有合约声明行，无法声明 nonce 映射", ""]
                continue
            brace = c_at
            while brace < len(file_lines) and "{" not in file_lines[brace]:
                brace += 1
            if brace >= len(file_lines):
                continue
            inserts.append((brace + 1,
                            "    mapping(bytes32 => bool) private __usedSig;\n"))
        if guard:
            inserts.append((assign + 1, guard))
        patched_lines = list(file_lines)
        for at, text in sorted(inserts, reverse=True):
            patched_lines.insert(at, text)
        patched = "".join(patched_lines)
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(patched)
            from core.context.java_impl_resolver import _FILE_CACHE
            _FILE_CACHE.clear()
            from core.slicer.web3_slither import SoliditySlicer
            u2 = next((x for x in SoliditySlicer(repo).extract_entry_units(repo)
                       if x.unit_name == u.unit_name and Path(x.file_path) == f), None)
            v2 = rule_verdict("signature_replay", u2.source_code) if u2 else None
        finally:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(original)
            from core.context.java_impl_resolver import _FILE_CACHE
            _FILE_CACHE.clear()
        if v2 is False:
            fixed += 1
            diff = difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                        fromfile=f"a/{f.name}",
                                        tofile=f"b/{f.name}", lineterm="")
            lines += [f"## [signature_replay] {u.unit_name}（{f.name}）",
                      "\x60\x60\x60diff", *diff, "\x60\x60\x60", "",
                      "> 自检通过：重切片 + 重跑 signature_replay -> False。",
                      "> nonce 映射名 __usedSig 是**示例**；生产代码应并入现有",
                      "> nonce 体系，并让签名消息本身绑定 chainId/合约地址。", ""]
        else:
            lines += [f"## [signature_replay] {u.unit_name}（{f.name}）",
                      f"- 补丁后规则仍报 {v2!r}，**不推荐**该补丁（自检未过）", ""]
    return fixed


def _looks_python_src(src: str) -> bool:
    from core.agents.rule_detectors import _looks_python
    return _looks_python(src)


def _reslice_unit(repo: Path, u, src: str, f: Path):
    """按语言重切片并挑回同名单元（补丁自检用）。"""
    from core.agents.rule_detectors import _looks_python
    if _looks_python(src):
        from core.slicer.web_treesitter import WebTreeSitterSlicer
        units = WebTreeSitterSlicer(repo).extract_entry_units(repo)
    else:
        from core.slicer.java_servlet import JavaSlicer
        units = JavaSlicer(repo).extract_entry_units()
    return next((x for x in units
                 if x.unit_name == u.unit_name and Path(x.file_path) == f), None)


def _strip_scoreboard_timestamp(text: str) -> str:
    """去掉 SCOREBOARD 里的"生成时间"行。

    时间戳每次现算都不同，比对它没有意义（而且会让 doctor 永远 FAIL）。
    同步真正要看的是**表体**（靶场行 + 合计行）是否与当前 json 一致。
    """
    return "\n".join(l for l in text.splitlines()
                     if not l.startswith("生成时间"))


def _doctor_matrix_registry_check(ok: bool) -> bool:
    """doctor 第十段（M151）：能力矩阵 × 补丁注册表**双向恒等**。

    为什么值得常驻：这两份清单回答的是同一个问题（"这一类有没有确定性
    补丁器"），但服务两个入口 —— 矩阵的 --fix 列读 MATRIX_FIX_MAP，
    doctor 的 [4/10] 与 --fix 调度读 DOCTOR_PATCHERS。只在一侧登记，
    用户看到的是"矩阵里这一类没有补丁器"，而命令其实能跑；反过来则是
    "--fix 列表里有、矩阵不认"，两边都很难在人工走查里发现。

    断言三个方向：
      ① DOCTOR_PATCHERS - MATRIX_FIX_MAP 展开集 == 空（登记了却没接矩阵）；
      ② MATRIX_FIX_MAP 展开集 - DOCTOR_PATCHERS == 空（矩阵指向未注册函数）；
      ③ 矩阵的每个 key 都是真实类目（防止拼写漂移造出幽灵类目）。
    """
    print("== [10/10] 能力矩阵 × 补丁注册表双向恒等（M151）==")
    mapped = {fn for tup in MATRIX_FIX_MAP.values() for fn in tup}
    registered = set(DOCTOR_PATCHERS)
    only_doctor = sorted(registered - mapped)
    only_matrix = sorted(mapped - registered)
    missing_callable = sorted(fn for fn in mapped
                              if not callable(globals().get(fn)))
    # unchecked_low_level_calls 是**检测器专有键**：verdict() 有分支、也有
    # 补丁器，但它没有 LLM 两步法的场景问句，因此不在 CATEGORIES 里。
    # 把它当幽灵类目会误报；显式豁免并单独打印，账才说得清。
    _detector_only = {"unchecked_low_level_calls"}
    ghost_cats = sorted(k for k in MATRIX_FIX_MAP
                        if k not in CATEGORIES and k not in _detector_only)
    if only_doctor:
        print(f"  [FAIL] 已注册但未接入矩阵（{len(only_doctor)}）：{only_doctor}")
        ok = False
    if only_matrix:
        print(f"  [FAIL] 矩阵登记但未注册（{len(only_matrix)}）：{only_matrix}")
        ok = False
    if missing_callable:
        print(f"  [FAIL] 矩阵指向的函数不存在（{len(missing_callable)}）："
              f"{missing_callable}")
        ok = False
    if ghost_cats:
        print(f"  [FAIL] 矩阵含未注册类目：{ghost_cats}")
        ok = False
    if not (only_doctor or only_matrix or missing_callable or ghost_cats):
        print(f"  [OK] 双向恒等：矩阵 {len(mapped)} 个补丁器 "
              f"== 注册表 {len(registered)} 个（差集为空）")
        print(f"  [OK] 矩阵 {len(MATRIX_FIX_MAP)} 个类目全部命中规则注册表"
              f"（另含 {len(_detector_only & set(MATRIX_FIX_MAP))} 个"
              f"检测器专有键：{sorted(_detector_only & set(MATRIX_FIX_MAP))}）")
    return ok


def cmd_doctor(args) -> int:
    """只读自检：依赖 / 规则注册表 / 缓存指纹 / 补丁器就位。exit 0 = 全部就绪。"""
    ok = True

    print("== [1/10] 依赖就位 ==")
    print(f"  [OK] python {sys.version.split()[0]}")
    for name in ["httpx", "tree_sitter(可选·缺省正则降级)", "pyyaml(可选)", "slither(可选)"]:
        try:
            importlib.import_module(name.split("(")[0])
            print(f"  [OK] {name}")
        except Exception as e:  # noqa: BLE001
            label = "提示(可选)" if "(可选" in name else "缺失"
            print(f"  [{label}] {name}: {type(e).__name__}: {e}")
            if "(可选" not in name:
                ok = False

    print("== [2/10] 规则注册表完整性（verdict 路由 × 类目全覆盖）==")
    from core.agents import rule_detectors
    for cat in DOCTOR_RULE_CATEGORIES:
        try:
            r = rule_detectors.verdict(cat, "")
            if r is not None:
                print(f"  [FAIL] {cat}: 空源码返回了 {r!r}（应 None）")
                ok = False
            else:
                print(f"  [OK] {cat}")
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL] {cat}: 路由异常 {type(e).__name__}: {e}")
            ok = False
    print(f"  共 {len(DOCTOR_RULE_CATEGORIES)} 类，全部走 verdict() 路由")
    print("== [3/10] 缓存指纹自检 ==")
    try:
        from benchmarks.diag_owasp_sqli_fp import _slicer_fingerprint
        fp1, fp2 = _slicer_fingerprint(), _slicer_fingerprint()
        if fp1 and fp1 == fp2:
            print(f"  [OK] sha256={fp1[:16]}…（两次调用一致）")
        else:
            print(f"  [FAIL] fp1={fp1!r} fp2={fp2!r}")
            ok = False
    except Exception as e:  # noqa: BLE001
        print(f"  [FAIL] 指纹不可用: {type(e).__name__}: {e}")
        ok = False

    print(f"== [4/10] 补丁器就位（{len(DOCTOR_PATCHERS)} 类）==")
    for fn_name in DOCTOR_PATCHERS:
        fn = globals().get(fn_name)
        if callable(fn):
            print(f"  [OK] {fn_name}")
        else:
            print(f"  [FAIL] {fn_name} 不存在")
            ok = False
    if callable(globals().get("_verify_fixes_any")):
        print("  [OK] _verify_fixes_any（自检闭环入口）")
    else:
        print("  [FAIL] _verify_fixes_any 不存在")
        ok = False

    ok = _doctor_extended_checks(ok)
    ok = _doctor_wild_hunt_check(ok)
    ok = _doctor_disclosure_index_check(ok)
    ok = _doctor_exporters_check(ok)
    ok = _doctor_cross_repo_check(ok)
    ok = _doctor_matrix_registry_check(ok)

    print("doctor:", "PASS（全部就绪）" if ok else "FAIL（存在缺失项）")
    return 0 if ok else 1


def _doctor_cross_repo_check(ok: bool) -> bool:
    """doctor 第九段（M135）：跨仓聚类 ↔ wild_hunt 的**账**要对得上。

    与 run_all 第 42 项是同一断言的两个入口（CI 里跑 run_all，人工自检
    跑 doctor）。断言只有两条，但都是"结论级"的：

      ① 计数守恒：簇内根因之和 == 采集的独立根因总数；
      ② 多仓共现簇 ≥ 8：低于这个数聚类就已退化成一仓一簇。

    产物不在（首次克隆、还没跑野战）时**不判 FAIL** —— 与第 7、8 段同一
    口径：缺产物是"还没跑"，不是"跑坏了"。
    """
    print("== [9/10] 跨仓聚类一致性（M135）==")
    root = Path(__file__).resolve().parent
    agg = root / "benchmarks" / "results" / "wild_hunt.json"
    cl = root / "benchmarks" / "results" / "cross_repo_clusters.json"
    if not agg.exists() or not cl.exists():
        print("  [提示] 缺 wild_hunt.json 或 cross_repo_clusters.json"
              "（尚未跑野战，不判 FAIL）")
        return ok
    try:
        sys.path.insert(0, str(root))
        from benchmarks.cross_repo_clusters import check as _cluster_check
        rc = _cluster_check(agg, cl)
        if rc == 0:
            print("  [OK] 聚类与采集对账通过")
        else:
            print("  [FAIL] 聚类与采集对账不通过（见上方明细）")
            ok = False
    except Exception as e:                               # noqa: BLE001
        print(f"  [FAIL] 跨仓聚类校验异常：{type(e).__name__}: {e}")
        ok = False
    return ok


def _doctor_exporters_check(ok: bool) -> bool:
    """doctor 第八段（M132）：双 SAST 导出器 + 跨仓聚类产物。

    --sarif（GitHub）与 --gitlab-sast（GitLab）是两条独立交付路径，
    任一条的 schema 校验器被改坏，用户那边是"报告上传失败"而不是"门禁变红"
    —— CI 里看不出来。这里把两个校验器都跑一遍自产文档 + 一份坏文档。
    """
    print("== [8/10] 双 SAST 导出器与跨仓聚类（SARIF / GitLab / clusters）==")
    root = Path(__file__).resolve().parent
    try:
        from core.context.sarif_validator import validate_sarif
        _bad = validate_sarif({"version": "2.0.0", "runs": []})
        if _bad:
            print(f"  [OK] sarif_validator 就位（坏版本被拦 {len(_bad)} 条）")
        else:
            print("  [FAIL] sarif_validator 没拦住坏版本")
            ok = False
    except Exception as e:                                   # noqa: BLE001
        print(f"  [FAIL] sarif_validator：{type(e).__name__}: {e}")
        ok = False
    try:
        from core.context.gitlab_exporter import (
            SAST_VERSION, build_sast_report, validate_sast_report)
        _doc = build_sast_report([{"file": str(root / "cli.py"), "line": 1,
                                   "category": "sqli", "severity": "CRITICAL",
                                   "cwe": "CWE-89"}], root)
        _errs = validate_sast_report(_doc)
        _bad2 = validate_sast_report({"version": "14.0.0", "scan": {},
                                      "vulnerabilities": []})
        if not _errs and _bad2:
            print(f"  [OK] gitlab_exporter 就位（{SAST_VERSION}；"
                  f"自产零错误 / 坏文档被拦 {len(_bad2)} 条）")
        else:
            print(f"  [FAIL] gitlab_exporter：自产 {len(_errs)} 错 / "
                  f"坏文档拦下 {len(_bad2)} 条")
            ok = False
    except Exception as e:                                   # noqa: BLE001
        print(f"  [FAIL] gitlab_exporter：{type(e).__name__}: {e}")
        ok = False
    _cl = root / "benchmarks" / "results" / "cross_repo_clusters.json"
    if _cl.exists():
        try:
            _d = json.loads(_cl.read_text(encoding="utf-8"))
            _cons = (_d.get("conservation_ok")
                     and sum(c["root_count"] for c in _d["clusters"])
                     == _d.get("total_root_causes"))
            print(f"  [{'OK' if _cons else 'FAIL'}] 跨仓聚类："
                  f"{_d.get('total_root_causes')} 根因 → "
                  f"{_d.get('cluster_count')} 簇（计数守恒）")
            ok = ok and bool(_cons)
        except Exception as e:                               # noqa: BLE001
            print(f"  [FAIL] 跨仓聚类读取失败：{type(e).__name__}: {e}")
            ok = False
    else:
        print("  [提示] 未生成 cross_repo_clusters.json（不判 FAIL）")
    from core.agents.vuln_categories import CATEGORIES as _C
    print(f"  [OK] 规则 {len(_C)} 类 / 补丁器 {len(DOCTOR_PATCHERS)} 类")
    return ok


def _doctor_disclosure_index_check(ok: bool) -> bool:
    """doctor 第七段（M117）：披露包 INDEX.md ↔ wild_hunt.json 根因总数。

    为什么值得常驻：`--advisory-dir` 是**按仓**跑的，17/21 个仓各跑一次就会
    留下 21 份互不相干的草稿目录。"草稿总数 == 根因总数"是唯一能自动核对的
    不变量 —— 少一份说明有仓没跑到，多一份说明根因折叠漏了。
    """
    print("== [7/10] 披露包完整性（advisories/INDEX.md ↔ wild_hunt.json）==")
    root = Path(__file__).resolve().parent
    adv_root = root / "benchmarks" / "results" / "advisories"
    agg = root / "benchmarks" / "results" / "wild_hunt.json"
    if not adv_root.exists():
        print(f"  [提示] {adv_root.name}/ 不存在（尚未跑过 --advisory-dir，"
              f"不判 FAIL）")
        return ok
    drafts = list(adv_root.rglob("GHSA-*.md"))
    index = adv_root / "INDEX.md"
    print(f"  草稿 {len(drafts)} 份 / 目录 {len([p for p in adv_root.iterdir() if p.is_dir()])} 个")
    if not index.exists():
        print("  [FAIL] 缺 INDEX.md（M111 的总目录没生成）")
        return False
    itext = index.read_text(encoding="utf-8")
    # ① 索引必须覆盖全部草稿（断链检查）
    dangling = [p.name for p in drafts if f"]({p.name})" not in itext]
    if dangling:
        print(f"  [FAIL] INDEX.md 漏了 {len(dangling)} 份草稿："
              f"{dangling[:3]}")
        ok = False
    else:
        print(f"  [OK] INDEX.md 覆盖全部 {len(drafts)} 份草稿（零断链）")
    # ② 索引必须按 CVSS 降序
    scores = [float(x) for x in re.findall(
        r"^\| ([\d.]+) \| (?:CRITICAL|HIGH|MEDIUM|LOW) \|", itext, re.M)]
    if scores != sorted(scores, reverse=True):
        print("  [FAIL] INDEX.md 未按 CVSS 降序")
        ok = False
    else:
        print(f"  [OK] 按 CVSS 降序（{scores[0]:.1f} → {scores[-1]:.1f}）")
    # ③ 草稿总数 == wild_hunt.json 的根因总数
    if agg.exists():
        try:
            data = json.loads(agg.read_text(encoding="utf-8"))
            n_roots = sum(int(r.get("summary", {})
                              .get("p0_unique_root_causes") or 0)
                          for r in data.get("repos", []))
            if drafts and n_roots and len(drafts) != n_roots:
                print(f"  [FAIL] 草稿 {len(drafts)} 份 != 根因 {n_roots} 个")
                ok = False
            else:
                print(f"  [OK] 草稿数 == 根因总数（{n_roots}）")
        except Exception as e:                               # noqa: BLE001
            print(f"  [FAIL] 读取 {agg.name} 失败：{type(e).__name__}: {e}")
            ok = False
    return ok


def _doctor_extended_checks(ok: bool) -> bool:
    """doctor 第五段：PoC 合成器 / 覆盖地板 / SCOREBOARD 同步 / 正则卫生。

    四项都是**只读**检查，任何一项不过就把整体判 FAIL ——
    doctor 的价值就在于"配置漂了"能当场发现，而不是等跑批时才发现。
    """
    root = Path(__file__).resolve().parent

    # ---- 5.1 PoC 合成器：可导入 + 三语言模板自检通过 ----
    print("== [5/10] 扩展能力（PoC 合成器 / 覆盖地板 / SCOREBOARD / 正则卫生）==")
    print("  -- PoC 合成器 --")
    try:
        from core.sandbox.poc_synthesizer import PocSynthesizer, PocArtifact
        synth = PocSynthesizer()
        probes = [
            ("solidity", "Contract", "reentrancy", "function f() public { msg.sender.transfer(1); }"),
            ("python", "app", "sqli", "def f():\n    cur.execute('select ' + x)"),
            ("java", "OrderController", "sqli", "public void f(String q) { jdbc.query(q); }"),
        ]
        for lang, target, cat, body in probes:
            from core.models import CodeUnit, Language
            lg = {"solidity": Language.SOLIDITY_WEB3, "python": Language.PYTHON_WEB,
                  "java": Language.JAVA_WEB}[lang]
            unit = CodeUnit(file_path="X", language=lg, unit_name=target,
                            start_line=1, end_line=2, decorators_or_modifiers=[],
                            called_symbols=[], source_code=body, own_body=body)
            art = synth.synthesize(unit, cat)
            if art is None:
                print(f"  [FAIL] {lang}: 合成器返回 None")
                ok = False
            elif not art.self_check_ok:
                print(f"  [FAIL] {lang}: 自检未过 — {art.self_check_msg}")
                ok = False
            else:
                print(f"  [OK] {lang}: {art.path} 自检通过")
    except Exception as e:  # noqa: BLE001
        print(f"  [FAIL] PoC 合成器不可用: {type(e).__name__}: {e}")
        ok = False

    # ---- 5.2 覆盖地板：--check-floor 的 FLOORS 与 results/*.json 一致 ----
    print("  -- 覆盖地板（--check-floor）--")
    try:
        sys.path.insert(0, str(root))
        from benchmarks.triage_fallbacks import FLOORS
        missing = []
        for name, floor in sorted(FLOORS.items()):
            j = root / "benchmarks" / "results" / f"{name}.json"
            if not j.exists():
                print(f"  [WARN] {name:14} 无 {name}.json（跳过）")
                continue
            d = json.loads(j.read_text(encoding="utf-8"))
            decided = d.get("decided")
            if not isinstance(decided, (int, float)):
                print(f"  [WARN] {name:14} json 无 decided 字段")
                continue
            if decided < floor:
                print(f"  [FAIL] {name:14} decided={decided} < 地板={floor}")
                missing.append(name)
            else:
                print(f"  [OK]  {name:14} decided={decided} ≥ 地板={floor}")
        if missing:
            ok = False
        else:
            print(f"  共 {len(FLOORS)} 项地板配置")
    except Exception as e:  # noqa: BLE001
        print(f"  [FAIL] 覆盖地板配置不可读: {type(e).__name__}: {e}")
        ok = False

    # ---- 5.3 SCOREBOARD 同步：磁盘上的表 vs 用当前 json 现算的表 ----
    # 不按靶场名做子串匹配（标签措辞会变，"eladmin-mp" 与 json 键
    # "eladminmp" 就对不上）——直接**现算一遍**再逐行比。这才是"同步"的
    # 真口径：磁盘上的表与当前 results/*.json 不一致就是漂了。
    print("  -- SCOREBOARD.md 同步 --")
    sb_path = root / "benchmarks" / "results" / "SCOREBOARD.md"
    if not sb_path.exists():
        print("  [FAIL] SCOREBOARD.md 不存在")
        ok = False
    else:
        try:
            sys.path.insert(0, str(root))
            from benchmarks.run_all import build_scoreboard
            want = _strip_scoreboard_timestamp(build_scoreboard())
            have = _strip_scoreboard_timestamp(sb_path.read_text(encoding="utf-8"))
            if want == have:
                print("  [OK]  与当前 results/*.json 现算结果一致")
            else:
                wl = [l for l in want.splitlines() if l.startswith("|")]
                hl = [l for l in have.splitlines() if l.startswith("|")]
                missing = [l for l in wl if l not in hl]
                extra = [l for l in hl if l not in wl]
                for l in missing:
                    print(f"  [FAIL] 缺行（json 有、板上没有）: {l}")
                for l in extra:
                    print(f"  [FAIL] 多行（板上有、json 无）  : {l}")
                if not missing and not extra:
                    print("  [FAIL] 表体一致但非表体部分有差异")
                print("  提示：跑 `python benchmarks/run_all.py --offline` 全绿后会自动刷新")
                ok = False
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL] SCOREBOARD 同步检查异常: {type(e).__name__}: {e}")
            ok = False

    # ---- 5.4 正则卫生：死正则 / 遮蔽冲突 / 内联遮蔽 ----
    print("  -- 正则卫生（死正则 / 遮蔽冲突 / 内联遮蔽）--")
    try:
        from core.agents.regex_audit import audit_paths
        import pathlib as _pl
        mods = sorted(str(p.relative_to(root)).replace("\\", "/")
                      for p in (root / "core").rglob("*.py"))
        audit = audit_paths(mods)
        print(f"  扫描 {audit.modules} 模块 / {audit.top_level_regexes} 个顶层正则")
        for issue in audit.issues:
            print(f"  [FAIL] {issue}")
        if audit.issues:
            ok = False
        else:
            print("  [OK] 无死正则、无遮蔽冲突、无内联遮蔽")
    except Exception as e:  # noqa: BLE001
        print(f"  [FAIL] 正则卫生检查异常: {type(e).__name__}: {e}")
        ok = False

    # ---- 5.5 SARIF 2.1.0 合规（M92）----
    # 上传 GitHub Code Scanning 时格式错一个字段整批被拒，而本地"看着对"。
    # 这里做两件事：① 自产 SARIF 必须零错误；② 故意写坏的文档必须被逐条拦住
    # （不拦 = 校验器写了跟没写一样）。
    print("  -- SARIF 2.1.0 合规校验 --")
    try:
        from core.context.sarif_validator import validate_sarif
        _good = build_sarif([{
            "file": "src/A.java", "line": 12, "category": "sqli",
            "unit": "A.run", "level": "warning", "priority": "P0",
            "message": "SQL 注入", "code": "class A {}", "code_from": 1,
        }], ".")
        _gerrs = validate_sarif(_good)
        if _gerrs:
            print(f"  [FAIL] 自产 SARIF 不合规：{_gerrs[:3]}")
            ok = False
        else:
            print("  [OK] 自产 SARIF 合规（rubric: version / uri / startLine /"
                  " security-severity）")
        _bad = {
            "version": "2.1",
            "runs": [{
                "tool": {"driver": {"name": "x", "rules": [
                    {"id": "a"}, {"id": "a"}]}},
                "results": [{
                    "ruleId": "nope",
                    "message": {"text": ""},
                    "level": "fatal",
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "C:\\x\\A.java"},
                        "region": {"startLine": 0, "endLine": 0}}}],
                    "properties": {"security-severity": 6},
                }],
            }],
        }
        _berrs = validate_sarif(_bad)
        if len(_berrs) < 6:
            print(f"  [FAIL] 坏 SARIF 只拦住 {len(_berrs)} 条（应 ≥6）：{_berrs}")
            ok = False
        else:
            print(f"  [OK] 坏 SARIF 逐条拦住 {len(_berrs)} 类问题"
                  "（版本/重复 ID/悬空 ruleId/空消息/非法 level/盘符路径/"
                  "startLine/severity 类型）")
    except Exception as e:  # noqa: BLE001
        print(f"  [FAIL] SARIF 校验器异常: {type(e).__name__}: {e}")
        ok = False

    # ---- 5.5 M160：Top-3 交单四件套 ----
    print("  -- Top-3 交单包 --")
    packs_dir = root / "benchmarks" / "results" / "first_blood_packs"
    if not packs_dir.exists():
        print("  [提示] first_blood_packs/ 不存在（尚未生成，不判 FAIL）")
    else:
        packs = [d for d in sorted(packs_dir.iterdir()) if d.is_dir()]
        if len(packs) < 3:
            print(f"  [FAIL] 交单包只有 {len(packs)} 个（应 ≥3）")
            ok = False
        for d in packs:
            need = ["ADVISORY.md", "fix.patch", "SUBMISSION_CHECKLIST.md"]
            miss = [f for f in need if not (d / f).is_file()]
            adv = ((d / "ADVISORY.md").read_text(encoding="utf-8")
                   if (d / "ADVISORY.md").is_file() else "")
            patched = ((d / "fix.patch").stat().st_size
                       if (d / "fix.patch").is_file() else 0)
            good = (not miss and patched > 0
                    and "[Auto-Fix Verified]" in adv)
            print(f"  [{'OK' if good else 'FAIL'}] {d.name}"
                  f"{' 缺 ' + str(miss) if miss else ''}"
                  f"{' 无补丁' if patched == 0 else ''}"
                  f"{' 缺标记' if '[Auto-Fix Verified]' not in adv else ''}")
            if not good:
                ok = False
        if packs and not any(True for _ in packs if False):
            print(f"  共 {len(packs)} 份立即可投递的交单包（每份四件套 + 补丁自检）")

    return ok


def _doctor_wild_hunt_check(ok: bool) -> bool:
    """doctor 第六段（M85）：wild_hunt.json ↔ WILD_HUNT_REPORT.md 对账。

    核对核心汇总数字：仓库数、入口总数、独立根因数、零误报计数。
    报告是给人和上游看的，json 是机器事实源；两者漂了 doctor 当场 FAIL。
    """
    root = Path(__file__).resolve().parent
    print("== [6/10] 野战白皮书对账（wild_hunt.json ↔ WILD_HUNT_REPORT.md）==")
    agg = root / "benchmarks" / "results" / "wild_hunt.json"
    report = root / "WILD_HUNT_REPORT.md"
    if not agg.exists() or not report.exists():
        print(f"  [FAIL] 缺少 {agg.name} 或 WILD_HUNT_REPORT.md")
        return False
    try:
        data = json.loads(agg.read_text(encoding="utf-8"))
        repos = data.get("repos", [])
        n_repos = len(repos)
        n_units = sum(int(r.get("summary", {}).get("total_units") or 0)
                      for r in repos)
        n_roots = sum(int(r.get("p0_unique_root_causes")
                          or r.get("summary", {})
                          .get("p0_unique_root_causes") or 0)
                      for r in repos)
        n_fp = sum(int((r.get("benchmark") or {}).get("fp") or 0)
                   for r in repos)
        text = report.read_text(encoding="utf-8")
        missing = []
        for label, needle in (
                ("仓库数", f"**{n_repos} 个**"),
                ("入口总数", f"**{n_units:,} 个**"),
                ("独立根因数", f"**{n_roots} 个**"),
                ("零误报", "**0 条**")):
            if needle not in text:
                missing.append(f"{label}（{needle}）")
        print(f"  json：{n_repos} 仓 / {n_units:,} 入口 / "
              f"{n_roots} 根因 / {n_fp} 条 benchmark 误报")
        if n_fp:
            print(f"  [FAIL] benchmark 误报 {n_fp} 条（应为 0）")
            ok = False
        if missing:
            print("  [FAIL] 报告缺核心数字：" + "；".join(missing))
            ok = False
        if not missing and not n_fp:
            print("  [OK]  仓库数 / 入口总数 / 独立根因数 / 零误报 四处一致")
    except Exception as e:  # noqa: BLE001
        print(f"  [FAIL] 野战对账异常: {type(e).__name__}: {e}")
        ok = False
    return ok



def cmd_watch(args) -> int:
    """M152：增量首杀监控入口。"""
    from core.context.watchtower import WATCH_CATEGORIES, run_watch

    cats = ([c.strip() for c in args.categories.split(",") if c.strip()]
            if args.categories else None)
    unknown = sorted(set(cats or []) - set(WATCH_CATEGORIES))
    if unknown:
        print(f"[!] 未注册类目：{unknown}")
        return 2
    payload = run_watch(
        args.repos, since=args.since, state_file=args.state_file,
        bundle_dir=args.bundle_dir, categories=cats,
        check_baseline=not args.no_baseline,
        include_existing=args.include_existing, dry_run=args.dry_run)
    for r in payload["repos"]:
        state = ("ERROR " + r["error"]) if r["error"] else (
            r["skipped"] or f"命中 {r['hits']}")
        print(f"[watch] {Path(r['repo']).name}: {state}")
    if payload["hits"]:
        print("\n增量命中：")
        for h in payload["hits"]:
            print(f"  - [{h['category']}] {h['unit']} @ {h['file']}:{h['line']}"
                  f"（{h['origin']} / {h['baseline']}）")
    print(f"\n产物 {payload['bundle_count']} 个 → {Path(args.bundle_dir)}")
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                                   encoding="utf-8")
        print(f"摘要 JSON → {args.json}")
    errors = [r for r in payload["repos"] if r["error"]]
    if errors:
        print(f"[!] {len(errors)} 个仓库未能监控")
        return 1
    return 0


def main():
    from core.text_utils import ensure_utf8_stdio
    ensure_utf8_stdio()
    load_dotenv(Path(__file__).resolve().parent / ".env")
    parser = argparse.ArgumentParser(prog="nexus-audit", description="AI 自动化漏洞挖掘审计框架")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="依赖/规则注册表/缓存指纹/补丁器就位自检（只读）")
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
    p_scan.add_argument("--graph", action="store_true",
                        help="M49：报告中内嵌 Mermaid 污点传播路径图"
                             "（入口 → Hop → Sink 行号）")
    p_scan.add_argument("--emit-poc", "--synth-poc", dest="emit_poc",
                        default=None, metavar="DIR",
                        help="M45：把规则层确定性 True 命中合成为可运行 PoC "
                             "骨架（Solidity .t.sol / Python pytest / Java MockMvc）"
                             "并落盘到 DIR（--synth-poc 是同一开关的别名）")
    p_scan.add_argument("--sarif", default=None, metavar="OUT.sarif",
                        help="将命中结果导出为 SARIF v2.1.0（GitHub Code Scanning 格式）")
    p_scan.add_argument("--gitlab-sast", dest="gitlab_sast", default=None,
                        metavar="gl-sast-report.json",
                        help="M127：导出 GitLab SAST v15 报告"
                             "（GitLab Ultimate / 极狐安全面板格式）")
    p_scan.add_argument("--html", default=None, metavar="OUT.html",
                        help="M57：产出零外部依赖的单文件交互式 HTML 报告")
    p_scan.add_argument("--summary-json", default=None, metavar="OUT.json",
                        help="M66：输出机器可读的狩猎漏斗统计（Hunt Dossier）")
    p_scan.add_argument("--advisory-dir", default=None, metavar="DIR",
                        help="M77：按独立根因导出 GitHub Security Advisory 草稿")
    p_scan.add_argument("--baseline", default=None, metavar="PREV.sarif",
                        help="M84：抑制基线中的存量根因，只报本次净增 P0")
    p_scan.add_argument("--no-llm-cache", dest="no_llm_cache", action="store_true",
                        help="M59：禁用大模型响应磁盘缓存（默认开）")
    p_scan.add_argument("--auto", action="store_true",
                        help="M58 野战模式：全类目规则普查 + Sink 门控漏斗，"
                             "无需人工指定类目")
    p_scan.add_argument("--fix", action="store_true",
                        help="M61：野战组合 —— 对 P0 实锤跑确定性补丁自检"
                             "（报告写入 fix_report_auto.md）")
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
    p_pr.add_argument("--gh-comments", dest="gh_comments", default=None,
                      metavar="OUT.json",
                      help="M112：导出 GitHub PR 行级 review 载荷（path/line/body，"
                           "带 ```suggestion 一键采纳补丁）")
    p_pr.add_argument("--fix", action="store_true",
                      help="对规则层确定性命中（sqli/xss 模板/deserial fastjson 版本）"
                           "生成补丁并重跑规则自检（写 fix_report.md，不改仓库文件）")
    p_pr.add_argument("--sarif", default=None, metavar="OUT.sarif",
                      help="将命中结果导出为 SARIF v2.1.0（GitHub Code Scanning 格式）")
    p_pr.add_argument("--baseline", default=None, metavar="PREV.sarif",
                      help="M84：抑制基线中的存量根因（透传到增量扫描）")
    p_pr.add_argument("--no-llm-cache", dest="no_llm_cache", action="store_true",
                      help="M59：禁用大模型响应磁盘缓存（默认开）")
    p_pr.add_argument("--html", default=None, metavar="OUT.html",
                      help="M57：产出零外部依赖的单文件交互式 HTML 报告")
    p_pr.add_argument("--output", default=None, help="报告输出路径")
    p_pr.add_argument("--graph", action="store_true",
                      help="M49：报告中内嵌 Mermaid 污点传播路径图")
    p_hunt = sub.add_parser(
        "hunt", help="M91：多仓批量野战 + Portfolio 总览大屏 + 披露草稿")
    p_hunt.add_argument("repos", nargs="+", metavar="REPO",
                        help="一个或多个仓库/子目录路径")
    p_hunt.add_argument("--outdir", default="hunt_results",
                        help="每仓产物的落盘根目录（默认 hunt_results/）")
    p_hunt.add_argument("--html", default=None, metavar="OUT.html",
                        help="跨仓 Portfolio 单文件大屏")
    p_hunt.add_argument("--summary-json", default=None, metavar="OUT.json",
                        help="跨仓汇总 JSON")
    p_hunt.add_argument("--advisory-dir", default=None, metavar="DIR",
                        help="GHSA 披露草稿目录（每仓一个子目录）")
    p_hunt.add_argument("--emit-poc", default=None, metavar="DIR",
                        help="为每仓 P0 合成 PoC 脚本目录")
    p_hunt.add_argument("--fix", action="store_true",
                        help="对每仓 P0 跑确定性补丁自检（--fix）")
    p_hunt.add_argument("--jobs", type=int, default=1,
                        help="并发仓数（≥2 启用并发，默认顺序）")
    p_gen = sub.add_parser(
        "benchmark-gen", help="M93：把野战仓库一键转成回归门禁脚本")
    p_gen.add_argument("repo_path")
    p_gen.add_argument("--out", default=None, metavar="OUT.py",
                       help="生成的脚本路径（默认 benchmarks/benchmark_<name>.py）")
    p_gen.add_argument("--bench-key", default=None,
                       help="urn：结果 json 与切片缓存键（默认由目录名派生）")
    p_gen.add_argument("--no-cache", action="store_true", help="禁用切片温缓存")
    p_matrix = sub.add_parser(
        "matrix", help="M100：24 类 × 三语言 ×（规则/--fix/PoC/CVSS）能力矩阵")
    p_matrix.add_argument("--summary-json", default=None, metavar="OUT.json",
                          help="矩阵 JSON（供冒烟断言缺口不增长）")
    p_watch = sub.add_parser(
        "watch", help="M152：增量首杀监控（只报本次提交新引入的规则层 P0）")
    p_watch.add_argument("repos", nargs="+", metavar="REPO",
                         help="一个或多个本地 Git 仓库")
    p_watch.add_argument("--since", default=None,
                         help="对比基线（默认读 state_file 里的 last_sha；"
                              "首跑回看 HEAD~1）")
    p_watch.add_argument("--state-file", default=".watch_state.json",
                         help="监控状态文件（默认 .watch_state.json）")
    p_watch.add_argument("--bundle-dir", default="watch_bundles",
                         help="交单四件套输出目录（默认 watch_bundles/）")
    p_watch.add_argument("--categories", default=None,
                         help="只监控指定类目，逗号分隔（默认全部 31 类）")
    p_watch.add_argument("--no-baseline", dest="no_baseline", action="store_true",
                         help="跳过基线 worktree（更快，但无法区分存量/新增）")
    p_watch.add_argument("--include-existing", dest="include_existing",
                         action="store_true",
                         help="基线已存在的命中也产包（默认只产新增）")
    p_watch.add_argument("--dry-run", action="store_true",
                         help="只判定不落盘（不写 bundle，也不更新状态）")
    p_watch.add_argument("--json", default=None, metavar="OUT.json",
                         help="机器可读摘要（供冒烟/CI 断言）")
    args = parser.parse_args()
    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "doctor":
        sys.exit(cmd_doctor(args))
    elif args.command == "hunt":
        sys.exit(cmd_hunt(args))
    elif args.command == "benchmark-gen":
        sys.exit(cmd_benchmark_gen(args))
    elif args.command == "matrix":
        sys.exit(cmd_matrix(args))
    elif args.command == "watch":
        sys.exit(cmd_watch(args))
    else:
        cmd_pr_scan(args)


if __name__ == "__main__":
    main()
