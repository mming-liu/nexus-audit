"""M258/M260：用 OpenCode Go 二级漏斗复核野战根因（LLM triage，不是人工核验）。

背景：wild_hunt.json 里的 208 条独立根因是规则层确定性判据的产物，
不是人工逐条读源码锁定的。v1.1 要求把第 31-50 仓（ruoyi-vue-pro / apollo /
xxl-job / Sentinel 等）尚未人工锁定的根因过一遍"模型反方挑刺"，把明显被
框架守卫覆盖的噪音先压下去，再交人工。

本脚本做三件事，且绝不把模型结论写成人工核验：

  1. 取 wild_hunt.json 第 31-50 仓的 root_causes，读源码切片 + 仓级框架装配线索；
  2. Tier-1 用 beam-free（免费）做初筛，Tier-2 用 SkepticReviewer（glm-5.3-flash，
     失败时显式切 deepseek-v4.1-flash）做反方挑刺；
  3. 输出 benchmarks/results/llm_root_triage.json + .md，逐条记录
     CONFIRMED_TP / LIKELY_FP_GUARDED / NEEDS_HUMAN 及双方理由。

计费边界：Tier-1 走免费模型；Tier-1 不可用时不会静默降级付费，该条直接
记 NEEDS_HUMAN（保留人工队列）。Tier-2 是显式付费复核层，失败才切备用付费
模型，并在记录里写明实际使用的模型。

用法：
    python benchmarks/llm_triage_roots.py                 # 复核第 31-50 仓
    python benchmarks/llm_triage_roots.py --limit 2       # 先试两条
    python benchmarks/llm_triage_roots.py --only apollo,xxl-job
    python benchmarks/llm_triage_roots.py --check         # 校验台账完整性（冒烟用）

断点续跑：每完成一条追加到 llm_root_triage.jsonl；重跑默认跳过已完成条目，
--force 才重算（会命中 .cache/llm_responses.jsonl 的磁盘缓存）。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.text_utils import ensure_utf8_stdio                    # noqa: E402
ensure_utf8_stdio()

WILD = ROOT / "benchmarks" / "results" / "wild_hunt.json"
OUT_JSON = ROOT / "benchmarks" / "results" / "llm_root_triage.json"
OUT_MD = ROOT / "benchmarks" / "results" / "llm_root_triage.md"
OUT_JSONL = ROOT / "benchmarks" / "results" / "llm_root_triage.jsonl"
CACHE = ROOT / ".cache" / "llm_responses.jsonl"

ALLOWED = ("CONFIRMED_TP", "LIKELY_FP_GUARDED", "NEEDS_HUMAN")
TIER1_MODEL = "beam-free"
TIER2_PRIMARY = "glm-5.3-flash"
TIER2_BACKUP = "deepseek-v4.1-flash"

LANG_BY_EXT = {".java": "java", ".sol": "solidity", ".py": "python",
               ".js": "javascript", ".ts": "typescript", ".go": "go"}

JAVA_SIG = re.compile(
    r"^\s*(?:public|protected|private|static|final|synchronized|abstract|"
    r"native|default)\b[^;{}]*\([^;]*\)\s*(?:throws [\w, .<>]+)?\s*\{?\s*$")
PY_SIG = re.compile(r"^\s*(?:async\s+)?def\s+\w+")
SOL_SIG = re.compile(
    r"^\s*(?:function|constructor|modifier|fallback|receive)\b[^;]*[\(\{]")

CONFIG_NAME_HINT = re.compile(
    r"(security|shiro|interceptor|webmvc|cors|auth|filter|permission|"
    r"settings|urls|middleware|config)", re.I)
CONFIG_LINE_HINT = re.compile(
    r"addInterceptor|addPathPatterns|excludePathPatterns|permitAll|"
    r"authorizeRequests|authorizeHttpRequests|SecurityFilterChain|filterChain|"
    r"allowedOrigin|CorsConfiguration|addCorsMappings|@PreAuthorize|@Secured|"
    r"@RequiresPermissions|login_required|permission_classes|before_request|"
    r"requires_auth|middleware|hasRole|hasAuthority|ROLE_", re.I)

SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", ".idea",
             ".pytest_cache", "__pycache__", "venv", ".venv", "site-packages"}

TIER1_PROMPT = """你是 nexus-audit 的 Tier-1 初筛员，只做证据核对，不做最终定性。

规则层在下列位置判出一条 {category}（{cwe}）P0 根因，影响 {routes} 条路由。
仓库：{repo}（repo_role={role}）
根因签名：{unit}
位置：{file}:{line}
受影响路由（前 8 条）：{route_list}

待审代码（{start_line}-{end_line} 行，可能被截断）：
{code}

仓级框架装配线索（可能覆盖/收窄该路由；空表示未采集到）：
{context}

请判断这条结论最可能是：
- CONFIRMED_TP：代码路径上确实缺少必要校验/清洗，规则层结论成立；
- LIKELY_FP_GUARDED：上游/框架级已有守卫（全局鉴权、白名单、编码、参数化、
  框架默认转义等）覆盖了该路径；
- NEEDS_HUMAN：证据不足、代码被截断、或需要仓库全局装配才能判断。

只输出 JSON，不要 markdown：
{{"verdict":"CONFIRMED_TP|LIKELY_FP_GUARDED|NEEDS_HUMAN",
  "confidence":0.0,
  "reason":"不超过 120 字的中文理由",
  "guard":"若判 FP，指出具体守卫；否则空字符串"}}
"""


def load_env() -> None:
    """加载 .env（不覆盖已有环境变量）。"""
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")
        return
    except Exception:                                        # noqa: BLE001
        pass
    p = ROOT / ".env"
    if not p.is_file():
        return
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


def _read_text(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _lang_of(path: str) -> str:
    return LANG_BY_EXT.get(Path(path).suffix.lower(), "text")


def _sig_re(lang: str):
    return {"java": JAVA_SIG, "python": PY_SIG,
            "solidity": SOL_SIG}.get(lang)


def _method_start(lines: list[str], line_no: int, lang: str) -> int:
    """从根因行向上找方法/函数声明；找不到就用 line-8。"""
    pat = _sig_re(lang)
    idx = max(0, min(len(lines) - 1, line_no - 1))
    if pat is not None:
        for i in range(idx, max(-1, idx - 90), -1):
            if pat.search(lines[i]):
                idx = i
                break
    # 把紧邻的注解/文档注释一起带上（Java @PreAuthorize 就在上一行）
    j = idx
    while j > 0:
        prev = lines[j - 1].strip()
        if prev.startswith("@") or prev.startswith("///") or \
                prev.startswith("//") or prev.startswith("*") or \
                prev.startswith("/*") or prev.startswith("#"):
            j -= 1
            continue
        break
    return max(0, j - 1)


def build_evidence(rc: dict, repo_path: Path, context: str) -> dict:
    """构造带行号/上下文的证据切片（只读源码，不改任何文件）。"""
    path = str(rc.get("file") or "")
    line_no = max(1, int(rc.get("line") or 1))
    lang = _lang_of(path)
    lines = _read_text(path).splitlines()
    if not lines:
        return {"code": "", "start_line": line_no, "end_line": line_no,
                "lang": lang, "missing": True, "context": context}
    start = _method_start(lines, line_no, lang)
    # 至少覆盖根因行前后：前 60 / 后 90，再按 170 行封顶
    end = min(len(lines), max(line_no + 90, start + 120))
    if end - start > 170:
        end = start + 170
    code = "\n".join(lines[start:end])
    # 行号给审计/报告；给模型的是纯代码 + 头注释，避免行号破坏语法
    header = {"java": "//", "solidity": "//", "python": "#"}.get(lang, "#")
    header_line = (f"{header} repo={repo_path.name} file={path} "
                   f"lines={start + 1}-{end} root_line={line_no} "
                   f"category={rc.get('category')}")
    llm_code = header_line + "\n" + code
    return {"code": llm_code, "start_line": start + 1, "end_line": end,
            "lang": lang, "missing": False, "context": context}


def _repo_config_context(repo_path: Path, max_files: int = 5,
                         max_chars: int = 3500) -> str:
    """采集仓级鉴权/CORS 装配线索（只读，按文件名与关键字过滤）。"""
    if not repo_path.is_dir():
        return ""
    candidates: list[Path] = []
    try:
        for dirpath, dirnames, filenames in os.walk(repo_path):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if not fn.endswith((".java", ".py", ".yml", ".yaml", ".properties")):
                    continue
                if not CONFIG_NAME_HINT.search(fn):
                    continue
                p = Path(dirpath) / fn
                try:
                    if p.stat().st_size > 300_000:
                        continue
                except OSError:
                    continue
                candidates.append(p)
                if len(candidates) >= 400:
                    break
            if len(candidates) >= 400:
                break
    except OSError:
        pass
    # 名字越像全局装配越靠前
    def score(p: Path) -> tuple:
        n = p.name.lower()
        return (0 if "security" in n else 1 if "shiro" in n else
                2 if "interceptor" in n else 3 if "cors" in n else
                4 if "webmvc" in n else 5, len(str(p)))
    blocks: list[str] = []
    used = 0
    for p in sorted(candidates, key=score)[:max_files]:
        text = _read_text(p)
        if not text:
            continue
        ls = text.splitlines()
        hits = [i for i, ln in enumerate(ls) if CONFIG_LINE_HINT.search(ln)]
        if not hits:
            continue
        try:
            rel = p.relative_to(repo_path).as_posix()
        except ValueError:
            rel = p.name
        chunk: list[str] = [f"// {rel}"]
        last_end = -10
        for i in hits[:3]:
            a, b = max(0, i - 6), min(len(ls), i + 7)
            if a <= last_end:
                a = last_end + 1
            if a >= b:
                continue
            chunk.extend(f"{j + 1:5d}| {ls[j]}" for j in range(a, b))
            chunk.append("// ...")
            last_end = b
        piece = "\n".join(chunk)
        if used + len(piece) > max_chars:
            piece = piece[:max(0, max_chars - used)]
        blocks.append(piece)
        used += len(piece)
        if used >= max_chars:
            break
    return "\n".join(blocks)


def select_roots(data: dict, start: int, end: int,
                 only: set[str] | None = None) -> list[dict]:
    out: list[dict] = []
    for idx, repo in enumerate(data.get("repos", []), 1):
        if idx < start or idx > end:
            continue
        name = repo.get("name", "")
        if only and name not in only:
            continue
        for rc in repo.get("summary", {}).get("root_causes") or []:
            out.append({
                "repo_index": idx, "repo": name,
                "repo_role": repo.get("repo_role", "production"),
                "category": rc.get("category", ""),
                "representative": rc.get("representative", ""),
                "file": rc.get("file", ""), "line": int(rc.get("line") or 0),
                "affected_routes": int(rc.get("affected_routes") or 0),
                "routes": rc.get("routes") or [],
                "kind": rc.get("kind", ""),
            })
    return out


def _key(item: dict) -> str:
    return f"{item['repo']}|{item['category']}|{item['representative']}"


def _load_done(force: bool) -> dict[str, dict]:
    done: dict[str, dict] = {}
    if force or not OUT_JSONL.is_file():
        return done
    for line in OUT_JSONL.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("verdict") in ALLOWED:
            done[rec.get("_key", "")] = rec
    return done


async def _append_jsonl(rec: dict, lock: asyncio.Lock) -> None:
    async with lock:
        OUT_JSONL.parent.mkdir(parents=True, exist_ok=True)
        with OUT_JSONL.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _tier1_parse(raw: str) -> dict:
    from core.agents.router import extract_json
    try:
        data = extract_json(raw)
    except Exception as e:                                   # noqa: BLE001
        return {"verdict": "NEEDS_HUMAN", "confidence": 0.0,
                "reason": f"Tier-1 JSON 解析失败：{type(e).__name__}: {e}"[:200],
                "guard": ""}
    if not isinstance(data, dict):
        return {"verdict": "NEEDS_HUMAN", "confidence": 0.0,
                "reason": "Tier-1 返回非对象 JSON", "guard": ""}
    verdict = str(data.get("verdict", "")).strip().upper()
    if verdict not in ALLOWED:
        verdict = "NEEDS_HUMAN"
    try:
        conf = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    return {"verdict": verdict, "confidence": max(0.0, min(1.0, conf)),
            "reason": str(data.get("reason", ""))[:500],
            "guard": str(data.get("guard", ""))[:300]}


def combine(t1: dict, t2: dict) -> str:
    """保守合并：Tier-2 说被守卫覆盖就降为 FP；只有两级都支持才 CONFIRMED。"""
    if t2.get("error"):
        return "NEEDS_HUMAN"
    if t2.get("rejected"):
        return "LIKELY_FP_GUARDED"
    if t1.get("verdict") == "CONFIRMED_TP":
        return "CONFIRMED_TP"
    if t1.get("verdict") == "LIKELY_FP_GUARDED":
        return "LIKELY_FP_GUARDED"
    return "NEEDS_HUMAN"


def _build_clients():
    from core.agents.router import (CachedLLMClient, LLMDiskCache,
                                    OpenAICompatClient, TwoTierRouter)
    from core.agents.model_selector import BASE_URL
    cache = LLMDiskCache(CACHE)
    tier1 = CachedLLMClient(OpenAICompatClient(
        base_url=os.getenv("LLM_TIER1_BASE_URL") or BASE_URL,
        model=TIER1_MODEL,
        api_key=os.getenv("LLM_TIER1_API_KEY") or os.getenv("LLM_API_KEY", ""),
        timeout=75.0, max_retries=3), cache)
    primary = CachedLLMClient(OpenAICompatClient(
        base_url=os.getenv("LLM_TIER2_BASE_URL") or BASE_URL,
        model=TIER2_PRIMARY,
        api_key=os.getenv("LLM_TIER2_API_KEY") or os.getenv("LLM_API_KEY", ""),
        timeout=90.0, max_retries=2), cache)
    backup = CachedLLMClient(OpenAICompatClient(
        base_url=os.getenv("LLM_TIER2_BASE_URL") or BASE_URL,
        model=TIER2_BACKUP,
        api_key=os.getenv("LLM_TIER2_API_KEY") or os.getenv("LLM_API_KEY", ""),
        timeout=90.0, max_retries=2), cache)
    return tier1, primary, backup, TwoTierRouter


class _FailoverTier2:
    """按顺序尝试付费复核模型；记录本次真正成功的模型名。"""

    def __init__(self, clients: list):
        self.clients = clients
        self.model = getattr(clients[0], "model", TIER2_PRIMARY) if clients else ""
        self.used: list[str] = []

    async def chat(self, messages: list[dict[str, str]],
                   temperature: float = 0.0) -> str:
        last: Exception | None = None
        for c in self.clients:
            try:
                raw = await c.chat(messages, temperature)
                self.model = getattr(c, "model", self.model)
                self.used.append(self.model)
                return raw
            except Exception as e:                            # noqa: BLE001
                last = e
                continue
        raise last or RuntimeError("Tier-2 无可用模型")


async def review_one(item: dict, ctx: str, tier1, primary, backup,
                     RouterCls) -> dict:
    from core.agents.skeptic_reviewer import SkepticReviewer
    from core.models import CodeUnit, Language, VulnHypothesis
    from core.agents.vuln_categories import CATEGORIES

    cat = item["category"]
    meta = CATEGORIES.get(cat)
    cwe = getattr(meta, "cwe", "") if meta else ""
    display = getattr(meta, "display", cat) if meta else cat
    repo_path = Path(item["file"]).parents[0] if Path(item["file"]).parents else Path(".")
    for parent in Path(item["file"]).parents:
        if (parent / ".git").exists():
            repo_path = parent
            break
    evidence = build_evidence(item, repo_path, ctx)
    prompt = TIER1_PROMPT.format(
        category=cat, cwe=cwe or "CWE", routes=item["affected_routes"],
        repo=item["repo"], role=item["repo_role"], unit=item["representative"],
        file=item["file"], line=item["line"],
        route_list=", ".join(item["routes"][:8]) or "(未记录)",
        start_line=evidence["start_line"], end_line=evidence["end_line"],
        code=evidence["code"] or "(源码不可读)",
        context=evidence.get("context") or "(未采集到仓级装配线索)")

    t1: dict = {"model": getattr(tier1, "model", TIER1_MODEL)}
    try:
        raw1 = await tier1.chat([
            {"role": "system", "content": "You are a conservative static-analysis screener. Output JSON only."},
            {"role": "user", "content": prompt}])
        t1.update(_tier1_parse(raw1))
        t1["raw"] = raw1[:3000]
    except Exception as e:                                    # noqa: BLE001
        # Tier-1 不可用 → 不触发付费兜底，直接保留人工队列（计费边界）
        t1.update({"verdict": "NEEDS_HUMAN", "confidence": 0.0,
                   "reason": f"Tier-1 不可用（未降级付费）：{type(e).__name__}: {e}"[:300],
                   "guard": "", "error": f"{type(e).__name__}: {e}"[:300]})
        return {"_key": _key(item), **item, "tier1": t1,
                "tier2": {"model": "", "rejected": None,
                          "reason": "Tier-1 不可用，按计费边界跳过 Tier-2",
                          "skipped": True},
                "verdict": "NEEDS_HUMAN", "reason": t1["reason"],
                "human_verified": False,
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    # Tier-2：SkepticReviewer 走同一套反方挑刺提示词；source_code 里带上
    # 文件/路由/Tier-1 结论，避免质检员只看到孤立方法体。
    recorder = _FailoverTier2([primary, backup])
    router = RouterCls(tier1=tier1, tier2=recorder)
    lang = {"java": Language.JAVA_WEB, "python": Language.PYTHON_WEB,
            "solidity": Language.SOLIDITY_WEB3}.get(
                evidence["lang"], Language.PYTHON_WEB)
    unit = CodeUnit(
        file_path=item["file"], language=lang,
        unit_name=item["representative"], start_line=item["line"],
        end_line=evidence["end_line"], source_code=evidence["code"] or "(源码不可读)")
    ctx_header = (
        f"repo={item['repo']} role={item['repo_role']} category={display} "
        f"file={item['file']}:{item['line']} routes={item['affected_routes']}\n"
        f"Tier-1 verdict={t1['verdict']} reason={t1.get('reason', '')}\n"
        f"仓级装配线索:\n{evidence.get('context') or '(未采集到)'}\n")
    hyp = VulnHypothesis(
        unit=unit, vuln_type=display, scenario_hit=True,
        property_missing=ctx_header, confidence=float(t1.get("confidence") or 0.0))
    reviewer = SkepticReviewer(router=router)
    t2: dict = {"model": ""}
    try:
        await reviewer.review(hyp)
        verdict2 = reviewer.last_verdict or {}
        t2.update({
            "model": recorder.model,
            "rejected": bool(verdict2.get("rejected")),
            "reason": str(verdict2.get("reason", ""))[:600],
            "raw": (reviewer.last_raw or "")[:3000],
        })
    except Exception as e:                                    # noqa: BLE001
        t2.update({"model": recorder.model or TIER2_PRIMARY,
                   "rejected": None,
                   "reason": f"Tier-2 失败：{type(e).__name__}: {e}"[:300],
                   "error": f"{type(e).__name__}: {e}"[:300]})

    final = combine(t1, t2)
    reason = t2.get("reason") or t1.get("reason") or ""
    return {"_key": _key(item), **item, "tier1": t1, "tier2": t2,
            "verdict": final, "reason": reason,
            "human_verified": False,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}


def _md_table(records: list[dict]) -> str:
    order = {"CONFIRMED_TP": 0, "LIKELY_FP_GUARDED": 1, "NEEDS_HUMAN": 2}
    rows = sorted(records, key=lambda r: (order.get(r["verdict"], 9),
                                          r["repo_index"], r["category"],
                                          r["representative"]))
    out = ["# LLM 根因复核台账（M258 / 非人工核验）", "",
           "> **这是模型复核，不是人工锁定的事实。** human_verified 一律为 "
           "false；任何对外披露前仍需人工逐条读源码。", "",
           f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
           f"- Tier-1：{TIER1_MODEL}（免费初筛）",
           f"- Tier-2：{TIER2_PRIMARY}（主）/ {TIER2_BACKUP}（备）",
           f"- 条目：{len(records)}", ""]
    counts = {v: sum(1 for r in records if r["verdict"] == v) for v in ALLOWED}
    out += ["| 结论 | 条数 |", "|---|---|"]
    out += [f"| {v} | {counts[v]} |" for v in ALLOWED]
    out += ["", "## 逐条结论", "",
            "| # | 仓库 | 类目 | 根因 | 路由 | Tier-1 | Tier-2 | 最终 | 理由（Tier-2 优先） |",
            "|---|---|---|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        t1 = r["tier1"].get("verdict", "-")
        rej = r["tier2"].get("rejected")
        t2 = ("rejected" if rej else "not-rejected" if rej is False
              else "skipped/error")
        reason = (r.get("reason") or "").replace("|", "\\|").replace("\n", " ")[:160]
        out.append(f"| {i} | {r['repo']} | {r['category']} | "
                   f"{r['representative']} | {r['affected_routes']} | "
                   f"{t1} | {t2} | **{r['verdict']}** | {reason} |")
    out += ["", "## 说明", "",
            "- CONFIRMED_TP：Tier-1 判成立且 Tier-2 未推翻；仍不是人工核验。",
            "- LIKELY_FP_GUARDED：Tier-2 找到框架/全局守卫或 Tier-1 判 FP；"
            "交单包会优先剔除这类根因。",
            "- NEEDS_HUMAN：证据不足、Tier-1 限流（按计费边界未降级付费）或"
            "两级结论不一致；保留人工队列。", ""]
    return "\n".join(out)


def _write_outputs(records: list[dict], expected: int, args) -> None:
    records = sorted(records, key=lambda r: (r["repo_index"], r["category"],
                                             r["representative"]))
    counts = {v: sum(1 for r in records if r["verdict"] == v) for v in ALLOWED}
    payload = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "generator": "benchmarks/llm_triage_roots.py",
        "human_verified": False,
        "disclaimer": "LLM triage only. Not human verification; do not publish as verified.",
        "models": {"tier1": TIER1_MODEL, "tier2_primary": TIER2_PRIMARY,
                   "tier2_backup": TIER2_BACKUP},
        "selection": {"repos": f"{args.start}-{args.end}",
                      "only": sorted(args.only) if args.only else None,
                      "expected_roots": expected, "completed": len(records)},
        "summary": counts,
        "roots": records,
    }
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    OUT_MD.write_text(_md_table(records), encoding="utf-8")
    print(f"\n[llm-triage] {len(records)} 条 → {OUT_JSON}")
    print(f"[llm-triage] 摘要 → {OUT_MD}")
    print("[llm-triage] " + " / ".join(f"{v}={counts[v]}" for v in ALLOWED))


def check() -> int:
    if not OUT_JSON.is_file():
        print("[llm-triage][FAIL] 缺少 llm_root_triage.json")
        return 1
    try:
        data = json.loads(OUT_JSON.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"[llm-triage][FAIL] JSON 解析失败：{e}")
        return 1
    bad: list[str] = []
    if data.get("human_verified") is not False:
        bad.append("human_verified 必须为 false（LLM 复核不得冒充人工核验）")
    wild = json.loads(WILD.read_text(encoding="utf-8"))
    expected = sum(len(r.get("summary", {}).get("root_causes") or [])
                   for r in wild["repos"][30:50])
    roots = data.get("roots") or []
    if len(roots) != expected:
        bad.append(f"条目数 {len(roots)} != 第 31-50 仓根因数 {expected}")
    for r in roots:
        if r.get("verdict") not in ALLOWED:
            bad.append(f"{r.get('repo')}/{r.get('representative')}: 非法 verdict")
        if not r.get("tier1") or not r.get("tier2"):
            bad.append(f"{r.get('repo')}/{r.get('representative')}: 缺两级记录")
        if r.get("human_verified") is not False:
            bad.append(f"{r.get('repo')}/{r.get('representative')}: human_verified 非 false")
    counts = {v: sum(1 for r in roots if r.get("verdict") == v) for v in ALLOWED}
    print(f"[llm-triage] {len(roots)}/{expected} 条；"
          + " / ".join(f"{v}={counts[v]}" for v in ALLOWED))
    if bad:
        for b in bad[:10]:
            print(f"[llm-triage][FAIL] {b}")
        return 1
    print("[llm-triage][OK] 台账完整，且明确未冒充人工核验")
    return 0


async def main_async(args) -> int:
    load_env()
    if not WILD.is_file():
        print(f"[llm-triage][FAIL] 缺少 {WILD}")
        return 2
    data = json.loads(WILD.read_text(encoding="utf-8"))
    items = select_roots(data, args.start, args.end, args.only)
    if args.limit:
        items = items[:args.limit]
    print(f"[llm-triage] 选中 {len(items)} 条根因（第 {args.start}-{args.end} 仓）")
    done = _load_done(args.force)
    todo = [x for x in items if _key(x) not in done]
    print(f"[llm-triage] 已完成 {len(items) - len(todo)} 条，待复核 {len(todo)} 条")
    if not todo:
        records = [done[_key(x)] for x in items]
        _write_outputs(records, len(items), args)
        return 0

    from core.agents.model_selector import probe_model
    if not probe_model(TIER1_MODEL, attempts=5):
        print(f"[llm-triage][FAIL] Tier-1 {TIER1_MODEL} 不可用；"
              "按计费边界不降级付费，保留人工队列")
        return 3
    tier2_clients = []
    for m in (TIER2_PRIMARY, TIER2_BACKUP):
        if probe_model(m, attempts=3):
            tier2_clients.append(m)
        else:
            print(f"[llm-triage][warn] Tier-2 {m} 预检失败（仍可能在线，运行时会再试）")
    if not tier2_clients:
        print("[llm-triage][FAIL] Tier-2 主备预检都不可用")
        return 3
    # 预检只用于快速失败：只要主模型在线，备用也保留在链路上，运行期再试。
    if TIER2_PRIMARY in tier2_clients:
        tier2_clients = [TIER2_PRIMARY, TIER2_BACKUP]
    else:
        tier2_clients = [TIER2_BACKUP]
    print(f"[llm-triage] Tier-2 链路：{tier2_clients}")

    tier1, primary, backup, RouterCls = _build_clients()
    if tier2_clients[0] != TIER2_PRIMARY:
        primary, backup = backup, primary

    lock = asyncio.Lock()
    sem = asyncio.Semaphore(max(1, args.concurrency))
    results: dict[str, dict] = dict(done)

    async def worker(item: dict) -> None:
        async with sem:
            repo_path = Path(item["file"]).parents[0] if Path(item["file"]).parents else Path(".")
            for parent in Path(item["file"]).parents:
                if (parent / ".git").exists():
                    repo_path = parent
                    break
            ctx = _repo_context_cached(repo_path)
            try:
                rec = await review_one(item, ctx, tier1, primary, backup, RouterCls)
            except Exception as e:                            # noqa: BLE001
                rec = {"_key": _key(item), **item,
                       "tier1": {"verdict": "NEEDS_HUMAN", "reason": str(e)[:300]},
                       "tier2": {"rejected": None, "reason": "内部异常"},
                       "verdict": "NEEDS_HUMAN", "human_verified": False,
                       "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
            results[_key(item)] = rec
            await _append_jsonl(rec, lock)
            print(f"[{len(results):3d}/{len(items)}] {item['repo']} / "
                  f"{item['category']} / {item['representative']} → {rec['verdict']}",
                  flush=True)

    await asyncio.gather(*(worker(x) for x in todo))
    records = [results[_key(x)] for x in items if _key(x) in results]
    _write_outputs(records, len(items), args)
    return 0


_CTX_CACHE: dict[str, str] = {}


def _repo_context_cached(repo_path: Path) -> str:
    key = str(repo_path)
    if key not in _CTX_CACHE:
        _CTX_CACHE[key] = _repo_config_context(repo_path)
    return _CTX_CACHE[key]


def main() -> int:
    ap = argparse.ArgumentParser(description="OpenCode Go 二级漏斗根因复核（M258）")
    ap.add_argument("--start", type=int, default=31, help="起始仓序号（1-based）")
    ap.add_argument("--end", type=int, default=50, help="结束仓序号（含）")
    ap.add_argument("--only", default="", help="逗号分隔的仓库显示名")
    ap.add_argument("--limit", type=int, default=0, help="只跑前 N 条（试跑）")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--force", action="store_true", help="忽略 JSONL 断点，全部重算")
    ap.add_argument("--check", action="store_true", help="只校验台账完整性")
    args = ap.parse_args()
    args.only = {x.strip() for x in args.only.split(",") if x.strip()}
    if args.check:
        return check()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
