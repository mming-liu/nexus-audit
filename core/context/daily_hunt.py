"""M286/M288：每日自动巡猎（daily-hunt）。

把「找新仓 → 浅克隆 → 同 SHA 直接跳过 → 只扫新提交 → 只报新根因 →
写手册 → 即扫即焚」串成一条可挂机流水线。调度不写进仓库：由 harness
的定时任务（session schedule）每天触发 python cli.py daily-hunt，
不生成 GitHub Actions，也不注册 Windows 计划任务。

状态账本（默认 benchmarks/results/daily_hunt_state.json）记录
last_scanned_sha 与 exported_roots；同 SHA 直接 0.1 秒跳过，同一个
“类目|入口|文件”根因只报一次。

M299：克隆前冷却期（--cooldown-days，默认 7 天）。距上次扫描不足 N 天
的仓，无论远端是否又推了新 Commit，都不再克隆，直接 0 秒记
SKIPPED (cooldown_Nd) 并顺延下一个候选 —— 否则 metasfresh 这类每天
推若干次的高频大仓会永久霸占当天的实扫名额，排在后面的新仓永远轮不到。
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import time
from datetime import datetime
from pathlib import Path

from core.context import cve_dedup, live_hunt, live_hunt_report, target_scout
from core.context import upstream_sync, wild_noise

STATE_VERSION = 1
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STATE = ROOT / "benchmarks" / "results" / "daily_hunt_state.json"
DEFAULT_REPORT = ROOT / "LIVE_HUNT_REPORT.md"
DEFAULT_JSON = ROOT / "benchmarks" / "results" / "daily_hunt.json"
DEFAULT_PACKS = ROOT / "benchmarks" / "results" / "daily_hunt_packs"
MAX_LEDGER_ROWS = 40
# M299：同一个仓默认 7 天内只完整克隆扫描一次（--cooldown-days 0 关闭）。
DEFAULT_COOLDOWN_DAYS = 7
_TIME_FMT = "%Y-%m-%d %H:%M:%S"


def _now() -> str:
    return time.strftime(_TIME_FMT)


def parse_scanned_at(value) -> datetime | None:
    """解析账本 last_scanned_at（本地时间；容忍 ISO 8601 与空格分隔写法）。"""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in (_TIME_FMT, "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def last_scan_age_days(entry: dict, now: datetime | None = None) -> float | None:
    """距上次扫描过去了多少天；无记录/解析失败返回 None（按可扫处理）。"""
    stamp = parse_scanned_at((entry or {}).get("last_scanned_at"))
    if stamp is None:
        return None
    now = now or datetime.now()
    if stamp.tzinfo is not None and now.tzinfo is None:
        now = now.astimezone()
    return (now - stamp).total_seconds() / 86400.0


def empty_state() -> dict:
    return {"version": STATE_VERSION, "updated_at": "", "repos": {}}


def load_state(path: Path) -> dict:
    path = Path(path)
    if not path.is_file():
        return empty_state()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return empty_state()
    if not isinstance(data, dict):
        return empty_state()
    data.setdefault("repos", {})
    data.setdefault("version", STATE_VERSION)
    return data


def save_state(path: Path, state: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    state["version"] = STATE_VERSION
    state["updated_at"] = _now()
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2,
                              sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def root_key(record: dict) -> str:
    """账本去重键：类目 + 入口 + 文件（同一入口的多条路由只算一条）。"""
    return "|".join((str(record.get("category") or ""),
                     str(record.get("unit") or ""),
                     str(record.get("file") or "")))


# M304：CVE 交单价值第一梯队。联网查重配额只花在这些类目 + HIGH authz 上。
HIGH_VALUE_CATEGORIES = (
    "sqli", "cmdi", "deserial", "ssti", "ssrf", "xxe", "jndi_injection",
    "unrestricted_upload", "zip_slip", "pathtraver", "arbitrary_file_delete",
    "spel",
)
_CATEGORY_RANK = {c: i for i, c in enumerate(HIGH_VALUE_CATEGORIES)}


def root_priority(record: dict, confidence: str = "") -> tuple[int, int]:
    """查重优先级：第一梯队 0，其余 1；同档按类目重要度、再按扫描顺序。"""
    cat = str(record.get("category") or "")
    if cat in _CATEGORY_RANK:
        return (0, _CATEGORY_RANK[cat])
    if cat == "authz" and str(confidence or record.get("confidence") or "") == "HIGH":
        return (0, len(_CATEGORY_RANK))
    return (1, 0)


def _root_view(rc: dict, repo: Path) -> dict:
    """根因 → 降噪/提拔可读的最小记录（相对路径 + 入口名）。"""
    return {
        "category": str(rc.get("category") or ""),
        "unit": str(rc.get("unit_name") or rc.get("representative") or ""),
        "file": live_hunt._rel(repo, str(rc.get("file") or "")),
        "routes": list(rc.get("routes") or []),
    }


def process_repo(slug: str, repo: Path, entry: dict | None = None, *,
                 dedup_online: bool = False, max_roots: int = 0,
                 max_head_age_days: int = 180, dedup_fn=None,
                 repo_timeout: int = 900) -> dict:
    """扫一个仓库，返回本次“新引入且未导出”的根因（含本地拦截的 B 项）。

    返回值：records / entry / skipped_unchanged / head_sha / raw_roots /
    total_units（M293：0 表示纯库无路由，调用方据此不占名额）。

    M304：顺序必须是 **本地降噪 → 优先级排序 → 截断 → 联网查重**。
    旧实现先 roots[:max_roots] 再降噪，前 5 条若全是 UNVERIFIED_WILD_AUTHZ
    / log_injection，第 6 条真 sqli 会被直接丢掉，还白烧 5 次 API 配额。
    """
    repo = Path(repo)
    entry = dict(entry or {})
    head = upstream_sync.local_head(repo)
    head_sha = head.get("head_sha") or ""
    base = {"scans": int(entry.get("scans") or 0) + 1}

    if head_sha and entry.get("last_scanned_sha") == head_sha:
        return {"records": [], "entry": {**entry, **base},
                "skipped_unchanged": True, "head_sha": head_sha,
                "raw_roots": 0, "total_units": None}

    scan = live_hunt.scan_repo(repo, timeout=repo_timeout)
    roots = list(scan["roots"])
    exported = set(entry.get("exported_roots") or [])

    kept: list[tuple[tuple[int, int], dict, dict]] = []
    blocked_roots: list[tuple[dict, dict]] = []
    for rc in roots:
        view = _root_view(rc, repo)
        if root_key(view) in exported:
            continue                     # 已导出过：不查重、不占名额
        noise = wild_noise.classify(view, repo)
        if noise.get("blocked"):
            blocked_roots.append((rc, noise))
            continue
        promo = wild_noise.promote(view, repo)
        kept.append((root_priority(view, promo.get("level", "")), rc, promo))
    kept.sort(key=lambda x: x[0])        # 稳定排序：同档保持扫描顺序
    if max_roots:
        kept = kept[:max_roots]

    recs = live_hunt.run_one(repo, slug=slug, offline=not dedup_online,
                             max_head_age_days=max_head_age_days,
                             roots=[rc for _p, rc, _m in kept],
                             dedup_fn=dedup_fn)

    promo_by_key = {root_key(_root_view(rc, repo)): promo
                    for _p, rc, promo in kept}
    for rec in recs:
        promo = promo_by_key.get(root_key(rec)) or {}
        if promo.get("level"):
            rec["confidence"] = promo["level"]
            rec["authz_evidence"] = promo.get("evidence", "")

    # 噪音项：0 网络请求、不占 --max-roots 名额，直接进板块 B 留证。
    for rc, noise in blocked_roots:
        rec = live_hunt._base_record(repo, slug, rc, head, max_head_age_days)
        rec["status"] = cve_dedup.STATUS_UNKNOWN
        rec["noise_code"] = noise.get("code", "")
        rec["reason"] = f"{noise.get('code', '')}: {noise.get('reason', '')}"
        if rec["head_sha"]:
            rec["permalink"] = upstream_sync.head_permalink(
                slug, rec["head_sha"], rec["file"], rec["line"])
        recs.append(rec)

    fresh_keys: list[str] = []
    new: list[dict] = []
    for rec in recs:
        if rec.get("noise_code"):
            new.append(rec)              # 本地已判 B，无需再查重
            continue
        if rec.get("status") != cve_dedup.STATUS_FRESH:
            continue
        key = root_key(rec)
        fresh_keys.append(key)
        if key in exported:
            continue
        new.append(rec)

    upd = {
        **entry, **base,
        "last_scanned_sha": head_sha,
        "last_scanned_at": _now(),
        "head_commit_date": head.get("head_commit_date", ""),
        "branch": head.get("branch", ""),
        "fresh_total": len(fresh_keys),
        "last_new_roots": len(new),
        "exported_roots": sorted(exported | set(fresh_keys)),
    }
    return {"records": new, "entry": upd, "skipped_unchanged": False,
            "head_sha": head_sha, "raw_roots": len(roots),
            "total_units": int(scan.get("total_units") or 0)}


def _force_rmtree(path: Path) -> None:
    """Windows 下 .git/objects 是只读文件，直接 rmtree 会静默失败。"""
    for base, dirs, files in os.walk(path):
        for name in dirs + files:
            try:
                os.chmod(os.path.join(base, name), stat.S_IWRITE)
            except OSError:
                pass
    try:
        os.chmod(path, stat.S_IWRITE)
    except OSError:
        pass
    shutil.rmtree(path, ignore_errors=True)


def _evict(slug: str, evicted: list[str]) -> bool:
    """删掉 .cache/upstream/<repo>，只留报告与账本；拒绝越界路径。"""
    root = upstream_sync.CACHE_ROOT.resolve()
    target = (root / upstream_sync.safe_dirname(slug)).resolve()
    if target.parent != root or not target.is_dir():
        return False
    _force_rmtree(target)
    if target.exists():
        return False
    evicted.append(slug)
    return True


def downgrade_wild_authz(record: dict) -> bool:
    """M294：动态野仓模式下的裸 authz 不直接进 A。

    没有“兄弟接口都有鉴权、唯它没有”的反差（置信度非 HIGH），又不是 /admin
    入口的 authz，一律降成 UNVERIFIED_WILD_AUTHZ 压进板块 B。
    """
    if record.get("category") != "authz":
        return False
    if str(record.get("confidence") or "") == "HIGH":
        return False
    routes = [str(r).lower() for r in (record.get("routes") or [])]
    if any("/admin" in r for r in routes):
        return False
    record["status"] = cve_dedup.STATUS_UNKNOWN
    record["noise_code"] = wild_noise.UNVERIFIED_WILD_AUTHZ
    record["reason"] = ("UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，"
                        "野仓模式不直接进 A")
    return True


def _counts(records: list[dict]) -> dict:
    a = sum(1 for r in records if live_hunt_report._board(r) == "A")
    return {"total": len(records), "board_a": a,
            "board_b": len(records) - a}


def _header(ledger: list[dict], scout: dict, *, days: int,
            languages: list[str], evicted: list[str], summary: dict,
            blocked: int, cooldown_days: int = 0,
            cooldown_skipped: int = 0) -> str:
    scanned = [x for x in ledger if x["result"] == "SCANNED"]
    skipped = [x for x in ledger if x["result"] == "SKIPPED"]
    failed = [x for x in ledger if x["result"] == "FAILED"]
    lines = [
        "## 今日巡猎（daily-hunt）", "",
        f"> 自动流水线：近 {days} 天有提交的 {'/'.join(languages)} 仓 → "
        f"同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；"
        f"本次即扫即焚 {len(evicted)} 个缓存。",
        "",
        f"- 候选仓：{len(ledger)} ｜ 实扫：{len(scanned)} ｜ "
        f"跳过：{len(skipped)} ｜ 失败：{len(failed)} ｜ "
        f"候选来源：{scout.get('source', '') or '—'}",
        f"- 本次新增根因：{summary['total']} ｜ 板块 A：{summary['board_a']} ｜ "
        f"拦截进 B：{blocked}",
        f"- 冷却期免克隆：{cooldown_skipped} 个"
        + (f"（--cooldown-days {cooldown_days}：距上次扫描不足 "
           f"{cooldown_days} 天的仓直接 0 秒顺延）" if cooldown_days else "（已关闭）"),
        "",
        "| 仓库 | HEAD | 结果 | 新增 |",
        "|---|---|---|---|",
    ]
    for x in ledger[:MAX_LEDGER_ROWS]:
        lines.append(f"| {x.get('slug', '')} | "
                     f"{str(x.get('head_sha') or '')[:12]} | "
                     f"{x.get('result', '')} | {x.get('new_roots', 0)} |")
    return "\n".join(lines)


def run(*, languages=("java", "python", "solidity"), days: int = 14,
        limit: int = 10, min_stars: int = 300, max_stars: int = 30000,
        max_roots: int = 0, state_path: Path | str | None = None,
        report: Path | str | None = None, json_path: Path | str | None = None,
        packs_dir: Path | str | None = None, evict_cache: bool = False,
        offline: bool = False, dedup_online: bool = True,
        dry_run: bool = False, max_head_age_days: int = 180,
        repo_timeout: int = 900, cooldown_days: int = DEFAULT_COOLDOWN_DAYS,
        scout_fn=None, sync_fn=None, dedup_fn=None) -> dict:
    """M286 主流程；scout_fn / sync_fn 可注入（冒烟测试不联网）。"""
    started = _now()
    state_path = Path(state_path) if state_path else DEFAULT_STATE
    report = Path(report) if report else DEFAULT_REPORT
    json_path = Path(json_path) if json_path else DEFAULT_JSON
    packs_dir = Path(packs_dir) if packs_dir else DEFAULT_PACKS
    scout_fn = scout_fn or target_scout.scout_daily
    sync_fn = sync_fn or upstream_sync.sync_repo
    lang_list = [str(x) for x in languages if str(x).strip()]
    cooldown_days = max(0, int(cooldown_days or 0))

    scout = scout_fn(languages=lang_list, days=days, limit=limit,
                     min_stars=min_stars, max_stars=max_stars,
                     allow_online=not offline)
    # M293：候选不再硬截断到 limit —— 纯库/无路由仓不占名额，顺延抓下一个。
    items = list(scout.get("items") or [])
    state = load_state(state_path)
    state.setdefault("repos", {})

    records: list[dict] = []
    ledger: list[dict] = []
    evicted: list[str] = []
    blocked = 0
    scanned_slots = 0
    cooldown_skipped = 0

    for item in items:
        if scanned_slots >= max(1, int(limit)):
            break
        slug = str(item.get("slug") or "").strip()
        if not slug:
            continue
        entry = dict(state["repos"].get(slug) or {})
        # M299：克隆前冷却期 —— 不足 N 天就免克隆跳过，把名额让给新候选。
        if cooldown_days > 0:
            age_days = last_scan_age_days(entry)
            if age_days is not None and age_days < cooldown_days:
                ledger.append({
                    "slug": slug, "result": "SKIPPED",
                    "reason": f"cooldown_{cooldown_days}d",
                    "age_days": round(age_days, 2),
                    "head_sha": str(entry.get("last_scanned_sha") or "")})
                cooldown_skipped += 1
                continue
        try:
            if offline:
                cached = (upstream_sync.CACHE_ROOT /
                          upstream_sync.safe_dirname(slug))
                if not cached.is_dir():
                    ledger.append({"slug": slug, "result": "SKIPPED",
                                   "reason": "offline_no_cache"})
                    continue
                repo = cached
            else:
                sync = sync_fn(slug)
                if sync.get("status") != "OK":
                    ledger.append({
                        "slug": slug, "result": "FAILED",
                        "reason": str(sync.get("reason") or "sync_failed")[:200]})
                    continue
                repo = Path(sync["path"])

            res = process_repo(slug, repo, entry, dedup_online=dedup_online,
                               max_roots=max_roots,
                               max_head_age_days=max_head_age_days,
                               dedup_fn=dedup_fn, repo_timeout=repo_timeout)
            if res["skipped_unchanged"]:
                state["repos"][slug] = res["entry"]
                ledger.append({"slug": slug, "result": "SKIPPED",
                               "head_sha": res["head_sha"],
                               "reason": "unchanged_head"})
                continue

            if res.get("total_units") == 0:
                # M293③：纯库/文档仓，没有任何入口 —— 记账但不占当天名额。
                state["repos"][slug] = res["entry"]
                ledger.append({"slug": slug, "result": "SKIPPED",
                               "head_sha": res["head_sha"],
                               "reason": wild_noise.ZERO_ENTRY_LIB})
                continue

            new: list[dict] = []
            for rec in res["records"]:
                # M304：降噪/提拔已在 process_repo 的联网查重之前完成，
                # 这里只做计数与 authz 置信度门槛，不再重复读文件。
                if rec.get("noise_code"):
                    blocked += 1
                elif downgrade_wild_authz(rec):
                    blocked += 1
                new.append(rec)

            records.extend(new)
            state["repos"][slug] = res["entry"]
            scanned_slots += 1
            ledger.append({"slug": slug, "result": "SCANNED",
                           "head_sha": res["head_sha"],
                           "new_roots": len(new),
                           "fresh_total": res["entry"].get("fresh_total", 0)})
        except Exception as e:                                # noqa: BLE001
            ledger.append({"slug": slug, "result": "FAILED",
                           "reason": f"{type(e).__name__}: {e}"[:300]})
        finally:
            # M295：缓存清理放进 finally —— 扫描失败/超时也不留 50MB 垃圾。
            if evict_cache and not dry_run:
                _evict(slug, evicted)

    summary = _counts(records)
    daily_meta = {
        "generated_at": started, "languages": lang_list, "days": days,
        "candidates": len(items),
        "scanned": sum(1 for x in ledger if x["result"] == "SCANNED"),
        "skipped": sum(1 for x in ledger if x["result"] == "SKIPPED"),
        "failed": sum(1 for x in ledger if x["result"] == "FAILED"),
        "new_roots": summary["total"], "board_a": summary["board_a"],
        "blocked": blocked, "evicted": evicted,
        "cooldown_days": cooldown_days,
        "cooldown_skipped": cooldown_skipped,
        "scout_source": scout.get("source", ""),
        "state_path": str(state_path),
    }

    if dry_run:
        return {"ok": True, "dry_run": True, "scout": scout, "ledger": ledger,
                "records": records, "summary": summary, "daily": daily_meta,
                "state_path": str(state_path), "report": str(report),
                "json": str(json_path), "evicted": evicted}

    live_hunt_report.write_outputs(
        records, report, json_path, packs_dir, generated_at=started,
        header_extra=_header(ledger, scout, days=days, languages=lang_list,
                             evicted=evicted, summary=summary,
                             blocked=blocked, cooldown_days=cooldown_days,
                             cooldown_skipped=cooldown_skipped),
        with_confidence=True, extra={"daily": daily_meta})
    save_state(state_path, state)

    return {"ok": True, "dry_run": False, "scout": scout, "ledger": ledger,
            "records": records, "summary": summary, "daily": daily_meta,
            "state_path": str(state_path), "report": str(report),
            "json": str(json_path), "evicted": evicted}
