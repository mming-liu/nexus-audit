"""SHA-256 切片温缓存（M47）。

## 为什么需要

OWASP 之外的大中型靶场每次回归都在**冷切片**：RuoYi 15s / mall 13s /
JavaSecLab 7s / Hello-Java-Sec 2.4s —— 全量回归里光切片就吃掉半分钟，
而判定本身只要零点几秒。温缓存把这部分压到秒级，让"改一条判据 → 跑全量
回归"这个动作可以随手做。

## 指纹两段（缺一不可）

① **切片器源码指纹**：`core/slicer/` + `core/context/` + `core/models.py`
   下全部文件的**内容** sha256。
   为什么必须是内容哈希而不是 mtime：M35/M32 实测 mtime 指纹被任何进程
   触碰（编辑器、git checkout、编译产物）就假失配 → 12 分钟假重建；
   内容哈希是唯一可靠口径（铁律 11）。

② **靶场内容指纹**：文件清单（相对路径 + size + mtime_ns）的 sha256。
   靶场都是 zip 解压来的（没有 .git），所以用清单哈希而不是 git HEAD。
   方向是**保守的**：清单一变就重建 —— 宁可多花几秒，也不能拿旧切片说
   "回归通过"（那正是缓存最危险的失败模式）。

两段指纹拼在一起当 stamp；stamp 不匹配就重建并覆盖缓存。

## 温冷一致性

缓存存的是**切片产物本身**（CodeUnit 列表，pickle），不是判定结果 ——
判定永远现算，缓存只省切片。所以温缓存与冷切片的判定数字必然逐位一致；
冒烟 [90] 会显式验证这一点（同一靶场两条路径，units 列表与判定逐位比对）。

用法：
    from benchmarks.slice_cache import cached_units
    units = cached_units(repo, "ruoyi",
                         lambda: JavaSlicer(repo).extract_entry_units(),
                         no_cache=args.no_cache)
"""
from __future__ import annotations

import hashlib
import os
import pickle
import time
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / "benchmarks" / "results" / ".slice_cache"

# 进指纹的源码目录/文件：凡是**能改变切片内容**的都要登记。漏登记一个，
# 就是留一条"改了 slicer 但回归说你没改"的后门（M32 差点又漏掉它）。
_FINGERPRINT_DIRS = ("core/slicer", "core/context")
_FINGERPRINT_FILES = ("core/models.py",)


def slicer_fingerprint() -> str:
    """切片器 / 上下文层的源码内容指纹（sha256）。"""
    h = hashlib.sha256()
    files: list[Path] = []
    for d in _FINGERPRINT_DIRS:
        base = ROOT / d
        if base.exists():
            files += sorted(p for p in base.rglob("*.py")
                            if "__pycache__" not in p.parts)
    for f in _FINGERPRINT_FILES:
        p = ROOT / f
        if p.exists():
            files.append(p)
    for p in files:
        h.update(str(p.relative_to(ROOT)).replace("\\", "/").encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def repo_fingerprint(repo: Path) -> str:
    """靶场内容指纹：文件清单（路径 + 大小 + mtime_ns）的 sha256。"""
    h = hashlib.sha256()
    repo = Path(repo)
    if not repo.exists():
        return "missing"
    for p in sorted(repo.rglob("*")):
        if p.is_dir() or "__pycache__" in p.parts or ".git" in p.parts:
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        h.update(str(p.relative_to(repo)).replace("\\", "/").encode())
        h.update(str(st.st_size).encode())
        h.update(str(st.st_mtime_ns).encode())
    return h.hexdigest()


def cache_stamp(repo: Path, bench: str) -> str:
    """stamp = 切片器指纹 ⊕ 靶场指纹。"""
    h = hashlib.sha256()
    h.update(slicer_fingerprint().encode())
    h.update(repo_fingerprint(Path(repo)).encode())
    h.update(bench.encode())
    return h.hexdigest()


def cached_units(repo: Path, bench: str, builder: Callable[[], list],
                 no_cache: bool = False, verbose: bool = True) -> list:
    """带透明磁盘缓存的切片入口。

    builder 必须是**纯切片**（不产判定结果）—— 缓存只省切片，判定永远现算。
    """
    repo = Path(repo)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / f"{bench}.pkl"
    stamp_file = CACHE_DIR / f"{bench}.fp"
    stamp = cache_stamp(repo, bench)

    if not no_cache and cache_file.exists() and stamp_file.exists():
        try:
            if stamp_file.read_text(encoding="utf-8").strip() == stamp:
                t0 = time.monotonic()
                with open(cache_file, "rb") as fh:
                    units = pickle.load(fh)
                if verbose:
                    print(f"      [cache] 温缓存命中 {len(units)} 单元"
                          f"（{time.monotonic() - t0:.2f}s）")
                return units
        except Exception as e:  # noqa: BLE001 —— 缓存坏了就重建，不算失败
            if verbose:
                print(f"      [cache] 缓存不可用（{type(e).__name__}），重建")

    t0 = time.monotonic()
    units = builder()
    if verbose:
        print(f"      [cache] 冷切片 {len(units)} 单元"
              f"（{time.monotonic() - t0:.2f}s）")
    try:
        with open(cache_file, "wb") as fh:
            pickle.dump(units, fh)
        stamp_file.write_text(stamp, encoding="utf-8")
    except Exception as e:  # noqa: BLE001 —— 写缓存失败不影响主流程
        if verbose:
            print(f"      [cache] 写入失败（{type(e).__name__}），本次不缓存")
    return units


def clear_cache() -> int:
    """清空温缓存目录，返回删除的文件数。"""
    n = 0
    if CACHE_DIR.exists():
        for p in CACHE_DIR.glob("*"):
            try:
                p.unlink()
                n += 1
            except OSError:
                pass
    return n


if __name__ == "__main__":
    import sys
    if "--clear" in sys.argv:
        print(f"已清空 {clear_cache()} 个缓存文件")
    else:
        print("slicer 指纹 :", slicer_fingerprint()[:16], "…")
        for d in sorted((ROOT / "reference_repos").glob("*/")):
            if d.is_dir():
                print(f"  {d.name:36} {repo_fingerprint(d)[:16]} …")
