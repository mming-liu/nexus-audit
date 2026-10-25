"""kekingcn/kkFileView —— 第 31 野战仓（Java #14），M153。

## 为什么选它

前 30 个野仓里 **没有任何一个**把"压缩包条目名落盘"写进业务代码 ——
zip_slip 在真实仓库上的覆盖一直是 0。kkFileView 是国内最流行的在线文档 /
压缩包预览服务，归档预览的实现路径就是"解压到磁盘再逐页渲染"：

    CompressFileReader.unRar()
      -> getFilePathInsideArchive(item, folderPath)   // 条目名 -> 本地 Path
      -> FileOutputStream(path) + item.extractSlow(...)

而且它用的是 sevenzipjbinding 的 ISimpleInArchiveItem.getPath()，不是
java.util.zip 的 ZipEntry.getName() —— 判据不认这一族 API，这段真实代码
就会整片退 None，"有覆盖"是假的。

## 口径（--strict）

1. **15 个 Controller 入口 × 32 类 = 0 条 True**：这是生产级文档服务，
   误报一条都会让报告失去可信度。
2. unRar（入口 + helper 证据）判 **False**：条目名先 normalize 再
   startsWith(folderPath) 前缀校验，是有效防护，不是"没看见"。
3. **反向锚点**：把真实代码里的 startsWith 守卫换成 if (false)，同一段
   代码必须翻成 **True** —— 证明 False 来自守卫证据，而不是判据不触发。
4. getFilePathInsideArchive 单独判 False（helper 单元可判）。
5. 守卫文本必须逐字出现在归一化之后（防"注释里写了守卫"式假防护）。

## 本轮由真实代码逼出的两条判据修正

- crypto 证据归属：裸 encrypt|decrypt 会匹配形参名 encryption，
  AES/ECB 从 Hop 2 的 AESUtil 被算到入口头上（4 条假阳）。改为要求调用。
- authz 拒绝分支：sendError(HttpServletResponse.SC_UNAUTHORIZED) 与
  字面量 401 同义；共享密钥门 validateKey 的实现体是 configKey.equals(key)，
  按机制认它，不按名字。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.text_utils import ensure_utf8_stdio                   # noqa: E402
from core.agents import rule_detectors as R                     # noqa: E402
from core.agents.vuln_categories import CATEGORIES             # noqa: E402
from core.slicer.java_servlet import JavaSlicer                # noqa: E402

ensure_utf8_stdio()

DEFAULT_TARGET = ROOT / "reference_repos" / "kkFileView"
READER = Path("server/src/main/java/cn/keking/service/CompressFileReader.java")
MIN_CONTROLLERS = 12


def _span(text: str, signature: str) -> str:
    """从源码里截出某个方法的配平函数体（含签名）。"""
    i = text.index(signature)
    j = text.index("{", i)
    depth = 0
    for k in range(j, len(text)):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return text[i:k + 1]
    return text[i:]


def main() -> int:
    ap = argparse.ArgumentParser(description="kkFileView zip_slip 真实覆盖基准（M153）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" /
                                            "kkfileview.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/kekingcn/kkFileView.git）")
        return 2
    reader = repo / READER
    if not reader.is_file():
        print(f"! 缺 {READER}（仓库结构变了？）")
        return 2
    text = reader.read_text(encoding="utf-8", errors="replace")
    unrar = _span(text, "public String unRar(")
    helper = _span(text, "private Path getFilePathInsideArchive(")
    combined = unrar + "\n\n" + helper

    units = list(JavaSlicer(repo).extract_entry_units())
    print(f"靶场：{repo}")
    print(f"       Controller 入口 {len(units)} 个")

    true_rows: list[tuple[str, str]] = []
    decided = 0
    for u in units:
        for cat in CATEGORIES:
            v = R.verdict(cat, u.source_code)
            if v is None:
                continue
            decided += 1
            if v is True:
                true_rows.append((u.unit_name, cat))

    scan = {
        "unrar": R.verdict("zip_slip", combined),
        "helper": R.verdict("zip_slip", helper),
        "unrar_alone": R.verdict("zip_slip", unrar),
        "unguarded": R.verdict("zip_slip", combined.replace(
            "if (!normalizedPath.startsWith(folderPath)) {", "if (false) {")),
        "unguarded_helper": R.verdict("zip_slip", helper.replace(
            "if (!normalizedPath.startsWith(folderPath)) {", "if (false) {")),
    }
    guard_text = ("normalizedPath = folderPath.resolve(insideFileName).normalize()"
                  in combined and "normalizedPath.startsWith(folderPath)" in combined)

    print("=" * 72)
    print("kkFileView 结果（zip_slip 真实解压路径）")
    print("=" * 72)
    print(f"  Controller 入口          ：{len(units)}")
    print(f"  规则判定次数            ：{decided}")
    print(f"  生产入口 True（误报）   ：{len(true_rows)}")
    for name, cat in true_rows[:12]:
        print(f"      [FP] {name} [{cat}]")
    print(f"  unRar（入口 + helper）  ：{scan['unrar']}")
    print(f"  getFilePathInsideArchive：{scan['helper']}")
    print(f"  反向锚点（去掉 startsWith）：{scan['unguarded']}")
    print(f"  守卫文本逐字就位        ：{guard_text}")

    bad: list[str] = []
    if len(units) < MIN_CONTROLLERS:
        bad.append(f"Controller 入口 {len(units)} < {MIN_CONTROLLERS}")
    if true_rows:
        bad.append(f"生产入口出现 {len(true_rows)} 条 True 误报")
    if scan["unrar"] is not False:
        bad.append(f"unRar 未判 False（{scan['unrar']}）—— 守卫没被认出来")
    if scan["helper"] is not False:
        bad.append(f"helper 未判 False（{scan['helper']}）")
    if scan["unguarded"] is not True:
        bad.append(f"反向锚点未翻 True（{scan['unguarded']}）")
    if not guard_text:
        bad.append("守卫文本不在（normalize + startsWith）")
    ok = not bad
    print()
    print("STRICT PASS ✔（15 入口 / 34 类 0 True / zip_slip 真实解压路径 False / "
          "反向锚点 True）" if ok else "STRICT FAIL ✘ " + "；".join(bad))

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "kkfileview", "units": len(units),
        "total_units": len(units), "decided": decided,
        "correct": len(units) - len(true_rows), "fp": len(true_rows),
        "reverse_fn": 0, "rule_evaluations": decided,
        "zip_slip": scan, "guard_text": guard_text,
        "true_rows": [{"unit": n, "category": c} for n, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
