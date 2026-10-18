"""配置值解析器（第5周补充）。

解决的问题：很多安全缺陷的判定依据不在代码里，而在配置文件中。
例如 OWASP Benchmark 的 Cipher 算法名来自 benchmark.properties：

    String algorithm = props.getProperty("cryptoAlg2", "AES/ECB/PKCS5Padding");
    Cipher.getInstance(algorithm);

只给模型看代码，它无法知道 cryptoAlg2 到底是 DES 还是 AES，只能猜 —— 这是
crypto / hash 两类误报率居高不下的根因。把仓库内的配置键值解析后拼进切片尾部，
模型就能拿到确定答案。

支持 .properties / .yaml / .yml / .json，只做扁平键值提取，不追求完整解析语义。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

CONFIG_SUFFIXES = {".properties", ".yaml", ".yml", ".json"}
IGNORE_DIRS = {".git", "target", "build", "node_modules", "test", "tests"}

# 代码里以字符串字面量引用的配置键：getProperty("xxx" / getValue("xxx" / os.getenv("xxx")
KEY_REF_RE = re.compile(r"""(?:getProperty|getPropertyOr|getValue|get|env|getenv)\s*\(\s*
                            (?:"([^"]+)"|'([^']+)')""", re.X)


class ConfigResolver:
    """扫描仓库配置，按代码中出现的键回填取值。"""

    def __init__(self, repo_root: str | Path, max_entries: int = 60):
        self.repo_root = Path(repo_root)
        self.max_entries = max_entries
        self._cache: dict[str, str] | None = None

    # ---------- 索引 ----------

    def _iter_configs(self):
        for p in self.repo_root.rglob("*"):
            if p.suffix.lower() not in CONFIG_SUFFIXES:
                continue
            if any(part in IGNORE_DIRS for part in p.parts):
                continue
            if p.stat().st_size > 2_000_000:      # 跳过超大文件
                continue
            yield p

    def load(self) -> dict[str, str]:
        if self._cache is not None:
            return self._cache
        table: dict[str, str] = {}
        for p in self._iter_configs():
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            suffix = p.suffix.lower()
            if suffix == ".properties":
                table.update(self._parse_properties(text))
            elif suffix == ".json":
                table.update(self._flatten(self._safe_json(text)))
            else:
                table.update(self._parse_yaml_flat(text))
        # 同名键后者覆盖前者：更靠近代码的配置通常优先级更高，这里不做精细排序
        self._cache = table
        return table

    @staticmethod
    def _parse_properties(text: str) -> dict[str, str]:
        out = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "!")):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
            elif ":" in line:
                k, v = line.split(":", 1)
            else:
                continue
            out[k.strip()] = v.strip()
        return out

    @staticmethod
    def _safe_json(text: str) -> dict:
        try:
            data = json.loads(text)
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _flatten(data: dict, prefix: str = "") -> dict[str, str]:
        out = {}
        for k, v in data.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                out.update(ConfigResolver._flatten(v, key))
            else:
                out[key] = str(v)
        return out

    @staticmethod
    def _parse_yaml_flat(text: str) -> dict[str, str]:
        """极简 YAML 扁平解析：只处理 `key: value` 两层以内，够用即可。"""
        out: dict[str, str] = {}
        stack: list[tuple[int, str]] = []
        for raw in text.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip())
            if ":" not in raw:
                continue
            k, _, v = raw.strip().partition(":")
            k, v = k.strip(), v.strip().strip('"\'')
            while stack and stack[-1][0] >= indent:
                stack.pop()
            key = ".".join([s[1] for s in stack] + [k]) if stack else k
            if v:
                out[key] = v
            else:
                stack.append((indent, k))
        return out

    # ---------- 回填 ----------

    def resolve_for(self, source: str) -> str:
        """从源码中找出被引用的配置键，返回可拼进切片的「配置取值」文本块。"""
        table = self.load()
        if not table:
            return ""
        keys: list[str] = []
        for m in KEY_REF_RE.finditer(source):
            key = m.group(1) or m.group(2)
            if key and key not in keys:
                keys.append(key)

        lines = [f"{k} = {table[k]}" for k in keys if k in table]
        # 没找到引用键时，回填少量与安全强相关的键（算法/随机数/密钥类）
        if not lines:
            hints = ("alg", "hash", "crypt", "cipher", "key", "random", "secret", "mode")
            for k, v in list(table.items())[:500]:
                if any(h in k.lower() for h in hints):
                    lines.append(f"{k} = {v}")
                if len(lines) >= self.max_entries:
                    break
        if not lines:
            return ""
        body = "\n".join(lines[: self.max_entries])
        return (f"\n\n// ---- 相关配置实际取值（来自仓库配置文件，判定算法/参数时以此为准）----\n"
                f"// {body}")
