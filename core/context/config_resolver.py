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

# 凭据类键名：取值必须脱敏后才允许进入切片。
#
# 这是实测出来的问题，不是预防性设计：java-sec-code 的 application.properties
# 里有阿里云 accessKey 的 id/secret，而 `_hint_lines` 的回填条件里恰好有 "key"，
# 于是**132 个入口的切片里全部带上了这组真实凭据**，并且原样发给远端模型。
# 切片会进报告、进日志、进前端展示，等于把密钥一路扩散出去。
# 判定算法强度（crypto/hash）从来不需要看到 secret 的原文，只需要看到长度/形态，
# 所以掩码不会损失任何判定能力。
SECRET_KEY_RE = re.compile(
    r"(?i)(secret|passw(or)?d|pwd|token|access[_.-]?key|private[_.-]?key|"
    r"api[_.-]?key|credential|session[_.-]?key|signing[_.-]?key)")
# 形如 ${DB_PASSWORD} 的占位符不含真实值，保留原文（对判定无害且有信息量）
PLACEHOLDER_RE = re.compile(r"^\$\{[^}]*\}$|^\{\{[^}]*\}\}$")

# 代码里以字符串字面量引用的配置键：getProperty("xxx" / getValue("xxx" / os.getenv("xxx")
KEY_REF_RE = re.compile(r"""(?:getProperty|getPropertyOr|getValue|get|env|getenv)\s*\(\s*
                            (?:"([^"]+)"|'([^']+)')""", re.X)


class ConfigResolver:
    """扫描仓库配置，按代码中出现的键回填取值。"""

    def __init__(self, repo_root: str | Path, max_entries: int = 60):
        self.repo_root = Path(repo_root)
        self.max_entries = max_entries
        self._cache: dict[str, str] | None = None
        self._hints: list[str] | None = None

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

    SECURITY_HINTS = ("alg", "hash", "crypt", "cipher", "key", "random", "secret", "mode")

    @staticmethod
    def mask_secret(key: str, value: str) -> str:
        """凭据脱敏：保留长度与形态，抹掉原文。

        不脱敏的键（算法/模式/随机数等）原样返回 —— 那才是判定需要的证据。
        """
        if not SECRET_KEY_RE.search(key):
            return value
        v = (value or "").strip()
        if not v or PLACEHOLDER_RE.match(v):
            return value
        if len(v) < 8:
            # 短值多半是 "true"/"none"/"1" 这类开关，不是真凭据
            return value
        return f"<已脱敏 len={len(v)}>"

    def _hint_lines(self) -> list[str]:
        """安全强相关的配置行（惰性算一次并缓存）。

        原实现在每个切片里都遍历全表 + `list(table.items())[:500]` 反复拷贝，
        2740 个用例下占了 65% 的总耗时。
        """
        if getattr(self, "_hints", None) is None:
            self._hints = [f"{k} = {self.mask_secret(k, v)}"
                           for k, v in self.load().items()
                           if any(h in k.lower() for h in self.SECURITY_HINTS)][: self.max_entries]
        return self._hints

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

        lines = [f"{k} = {self.mask_secret(k, table[k])}" for k in keys if k in table]
        # 没找到引用键时，回填少量与安全强相关的键（算法/随机数/密钥类）
        if not lines:
            lines = self._hint_lines()
        if not lines:
            return ""
        body = "\n".join(lines[: self.max_entries])
        return (f"\n\n// ---- 相关配置实际取值（来自仓库配置文件，判定算法/参数时以此为准）----\n"
                f"// {body}")
