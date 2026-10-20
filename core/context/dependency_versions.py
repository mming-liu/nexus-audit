"""从构建文件提取敏感组件版本，注入切片 —— 让"版本决定结论"的类目可判定。

为什么需要独立一层：`JSON.parseObject(body, X.class)` 这一行在
fastjson **1.2.31** 与 **1.2.83** 上语义完全不同 —— 前者 autoType 可被
`@type` 劫持，后者默认 safeMode。代码一模一样，只看代码只能退回模型猜，
而模型手里没有 pom.xml，它连"这个项目用的是 1.2.31"都不知道。

设计边界：

* **只收"版本直接决定是不是漏洞"的组件**（fastjson / shiro / jackson /
  snakeyaml / commons-collections / xstream / log4j …），不做完整 SBOM。
* **只渲染真的出现的那几个**。给 2740 条切片每条塞一份依赖清单，
  既烧 token 又把"这条路由用了什么"稀释掉。
* 渲染格式与 `config_resolver` 的配置块同构（`// key = value`），
  便于 `parse_block()` 读回；整块以 `// ----` 开头，
  `entry_body()` 会在那里截断，不会污染入口体。
"""
from __future__ import annotations

import re
from pathlib import Path

# 版本直接决定真值的组件。键 = artifactId 小写。
# 值只用于注释之外的判断场景，这里保留成"是否版本敏感"的白名单。
SENSITIVE_ARTIFACTS: dict[str, str] = {
    "fastjson": "1.2.83 起默认 safeMode；更早版本 autoType 可被 @type 劫持",
    "shiro-core": "1.7.1 起移除硬编码密钥并加白名单",
    "shiro-spring": "同上（RememberMe 反序列化）",
    "shiro-web": "同上",
    "jackson-databind": "2.9.10.x / 2.10.0 之前有大量多态 gadgets",
    "snakeyaml": "2.0 起默认 SafeConstructor",
    "commons-collections": "3.x 的 InvokerTransformer 是 ysoserial 主链",
    "xstream": "1.4.18 起默认白名单",
    "log4j-core": "2.15.0 之前 JNDI lookup RCE",
    "struts2-core": "OGNL 表达式注入，版本敏感",
}

_PROP_BLOCK_RE = re.compile(r"<properties>(.*?)</properties>", re.S)
_TAG_RE = re.compile(r"<([A-Za-z_][\w.\-]*)>([^<]*)</\1>")
_DEP_BLOCK_RE = re.compile(r"<dependency>(.*?)</dependency>", re.S)
_PLACEHOLDER_RE = re.compile(r"\$\{([^}]+)\}")

# 版本比较用：取开头的数字段。`1.2.83.sec10` / `1.2.31_noneautotype` 都按 1.2.83 / 1.2.31 算。
_VERSION_HEAD_RE = re.compile(r"(\d+(?:\.\d+)*)")


def version_tuple(ver: str | None) -> tuple[int, ...] | None:
    """`"1.2.31"` → `(1, 2, 31)`；读不出数字返回 None（调用方必须退回 None，不许猜）。"""
    if not ver:
        return None
    m = _VERSION_HEAD_RE.match(ver.strip())
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """补零对齐后比较（`(1,2)` 与 `(1,2,0)` 相等）。"""
    n = max(len(a), len(b))
    aa = a + (0,) * (n - len(a))
    bb = b + (0,) * (n - len(b))
    return (aa > bb) - (aa < bb)


def compare_versions(a: str | None, b: str | None) -> int | None:
    """`1.2.31` vs `1.2.83` → -1 / 0 / 1；任一侧读不出数字 → None。

    调用方拿到 None 必须**退回不表态**：把"读不出"当成"小于"就是
    把不确定伪装成有把握。
    """
    ta, tb = version_tuple(a), version_tuple(b)
    if ta is None or tb is None:
        return None
    return _cmp(ta, tb)


class DependencyVersionResolver:
    """按仓库聚合所有 pom.xml 的敏感组件版本（多模块 / 占位符都会还原）。"""

    MAX_POMS = 80            # 防御性上限：超大仓库别为 SCA 拖垮切片

    def __init__(self, repo_root: str | Path):
        self.repo_root = Path(repo_root)
        self._versions: dict[str, str] | None = None

    # ---------- 解析 ----------

    def _poms(self) -> list[Path]:
        root = self.repo_root
        if not root.exists():
            # config_root 可能指到仓库外，退到"含 pom.xml 的上级"
            for cand in [root, *root.parents]:
                if (cand / "pom.xml").exists():
                    root = cand
                    break
            else:
                return []
        out = [p for p in root.rglob("pom.xml")
               if "target" not in p.parts]
        # 父模块先解析：子模块的 `${xxx.version}` 常常定义在父 pom 的 <properties>
        out.sort(key=lambda p: (len(p.parts), str(p)))
        return out[: self.MAX_POMS]

    @staticmethod
    def _props_of(text: str) -> dict[str, str]:
        props: dict[str, str] = {}
        for blk in _PROP_BLOCK_RE.finditer(text):
            for m in _TAG_RE.finditer(blk.group(1)):
                props[m.group(1).strip()] = m.group(2).strip()
        return props

    @staticmethod
    def _resolve(value: str, props: dict[str, str], depth: int = 3) -> str:
        """`${fastjson.version}` → `1.2.31`，递归但限深（防自引用死循环）。"""
        for _ in range(depth):
            m = _PLACEHOLDER_RE.search(value)
            if not m:
                break
            key = m.group(1).strip()
            rep = props.get(key)
            if rep is None:
                # `project.version` / `revision` 这类：解析不了就保留原样，
                # 让下游看到"这是个占位符"而不是看到一个假版本号。
                break
            value = value.replace(m.group(0), rep)
        return value.strip()

    def versions(self) -> dict[str, str]:
        if self._versions is not None:
            return self._versions
        props: dict[str, str] = {}
        blocks: list[str] = []
        for pom in self._poms():
            try:
                text = pom.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for k, v in self._props_of(text).items():
                props.setdefault(k, v)
            blocks.append(text)

        found: dict[str, str] = {}
        for text in blocks:
            for dep in _DEP_BLOCK_RE.finditer(text):
                body = dep.group(1)
                aid = re.search(r"<artifactId>([^<]+)</artifactId>", body)
                ver = re.search(r"<version>([^<]+)</version>", body)
                if not aid:
                    continue
                name = aid.group(1).strip().lower()
                if name not in SENSITIVE_ARTIFACTS:
                    continue
                if not ver:
                    continue                    # 版本在别处管理，等 management 那条
                value = self._resolve(ver.group(1), props)
                if _PLACEHOLDER_RE.search(value):
                    continue                    # 占位符没还原 → 不记假版本
                found.setdefault(name, value)
        self._versions = found
        return found

    def describe(self, max_items: int = 8) -> str:
        """渲染成可拼进切片的证据块；没有敏感组件时返回空串（不制造噪声）。"""
        v = self.versions()
        if not v:
            return ""
        lines = ["// ---- 依赖组件版本（来自构建文件；判定版本敏感漏洞时以此为准）----"]
        for name in sorted(v)[:max_items]:
            lines.append(f"// {name} = {v[name]}")
        return "\n".join(lines) + "\n"


def parse_block(source: str) -> dict[str, str]:
    """从切片里读回 `依赖组件版本` 块（与 `parse_config_block` 同构）。"""
    out: dict[str, str] = {}
    in_block = False
    for line in source.splitlines():
        if "依赖组件版本" in line:
            in_block = True
            continue
        if not in_block:
            continue
        s = line.strip()
        if not s.startswith("//"):
            break
        body = s[2:].strip()
        if "=" in body:
            k, _, v = body.partition("=")
            out[k.strip().lower()] = v.strip()
    return out
