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


# ================= M145：供应链组件风险 ↔ 代码入口可达性 =================
#
# 要回答的问题：**"这个仓既用了有已知漏洞的组件版本，又有一条代码级 P0"的
# 仓有几个？** 单看组件版本会给出"全库都在用旧依赖"的噪声，单看代码又看不见
# "这条路由的 JSON 解析由 fastjson 1.2.31 承担"。两张表叠在一起才是"实锤"。
#
# 表的口径（刻意保守）：
#   · 每条都写**修复版本**（fixed_in）与 CVE 编号，来自公开 advisory；
#   · 只收"版本区间直接决定是否受影响"的条目 —— 收不进来的组件就报
#     "未收录"，不猜；
#   · 版本比较用 `compare_versions()`（人手写的 1.2.83.sec10 这类后缀按
#     数字头比较），读不出版本一律不算命中。
DEPENDENCY_ADVISORIES: dict[str, list[tuple[str, str, str]]] = {
    # (fixed_in, CVE, 标题) —— 安装版本 < fixed_in 即受影响
    "shiro-core": [
        ("1.2.5", "CVE-2016-4437",
         "Shiro-550：rememberMe 硬编码 AES 密钥 → 反序列化 RCE"),
        ("1.7.1", "CVE-2020-1957",
         "认证绕过：路径规范化差异导致未授权访问"),
    ],
    "shiro-web": [("1.2.5", "CVE-2016-4437", "同 shiro-core（Shiro-550）")],
    "shiro-spring": [("1.2.5", "CVE-2016-4437", "同 shiro-core（Shiro-550）")],
    "fastjson": [
        ("1.2.83", "CVE-2022-25845",
         "autoType 绕过 → 反序列化 gadget 链（1.2.83 起默认 safeMode）"),
    ],
    "log4j-core": [
        ("2.17.1", "CVE-2021-44228",
         "Log4Shell：JNDI lookup RCE（2.17.1 才完整修复）"),
    ],
    "commons-collections": [
        ("3.2.2", "CVE-2015-6420",
         "InvokerTransformer 反序列化 gadget（ysoserial 主链）"),
    ],
    "snakeyaml": [
        ("2.0", "CVE-2022-1471",
         "Constructor 实例化 RCE（2.0 起默认 SafeConstructor）"),
    ],
    "jackson-databind": [
        ("2.9.10.8", "CVE-2020-36518",
         "深层嵌套 JSON 栈溢出 DoS"),
    ],
    "django": [
        ("1.11.15", "CVE-2018-14574",
         "CommonMiddleware 开放重定向"),
        ("1.11.5", "CVE-2017-12794",
         "调试页 XSS（模板异常信息未转义）"),
    ],
    "djangorestframework": [
        ("3.11.2", "CVE-2020-25626",
         "可浏览 API 的 XSS（data-* 属性未转义）"),
    ],
    "pyjwt": [
        ("2.4.0", "CVE-2022-29217",
         "密钥类型混淆：非对称公钥可被当作 HMAC 密钥验签"),
    ],
    "jinja2": [
        ("2.10.1", "CVE-2019-10906",
         "沙箱逃逸（str.format_map 绕过 SandboxedEnvironment）"),
    ],
    "requests": [
        ("2.20.0", "CVE-2018-18074",
         "重定向到新主机时泄漏 Authorization 头"),
    ],
    "flask": [
        ("0.12.3", "CVE-2018-1000656",
         "特制 JSON 触发内存耗尽 DoS"),
    ],
    "werkzeug": [
        ("0.15.3", "CVE-2019-14322",
         "Windows 平台路径遍历（safe_join 未处理盘符）"),
    ],
    "urllib3": [
        ("1.24.2", "CVE-2019-11324",
         "证书验证绕过（CA 链处理缺陷）"),
    ],
    "sqlalchemy": [
        ("1.3.0", "CVE-2019-7548",
         "order_by/group_by 拼接用户输入 → SQL 注入"),
    ],
    "pyyaml": [
        ("5.4", "CVE-2020-14343",
         "full_load 可实例化任意 Python 对象 → RCE"),
    ],
    "pycrypto": [
        ("2.7.0", "CVE-2013-7459",
         "AES-NI 实现堆溢出（项目已停止维护，建议迁移 pycryptodome）"),
    ],
}


def _norm_component(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def collect_components(repo_root: str | Path) -> dict[str, str]:
    """收集一个仓库的组件版本（Maven pom + Python requirements）。

    **刻意不解析 package.json**：30 个野仓里的 JS 依赖绝大多数是
    hardhat/editormd 这类**构建期**工具，不在运行时链路上 —— 把它们算进
    "供应链风险"只会制造噪声。

    同名组件多次出现时取**第一个**（父 pom / 主 requirements 优先），
    并保留原样版本串（`1.2.83.sec10` 不截断，比较时再归一）。
    """
    root = Path(repo_root)
    out: dict[str, str] = {}
    if not root.exists():
        return out
    for name, ver in DependencyVersionResolver(root).versions().items():
        out.setdefault(_norm_component(name), ver)
    # requirements.txt 与 **requirements/ 目录下的分片**（flasky 就是
    # `requirements/common.txt` + `dev.txt` 的布局，只按文件名 glob 会全漏）
    req_files = [p for p in root.rglob("requirements*.txt")]
    req_files += [p for p in root.rglob("*.txt")
                  if p.parent.name == "requirements"]
    seen: set[Path] = set()
    for req in sorted(req_files, key=str)[:10]:
        if req in seen:
            continue
        seen.add(req)
        if any(p in ("node_modules", ".git", "venv", ".venv") for p in req.parts):
            continue
        try:
            text = req.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([\w.\-]+)", line)
            if m:
                out.setdefault(_norm_component(m.group(1)), m.group(2))
    return out


def evaluate_components(components: dict[str, str]) -> list[dict]:
    """把组件版本对到已知 advisory 上，返回命中的条目列表。

    每条：`{component, version, cve, title, fixed_in}`。版本读不出/未收录
    的组件**不进结果**（"没收录"不等于"安全"，报告里会单列未收录项）。
    """
    hits: list[dict] = []
    for name, ver in sorted(components.items()):
        rules = DEPENDENCY_ADVISORIES.get(name)
        if not rules:
            continue
        for fixed_in, cve, title in rules:
            cmp = compare_versions(ver, fixed_in)
            if cmp is None:
                continue
            if cmp < 0:
                hits.append({"component": name, "version": ver, "cve": cve,
                             "title": title, "fixed_in": fixed_in})
    return hits


def uncovered_components(components: dict[str, str]) -> dict[str, str]:
    """有版本但**不在 advisory 表里**的组件（报告里如实列作"未收录"）。"""
    return {k: v for k, v in sorted(components.items())
            if k not in DEPENDENCY_ADVISORIES}


# 同一组件多条命中只保留"最高危"的那条（版本区间由窄到宽）时的排序权重
def severity_rank(cve: str) -> int:
    """已知高危机型给更高权重（仅用于报告排序，不参与判定）。"""
    high = ("CVE-2021-44228", "CVE-2016-4437", "CVE-2022-1471",
            "CVE-2015-6420", "CVE-2022-25845", "CVE-2020-14343")
    return 0 if cve in high else 1
