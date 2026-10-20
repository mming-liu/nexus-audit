"""形参主体注解解析：从 HandlerMethodArgumentResolver 反查"哪个注解注入的是当前用户"。

**为什么必须有这一层**

前后端分离项目的控制器长这样：

    @PostMapping("/orders")
    public Result orders(@TokenToMallUser MallUser loginMallUser, @RequestBody PageParam p) {
        return Result.success(orderService.getMyOrders(p, loginMallUser.getUserId()));
    }

主体不在方法体里，而在**形参注解**里。`authz_verdict` 的 2b 分支
（"主体 id 作资源键"）其实完全成立，但 `_AUTHZ_SUBJECT_RE` 只认
`session.getAttribute` / `@AuthenticationPrincipal` / `SecurityContextHolder`，
`@TokenToMallUser` 一个字都不认 —— newbee-mall-api 实测 18 条 True 里
17 条是这一个机制造成的误报（与 Web 版同构的真漏洞 `/paySuccess` 除外）。

**判据（为什么不能按注解名猜）**

"注解名带 User 就是主体"是名字启发式：项目里叫 `@CurrentViewer` /
`@LoginAccount` / `@Self` 的都有，而叫 `@UserAgent` 的恰恰不是。
可逐行核对的事实只有一条 —— 某个参数解析器同时满足：

    1. `implements HandlerMethodArgumentResolver`（参数由框架注入，
       不是客户端随手构造的 DTO）
    2. `supportsParameter` 里 `parameter.hasParameterAnnotation(X.class)`
       —— X 就是它认的注解
    3. 解析逻辑里存在**身份来源**：`getHeader("…token…")` / `getCookies`
       / `getUserPrincipal` / `getAuthentication` / `getAttribute` /
       `selectBy…Token` / `…UserMapper.xxx`

只满足 1+2 不够：`@CurrentTenant String tenant` 同样由 resolver 注入，
但它只是个过滤维度，把它当主体会把"多租户过滤"误判成"归属校验"。
这就是本条判据必须带 3 的原因。

**不做什么**

- 不解析泛型/继承来的 `supportsParameter`（`extends AbstractResolver` 的间接实现
  看不出来）—— 判不出就不认，宁可退回 None
- 不认 Spring Security 的 `@AuthenticationPrincipal`：它由框架内置解析，
  已在 `rule_detectors._AUTHZ_SUBJECT_RE` 里单独覆盖
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# 与 framework_wiring 保持同一套跳过规则
SKIP_DIR_PARTS = {".git", "target", "build", "node_modules", "test", "tests"}

RESOLVER_IMPL_RE = re.compile(
    r"implements[^{;]{0,240}?\bHandlerMethodArgumentResolver\b")

# `parameter.hasParameterAnnotation(TokenToMallUser.class)`
SUPPORTED_ANN_RE = re.compile(
    r"\b(?:hasParameterAnnotation|getParameterAnnotation)\s*"
    r"\(\s*(\w+)\s*\.\s*class\s*\)")

# 身份来源。命中的是"这段解析逻辑在拿请求凭据换用户对象"。
IDENTITY_SOURCE_RE = re.compile(
    r"\bgetHeader\s*\(|\bgetCookies?\s*\(|\bgetUserPrincipal\s*\("
    r"|\bgetAuthentication\s*\(|\bgetAttribute\s*\("
    r"|\bselectBy\w*[Tt]oken\b|\bfindBy\w*[Tt]oken\b|\bget\w*ByToken\b"
    r"|\b\w*[Uu]ser\w*(?:Mapper|Dao|DAO|Service|Repository)\s*\.",
    re.I)

# 注解块在切片里的标题（`parse_subject_params` 按它定位）
SUBJECT_BLOCK_MARK = "形参主体注解"

# `@TokenToMallUser MallUser loginMallUser` / `@X(a=b) List<SysUser> user`
_ANN_PARAM_RE = re.compile(
    r"@(\w+)\s*(?:\((?:[^()]|\([^()]*\))*\))?\s*"
    r"([A-Z][\w.]*(?:\s*<[^<>]*>)?(?:\s*\[\s*\])?)\s+(\w+)\s*[,)]")


@dataclass(frozen=True)
class SubjectAnnotation:
    annotation: str          # 注解简单名：TokenToMallUser
    resolver: str            # 解析器类名：TokenToMallUserMethodArgumentResolver
    source: str              # 文件相对路径，便于人工核对
    evidence: str            # 命中的身份来源原文（一行）


def _iter_java(root: Path):
    for p in root.rglob("*.java"):
        if any(part in SKIP_DIR_PARTS for part in p.parts):
            continue
        yield p


def _string_spans(text: str) -> list[tuple[int, int]]:
    """字符串字面量 / 行注释的区间（闭区间）。

    不能不看这些区间：`@ApiOperation(value = "购物车列表(网页移动端不分页)")`
    里的中文也是 `\\w`，`value = "…(` 长得就像一个方法调用 —— 括号配平会
    停在那个**字符串内部**的右括号上，签名被截成半句，形参一个都取不到。
    实测 `cartItemList` / `cartItemPageList` / `getMallUserAddress` 三条
    正是这样丢掉主体注解的（同文件别的入口却正常，症状很像随机）。
    """
    spans: list[tuple[int, int]] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == c:
                    break
                j += 1
            spans.append((i, min(j, n - 1)))
            i = j + 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n - 1 if j < 0 else j
            spans.append((i, j))
            i = j + 1
            continue
        i += 1
    return spans


def _signature(text: str) -> str:
    """取入口方法从开头到**签名右括号**的原文（含前面所有注解）。

    不能用 `text.split("{", 1)[0]`：`@RequestMapping({"/a", "/b"})` 的数组
    花括号出现在签名之前，一切就断在那里，形参一个都取不到。
    也不能用 `\\(([^)]*)\\)`：`@ApiParam(name = "p")` 的右括号先闭。
    也不能只看括号深度：字符串与注释里的括号不是括号（见 `_string_spans`）。
    唯一稳的办法是跳过注解、跳过字符串/注释、找到方法名后的左括号再配平。
    """
    spans = _string_spans(text)

    def in_span(pos: int) -> bool:
        return any(a <= pos <= b for a, b in spans)

    for m in re.finditer(r"(?<![@\w])\b\w+\s*\(", text):
        if in_span(m.start()):
            continue
        depth = 0
        for k in range(m.end() - 1, len(text)):
            if in_span(k):
                continue
            c = text[k]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return text[:k + 1]
        return ""
    return ""


class SubjectParamResolver:
    """仓库级索引：主体注解 → 它是被谁注入的。"""

    def __init__(self, repo_path: str | Path):
        self.repo = Path(repo_path)
        self._anns: dict[str, SubjectAnnotation] | None = None

    def annotations(self) -> dict[str, SubjectAnnotation]:
        if self._anns is not None:
            return self._anns

        out: dict[str, SubjectAnnotation] = {}
        for path in _iter_java(self.repo):
            try:
                raw = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if not RESOLVER_IMPL_RE.search(raw):
                continue
            anns = set(SUPPORTED_ANN_RE.findall(raw))
            if not anns:
                continue
            ident = IDENTITY_SOURCE_RE.search(raw)
            if not ident:
                # 只注入某个维度（租户/语言/版本），不代表身份 → 不认
                continue
            cls_m = re.search(r"\bclass\s+(\w+)", raw)
            cls = cls_m.group(1) if cls_m else path.stem
            line = ident.group(0)
            for a in anns:
                out.setdefault(a, SubjectAnnotation(
                    annotation=a, resolver=cls,
                    source=self._rel(path), evidence=line))
        self._anns = out
        return out

    def _rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.repo)).replace("\\", "/")
        except ValueError:
            return str(path)

    def subject_params(self, entry_src: str) -> dict[str, str]:
        """入口签名里的「主体注解 → 形参名」。没命中返回空 dict。"""
        anns = self.annotations()
        if not anns or not entry_src:
            return {}
        head = _signature(entry_src)               # 只看签名区，不看方法体
        if not head:
            return {}
        out: dict[str, str] = {}
        for m in _ANN_PARAM_RE.finditer(head):
            a, var = m.group(1), m.group(3)
            if a in anns:
                out[a] = var
        return out

    def describe(self, entry_src: str) -> str:
        """渲染成可拼进切片的证据块。没有主体形参时返回空串。"""
        params = self.subject_params(entry_src)
        if not params:
            return ""
        anns = self.annotations()
        lines = [f"// ---- {SUBJECT_BLOCK_MARK}（判定\"当前用户从哪来\"以此为准）----"]
        for a, var in params.items():
            info = anns[a]
            lines.append(
                f"// @{a} -> 形参 {var}   由 {info.resolver} 注入"
                f"（supportsParameter 认 @{a}，解析时取 {info.evidence}）"
                f"  来源 {info.source}")
        return "\n".join(lines) + "\n"
