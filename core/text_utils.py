"""文本工具：剥离 Java 注释。

单独成模块的原因：**规则层和装配分析都需要它**，而两者的依赖方向不能互相
引用（framework_wiring 在 core/context，rule_detectors 在 core/agents）。

## 为什么规则必须剥注释

Hello-Java-Sec 上暴露的：靶场作者把修复写法**注释掉**留在原地：

    // 修复：禁用外部实体
    // xmlReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    xmlReader.parse(new Source(...));

规则读到 `setFeature(..., true)` 就判"已禁用 DOCTYPE = 安全"，而实际执行的
代码完全没有防护。这不是靶场特例 —— 真实项目里"留一行注释掉的修复"极其常见，
java-sec-code 的整个 `CorsConfig2.java` 就是被注释掉的死配置。

结论：**凡是不许模型被误导的东西，规则自己也不许读到。**
模型侧靠 prompt 里"注释不算证据"约束，规则侧只能靠剥注释。
"""
from __future__ import annotations

import re

# 单遍扫描：字符串字面量 / 字符字面量 / 行注释 / 块注释 按出现顺序处理。
# 不能分两步（先剥行注释再剥块注释）：`x(); // /**表示path` 这种行注释里含 `/*`，
# 先剥行注释会留下孤立 `/**`，块注释正则会把后续真实代码整段吃掉。
_JAVA_COMMENT_RE = re.compile(
    r'"(?:\\.|[^"\\])*"'        # 字符串字面量整体跳过，避免把 "//" 当注释
    r"|'(?:\\.|[^'\\])*'"       # 字符字面量
    r"|//[^\n]*"                # 行注释
    r"|/\*.*?\*/",              # 块注释
    re.S,
)

# XML / HTML 注释（MyBatis Mapper、web.xml）
_XML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)


def strip_java_comments(text: str, keep_lines: bool = True) -> str:
    """去掉 `//` 行注释与 `/* */` 块注释。

    `keep_lines=True` 时用换行占位，保持行号不变 —— 后续按行定位的逻辑
    （_method_body 的偏移、切片行号）不会错位。

    行注释替换成空串而不是整行删除：`registry.addMapping("/x") // 注释`
    后面紧跟 `.allowedMethods(...)` 时，整行删除会把下一行"粘"到分号之后，
    看起来像链已结束。
    """
    def repl(m: re.Match) -> str:
        s = m.group(0)
        if s.startswith('"') or s.startswith("'"):
            return s                                # 字面量原样保留
        if keep_lines:
            return "\n" * s.count("\n")             # 只留换行，保住行号
        return " "

    return _JAVA_COMMENT_RE.sub(repl, text)


def strip_xml_comments(text: str, keep_lines: bool = True) -> str:
    """去掉 `<!-- -->`。Mapper XML 里注释掉的旧语句同样不能当证据。"""
    def repl(m: re.Match) -> str:
        s = m.group(0)
        return "\n" * s.count("\n") if keep_lines else " "
    return _XML_COMMENT_RE.sub(repl, text)


def strip_comments(text: str, keep_lines: bool = True) -> str:
    """Java + XML 两种注释都剥。切片里两套语法可能混排（Mapper 语句贴进 Java 切片）。"""
    return strip_xml_comments(strip_java_comments(text, keep_lines), keep_lines)
