"""统一数据契约：CodeUnit, CallEdge, VulnHypothesis, PoCResult"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Language(str, Enum):
    PYTHON_WEB = "python_web"
    JAVA_WEB = "java_web"
    SOLIDITY_WEB3 = "solidity_web3"


@dataclass
class CodeUnit:
    """第一层切片器输出的统一单元：路由函数或合约方法。"""
    file_path: str
    language: Language
    unit_name: str                       # 路由函数名或合约方法名
    start_line: int
    end_line: int
    decorators_or_modifiers: list[str] = field(default_factory=list)
    called_symbols: list[str] = field(default_factory=list)  # 供第2层按需展开
    source_code: str = ""                # 带行号的源码切片


@dataclass
class CallEdge:
    """跨文件调用边：caller -> callee。"""
    caller: str                          # 形如 "path/file.py:FuncName"
    callee: str
    callee_file: Optional[str] = None
    callee_line: Optional[int] = None


@dataclass
class VulnHypothesis:
    """第三层推理产出的漏洞假设（未经沙箱验证）。"""
    unit: CodeUnit
    vuln_type: str                       # 如 IDOR / RCE / reentrancy / unauthorized_withdraw
    scenario_hit: bool                   # GPTScan 第一步：场景匹配通过
    property_missing: str                # GPTScan 第二步：缺失的属性/校验描述
    reasoning_summary: str = ""
    confidence: float = 0.0
    skeptic_rejected: bool = False       # 反方挑刺 Agent 是否推翻


@dataclass
class PoCResult:
    """第四层沙箱验证结果。"""
    hypothesis: VulnHypothesis
    poc_script_path: str = ""
    verified: bool = False               # 是否成功复现
    output_digest: str = ""              # StateParser 压缩后的关键日志摘要
    self_heal_rounds: int = 0            # 编译报错自愈轮数
    patch_diff: str = ""                 # 修复补丁 Git Diff（验证通过后生成）
