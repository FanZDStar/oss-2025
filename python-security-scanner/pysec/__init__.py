"""
PySecScanner - Python代码安全漏洞静态分析工具

基于AST的轻量级Python安全扫描工具，支持检测：
- SQL注入
- 命令注入
- 硬编码敏感信息
- 危险函数调用
- 路径遍历
- XSS风险
"""

__version__ = "1.0.0"
__author__ = "PySecScanner Team"

from .models import Vulnerability, ScanResult, ScanConfig
from .scanner import Scanner
from .engine import RuleEngine

__all__ = [
    "Vulnerability",
    "ScanResult",
    "ScanConfig",
    "Scanner",
    "RuleEngine",
]
