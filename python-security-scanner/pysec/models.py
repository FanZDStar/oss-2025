"""
数据模型定义
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class Vulnerability:
    """漏洞信息数据类"""

    rule_id: str  # 规则ID，如 "SQL001"
    rule_name: str  # 规则名称
    severity: str  # 严重程度: critical/high/medium/low
    file_path: str  # 文件路径
    line_number: int  # 行号
    column: int  # 列号
    code_snippet: str  # 漏洞代码片段
    description: str  # 漏洞描述
    suggestion: str  # 修复建议

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "code_snippet": self.code_snippet,
            "description": self.description,
            "suggestion": self.suggestion,
        }


@dataclass
class ScanResult:
    """扫描结果"""

    target: str  # 扫描目标（文件或目录）
    scan_time: datetime = field(default_factory=datetime.now)  # 扫描时间
    duration: float = 0.0  # 耗时（秒）
    files_scanned: int = 0  # 扫描文件数
    vulnerabilities: List[Vulnerability] = field(default_factory=list)  # 发现的漏洞
    errors: List[str] = field(default_factory=list)  # 扫描过程中的错误
    ignored_count: int = 0  # 被忽略的漏洞数量（通过 pysec: ignore 注释）
    filtered_count: int = 0  # 被严重程度过滤的漏洞数量

    @property
    def summary(self) -> dict:
        """统计摘要"""
        return {
            "total": len(self.vulnerabilities),
            "critical": len([v for v in self.vulnerabilities if v.severity == "critical"]),
            "high": len([v for v in self.vulnerabilities if v.severity == "high"]),
            "medium": len([v for v in self.vulnerabilities if v.severity == "medium"]),
            "low": len([v for v in self.vulnerabilities if v.severity == "low"]),
            "ignored": self.ignored_count,
            "filtered": self.filtered_count,
        }

    def add_vulnerability(self, vuln: Vulnerability):
        """添加漏洞"""
        self.vulnerabilities.append(vuln)

    def add_error(self, error: str):
        """添加错误信息"""
        self.errors.append(error)

    def filter_by_severity(self, min_severity: str) -> int:
        """
        按最低严重程度过滤漏洞

        Args:
            min_severity: 最低严重程度

        Returns:
            被过滤的漏洞数量
        """
        if not min_severity:
            return 0

        min_level = get_severity_value(min_severity)
        original_count = len(self.vulnerabilities)

        self.vulnerabilities = [
            v for v in self.vulnerabilities if get_severity_value(v.severity) <= min_level
        ]

        filtered = original_count - len(self.vulnerabilities)
        self.filtered_count += filtered
        return filtered


# 严重程度级别顺序（从高到低）
SEVERITY_LEVELS = ["critical", "high", "medium", "low"]


def get_severity_value(severity: str) -> int:
    """获取严重程度的数值（用于比较）"""
    try:
        return SEVERITY_LEVELS.index(severity.lower())
    except ValueError:
        return len(SEVERITY_LEVELS)  # 未知级别放到最后


@dataclass
class ScanConfig:
    """扫描配置"""

    enabled_rules: Optional[List[str]] = None  # 启用的规则ID列表，None表示全部
    disabled_rules: Optional[List[str]] = None  # 禁用的规则ID列表
    exclude_patterns: Optional[List[str]] = None  # 排除的文件模式
    max_file_size: int = 1024 * 1024  # 最大文件大小（字节）
    output_format: str = "text"  # 输出格式: text/markdown/json
    verbose: bool = False  # 详细输出
    min_severity: Optional[str] = None  # 最低报告严重程度: critical/high/medium/low
    severity_overrides: Optional[dict] = None  # 规则严重程度覆盖配置，如 {"SQL001": "critical"}

    def should_scan_rule(self, rule_id: str) -> bool:
        """判断是否应该执行某个规则"""
        # 如果规则被禁用，则不执行
        if self.disabled_rules and rule_id in self.disabled_rules:
            return False
        # 如果指定了启用列表，则只执行列表中的规则
        if self.enabled_rules and rule_id not in self.enabled_rules:
            return False
        return True

    def get_effective_severity(self, rule_id: str, default_severity: str) -> str:
        """
        获取规则的有效严重程度（考虑覆盖配置）

        Args:
            rule_id: 规则ID
            default_severity: 规则默认严重程度

        Returns:
            有效的严重程度
        """
        if self.severity_overrides and rule_id in self.severity_overrides:
            override = self.severity_overrides[rule_id].lower()
            if override in SEVERITY_LEVELS:
                return override
        return default_severity

    def meets_min_severity(self, severity: str) -> bool:
        """
        判断漏洞严重程度是否满足最低要求

        Args:
            severity: 漏洞严重程度

        Returns:
            是否满足最低严重程度要求
        """
        if self.min_severity is None:
            return True
        return get_severity_value(severity) <= get_severity_value(self.min_severity)
