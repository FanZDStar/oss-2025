"""
检测规则基类
"""

import ast
from abc import ABC, abstractmethod
from typing import List

from ..models import Vulnerability


# 规则注册表
RULE_REGISTRY = {}


def register_rule(rule_class):
    """
    规则注册装饰器

    使用方法:
        @register_rule
        class MyRule(BaseRule):
            rule_id = "MY001"
            ...
    """
    if hasattr(rule_class, "rule_id") and rule_class.rule_id:
        RULE_REGISTRY[rule_class.rule_id] = rule_class
    return rule_class


class BaseRule(ABC):
    """
    检测规则基类

    所有检测规则都应继承此类并实现 check 方法
    """

    rule_id: str = ""  # 规则ID，如 "SQL001"
    rule_name: str = ""  # 规则名称
    severity: str = "medium"  # 默认严重程度
    description: str = ""  # 规则描述

    @abstractmethod
    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        """
        执行检测，返回发现的漏洞列表

        Args:
            ast_tree: 解析后的AST语法树
            file_path: 源文件路径
            source_code: 源代码内容

        Returns:
            发现的漏洞列表
        """
        pass

    def _get_source_line(self, source_code: str, line_number: int) -> str:
        """获取指定行的源代码"""
        lines = source_code.split("\n")
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1].strip()
        return ""

    def _get_source_segment(self, source_code: str, node: ast.AST, context_lines: int = 0) -> str:
        """
        获取AST节点对应的源代码片段

        Args:
            source_code: 源代码
            node: AST节点
            context_lines: 上下文行数

        Returns:
            代码片段
        """
        if not hasattr(node, "lineno"):
            return ""

        lines = source_code.split("\n")
        start_line = max(1, node.lineno - context_lines)
        end_line = min(len(lines), getattr(node, "end_lineno", node.lineno) + context_lines)

        return "\n".join(lines[start_line - 1 : end_line]).strip()

    def _create_vulnerability(
        self,
        file_path: str,
        line_number: int,
        column: int,
        code_snippet: str,
        description: str,
        suggestion: str,
        severity: str = None,
    ) -> Vulnerability:
        """
        创建漏洞对象的便捷方法
        """
        return Vulnerability(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=severity or self.severity,
            file_path=file_path,
            line_number=line_number,
            column=column,
            code_snippet=code_snippet,
            description=description,
            suggestion=suggestion,
        )
