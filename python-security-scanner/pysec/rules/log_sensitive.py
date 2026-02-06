"""
日志敏感信息泄露检测规则

检测代码中将密码、令牌等敏感信息写入日志的情况
"""

import ast
from typing import List, Optional, Set

from .base import BaseRule, register_rule
from ..models import Vulnerability


@register_rule
class LogSensitiveInfoRule(BaseRule):
    """日志敏感信息泄露检测规则"""

    rule_id = "LOG001"
    rule_name = "日志敏感信息泄露"
    severity = "medium"
    description = "检测日志中包含密码、令牌等敏感信息的情况"

    # 日志函数
    LOG_FUNCTIONS = {
        "debug", "info", "warning", "warn", "error", "critical",
        "exception", "log", "fatal",
    }

    # 日志模块/对象名称
    LOG_MODULES = {
        "logger", "logging", "log", "logs", "_logger", "app_logger",
        "console", "stdout", "stderr",
    }

    # 敏感变量名关键词
    SENSITIVE_KEYWORDS = {
        "password", "passwd", "pwd", "secret", "token", "api_key",
        "apikey", "auth", "credential", "private_key", "privatekey",
        "access_key", "accesskey", "secret_key", "secretkey",
        "session_id", "sessionid", "cookie", "jwt", "bearer",
        "credit_card", "creditcard", "ssn", "social_security",
        "bank_account", "bankaccount", "pin", "cvv", "card_number",
    }

    # print 函数也需要检查
    PRINT_FUNCTIONS = {"print"}

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        """检查日志敏感信息泄露"""
        vulnerabilities = []
        source_lines = source_code.splitlines()

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                vuln = self._check_log_call(node, source_lines, file_path)
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_log_call(self, node: ast.Call, source_lines: List[str], 
                        file_path: str) -> Optional[Vulnerability]:
        """检查日志调用"""
        if not self._is_log_call(node):
            return None

        # 检查参数中是否包含敏感变量
        sensitive_vars = self._find_sensitive_variables(node)
        if not sensitive_vars:
            return None

        code_snippet = self._get_code_snippet(source_lines, node.lineno)
        sensitive_list = ", ".join(sensitive_vars)

        return self._create_vulnerability(
            file_path=file_path,
            line_number=node.lineno,
            column=node.col_offset,
            code_snippet=code_snippet,
            description=f"日志中包含敏感变量: {sensitive_list}。这可能导致敏感信息泄露到日志文件中。",
            suggestion="请从日志中移除敏感信息，或使用脱敏处理。"
                       "示例：logger.info(f'User login: {username}') 而不包含密码。",
        )

    def _is_log_call(self, node: ast.Call) -> bool:
        """判断是否是日志调用"""
        # logger.info() 形式
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr.lower()
            if method_name in self.LOG_FUNCTIONS:
                # 检查是否是日志对象的方法
                if isinstance(node.func.value, ast.Name):
                    obj_name = node.func.value.id.lower()
                    if obj_name in self.LOG_MODULES:
                        return True
                    # 任何 xxx.info(), xxx.debug() 等都可能是日志
                    if method_name in self.LOG_FUNCTIONS:
                        return True
                # logging.info() 形式
                elif isinstance(node.func.value, ast.Attribute):
                    return True
                return True

        # print() 函数
        elif isinstance(node.func, ast.Name):
            if node.func.id.lower() in self.PRINT_FUNCTIONS:
                return True
            # logging.info 等直接导入的情况
            if node.func.id.lower() in self.LOG_FUNCTIONS:
                return True

        return False

    def _find_sensitive_variables(self, node: ast.Call) -> Set[str]:
        """查找调用参数中的敏感变量"""
        sensitive_vars = set()

        # 检查所有参数
        for arg in node.args:
            sensitive_vars.update(self._extract_sensitive_from_node(arg))

        # 检查关键字参数
        for keyword in node.keywords:
            if keyword.value:
                sensitive_vars.update(self._extract_sensitive_from_node(keyword.value))

        return sensitive_vars

    def _extract_sensitive_from_node(self, node: ast.AST) -> Set[str]:
        """从AST节点中提取敏感变量名"""
        sensitive_vars = set()

        if isinstance(node, ast.Name):
            if self._is_sensitive_name(node.id):
                sensitive_vars.add(node.id)

        elif isinstance(node, ast.JoinedStr):  # f-string
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    sensitive_vars.update(self._extract_sensitive_from_node(value.value))

        elif isinstance(node, ast.FormattedValue):
            sensitive_vars.update(self._extract_sensitive_from_node(node.value))

        elif isinstance(node, ast.BinOp):  # 字符串拼接
            sensitive_vars.update(self._extract_sensitive_from_node(node.left))
            sensitive_vars.update(self._extract_sensitive_from_node(node.right))

        elif isinstance(node, ast.Call):  # 函数调用如 str(password)
            for arg in node.args:
                sensitive_vars.update(self._extract_sensitive_from_node(arg))
            # 检查 .format() 调用
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                for arg in node.args:
                    sensitive_vars.update(self._extract_sensitive_from_node(arg))
                for kw in node.keywords:
                    if kw.value:
                        sensitive_vars.update(self._extract_sensitive_from_node(kw.value))

        elif isinstance(node, ast.Subscript):  # dict['password']
            if isinstance(node.slice, ast.Constant):
                if isinstance(node.slice.value, str) and self._is_sensitive_name(node.slice.value):
                    sensitive_vars.add(f"['{node.slice.value}']")

        elif isinstance(node, ast.Attribute):  # obj.password
            if self._is_sensitive_name(node.attr):
                sensitive_vars.add(node.attr)

        elif isinstance(node, ast.Tuple) or isinstance(node, ast.List):
            for elt in node.elts:
                sensitive_vars.update(self._extract_sensitive_from_node(elt))

        # 递归检查子节点
        for child in ast.iter_child_nodes(node):
            sensitive_vars.update(self._extract_sensitive_from_node(child))

        return sensitive_vars

    def _is_sensitive_name(self, name: str) -> bool:
        """判断变量名是否敏感"""
        name_lower = name.lower()
        for keyword in self.SENSITIVE_KEYWORDS:
            if keyword in name_lower:
                return True
        return False

    def _get_code_snippet(self, source_lines: List[str], line_number: int) -> str:
        """获取代码片段"""
        if 0 < line_number <= len(source_lines):
            return source_lines[line_number - 1].strip()
        return ""
