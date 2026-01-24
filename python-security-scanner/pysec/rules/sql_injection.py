"""
SQL注入检测规则

检测通过字符串拼接构造SQL语句的风险代码
"""

import ast
import re
from typing import List

from .base import BaseRule, register_rule
from ..models import Vulnerability


@register_rule
class SQLInjectionRule(BaseRule):
    """SQL注入检测规则"""

    rule_id = "SQL001"
    rule_name = "SQL注入风险"
    severity = "high"
    description = "检测通过字符串拼接构造SQL语句的风险代码"

    # SQL关键字模式（不区分大小写）
    SQL_PATTERNS = [
        r"\bSELECT\b",
        r"\bINSERT\b",
        r"\bUPDATE\b",
        r"\bDELETE\b",
        r"\bDROP\b",
        r"\bUNION\b",
        r"\bWHERE\b",
        r"\bFROM\b",
        r"\bJOIN\b",
        r"\bEXEC\b",
        r"\bEXECUTE\b",
    ]

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        vulnerabilities = []

        for node in ast.walk(ast_tree):
            vuln = None

            # 检测 % 格式化: "SELECT * FROM users WHERE id = %s" % user_id
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                if self._is_sql_string(node.left):
                    vuln = self._create_sql_vuln(
                        file_path, node, source_code, "使用 % 格式化拼接SQL语句，存在SQL注入风险"
                    )

            # 检测 f-string: f"SELECT * FROM users WHERE id = {user_id}"
            elif isinstance(node, ast.JoinedStr):
                # f-string 包含变量插值
                has_variable = any(isinstance(v, ast.FormattedValue) for v in node.values)
                if has_variable:
                    full_str = self._reconstruct_fstring(node)
                    if self._contains_sql(full_str):
                        vuln = self._create_sql_vuln(
                            file_path,
                            node,
                            source_code,
                            "使用 f-string 拼接SQL语句，存在SQL注入风险",
                        )

            # 检测 .format(): "SELECT * FROM users WHERE id = {}".format(user_id)
            elif isinstance(node, ast.Call):
                if self._is_format_call(node) and self._is_sql_format_string(node):
                    vuln = self._create_sql_vuln(
                        file_path, node, source_code, "使用 .format() 拼接SQL语句，存在SQL注入风险"
                    )

            # 检测字符串连接: "SELECT * FROM users WHERE id = " + user_id
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                if self._is_string_concat_sql(node):
                    vuln = self._create_sql_vuln(
                        file_path, node, source_code, "使用 + 连接拼接SQL语句，存在SQL注入风险"
                    )

            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_sql_string(self, node) -> bool:
        """判断节点是否为SQL语句字符串"""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return self._contains_sql(node.value)
        return False

    def _contains_sql(self, text: str) -> bool:
        """检查字符串是否包含SQL关键字"""
        if not text:
            return False
        text_upper = text.upper()
        return any(re.search(pattern, text_upper) for pattern in self.SQL_PATTERNS)

    def _reconstruct_fstring(self, node: ast.JoinedStr) -> str:
        """重构f-string的字符串内容"""
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                parts.append("{}")  # 占位符
        return "".join(parts)

    def _is_format_call(self, node: ast.Call) -> bool:
        """检查是否为 .format() 调用"""
        if isinstance(node.func, ast.Attribute):
            return node.func.attr == "format"
        return False

    def _is_sql_format_string(self, node: ast.Call) -> bool:
        """检查 .format() 调用的字符串是否为SQL"""
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Constant):
                return self._contains_sql(str(node.func.value.value))
        return False

    def _is_string_concat_sql(self, node: ast.BinOp) -> bool:
        """检查字符串连接是否涉及SQL"""

        # 递归检查左右操作数
        def check_node(n):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                return self._contains_sql(n.value)
            elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                return check_node(n.left) or check_node(n.right)
            return False

        return check_node(node)

    def _create_sql_vuln(
        self, file_path: str, node: ast.AST, source_code: str, detail: str
    ) -> Vulnerability:
        """创建SQL注入漏洞对象"""
        return self._create_vulnerability(
            file_path=file_path,
            line_number=node.lineno,
            column=node.col_offset,
            code_snippet=self._get_source_line(source_code, node.lineno),
            description=detail,
            suggestion="使用参数化查询（如 cursor.execute(sql, params)）代替字符串拼接，"
            "或使用ORM框架进行数据库操作",
        )
