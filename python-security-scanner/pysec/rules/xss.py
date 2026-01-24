"""
XSS检测规则

检测Web框架中的跨站脚本（XSS）风险
"""

import ast
from typing import List, Set

from .base import BaseRule, register_rule
from ..models import Vulnerability


@register_rule
class XSSRule(BaseRule):
    """XSS检测规则"""

    rule_id = "XSS001"
    rule_name = "XSS风险"
    severity = "medium"
    description = "检测Web框架中可能存在的跨站脚本（XSS）风险"

    # 危险的模板渲染函数（直接渲染字符串）
    DANGEROUS_TEMPLATE_FUNCTIONS: Set[str] = {
        "render_template_string",  # Flask
        "Markup",  # Flask/Jinja2
        "Template",  # Jinja2
    }

    # 标记为安全的危险函数
    MARK_SAFE_FUNCTIONS: Set[str] = {
        "mark_safe",  # Django
        "SafeString",  # Django
        "SafeText",  # Django
        "format_html",  # Django（相对安全，但需注意参数）
    }

    # 不安全的 HTML 响应构造
    UNSAFE_RESPONSE_PATTERNS: Set[str] = {
        "make_response",  # Flask
        "Response",  # Flask/Werkzeug
        "HttpResponse",  # Django
    }

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        vulnerabilities = []

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)

                # 检查危险的模板渲染函数
                if func_name in self.DANGEROUS_TEMPLATE_FUNCTIONS:
                    # 检查第一个参数是否包含用户输入
                    if node.args and self._contains_user_input(node.args[0]):
                        vulnerabilities.append(
                            self._create_vulnerability(
                                file_path=file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_source_line(source_code, node.lineno),
                                description=f"调用 {func_name}() 渲染包含用户输入的模板，存在XSS风险",
                                suggestion="使用 render_template() 渲染模板文件而非字符串；"
                                "确保对用户输入进行HTML转义；"
                                "使用模板引擎的自动转义功能",
                                severity="high",
                            )
                        )

                # 检查 mark_safe 类函数
                elif func_name in self.MARK_SAFE_FUNCTIONS:
                    if node.args and self._contains_user_input(node.args[0]):
                        vulnerabilities.append(
                            self._create_vulnerability(
                                file_path=file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_source_line(source_code, node.lineno),
                                description=f"调用 {func_name}() 将包含用户输入的内容标记为安全，存在XSS风险",
                                suggestion="永远不要将用户输入直接标记为安全；"
                                "使用 format_html() 或手动转义后再标记",
                                severity="high",
                            )
                        )

                # 检查直接构造 HTML 响应
                elif func_name in self.UNSAFE_RESPONSE_PATTERNS:
                    # 检查是否设置了 content_type 为 html 且内容包含用户输入
                    if (
                        self._is_html_response(node)
                        and node.args
                        and self._contains_user_input(node.args[0])
                    ):
                        vulnerabilities.append(
                            self._create_vulnerability(
                                file_path=file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_source_line(source_code, node.lineno),
                                description=f"构造 HTML 响应时包含未转义的用户输入，存在XSS风险",
                                suggestion="对用户输入进行HTML转义；"
                                "使用模板引擎渲染HTML；"
                                "设置正确的 Content-Type",
                            )
                        )

        return vulnerabilities

    def _get_func_name(self, node: ast.Call) -> str:
        """获取函数调用的简短名称"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    def _contains_user_input(self, node) -> bool:
        """
        判断节点是否可能包含用户输入
        """
        if isinstance(node, ast.Constant):
            return False
        elif isinstance(node, ast.Name):
            # 变量可能来自用户输入
            return True
        elif isinstance(node, ast.BinOp):
            # 字符串拼接
            return self._contains_user_input(node.left) or self._contains_user_input(node.right)
        elif isinstance(node, ast.JoinedStr):
            # f-string
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    return True
            return False
        elif isinstance(node, ast.Call):
            # 函数调用结果
            func_name = self._get_func_name(node)
            # 如果是格式化函数，检查其参数
            if func_name == "format":
                return True
            return True
        elif isinstance(node, ast.Subscript):
            return True
        elif isinstance(node, ast.Attribute):
            return True

        return False

    def _is_html_response(self, node: ast.Call) -> bool:
        """
        判断是否为 HTML 响应

        检查关键字参数中是否有 content_type/mimetype 包含 'html'
        """
        for keyword in node.keywords:
            if keyword.arg in ("content_type", "mimetype"):
                if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                    if "html" in keyword.value.value.lower():
                        return True

        # 默认假设可能是 HTML
        return True
