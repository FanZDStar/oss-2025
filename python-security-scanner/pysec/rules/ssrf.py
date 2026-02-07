"""
SSRF (服务端请求伪造) 检测规则

检测用户输入直接作为URL参数传递给HTTP请求库的风险代码
"""

import ast
from typing import List, Set

from .base import BaseRule, register_rule
from ..models import Vulnerability


@register_rule
class SSRFRule(BaseRule):
    """SSRF检测规则"""

    rule_id = "SSRF001"
    rule_name = "SSRF服务端请求伪造风险"
    severity = "high"
    description = "检测用户输入直接作为URL传递给HTTP请求函数的风险代码"

    # requests 库的危险函数
    REQUESTS_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "request"}

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        vulnerabilities = []

        for node in ast.walk(ast_tree):
            vuln = None

            if isinstance(node, ast.Call):
                # 检测 requests.get(url) 等调用
                vuln = self._check_requests_call(node, file_path, source_code)

            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_requests_call(
        self, node: ast.Call, file_path: str, source_code: str
    ) -> Vulnerability:
        """检测 requests 库的调用"""
        if not isinstance(node.func, ast.Attribute):
            return None

        # 检查是否是 requests.get/post/... 调用
        if not isinstance(node.func.value, ast.Name):
            return None

        if node.func.value.id != "requests":
            return None

        if node.func.attr not in self.REQUESTS_METHODS:
            return None

        # 检查第一个参数（URL）
        if not node.args:
            # 检查关键字参数 url=
            url_arg = None
            for keyword in node.keywords:
                if keyword.arg == "url":
                    url_arg = keyword.value
                    break
            if not url_arg:
                return None
        else:
            url_arg = node.args[0]

        # 检查URL参数是否可能来自用户输入
        if self._is_potentially_user_input(url_arg):
            return self._create_vulnerability(
                file_path=file_path,
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self._get_source_line(source_code, node.lineno),
                description=f"requests.{node.func.attr}() 的URL参数可能来自用户输入，存在SSRF风险",
                suggestion="建议对URL进行白名单验证，只允许访问可信的域名。可使用 urllib.parse 解析URL并验证域名。",
                severity=self.severity,
            )

        return None

    def _is_potentially_user_input(self, node: ast.AST) -> bool:
        """判断节点是否可能来自用户输入"""
        # 如果是变量名，视为可能的用户输入
        if isinstance(node, ast.Name):
            return True

        # 如果是下标访问，如 request.args['url']、data['url']
        if isinstance(node, ast.Subscript):
            return True

        # 如果是属性访问后的方法调用结果，如 request.args.get('url')
        if isinstance(node, ast.Call):
            return True

        # 如果是 f-string，检查是否包含变量
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    return True

        # 如果是字符串拼接
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._is_potentially_user_input(node.left) or self._is_potentially_user_input(
                node.right
            )

        # 如果是 % 格式化
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return True

        # 如果是 .format() 调用
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "format":
                return True

        return False
