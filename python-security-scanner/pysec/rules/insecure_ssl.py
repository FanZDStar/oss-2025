"""
不安全的SSL/TLS配置检测规则

检测代码中禁用SSL证书验证或使用不安全SSL配置的情况
"""

import ast
from typing import List, Optional

from .base import BaseRule, register_rule
from ..models import Vulnerability


@register_rule
class InsecureSSLRule(BaseRule):
    """不安全的SSL/TLS配置检测规则"""

    rule_id = "SSL001"
    rule_name = "不安全的SSL/TLS配置"
    severity = "high"
    description = "检测禁用SSL证书验证或使用不安全SSL配置的情况"

    # 不安全的SSL函数调用
    INSECURE_SSL_FUNCTIONS = {
        "ssl._create_unverified_context",
        "ssl._create_stdlib_context",
    }

    # 过时的SSL/TLS版本常量
    DEPRECATED_SSL_VERSIONS = {
        "PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_SSLv23",
        "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1",
        "SSLv2_METHOD", "SSLv3_METHOD", "SSLv23_METHOD",
        "TLSv1_METHOD", "TLSv1_1_METHOD",
    }

    # 检测 verify=False 的函数
    VERIFY_FUNCTIONS = {
        "get", "post", "put", "delete", "patch", "head", "options",
        "request", "Session", "session",
    }

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        """检查不安全的SSL/TLS配置"""
        vulnerabilities = []
        source_lines = source_code.splitlines()

        imports = self._collect_imports(ast_tree)

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                # 检查 verify=False
                vuln = self._check_verify_false(node, imports, source_lines, file_path)
                if vuln:
                    vulnerabilities.append(vuln)
                
                # 检查不安全的SSL函数
                vuln = self._check_insecure_ssl_call(node, imports, source_lines, file_path)
                if vuln:
                    vulnerabilities.append(vuln)

            elif isinstance(node, ast.Attribute):
                # 检查过时的SSL版本常量
                vuln = self._check_deprecated_ssl_version(node, imports, source_lines, file_path)
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _collect_imports(self, ast_tree: ast.AST) -> dict:
        """收集import信息"""
        imports = {"names": {}, "from_imports": set(), "has_requests": False}

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname if alias.asname else alias.name
                    imports["names"][name] = alias.name
                    if alias.name == "requests":
                        imports["has_requests"] = True
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module == "requests" or module.startswith("requests."):
                    imports["has_requests"] = True
                for alias in node.names:
                    name = alias.asname if alias.asname else alias.name
                    imports["from_imports"].add((module, alias.name, name))
                    imports["names"][name] = f"{module}.{alias.name}"

        return imports

    def _check_verify_false(self, node: ast.Call, imports: dict, 
                             source_lines: List[str], file_path: str) -> Optional[Vulnerability]:
        """检查 verify=False 参数"""
        # 获取函数名
        func_name = self._get_func_name(node)
        if not func_name:
            return None

        # 检查是否是requests相关调用
        is_requests_call = False
        if imports.get("has_requests"):
            if func_name in self.VERIFY_FUNCTIONS:
                is_requests_call = True
            elif "." in func_name:
                parts = func_name.split(".")
                if parts[-1] in self.VERIFY_FUNCTIONS:
                    is_requests_call = True

        # 也检查 urllib3, httpx 等
        current_line = source_lines[node.lineno - 1].lower() if node.lineno <= len(source_lines) else ""
        if "urllib" in current_line or "httpx" in current_line or "aiohttp" in current_line:
            is_requests_call = True

        if not is_requests_call:
            return None

        # 检查 verify=False 关键字参数
        for keyword in node.keywords:
            if keyword.arg == "verify":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                    code_snippet = self._get_code_snippet(source_lines, node.lineno)
                    return self._create_vulnerability(
                        file_path=file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=code_snippet,
                        description="禁用了SSL证书验证 (verify=False)，这会使应用程序容易受到中间人攻击。",
                        suggestion="请移除 verify=False 或设置 verify=True。"
                                   "如需使用自签名证书，请使用 verify='/path/to/cert.pem' 指定证书。",
                    )

        return None

    def _check_insecure_ssl_call(self, node: ast.Call, imports: dict,
                                  source_lines: List[str], file_path: str) -> Optional[Vulnerability]:
        """检查不安全的SSL函数调用"""
        call_name = self._get_full_call_name(node, imports)
        if not call_name:
            return None

        for insecure_func in self.INSECURE_SSL_FUNCTIONS:
            if call_name.endswith(insecure_func) or insecure_func in call_name:
                code_snippet = self._get_code_snippet(source_lines, node.lineno)
                return self._create_vulnerability(
                    file_path=file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=code_snippet,
                    description=f"使用了不安全的SSL上下文创建函数 {insecure_func}，这会禁用证书验证。",
                    suggestion="请使用 ssl.create_default_context() 创建安全的SSL上下文。",
                )

        return None

    def _check_deprecated_ssl_version(self, node: ast.Attribute, imports: dict,
                                       source_lines: List[str], file_path: str) -> Optional[Vulnerability]:
        """检查过时的SSL版本常量"""
        if node.attr in self.DEPRECATED_SSL_VERSIONS:
            # 确认是ssl模块的属性
            if isinstance(node.value, ast.Name):
                module_name = node.value.id
                actual_module = imports["names"].get(module_name, module_name)
                if actual_module in ["ssl", "OpenSSL.SSL", "OpenSSL"]:
                    code_snippet = self._get_code_snippet(source_lines, node.lineno)
                    return self._create_vulnerability(
                        file_path=file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=code_snippet,
                        description=f"使用了过时且不安全的SSL/TLS版本 {node.attr}。",
                        suggestion="请使用 TLS 1.2 或更高版本。"
                                   "推荐使用 ssl.PROTOCOL_TLS_CLIENT 或 ssl.create_default_context()。",
                    )

        return None

    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        """获取函数名"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    def _get_full_call_name(self, node: ast.Call, imports: dict) -> Optional[str]:
        """获取完整的函数调用名称"""
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            parts.reverse()
            return ".".join(parts)
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return None

    def _get_code_snippet(self, source_lines: List[str], line_number: int) -> str:
        """获取代码片段"""
        if 0 < line_number <= len(source_lines):
            return source_lines[line_number - 1].strip()
        return ""
