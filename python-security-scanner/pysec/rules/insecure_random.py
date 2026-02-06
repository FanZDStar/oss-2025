"""
不安全的随机数生成检测规则

检测代码中使用random模块生成安全相关的随机数（如token、密钥等）
"""

import ast
from typing import List, Set

from .base import BaseRule, register_rule
from ..models import Vulnerability


@register_rule
class InsecureRandomRule(BaseRule):
    """不安全的随机数生成检测规则"""

    rule_id = "RND001"
    rule_name = "不安全的随机数生成"
    severity = "medium"
    description = "检测使用random模块生成安全相关随机数的情况，应使用secrets模块"

    # random模块中不安全的函数
    UNSAFE_RANDOM_FUNCTIONS = {
        "random": ["random", "randint", "randrange", "choice", "choices", 
                   "sample", "shuffle", "getrandbits", "uniform"],
        "numpy.random": ["rand", "randn", "randint", "random", "choice"],
    }

    # 安全上下文关键词（变量名或字符串中包含这些词表示可能用于安全目的）
    SECURITY_CONTEXT_KEYWORDS = {
        "token", "secret", "key", "password", "passwd", "pwd",
        "auth", "session", "cookie", "csrf", "nonce", "salt",
        "credential", "api_key", "apikey", "access_key", "private",
        "encryption", "signing", "jwt", "otp", "verification",
        "reset", "activation", "invite", "uuid", "id",
    }

    # 非安全上下文关键词（这些通常表示非安全用途）
    NON_SECURITY_KEYWORDS = {
        "shuffle", "sample", "test", "demo", "example", "mock",
        "game", "play", "dice", "lottery", "color", "position",
        "index", "offset", "delay", "sleep", "jitter",
    }

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        """检查不安全的随机数生成"""
        vulnerabilities = []
        source_lines = source_code.splitlines()

        # 收集导入信息
        imports = self._collect_imports(ast_tree)

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                vuln = self._check_random_call(node, imports, source_lines, file_path)
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _collect_imports(self, ast_tree: ast.AST) -> dict:
        """收集import信息"""
        imports = {"names": {}, "from_imports": set()}

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname if alias.asname else alias.name
                    imports["names"][name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    name = alias.asname if alias.asname else alias.name
                    imports["from_imports"].add((module, alias.name, name))
                    imports["names"][name] = f"{module}.{alias.name}"

        return imports

    def _check_random_call(self, node: ast.Call, imports: dict, 
                           source_lines: List[str], file_path: str) -> Vulnerability:
        """检查random模块调用"""
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        # 检查是否是random模块的函数调用
        is_random_call = False
        matched_module = None

        # 检查 random.xxx() 形式
        if "." in func_name:
            parts = func_name.split(".")
            if len(parts) == 2:
                module_name, method_name = parts
                # 检查是否是random模块的调用
                actual_module = imports["names"].get(module_name, module_name)
                if actual_module in ["random", "numpy.random"]:
                    if method_name in self.UNSAFE_RANDOM_FUNCTIONS.get(actual_module, []):
                        is_random_call = True
                        matched_module = actual_module

        # 检查直接导入的函数 from random import randint
        else:
            for module, orig_name, alias in imports.get("from_imports", set()):
                if alias == func_name and module == "random":
                    if orig_name in self.UNSAFE_RANDOM_FUNCTIONS.get("random", []):
                        is_random_call = True
                        matched_module = "random"
                        break

        if not is_random_call:
            return None

        # 检查是否在安全上下文中使用
        if not self._is_security_context(node, source_lines):
            return None

        # 获取代码片段
        line_number = node.lineno
        code_snippet = self._get_code_snippet(source_lines, line_number)

        return self._create_vulnerability(
            file_path=file_path,
            line_number=line_number,
            column=node.col_offset,
            code_snippet=code_snippet,
            description=f"使用 {matched_module} 模块生成安全相关的随机数。random模块使用Mersenne Twister算法，不适合安全用途。",
            suggestion="请使用 secrets 模块替代 random 模块生成安全相关的随机数。"
                       "例如：secrets.token_urlsafe(32)、secrets.token_hex(32)、secrets.choice()。",
        )

    def _get_call_name(self, node: ast.Call) -> str:
        """获取函数调用名称"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return None

    def _is_security_context(self, node: ast.Call, source_lines: List[str]) -> bool:
        """判断是否在安全上下文中使用"""
        line_idx = node.lineno - 1
        if line_idx < 0 or line_idx >= len(source_lines):
            return False

        # 获取当前行和上下文
        current_line = source_lines[line_idx].lower()

        # 检查是否有非安全关键词（降低误报）
        for keyword in self.NON_SECURITY_KEYWORDS:
            if keyword in current_line:
                return False

        # 检查赋值目标变量名
        context_lines = []
        for i in range(max(0, line_idx - 2), min(len(source_lines), line_idx + 3)):
            context_lines.append(source_lines[i].lower())
        context_text = " ".join(context_lines)

        # 检查安全上下文关键词
        for keyword in self.SECURITY_CONTEXT_KEYWORDS:
            if keyword in context_text:
                return True

        # 检查常见的安全用途模式
        security_patterns = [
            "choices(string.",  # random.choices(string.ascii_letters, ...)
            "choices(ascii",    # 生成随机字符串
            "join(random",      # ''.join(random...)
            "join(choices",     # ''.join(choices...)
            "for _ in range",   # 循环生成随机值（常见于生成token）
        ]
        
        for pattern in security_patterns:
            if pattern in current_line:
                return True

        return False

    def _get_code_snippet(self, source_lines: List[str], line_number: int) -> str:
        """获取代码片段"""
        if 0 < line_number <= len(source_lines):
            return source_lines[line_number - 1].strip()
        return ""
