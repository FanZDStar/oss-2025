"""
不安全的哈希算法检测规则

检测代码中使用MD5、SHA1等弱哈希算法用于密码哈希或安全场景
"""

import ast
from typing import List, Set, Optional

from .base import BaseRule, register_rule
from ..models import Vulnerability


@register_rule
class InsecureHashRule(BaseRule):
    """不安全的哈希算法检测规则"""

    rule_id = "HSH001"
    rule_name = "不安全的哈希算法"
    severity = "medium"
    description = "检测使用MD5、SHA1等弱哈希算法用于密码或安全场景"

    # 弱哈希算法（不应用于密码或安全场景）
    WEAK_HASH_ALGORITHMS = {
        "md5", "md4", "md2",
        "sha1", "sha",
    }

    # hashlib中的弱算法调用
    WEAK_HASHLIB_METHODS = {
        "md5", "md4", "sha1", "sha",
        "new",  # hashlib.new('md5', ...)
    }

    # 密码相关上下文关键词
    PASSWORD_CONTEXT_KEYWORDS = {
        "password", "passwd", "pwd", "credential", "secret",
        "auth", "authenticate", "login", "user", "account",
        "hash", "hashed", "digest", "checksum",
    }

    # 安全上下文关键词（用于token、签名等）
    SECURITY_CONTEXT_KEYWORDS = {
        "token", "session", "cookie", "signature", "sign",
        "verify", "validate", "key", "encryption", "encrypt",
        "decrypt", "cipher", "hmac", "mac",
    }

    # 非安全上下文（这些场景使用MD5/SHA1是可以接受的）
    NON_SECURITY_CONTEXTS = {
        "checksum", "fingerprint", "etag", "cache", "content_hash",
        "file_hash", "data_hash", "asset", "resource", "dedup",
        "compare", "diff", "test", "mock", "example", "demo",
    }

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        """检查不安全的哈希算法使用"""
        vulnerabilities = []
        source_lines = source_code.splitlines()

        # 收集导入信息
        imports = self._collect_imports(ast_tree)

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                vuln = self._check_hash_call(node, imports, source_lines, file_path)
                if vuln:
                    vulnerabilities.append(vuln)
            elif isinstance(node, ast.Compare):
                vuln = self._check_plaintext_compare(node, source_lines, file_path)
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

    def _check_hash_call(self, node: ast.Call, imports: dict, 
                         source_lines: List[str], file_path: str) -> Optional[Vulnerability]:
        """检查哈希函数调用"""
        # 获取函数调用信息
        call_info = self._get_call_info(node, imports)
        if not call_info:
            return None

        module, method, algorithm = call_info

        # 检查是否是弱哈希算法
        if algorithm and algorithm.lower() not in self.WEAK_HASH_ALGORITHMS:
            return None

        # 检查是否在安全上下文中使用
        if not self._is_security_context(node, source_lines):
            return None

        # 获取代码片段
        line_number = node.lineno
        code_snippet = self._get_code_snippet(source_lines, line_number)

        algo_name = algorithm.upper() if algorithm else method.upper()
        return self._create_vulnerability(
            file_path=file_path,
            line_number=line_number,
            column=node.col_offset,
            code_snippet=code_snippet,
            description=f"使用弱哈希算法 {algo_name} 处理密码或安全相关数据。"
                        f"{algo_name} 容易受到碰撞攻击和暴力破解。",
            suggestion="密码哈希请使用 bcrypt、argon2 或 scrypt。"
                       "其他安全场景请使用 SHA-256 或更强的算法。"
                       "示例：import bcrypt; bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
        )

    def _get_call_info(self, node: ast.Call, imports: dict) -> Optional[tuple]:
        """获取函数调用信息 (module, method, algorithm)"""
        # hashlib.md5() 或 hashlib.sha1() 形式
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                method_name = node.func.attr
                
                # 检查是否是hashlib模块
                actual_module = imports["names"].get(module_name, module_name)
                if actual_module == "hashlib":
                    if method_name in self.WEAK_HASHLIB_METHODS:
                        # hashlib.new('md5', ...) 形式
                        if method_name == "new" and node.args:
                            if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                                algo = node.args[0].value.lower()
                                if algo in self.WEAK_HASH_ALGORITHMS:
                                    return ("hashlib", "new", algo)
                        else:
                            return ("hashlib", method_name, method_name)

        # 直接导入的函数调用 from hashlib import md5
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
            for module, orig_name, alias in imports.get("from_imports", set()):
                if alias == func_name and module == "hashlib":
                    if orig_name.lower() in self.WEAK_HASH_ALGORITHMS:
                        return ("hashlib", orig_name, orig_name)

        return None

    def _is_security_context(self, node: ast.Call, source_lines: List[str]) -> bool:
        """判断是否在安全上下文中使用"""
        line_idx = node.lineno - 1
        if line_idx < 0 or line_idx >= len(source_lines):
            return False

        # 获取上下文
        context_lines = []
        for i in range(max(0, line_idx - 3), min(len(source_lines), line_idx + 3)):
            context_lines.append(source_lines[i].lower())
        context_text = " ".join(context_lines)

        # 检查是否有非安全上下文关键词（降低误报）
        for keyword in self.NON_SECURITY_CONTEXTS:
            if keyword in context_text:
                # 但如果同时有密码关键词，仍然报告
                has_password_keyword = any(
                    pwd_kw in context_text 
                    for pwd_kw in ["password", "passwd", "pwd", "credential"]
                )
                if not has_password_keyword:
                    return False

        # 检查密码上下文
        for keyword in self.PASSWORD_CONTEXT_KEYWORDS:
            if keyword in context_text:
                return True

        # 检查安全上下文
        for keyword in self.SECURITY_CONTEXT_KEYWORDS:
            if keyword in context_text:
                return True

        return False

    def _check_plaintext_compare(self, node: ast.Compare, source_lines: List[str], 
                                  file_path: str) -> Optional[Vulnerability]:
        """检测明文密码比较"""
        # 检查是否是 == 或 != 比较
        if not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            return None

        line_idx = node.lineno - 1
        if line_idx < 0 or line_idx >= len(source_lines):
            return None

        current_line = source_lines[line_idx].lower()

        # 检查是否涉及密码变量的直接比较
        password_patterns = ["password", "passwd", "pwd"]
        has_password_var = any(pattern in current_line for pattern in password_patterns)

        # 检查是否是字符串比较（可能是明文密码比较）
        if not has_password_var:
            return None

        # 排除哈希比较（password_hash == stored_hash 是安全的）
        hash_indicators = ["hash", "hashed", "digest", "bcrypt", "argon", "scrypt", "pbkdf"]
        if any(indicator in current_line for indicator in hash_indicators):
            return None

        # 检查是否是输入验证而非密码验证
        validation_indicators = ["is not none", "is none", "!= none", "!= ''", "!= \"\"", "len("]
        if any(indicator in current_line for indicator in validation_indicators):
            return None

        code_snippet = self._get_code_snippet(source_lines, node.lineno)

        # 只有当看起来像是在比较两个密码值时才报告
        if "==" in current_line and has_password_var:
            # 进一步检查：是否像是 password == user_password 这样的比较
            if "input" in current_line or "request" in current_line or "form" in current_line:
                return self._create_vulnerability(
                    file_path=file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=code_snippet,
                    description="可能存在明文密码比较，这是不安全的做法。",
                    suggestion="不要直接比较密码，应使用安全的哈希比较函数。"
                               "示例：bcrypt.checkpw(password.encode(), stored_hash)",
                )

        return None

    def _get_code_snippet(self, source_lines: List[str], line_number: int) -> str:
        """获取代码片段"""
        if 0 < line_number <= len(source_lines):
            return source_lines[line_number - 1].strip()
        return ""
