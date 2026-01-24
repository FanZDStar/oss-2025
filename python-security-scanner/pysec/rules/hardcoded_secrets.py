"""
硬编码敏感信息检测规则

检测代码中硬编码的密码、密钥、Token等敏感信息
"""

import ast
import re
from typing import List

from .base import BaseRule, register_rule
from ..models import Vulnerability


@register_rule
class HardcodedSecretsRule(BaseRule):
    """硬编码敏感信息检测规则"""

    rule_id = "SEC001"
    rule_name = "硬编码敏感信息"
    severity = "high"
    description = "检测代码中硬编码的密码、密钥、Token等敏感信息"

    # 敏感变量名模式（不区分大小写）
    SENSITIVE_PATTERNS = [
        r"password",
        r"passwd",
        r"pwd",
        r"secret",
        r"token",
        r"api_?key",
        r"apikey",
        r"access_?key",
        r"auth_?key",
        r"credential",
        r"private_?key",
        r"secret_?key",
        r"encryption_?key",
        r"signing_?key",
        r"jwt_?secret",
        r"session_?key",
        r"cookie_?secret",
        r"db_?password",
        r"database_?password",
        r"mysql_?password",
        r"postgres_?password",
        r"redis_?password",
    ]

    # 排除的占位符值（这些值不应被视为硬编码）
    PLACEHOLDER_VALUES = [
        "",
        "xxx",
        "xxxx",
        "changeme",
        "your_password",
        "your_secret",
        "your_token",
        "your_api_key",
        "placeholder",
        "example",
        "test",
        "demo",
        "sample",
        "none",
        "null",
        "n/a",
        "na",
        "undefined",
        "todo",
        "fixme",
        "<password>",
        "<secret>",
        "<token>",
        "{password}",
        "{secret}",
        "${password}",
        "${secret}",
        "password",  # 变量名本身
        "secret",
        "token",
        "env",
        "os.environ",
        "os.getenv",
    ]

    # 看起来像真实密钥的最小长度
    MIN_SECRET_LENGTH = 6

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        vulnerabilities = []

        for node in ast.walk(ast_tree):
            # 检查变量赋值: password = "secret123"
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        if self._is_sensitive_name(var_name):
                            if self._is_hardcoded_secret(node.value):
                                vulnerabilities.append(
                                    self._create_secret_vuln(file_path, node, source_code, var_name)
                                )

            # 检查类型注解赋值: password: str = "secret123"
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name):
                    var_name = node.target.id
                    if self._is_sensitive_name(var_name):
                        if node.value and self._is_hardcoded_secret(node.value):
                            vulnerabilities.append(
                                self._create_secret_vuln(file_path, node, source_code, var_name)
                            )

            # 检查字典中的敏感键: {"password": "secret123"}
            elif isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if (
                        key is not None
                        and isinstance(key, ast.Constant)
                        and isinstance(key.value, str)
                    ):
                        if self._is_sensitive_name(key.value):
                            if self._is_hardcoded_secret(value):
                                vulnerabilities.append(
                                    self._create_secret_vuln(
                                        file_path, node, source_code, key.value
                                    )
                                )

            # 检查函数调用中的关键字参数: connect(password="secret123")
            elif isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg and self._is_sensitive_name(keyword.arg):
                        if self._is_hardcoded_secret(keyword.value):
                            vulnerabilities.append(
                                self._create_secret_vuln(file_path, node, source_code, keyword.arg)
                            )

        return vulnerabilities

    def _is_sensitive_name(self, name: str) -> bool:
        """检查变量名是否为敏感名称"""
        name_lower = name.lower()
        return any(re.search(pattern, name_lower) for pattern in self.SENSITIVE_PATTERNS)

    def _is_hardcoded_secret(self, node) -> bool:
        """检查值是否为硬编码的敏感信息"""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            value_lower = value.lower().strip()

            # 排除占位符
            if value_lower in self.PLACEHOLDER_VALUES:
                return False

            # 排除过短的值
            if len(value) < self.MIN_SECRET_LENGTH:
                return False

            # 排除看起来像环境变量引用的值
            if value.startswith("${") or value.startswith("$"):
                return False

            # 排除看起来像配置占位符的值
            if value.startswith("{") and value.endswith("}"):
                return False
            if value.startswith("<") and value.endswith(">"):
                return False

            return True

        return False

    def _create_secret_vuln(
        self, file_path: str, node: ast.AST, source_code: str, var_name: str
    ) -> Vulnerability:
        """创建硬编码敏感信息漏洞对象"""
        return self._create_vulnerability(
            file_path=file_path,
            line_number=node.lineno,
            column=node.col_offset,
            code_snippet=self._get_source_line(source_code, node.lineno),
            description=f"变量 '{var_name}' 包含硬编码的敏感信息，可能导致凭据泄露",
            suggestion="使用环境变量存储敏感信息，如 os.environ.get('SECRET_KEY')；"
            "或使用配置文件（不提交到版本控制）；"
            "或使用密钥管理服务",
        )
