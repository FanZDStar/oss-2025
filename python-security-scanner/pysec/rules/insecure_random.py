# pysec/rules/insecure_random.py
from pysec.rules.base import BaseRule, register_rule
from pysec.models import Vulnerability
import ast

@register_rule
class InsecureRandomRule(BaseRule):
    rule_id = "RND001"
    rule_name = "不安全的随机数生成"
    severity = "medium"
    description = "检测在安全上下文中使用不安全的随机数生成函数（如 random 模块）"

    def check(self, ast_tree, file_path, source_code):
        vulnerabilities = []
        dangerous_funcs = [
            'random.random',
            'random.randint',
            'random.choice',
            'random.choices',
            'random.sample',
            'random.randrange',
        ]

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node.func)
                for danger_func in dangerous_funcs:
                    if func_name == danger_func or func_name.endswith('.' + danger_func):
                        vuln = Vulnerability(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=self.severity,
                            file_path=file_path,
                            line_number=node.lineno,
                            description=f"发现不安全的随机函数调用: '{func_name}'。在安全上下文中应使用 `secrets` 模块。"
                        )
                        vulnerabilities.append(vuln)
                        break
        return vulnerabilities

    def _get_func_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_func_name(node.value) + '.' + node.attr
        return ""
