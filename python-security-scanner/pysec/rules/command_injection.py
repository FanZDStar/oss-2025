"""
命令注入检测规则

检测可能导致命令注入的危险函数调用
"""

import ast
from typing import List

from .base import BaseRule, register_rule
from ..models import Vulnerability


@register_rule
class CommandInjectionRule(BaseRule):
    """命令注入检测规则"""

    rule_id = "CMD001"
    rule_name = "命令注入风险"
    severity = "critical"
    description = "检测可能导致命令注入的危险函数调用"

    # 危险函数列表及其描述
    DANGEROUS_FUNCTIONS = {
        "os.system": {
            "desc": "直接执行shell命令",
            "severity": "critical",
        },
        "os.popen": {
            "desc": "执行命令并返回文件对象",
            "severity": "critical",
        },
        "os.spawn": {
            "desc": "执行程序",
            "severity": "high",
        },
        "os.spawnl": {
            "desc": "执行程序",
            "severity": "high",
        },
        "os.spawnle": {
            "desc": "执行程序",
            "severity": "high",
        },
        "os.spawnlp": {
            "desc": "执行程序",
            "severity": "high",
        },
        "os.spawnv": {
            "desc": "执行程序",
            "severity": "high",
        },
        "os.spawnve": {
            "desc": "执行程序",
            "severity": "high",
        },
        "os.exec": {
            "desc": "替换当前进程执行程序",
            "severity": "critical",
        },
        "os.execl": {
            "desc": "替换当前进程执行程序",
            "severity": "critical",
        },
        "os.execle": {
            "desc": "替换当前进程执行程序",
            "severity": "critical",
        },
        "os.execlp": {
            "desc": "替换当前进程执行程序",
            "severity": "critical",
        },
        "os.execv": {
            "desc": "替换当前进程执行程序",
            "severity": "critical",
        },
        "os.execve": {
            "desc": "替换当前进程执行程序",
            "severity": "critical",
        },
        "commands.getoutput": {
            "desc": "执行命令并获取输出（Python 2）",
            "severity": "critical",
        },
        "commands.getstatusoutput": {
            "desc": "执行命令并获取状态和输出（Python 2）",
            "severity": "critical",
        },
    }

    # subprocess 函数（需要检查 shell 参数）
    SUBPROCESS_FUNCTIONS = {
        "subprocess.call",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        vulnerabilities = []

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)

                # 检查是否为直接危险函数
                if func_name in self.DANGEROUS_FUNCTIONS:
                    info = self.DANGEROUS_FUNCTIONS[func_name]
                    vulnerabilities.append(
                        self._create_vulnerability(
                            file_path=file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_source_line(source_code, node.lineno),
                            description=f"调用危险函数 {func_name}(): {info['desc']}",
                            suggestion="避免执行外部命令；如必须执行，使用参数列表形式并严格校验输入",
                            severity=info["severity"],
                        )
                    )

                # 检查 subprocess 函数
                elif func_name in self.SUBPROCESS_FUNCTIONS:
                    if self._has_shell_true(node):
                        vulnerabilities.append(
                            self._create_vulnerability(
                                file_path=file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_source_line(source_code, node.lineno),
                                description=f"调用 {func_name}() 时使用 shell=True，存在命令注入风险",
                                suggestion="避免使用 shell=True；使用参数列表传递命令；对用户输入进行严格校验",
                                severity="critical",
                            )
                        )

        return vulnerabilities

    def _get_func_name(self, node: ast.Call) -> str:
        """获取函数调用的完整名称"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _has_shell_true(self, node: ast.Call) -> bool:
        """检查函数调用是否包含 shell=True"""
        for keyword in node.keywords:
            if keyword.arg == "shell":
                # 检查值是否为 True
                if isinstance(keyword.value, ast.Constant):
                    return keyword.value.value is True
                elif isinstance(keyword.value, ast.NameConstant):  # Python 3.7 兼容
                    return keyword.value.value is True
        return False
