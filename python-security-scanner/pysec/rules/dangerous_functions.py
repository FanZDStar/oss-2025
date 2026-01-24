"""
危险函数调用检测规则

检测可能导致任意代码执行的危险函数调用
"""

import ast
from typing import List, Dict

from .base import BaseRule, register_rule
from ..models import Vulnerability


@register_rule
class DangerousFunctionsRule(BaseRule):
    """危险函数调用检测规则"""

    rule_id = "DNG001"
    rule_name = "危险函数调用"
    severity = "critical"
    description = "检测可能导致任意代码执行的危险函数调用"

    # 危险内置函数
    DANGEROUS_BUILTINS: Dict[str, Dict] = {
        "eval": {
            "severity": "critical",
            "desc": "执行任意Python表达式，可导致远程代码执行",
            "fix": "避免使用eval；如需解析字面量，使用ast.literal_eval",
        },
        "exec": {
            "severity": "critical",
            "desc": "执行任意Python代码，可导致远程代码执行",
            "fix": "避免使用exec；重新设计程序逻辑避免动态代码执行",
        },
        "compile": {
            "severity": "high",
            "desc": "编译代码对象，配合eval/exec可执行任意代码",
            "fix": "确保compile的输入来自可信源；避免编译用户输入",
        },
        "__import__": {
            "severity": "medium",
            "desc": "动态导入模块，可能导致任意代码执行",
            "fix": "使用importlib.import_module并验证模块名白名单",
        },
        "input": {
            "severity": "low",
            "desc": "Python 2中input()会执行输入内容（Python 3安全）",
            "fix": "确保使用Python 3；或在Python 2中使用raw_input",
        },
    }

    # 危险模块方法
    DANGEROUS_METHODS: Dict[str, Dict] = {
        "pickle.loads": {
            "severity": "critical",
            "desc": "反序列化不可信数据可导致远程代码执行",
            "fix": "避免反序列化不可信数据；使用json等安全格式",
        },
        "pickle.load": {
            "severity": "critical",
            "desc": "从文件反序列化可导致远程代码执行",
            "fix": "避免反序列化不可信数据；使用json等安全格式",
        },
        "cPickle.loads": {
            "severity": "critical",
            "desc": "反序列化不可信数据可导致远程代码执行",
            "fix": "避免反序列化不可信数据；使用json等安全格式",
        },
        "cPickle.load": {
            "severity": "critical",
            "desc": "从文件反序列化可导致远程代码执行",
            "fix": "避免反序列化不可信数据；使用json等安全格式",
        },
        "yaml.load": {
            "severity": "high",
            "desc": "不安全的YAML解析，可执行任意Python代码",
            "fix": "使用yaml.safe_load代替yaml.load",
        },
        "yaml.unsafe_load": {
            "severity": "critical",
            "desc": "明确的不安全YAML解析",
            "fix": "使用yaml.safe_load",
        },
        "yaml.full_load": {
            "severity": "high",
            "desc": "YAML完整加载模式，存在代码执行风险",
            "fix": "使用yaml.safe_load",
        },
        "marshal.loads": {
            "severity": "high",
            "desc": "反序列化marshal数据可能导致代码执行",
            "fix": "避免处理不可信的marshal数据",
        },
        "marshal.load": {
            "severity": "high",
            "desc": "从文件反序列化marshal数据",
            "fix": "避免处理不可信的marshal数据",
        },
        "shelve.open": {
            "severity": "high",
            "desc": "shelve使用pickle，存在反序列化风险",
            "fix": "避免打开不可信的shelve文件",
        },
        "dill.loads": {
            "severity": "critical",
            "desc": "dill是pickle的扩展，存在同样的反序列化风险",
            "fix": "避免反序列化不可信数据",
        },
        "dill.load": {
            "severity": "critical",
            "desc": "dill是pickle的扩展，存在同样的反序列化风险",
            "fix": "避免反序列化不可信数据",
        },
        "jsonpickle.decode": {
            "severity": "critical",
            "desc": "jsonpickle可反序列化任意Python对象",
            "fix": "避免解码不可信的jsonpickle数据；使用标准json",
        },
    }

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        vulnerabilities = []

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)

                # 检查危险内置函数
                if func_name in self.DANGEROUS_BUILTINS:
                    info = self.DANGEROUS_BUILTINS[func_name]
                    vulnerabilities.append(
                        self._create_vulnerability(
                            file_path=file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_source_line(source_code, node.lineno),
                            description=f"调用危险函数 {func_name}(): {info['desc']}",
                            suggestion=info["fix"],
                            severity=info["severity"],
                        )
                    )

                # 检查危险模块方法
                elif func_name in self.DANGEROUS_METHODS:
                    info = self.DANGEROUS_METHODS[func_name]
                    vulnerabilities.append(
                        self._create_vulnerability(
                            file_path=file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_source_line(source_code, node.lineno),
                            description=f"调用危险方法 {func_name}(): {info['desc']}",
                            suggestion=info["fix"],
                            severity=info["severity"],
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
