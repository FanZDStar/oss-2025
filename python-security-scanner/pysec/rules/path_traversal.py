"""
路径遍历检测规则

检测文件操作中的路径遍历风险
"""

import ast
from typing import List, Set

from .base import BaseRule, register_rule
from ..models import Vulnerability


@register_rule
class PathTraversalRule(BaseRule):
    """路径遍历检测规则"""

    rule_id = "PTH001"
    rule_name = "路径遍历风险"
    severity = "medium"
    description = "检测文件操作中可能存在的路径遍历风险"

    # 文件操作函数
    FILE_FUNCTIONS: Set[str] = {
        "open",
        "file",  # Python 2
    }

    # 文件操作模块方法
    FILE_METHODS: Set[str] = {
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.mkdir",
        "os.makedirs",
        "os.rename",
        "os.renames",
        "os.replace",
        "os.chmod",
        "os.chown",
        "os.link",
        "os.symlink",
        "os.readlink",
        "os.listdir",
        "os.scandir",
        "os.walk",
        "os.path.exists",
        "os.path.isfile",
        "os.path.isdir",
        "os.path.getsize",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copytree",
        "shutil.move",
        "shutil.rmtree",
        "pathlib.Path",
        "io.open",
    }

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        vulnerabilities = []

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)

                # 检查文件操作函数
                if func_name in self.FILE_FUNCTIONS or func_name in self.FILE_METHODS:
                    # 检查第一个参数（文件路径）是否来自变量
                    if node.args and self._is_user_controlled(node.args[0]):
                        vulnerabilities.append(
                            self._create_vulnerability(
                                file_path=file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_source_line(source_code, node.lineno),
                                description=f"调用 {func_name}() 的路径参数可能来自用户输入，存在路径遍历风险",
                                suggestion="对文件路径进行严格校验；使用os.path.basename()提取文件名；"
                                "使用os.path.realpath()解析真实路径后验证是否在允许的目录内",
                            )
                        )

                # 特别检查 os.path.join 的使用
                if func_name == "os.path.join":
                    # 检查是否有参数来自用户输入
                    for arg in node.args[1:]:  # 跳过第一个基础路径参数
                        if self._is_user_controlled(arg):
                            vulnerabilities.append(
                                self._create_vulnerability(
                                    file_path=file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    code_snippet=self._get_source_line(source_code, node.lineno),
                                    description="os.path.join() 的参数可能来自用户输入，如果包含 '../' 可导致路径遍历",
                                    suggestion="在拼接前使用os.path.basename()清理用户输入；"
                                    "拼接后使用os.path.realpath()验证最终路径是否在允许的目录内",
                                )
                            )
                            break

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

    def _is_user_controlled(self, node) -> bool:
        """
        判断节点是否可能来自用户输入

        这是一个简化的启发式检测，检查参数是否为：
        - 变量引用（Name）
        - 下标访问（Subscript）
        - 属性访问（Attribute）
        - 函数调用结果（Call）
        - 二元操作（BinOp，如字符串拼接）

        如果是常量字符串，则认为是安全的
        """
        if isinstance(node, ast.Constant):
            # 常量字符串是安全的
            return False
        elif isinstance(node, ast.Name):
            # 变量引用可能来自用户输入
            return True
        elif isinstance(node, ast.Subscript):
            # 下标访问（如 request.args['filename']）
            return True
        elif isinstance(node, ast.Attribute):
            # 属性访问（如 request.filename）
            return True
        elif isinstance(node, ast.Call):
            # 函数调用结果
            return True
        elif isinstance(node, ast.BinOp):
            # 二元操作（字符串拼接等）
            return self._is_user_controlled(node.left) or self._is_user_controlled(node.right)
        elif isinstance(node, ast.JoinedStr):
            # f-string
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    return True
            return False

        return False
