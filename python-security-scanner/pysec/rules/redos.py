"""
正则表达式拒绝服务 (ReDoS) 检测规则

检测可能导致灾难性回溯的正则表达式模式，这些模式可能被利用进行DoS攻击
"""

import ast
import re
from typing import List, Optional, Tuple

from .base import BaseRule, register_rule
from ..models import Vulnerability


@register_rule
class ReDoSRule(BaseRule):
    """正则表达式DoS检测规则"""

    rule_id = "REX001"
    rule_name = "正则表达式DoS风险"
    severity = "medium"
    description = "检测可能导致灾难性回溯的正则表达式，可被利用进行DoS攻击"

    # re 模块的编译/匹配函数
    RE_FUNCTIONS = {
        "compile", "match", "search", "findall", "finditer",
        "fullmatch", "split", "sub", "subn",
    }

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        """检查正则表达式DoS风险"""
        vulnerabilities = []

        for node in ast.walk(ast_tree):
            # 检测 re.compile(), re.match() 等调用
            if isinstance(node, ast.Call):
                vuln = self._check_re_call(node, file_path, source_code)
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_re_call(
        self, node: ast.Call, file_path: str, source_code: str
    ) -> Optional[Vulnerability]:
        """检查 re 模块的函数调用"""
        # 检查是否是 re.xxx() 调用
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                if node.func.value.id == "re" and node.func.attr in self.RE_FUNCTIONS:
                    # 获取正则表达式参数
                    pattern = self._extract_pattern(node)
                    if pattern:
                        vuln_info = self._analyze_pattern(pattern)
                        if vuln_info:
                            return self._create_vulnerability(
                                file_path=file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_source_segment(source_code, node),
                                description=vuln_info["description"],
                                suggestion=vuln_info["suggestion"],
                            )

        # 检查是否是直接调用（如果通过 from re import compile）
        elif isinstance(node.func, ast.Name):
            if node.func.id in self.RE_FUNCTIONS:
                pattern = self._extract_pattern(node)
                if pattern:
                    vuln_info = self._analyze_pattern(pattern)
                    if vuln_info:
                        return self._create_vulnerability(
                            file_path=file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_source_segment(source_code, node),
                            description=vuln_info["description"],
                            suggestion=vuln_info["suggestion"],
                        )

        return None

    def _extract_pattern(self, node: ast.Call) -> Optional[str]:
        """从 re 函数调用中提取正则表达式模式"""
        if not node.args:
            return None

        # 第一个参数通常是正则表达式
        pattern_arg = node.args[0]

        # 提取字符串常量
        if isinstance(pattern_arg, ast.Constant) and isinstance(pattern_arg.value, str):
            return pattern_arg.value

        # 提取原始字符串 (Python 3.8+)
        if isinstance(pattern_arg, ast.Str):
            return pattern_arg.s

        return None

    def _analyze_pattern(self, pattern: str) -> Optional[dict]:
        """
        分析正则表达式模式，检测是否存在ReDoS风险

        Returns:
            如果有风险，返回包含 description 和 suggestion 的字典，否则返回 None
        """
        # 检测嵌套量词
        nested_quantifiers = self._detect_nested_quantifiers(pattern)
        if nested_quantifiers:
            return {
                "description": f"检测到嵌套量词 '{nested_quantifiers}'，可能导致灾难性回溯（ReDoS攻击）",
                "suggestion": "避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块",
            }

        # 检测重叠交替
        overlapping = self._detect_overlapping_alternation(pattern)
        if overlapping:
            return {
                "description": f"检测到重叠交替模式 '{overlapping}'，可能导致指数级回溯（ReDoS攻击）",
                "suggestion": "避免交替分支重叠；使用更精确的模式；或使用 regex 库（re2）限制回溯",
            }

        # 检测嵌套量词组合
        nested_combo = self._detect_nested_quantifier_combo(pattern)
        if nested_combo:
            return {
                "description": f"检测到嵌套量词组合 '{nested_combo}'，存在灾难性回溯风险",
                "suggestion": "简化正则表达式结构；避免在量词内部使用量词；考虑使用 re2 或设置 timeout",
            }

        return None

    def _detect_nested_quantifiers(self, pattern: str) -> Optional[str]:
        """
        检测嵌套量词模式，如：
        - (a+)+
        - (a*)*
        - (a+)*
        - (a?)+
        - ([a-z])+  (字符类后接量词)
        """
        # 匹配：(内容+量词)+量词
        nested_patterns = [
            r'\([^()]*[\+\*\?]\)+[\+\*\?]',  # (xxx+)+, (xxx*)*, etc.
            r'\([^()]*\{[0-9,]+\}\)+[\+\*\?]',  # (xxx{1,5})+
            r'\([^()]*[\+\*\?]\)+\{[0-9,]+\}',  # (xxx+){1,5}
            r'\(\[[^\]]+\]\)+[\+\*\?]',  # ([a-z])+, ([0-9])*, etc. 字符类嵌套
        ]

        for nested_pattern in nested_patterns:
            match = re.search(nested_pattern, pattern)
            if match:
                return match.group(0)

        return None

    def _detect_overlapping_alternation(self, pattern: str) -> Optional[str]:
        """
        检测重叠交替模式，如：
        - (a|a)+
        - (a|ab)+
        - (abc|abc)+
        """
        # 简单检测：(xxx|xxx)+ 或 (xxx|yyy)+ 其中 xxx 和 yyy 有共同前缀
        alternation_pattern = r'\(([^|()]+)\|([^|()]+)\)[\+\*]'
        matches = re.finditer(alternation_pattern, pattern)

        for match in matches:
            left = match.group(1)
            right = match.group(2)

            # 检查是否完全相同
            if left == right:
                return match.group(0)

            # 检查是否有共同前缀（简单检测）
            if left and right:
                # 如果一个是另一个的前缀
                if left.startswith(right) or right.startswith(left):
                    return match.group(0)

                # 检查是否有共同的开头字符或模式
                if len(left) > 0 and len(right) > 0 and left[0] == right[0]:
                    # 共同前缀可能导致回溯
                    common_prefix = self._get_common_prefix(left, right)
                    if len(common_prefix) >= 2:  # 至少2个字符的共同前缀
                        return match.group(0)

        return None

    def _detect_nested_quantifier_combo(self, pattern: str) -> Optional[str]:
        """
        检测嵌套量词组合模式，如：
        - (a+)+b
        - (a*)*c
        - (\w+)+
        - (.*)+
        """
        # 检测可能的危险组合
        dangerous_combos = [
            r'\([^()]*\\w[\+\*]\)+',  # (\w+)+
            r'\([^()]*\\d[\+\*]\)+',  # (\d+)+
            r'\([^()]*\.[\+\*]\)+',   # (.*)+
            r'\([^()]*\[.*\][\+\*]\)+',  # ([a-z]+)+
        ]

        for combo_pattern in dangerous_combos:
            match = re.search(combo_pattern, pattern)
            if match:
                return match.group(0)

        return None

    def _get_common_prefix(self, s1: str, s2: str) -> str:
        """获取两个字符串的公共前缀"""
        prefix = []
        for c1, c2 in zip(s1, s2):
            if c1 == c2:
                prefix.append(c1)
            else:
                break
        return ''.join(prefix)
