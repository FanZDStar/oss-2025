"""
XXE (XML外部实体注入) 检测规则

检测不安全的XML解析配置，可能导致外部实体注入攻击
"""

import ast
from typing import List

from .base import BaseRule, register_rule
from ..models import Vulnerability


@register_rule
class XXERule(BaseRule):
    """XXE检测规则"""

    rule_id = "XXE001"
    rule_name = "XML外部实体注入风险"
    severity = "high"
    description = "检测不安全的XML解析，可能导致XXE攻击"

    # xml.etree.ElementTree 的危险函数
    ET_DANGEROUS_FUNCS = {"parse", "fromstring", "iterparse", "XMLParser"}

    # lxml 的危险函数
    LXML_DANGEROUS_FUNCS = {"parse", "fromstring", "XML", "HTML"}

    # xml.sax 的危险函数
    SAX_DANGEROUS_FUNCS = {"parse", "parseString", "make_parser"}

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        vulnerabilities = []

        for node in ast.walk(ast_tree):
            vuln = None

            if isinstance(node, ast.Call):
                # 检测 xml.etree.ElementTree 调用
                vuln = self._check_elementtree_call(node, file_path, source_code)

                # 检测 lxml 调用
                if not vuln:
                    vuln = self._check_lxml_call(node, file_path, source_code)

                # 检测 xml.sax 调用
                if not vuln:
                    vuln = self._check_sax_call(node, file_path, source_code)

            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_elementtree_call(
        self, node: ast.Call, file_path: str, source_code: str
    ) -> Vulnerability:
        """检测 xml.etree.ElementTree 的不安全调用"""
        func_name = None
        is_et_call = False

        # 检查 ET.parse() / ElementTree.parse() 形式
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                # ET.parse() 或 ElementTree.parse()
                if node.func.value.id in ("ET", "ElementTree", "etree"):
                    is_et_call = True
            elif isinstance(node.func.value, ast.Attribute):
                # xml.etree.ElementTree.parse()
                if node.func.value.attr == "ElementTree":
                    is_et_call = True

        # 检查直接导入的函数调用 parse() / fromstring()
        elif isinstance(node.func, ast.Name):
            if node.func.id in self.ET_DANGEROUS_FUNCS:
                func_name = node.func.id
                # 这里假设直接调用的parse/fromstring来自ET模块（需要进一步分析导入）
                is_et_call = True

        if not is_et_call or func_name not in self.ET_DANGEROUS_FUNCS:
            return None

        return self._create_vulnerability(
            file_path=file_path,
            line_number=node.lineno,
            column=node.col_offset,
            code_snippet=self._get_source_line(source_code, node.lineno),
            description=f"使用 xml.etree.ElementTree.{func_name}() 解析XML，默认配置存在XXE风险",
            suggestion="建议使用 defusedxml 库代替标准库解析XML。例如: import defusedxml.ElementTree as ET",
            severity=self.severity,
        )

    def _check_lxml_call(self, node: ast.Call, file_path: str, source_code: str) -> Vulnerability:
        """检测 lxml 的不安全调用"""
        func_name = None
        is_lxml_call = False

        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

            # 检查 etree.parse() / etree.fromstring() 形式
            if isinstance(node.func.value, ast.Name):
                if node.func.value.id == "etree":
                    is_lxml_call = True
            # 检查 lxml.etree.parse() 形式
            elif isinstance(node.func.value, ast.Attribute):
                if node.func.value.attr == "etree":
                    if isinstance(node.func.value.value, ast.Name):
                        if node.func.value.value.id == "lxml":
                            is_lxml_call = True

        if not is_lxml_call or func_name not in self.LXML_DANGEROUS_FUNCS:
            return None

        # 检查是否有安全参数配置
        has_safe_config = self._check_lxml_safe_config(node)
        if has_safe_config:
            return None

        return self._create_vulnerability(
            file_path=file_path,
            line_number=node.lineno,
            column=node.col_offset,
            code_snippet=self._get_source_line(source_code, node.lineno),
            description=f"使用 lxml.etree.{func_name}() 解析XML，可能存在XXE风险",
            suggestion="建议使用 defusedxml 库，或配置 lxml 禁用外部实体: parser = etree.XMLParser(resolve_entities=False)",
            severity=self.severity,
        )

    def _check_lxml_safe_config(self, node: ast.Call) -> bool:
        """检查 lxml 是否配置了安全选项"""
        for keyword in node.keywords:
            # 检查 resolve_entities=False
            if keyword.arg == "resolve_entities":
                if isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is False:
                        return True
            # 检查 no_network=True
            if keyword.arg == "no_network":
                if isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is True:
                        return True
        return False

    def _check_sax_call(self, node: ast.Call, file_path: str, source_code: str) -> Vulnerability:
        """检测 xml.sax 的不安全调用"""
        func_name = None
        is_sax_call = False

        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            # 检查 sax.parse() / sax.parseString() 形式
            if isinstance(node.func.value, ast.Name):
                if node.func.value.id == "sax":
                    is_sax_call = True
            # 检查 xml.sax.parse() 形式
            elif isinstance(node.func.value, ast.Attribute):
                if node.func.value.attr == "sax":
                    if isinstance(node.func.value.value, ast.Name):
                        if node.func.value.value.id == "xml":
                            is_sax_call = True

        # 检查直接导入的函数调用
        elif isinstance(node.func, ast.Name):
            if node.func.id in self.SAX_DANGEROUS_FUNCS:
                func_name = node.func.id
                is_sax_call = True

        if not is_sax_call or func_name not in self.SAX_DANGEROUS_FUNCS:
            return None

        return self._create_vulnerability(
            file_path=file_path,
            line_number=node.lineno,
            column=node.col_offset,
            code_snippet=self._get_source_line(source_code, node.lineno),
            description=f"使用 xml.sax.{func_name}() 解析XML，默认配置存在XXE风险",
            suggestion="建议使用 defusedxml.sax 代替标准库。例如: from defusedxml import sax",
            severity=self.severity,
        )
