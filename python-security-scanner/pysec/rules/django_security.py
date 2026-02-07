"""
Django 框架安全检测规则

检测 Django 项目中常见的安全配置问题
"""

import ast
import re
from typing import List, Optional

from .base import BaseRule, register_rule
from ..models import Vulnerability


@register_rule
class DjangoDebugRule(BaseRule):
    """Django DEBUG 模式检测"""

    rule_id = "DJG001"
    rule_name = "Django DEBUG 模式开启"
    severity = "high"
    description = "检测 DEBUG = True，生产环境不应启用调试模式"

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        """检查 DEBUG = True"""
        vulnerabilities = []

        # 只检查 settings.py 文件
        if not file_path.endswith('settings.py') and 'settings' not in file_path.lower():
            return vulnerabilities

        for node in ast.walk(ast_tree):
            # 检测 DEBUG = True
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "DEBUG":
                        # 检查值是否为 True
                        if isinstance(node.value, ast.Constant) and node.value.value is True:
                            vuln = self._create_vulnerability(
                                file_path=file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_source_segment(source_code, node),
                                description="检测到 DEBUG = True，生产环境启用调试模式会泄露敏感信息",
                                suggestion="在生产环境设置 DEBUG = False；使用环境变量控制：DEBUG = os.getenv('DEBUG', 'False') == 'True'",
                            )
                            vulnerabilities.append(vuln)

        return vulnerabilities


@register_rule
class DjangoSecretKeyRule(BaseRule):
    """Django SECRET_KEY 硬编码检测"""

    rule_id = "DJG002"
    rule_name = "Django SECRET_KEY 硬编码"
    severity = "critical"
    description = "检测 SECRET_KEY 硬编码在代码中，密钥泄露会导致严重安全问题"

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        """检查 SECRET_KEY 硬编码"""
        vulnerabilities = []

        # 只检查 settings.py 文件
        if not file_path.endswith('settings.py') and 'settings' not in file_path.lower():
            return vulnerabilities

        for node in ast.walk(ast_tree):
            # 检测 SECRET_KEY = "..."
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "SECRET_KEY":
                        # 检查是否为硬编码字符串
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            # 检查是否像是真实的密钥（长度 > 20）
                            if len(node.value.value) > 20:
                                vuln = self._create_vulnerability(
                                    file_path=file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    code_snippet=self._get_source_segment(source_code, node),
                                    description="检测到 SECRET_KEY 硬编码在代码中，密钥泄露会导致会话伪造、CSRF 绕过等严重问题",
                                    suggestion="使用环境变量存储密钥：SECRET_KEY = os.environ.get('SECRET_KEY')；或使用 python-decouple、django-environ 等库管理配置",
                                )
                                vulnerabilities.append(vuln)

        return vulnerabilities


@register_rule
class DjangoAllowedHostsRule(BaseRule):
    """Django ALLOWED_HOSTS 配置检测"""

    rule_id = "DJG003"
    rule_name = "Django ALLOWED_HOSTS 配置不当"
    severity = "high"
    description = "检测 ALLOWED_HOSTS = ['*']，允许所有主机访问存在安全风险"

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        """检查 ALLOWED_HOSTS 配置"""
        vulnerabilities = []

        # 只检查 settings.py 文件
        if not file_path.endswith('settings.py') and 'settings' not in file_path.lower():
            return vulnerabilities

        for node in ast.walk(ast_tree):
            # 检测 ALLOWED_HOSTS = [...]
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "ALLOWED_HOSTS":
                        # 检查是否包含 '*'
                        if isinstance(node.value, ast.List):
                            for elt in node.value.elts:
                                if isinstance(elt, ast.Constant) and elt.value == '*':
                                    vuln = self._create_vulnerability(
                                        file_path=file_path,
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        code_snippet=self._get_source_segment(source_code, node),
                                        description="检测到 ALLOWED_HOSTS = ['*']，允许任意主机名访问，可能遭受 Host Header 攻击",
                                        suggestion="明确指定允许的主机名：ALLOWED_HOSTS = ['example.com', 'www.example.com']；或使用环境变量配置",
                                    )
                                    vulnerabilities.append(vuln)
                                    break  # 只报告一次

        return vulnerabilities


@register_rule
class DjangoCSRFRule(BaseRule):
    """Django CSRF 保护检测"""

    rule_id = "DJG004"
    rule_name = "Django CSRF 保护禁用"
    severity = "high"
    description = "检测 CSRF 保护被禁用或绕过"

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        """检查 CSRF 保护"""
        vulnerabilities = []

        for node in ast.walk(ast_tree):
            # 检测 @csrf_exempt 装饰器
            if isinstance(node, ast.FunctionDef):
                for decorator in node.decorator_list:
                    decorator_name = None
                    
                    if isinstance(decorator, ast.Name):
                        decorator_name = decorator.id
                    elif isinstance(decorator, ast.Attribute):
                        decorator_name = decorator.attr
                    
                    if decorator_name == "csrf_exempt":
                        vuln = self._create_vulnerability(
                            file_path=file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_source_segment(source_code, node),
                            description=f"视图函数 '{node.name}' 使用 @csrf_exempt 装饰器，禁用了 CSRF 保护",
                            suggestion="避免使用 @csrf_exempt；如必须禁用，确保实现其他安全机制（如自定义 token 验证）",
                        )
                        vulnerabilities.append(vuln)

            # 检测 MIDDLEWARE 中移除 CsrfViewMiddleware
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "MIDDLEWARE":
                        # 检查是否为列表
                        if isinstance(node.value, ast.List):
                            has_csrf = False
                            for elt in node.value.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    if 'CsrfViewMiddleware' in elt.value:
                                        has_csrf = True
                                        break
                            
                            # 如果没有找到 CSRF 中间件（且列表不为空）
                            if not has_csrf and len(node.value.elts) > 0:
                                # 只在 settings.py 中报告
                                if file_path.endswith('settings.py') or 'settings' in file_path.lower():
                                    vuln = self._create_vulnerability(
                                        file_path=file_path,
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        code_snippet=self._get_source_segment(source_code, node),
                                        description="MIDDLEWARE 配置中未找到 CsrfViewMiddleware，CSRF 保护可能被禁用",
                                        suggestion="确保在 MIDDLEWARE 中包含 'django.middleware.csrf.CsrfViewMiddleware'",
                                    )
                                    vulnerabilities.append(vuln)

        return vulnerabilities


@register_rule
class DjangoRawSQLRule(BaseRule):
    """Django 原始 SQL 查询检测"""

    rule_id = "DJG005"
    rule_name = "Django 不安全的原始 SQL 查询"
    severity = "high"
    description = "检测使用 raw()、extra()、RawSQL() 等原始 SQL 查询，可能存在 SQL 注入风险"

    # 危险的 Django ORM 方法
    DANGEROUS_ORM_METHODS = {
        "raw",       # Model.objects.raw(sql)
        "extra",     # QuerySet.extra(...)
        "RawSQL",    # django.db.models.expressions.RawSQL
    }

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        """检查原始 SQL 查询"""
        vulnerabilities = []

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                # 检测 Model.objects.raw() 或 queryset.raw()
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in self.DANGEROUS_ORM_METHODS:
                        # 检查 SQL 参数是否包含字符串拼接
                        is_dangerous = False
                        description = ""
                        
                        if node.args:
                            sql_arg = node.args[0]
                            
                            # 检查是否使用字符串格式化
                            if isinstance(sql_arg, (ast.BinOp, ast.JoinedStr)):
                                is_dangerous = True
                                description = f"调用 {node.func.attr}() 时使用字符串拼接构造 SQL，存在 SQL 注入风险"
                            
                            # 检查是否使用 .format()
                            elif isinstance(sql_arg, ast.Call):
                                if isinstance(sql_arg.func, ast.Attribute) and sql_arg.func.attr == "format":
                                    is_dangerous = True
                                    description = f"调用 {node.func.attr}() 时使用 .format() 构造 SQL，存在 SQL 注入风险"
                            
                            # 检查是否直接使用变量（可能不安全）
                            elif isinstance(sql_arg, ast.Name):
                                # 警告级别：使用变量可能不安全
                                is_dangerous = True
                                description = f"调用 {node.func.attr}() 使用原始 SQL 查询，确保使用参数化查询防止 SQL 注入"
                        
                        # 即使没有参数，使用 raw/extra 也需要警告
                        if not is_dangerous and node.func.attr in ["raw", "extra", "RawSQL"]:
                            is_dangerous = True
                            description = f"使用 {node.func.attr}() 执行原始 SQL 查询，可能存在安全风险"
                        
                        if is_dangerous:
                            vuln = self._create_vulnerability(
                                file_path=file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_source_segment(source_code, node),
                                description=description,
                                suggestion="使用 Django ORM 的查询方法避免原始 SQL；如必须使用，确保使用参数化查询：raw('SELECT * FROM table WHERE id = %s', [user_id])",
                            )
                            vulnerabilities.append(vuln)

        return vulnerabilities
