"""Flask 框架安全检测规则

检测 Flask Web 应用中的常见安全问题：
- FLK001: 检测 debug=True 配置
- FLK002: 检测 SECRET_KEY 硬编码
- FLK003: 检测不安全的 session 配置
- FLK004: 检测 Jinja2 模板注入风险
- FLK005: 检测不安全的文件上传
"""

import ast
import re
from typing import List, Optional
from ..models import Vulnerability
from .base import BaseRule, register_rule


@register_rule
class FlaskDebugRule(BaseRule):
    """检测 Flask Debug 模式"""
    
    rule_id = "FLK001"
    rule_name = "Flask Debug 模式启用"
    severity = "high"
    description = "Flask 应用在生产环境中启用了 debug 模式，可能泄露敏感信息"
    
    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        for node in ast.walk(ast_tree):
            # 检测 app.run(debug=True)
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == 'run':
                    for keyword in node.keywords:
                        if (keyword.arg == 'debug' and 
                            isinstance(keyword.value, ast.Constant) and 
                            keyword.value.value is True):
                            vuln = self._create_vulnerability(
                                file_path=file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_source_segment(source_code, node),
                                description="Flask 应用使用 app.run(debug=True) 启动，在生产环境中存在安全风险",
                                suggestion="在生产环境中禁用 debug 模式；使用环境变量控制：app.run(debug=os.getenv('FLASK_DEBUG', False))"
                            )
                            vulnerabilities.append(vuln)
            
            # 检测 app.debug = True
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if (isinstance(target, ast.Attribute) and 
                        target.attr == 'debug' and
                        isinstance(node.value, ast.Constant) and 
                        node.value.value is True):
                        vuln = self._create_vulnerability(
                            file_path=file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_source_segment(source_code, node),
                            description="Flask 应用设置 app.debug = True，在生产环境中存在安全风险",
                            suggestion="在生产环境中禁用 debug 模式；使用环境变量控制：app.debug = os.getenv('FLASK_DEBUG', False) == 'True'"
                        )
                        vulnerabilities.append(vuln)
            
            # 检测 app.config['DEBUG'] = True
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Subscript):
                        if (isinstance(target.value, ast.Attribute) and 
                            target.value.attr == 'config' and
                            isinstance(target.slice, ast.Constant) and
                            target.slice.value == 'DEBUG' and
                            isinstance(node.value, ast.Constant) and 
                            node.value.value is True):
                            vuln = self._create_vulnerability(
                                file_path=file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_source_segment(source_code, node),
                                description="Flask 配置中设置 DEBUG = True，在生产环境中存在安全风险",
                                suggestion="在生产环境中禁用 debug 模式；使用环境变量：app.config['DEBUG'] = os.getenv('FLASK_DEBUG', False) == 'True'"
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities


@register_rule
class FlaskSecretKeyRule(BaseRule):
    """检测 Flask SECRET_KEY 硬编码"""
    
    rule_id = "FLK002"
    rule_name = "Flask SECRET_KEY 硬编码"
    severity = "critical"
    description = "Flask SECRET_KEY 被硬编码在代码中，可能导致 session 被伪造"
    
    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        for node in ast.walk(ast_tree):
            # 检测 app.config['SECRET_KEY'] = 'hardcoded-value'
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Subscript):
                        if (isinstance(target.value, ast.Attribute) and 
                            target.value.attr == 'config' and
                            isinstance(target.slice, ast.Constant) and
                            target.slice.value == 'SECRET_KEY'):
                            # 检查是否是硬编码的字符串
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                vuln = self._create_vulnerability(
                                    file_path=file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    code_snippet=self._get_source_segment(source_code, node),
                                    description="Flask SECRET_KEY 被硬编码为字符串常量，存在安全风险",
                                    suggestion="使用环境变量存储 SECRET_KEY：app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')"
                                )
                                vulnerabilities.append(vuln)
            
            # 检测 app.secret_key = 'hardcoded-value'
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (isinstance(target, ast.Attribute) and 
                        target.attr == 'secret_key'):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            vuln = self._create_vulnerability(
                                file_path=file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_source_segment(source_code, node),
                                description="Flask secret_key 被硬编码为字符串常量，存在安全风险",
                                suggestion="使用环境变量存储 SECRET_KEY：app.secret_key = os.environ.get('SECRET_KEY')"
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities


@register_rule
class FlaskSessionConfigRule(BaseRule):
    """检测 Flask Session 配置"""
    
    rule_id = "FLK003"
    rule_name = "Flask Session 配置不安全"
    severity = "high"
    description = "Flask session 配置不安全"
    
    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Subscript):
                        if (isinstance(target.value, ast.Attribute) and 
                            target.value.attr == 'config' and
                            isinstance(target.slice, ast.Constant)):
                            
                            config_key = target.slice.value
                            
                            # 检测 SESSION_COOKIE_SECURE = False
                            if config_key == 'SESSION_COOKIE_SECURE':
                                if isinstance(node.value, ast.Constant) and node.value.value is False:
                                    vuln = self._create_vulnerability(
                                        file_path=file_path,
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        code_snippet=self._get_source_segment(source_code, node),
                                        description="SESSION_COOKIE_SECURE 设置为 False，cookie 可能通过非 HTTPS 传输",
                                        suggestion="设置 SESSION_COOKIE_SECURE = True 确保 cookie 仅通过 HTTPS 传输"
                                    )
                                    vulnerabilities.append(vuln)
                            
                            # 检测 SESSION_COOKIE_HTTPONLY = False
                            elif config_key == 'SESSION_COOKIE_HTTPONLY':
                                if isinstance(node.value, ast.Constant) and node.value.value is False:
                                    vuln = self._create_vulnerability(
                                        file_path=file_path,
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        code_snippet=self._get_source_segment(source_code, node),
                                        description="SESSION_COOKIE_HTTPONLY 设置为 False，cookie 可被 JavaScript 访问",
                                        suggestion="设置 SESSION_COOKIE_HTTPONLY = True 防止 XSS 攻击窃取 cookie"
                                    )
                                    vulnerabilities.append(vuln)
                            
                            # 检测 SESSION_COOKIE_SAMESITE = None
                            elif config_key == 'SESSION_COOKIE_SAMESITE':
                                if isinstance(node.value, ast.Constant):
                                    if node.value.value is None or node.value.value == 'None':
                                        vuln = self._create_vulnerability(
                                            file_path=file_path,
                                            line_number=node.lineno,
                                            column=node.col_offset,
                                            code_snippet=self._get_source_segment(source_code, node),
                                            description="SESSION_COOKIE_SAMESITE 未设置或设置为 None，可能受到 CSRF 攻击",
                                            suggestion="设置 SESSION_COOKIE_SAMESITE = 'Lax' 或 'Strict' 防止 CSRF 攻击"
                                        )
                                        vulnerabilities.append(vuln)
        
        return vulnerabilities


@register_rule
class FlaskTemplateInjectionRule(BaseRule):
    """检测 Jinja2 模板注入"""
    
    rule_id = "FLK004"
    rule_name = "Flask Jinja2 模板注入风险"
    severity = "high"
    description = "使用用户输入直接渲染模板，可能导致 SSTI"
    
    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        for node in ast.walk(ast_tree):
            # 检测 render_template_string() 调用
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == 'render_template_string':
                    # 检查是否使用了字符串拼接或格式化
                    if node.args:
                        template_arg = node.args[0]
                        is_dangerous = False
                        
                        # 检测 f-string
                        if isinstance(template_arg, ast.JoinedStr):
                            is_dangerous = True
                        # 检测字符串拼接
                        elif isinstance(template_arg, ast.BinOp) and isinstance(template_arg.op, ast.Add):
                            is_dangerous = True
                        # 检测 .format()
                        elif isinstance(template_arg, ast.Call):
                            if isinstance(template_arg.func, ast.Attribute) and template_arg.func.attr == 'format':
                                is_dangerous = True
                        # 检测变量直接传入
                        elif isinstance(template_arg, ast.Name):
                            is_dangerous = True
                        
                        if is_dangerous:
                            vuln = self._create_vulnerability(
                                file_path=file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_source_segment(source_code, node),
                                description="使用 render_template_string() 渲染动态模板内容，可能导致 SSTI 攻击",
                                suggestion="避免使用 render_template_string() 渲染用户输入；使用模板文件和自动转义"
                            )
                            vulnerabilities.append(vuln)
                
                # 检测 Markup() 包装用户输入
                elif isinstance(node.func, ast.Name) and node.func.id == 'Markup':
                    if node.args:
                        vuln = self._create_vulnerability(
                            file_path=file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_source_segment(source_code, node),
                            description="使用 Markup() 标记内容为安全 HTML，如果包含用户输入可能导致 XSS",
                            suggestion="确保 Markup() 中的内容已经过充分验证和过滤"
                        )
                        vuln.severity = "medium"
                        vulnerabilities.append(vuln)
        
        return vulnerabilities


@register_rule
class FlaskFileUploadRule(BaseRule):
    """检测 Flask 文件上传"""
    
    rule_id = "FLK005"
    rule_name = "Flask 不安全的文件上传"
    severity = "high"
    description = "文件上传未进行充分的安全验证"
    
    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        # 遍历所有函数定义
        for func_node in ast.walk(ast_tree):
            if isinstance(func_node, ast.FunctionDef):
                # 检查函数中是否使用了 request.files
                has_file_upload = self._has_file_upload(func_node)
                
                if has_file_upload:
                    # 检查是否使用了 secure_filename
                    has_secure_filename = self._has_secure_filename(func_node)
                    # 检查是否有扩展名验证
                    has_extension_check = self._has_extension_check(func_node)
                    
                    if not has_secure_filename:
                        vuln = self._create_vulnerability(
                            file_path=file_path,
                            line_number=func_node.lineno,
                            column=func_node.col_offset,
                            code_snippet=self._get_source_segment(source_code, func_node, context_lines=2),
                            description=f"函数 '{func_node.name}' 处理文件上传但未使用 secure_filename() 清理文件名",
                            suggestion="使用 werkzeug.utils.secure_filename() 清理文件名"
                        )
                        vulnerabilities.append(vuln)
                    
                    if not has_extension_check:
                        vuln = self._create_vulnerability(
                            file_path=file_path,
                            line_number=func_node.lineno,
                            column=func_node.col_offset,
                            code_snippet=self._get_source_segment(source_code, func_node, context_lines=2),
                            description=f"函数 '{func_node.name}' 处理文件上传但未验证文件扩展名",
                            suggestion="验证文件扩展名白名单；检查 MIME 类型；限制文件大小"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _has_file_upload(self, func_node: ast.FunctionDef) -> bool:
        """检查函数中是否使用了 request.files"""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Attribute):
                if (isinstance(node.value, ast.Name) and 
                    node.value.id == 'request' and 
                    node.attr == 'files'):
                    return True
        return False
    
    def _has_secure_filename(self, func_node: ast.FunctionDef) -> bool:
        """检查函数中是否使用了 secure_filename"""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == 'secure_filename':
                    return True
        return False
    
    def _has_extension_check(self, func_node: ast.FunctionDef) -> bool:
        """检查函数中是否有文件扩展名验证"""
        func_code = ast.unparse(func_node)
        # 简单检查是否包含扩展名相关的验证逻辑
        extension_patterns = [
            r'\.filename\..*\.',
            r'ALLOWED.*EXT',
            r'allowed.*ext',
            r'\.rsplit\(',
            r'splitext\(',
        ]
        return any(re.search(pattern, func_code, re.IGNORECASE) for pattern in extension_patterns)
