"""
代码修复器模块

提供自动修复功能和修复建议生成
"""

import difflib
import re
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Type

from .models import Vulnerability, FixResult


# 修复模式注册表
FIX_PATTERN_REGISTRY: Dict[str, Type["FixPattern"]] = {}


def register_fix_pattern(pattern_class):
    """
    修复模式注册装饰器

    使用方法:
        @register_fix_pattern
        class MyFixPattern(FixPattern):
            rule_id = "MY001"
            ...
    """
    if hasattr(pattern_class, "rule_id") and pattern_class.rule_id:
        FIX_PATTERN_REGISTRY[pattern_class.rule_id] = pattern_class
    return pattern_class


class FixPattern(ABC):
    """
    修复模式基类

    每个规则可以有一个对应的修复模式，定义如何修复该类型的漏洞
    """

    rule_id: str = ""  # 对应的规则ID
    risk_level: str = "high"  # 修复风险等级: low/medium/high
    auto_fixable: bool = False  # 是否支持自动修复

    @abstractmethod
    def can_fix(self, vuln: Vulnerability, source_code: str) -> bool:
        """
        判断是否可以修复该漏洞

        Args:
            vuln: 漏洞对象
            source_code: 完整源代码

        Returns:
            是否可以修复
        """
        pass

    @abstractmethod
    def generate_fix(self, vuln: Vulnerability, source_code: str) -> Optional[str]:
        """
        生成修复后的代码

        Args:
            vuln: 漏洞对象
            source_code: 完整源代码

        Returns:
            修复后的完整源代码，如果无法修复返回None
        """
        pass

    @abstractmethod
    def get_fix_example(self, vuln: Vulnerability) -> str:
        """
        获取修复示例代码

        Args:
            vuln: 漏洞对象

        Returns:
            修复示例代码字符串
        """
        pass


# ============================================================================
# 具体规则的修复模式实现
# ============================================================================


@register_fix_pattern
class HardcodedSecretFixPattern(FixPattern):
    """硬编码凭据修复模式 (SEC001)"""

    rule_id = "SEC001"
    risk_level = "low"
    auto_fixable = True

    def can_fix(self, vuln: Vulnerability, source_code: str) -> bool:
        """检查是否可以修复硬编码凭据"""
        # 检查是否是简单的变量赋值
        code = vuln.code_snippet.strip()
        # 支持 VAR = "value" 格式
        if re.match(r'^[\w_]+\s*=\s*["\'].*["\']', code):
            return True
        return False

    def generate_fix(self, vuln: Vulnerability, source_code: str) -> Optional[str]:
        """生成修复后的代码"""
        if not self.can_fix(vuln, source_code):
            return None

        lines = source_code.split("\n")
        line_idx = vuln.line_number - 1

        if line_idx >= len(lines):
            return None

        original_line = lines[line_idx]

        # 解析变量名
        match = re.match(r'^(\s*)([\w_]+)(\s*)([:=])(\s*)["\'](.+)["\'](.*)$', original_line)
        if not match:
            return None

        indent = match.group(1)
        var_name = match.group(2)
        space1 = match.group(3)
        operator = match.group(4)
        space2 = match.group(5)
        # value = match.group(6)  # 原始值不需要
        rest = match.group(7)

        # 生成环境变量名
        env_var_name = var_name.upper()

        # 生成修复后的行
        fixed_line = f'{indent}{var_name}{space1}{operator}{space2}os.environ.get("{env_var_name}", ""){rest}'

        # 替换原始行
        lines[line_idx] = fixed_line

        # 检查是否需要添加 os 导入
        fixed_source = "\n".join(lines)
        if "import os" not in fixed_source and "from os import" not in fixed_source:
            # 在文件开头添加 import os
            fixed_source = "import os\n" + fixed_source

        return fixed_source

    def get_fix_example(self, vuln: Vulnerability) -> str:
        """获取硬编码凭据的修复示例"""
        code = vuln.code_snippet.strip()
        match = re.match(r'^([\w_]+)\s*=\s*["\'].*["\']', code)
        if match:
            var_name = match.group(1)
            env_var_name = var_name.upper()
            return f'''# 修复前 (不安全):
{code}

# 修复后 (安全):
import os
{var_name} = os.environ.get("{env_var_name}", "")

# 或使用 python-dotenv:
from dotenv import load_dotenv
load_dotenv()
{var_name} = os.environ.get("{env_var_name}")'''
        return ""


@register_fix_pattern
class SQLInjectionFixPattern(FixPattern):
    """SQL注入修复模式 (SQL001)"""

    rule_id = "SQL001"
    risk_level = "high"
    auto_fixable = False  # 高风险，不自动修复

    def can_fix(self, vuln: Vulnerability, source_code: str) -> bool:
        """SQL注入通常需要手动修复，只提供示例"""
        return False

    def generate_fix(self, vuln: Vulnerability, source_code: str) -> Optional[str]:
        """不自动修复SQL注入"""
        return None

    def get_fix_example(self, vuln: Vulnerability) -> str:
        """获取SQL注入的修复示例"""
        return '''# 修复前 (不安全 - SQL注入风险):
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# 修复后 (安全 - 参数化查询):
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))

# 或使用 ORM (推荐):
user = User.objects.get(id=user_id)  # Django ORM
user = session.query(User).filter_by(id=user_id).first()  # SQLAlchemy'''


@register_fix_pattern
class CommandInjectionFixPattern(FixPattern):
    """命令注入修复模式 (CMD001)"""

    rule_id = "CMD001"
    risk_level = "high"
    auto_fixable = False

    def can_fix(self, vuln: Vulnerability, source_code: str) -> bool:
        return False

    def generate_fix(self, vuln: Vulnerability, source_code: str) -> Optional[str]:
        return None

    def get_fix_example(self, vuln: Vulnerability) -> str:
        return '''# 修复前 (不安全 - 命令注入风险):
import os
os.system(f"ping {host}")

# 修复后 (安全 - 使用参数列表):
import subprocess
subprocess.run(["ping", host], shell=False, check=True)

# 或使用 shlex 进行安全处理:
import shlex
import subprocess
subprocess.run(shlex.split(f"ping {shlex.quote(host)}"), check=True)'''


@register_fix_pattern
class DangerousFunctionFixPattern(FixPattern):
    """危险函数修复模式 (DNG001)"""

    rule_id = "DNG001"
    risk_level = "high"
    auto_fixable = False

    def can_fix(self, vuln: Vulnerability, source_code: str) -> bool:
        return False

    def generate_fix(self, vuln: Vulnerability, source_code: str) -> Optional[str]:
        return None

    def get_fix_example(self, vuln: Vulnerability) -> str:
        code = vuln.code_snippet.strip()
        if "eval" in code:
            return '''# 修复前 (不安全 - eval 风险):
result = eval(user_input)

# 修复后 (安全 - 使用 ast.literal_eval):
import ast
result = ast.literal_eval(user_input)  # 只允许字面量

# 或使用专门的解析器:
import json
result = json.loads(user_input)  # 解析 JSON'''
        elif "exec" in code:
            return '''# 修复前 (不安全 - exec 风险):
exec(code_string)

# 修复后 (安全 - 避免使用 exec):
# 考虑使用更安全的设计模式，如：
# 1. 使用配置文件而非动态执行代码
# 2. 使用白名单机制限制可执行的操作
# 3. 使用沙箱环境（如 RestrictedPython）'''
        elif "pickle" in code:
            return '''# 修复前 (不安全 - pickle 反序列化风险):
import pickle
data = pickle.loads(user_data)

# 修复后 (安全 - 使用 JSON):
import json
data = json.loads(user_data)

# 如果必须使用 pickle，使用安全的签名验证:
import hmac
import hashlib
# 验证签名后再反序列化'''
        return '''# 危险函数使用建议:
# 1. 避免使用 eval、exec、pickle 等危险函数
# 2. 使用安全的替代方案
# 3. 如必须使用，严格验证输入'''


@register_fix_pattern
class PathTraversalFixPattern(FixPattern):
    """路径遍历修复模式 (PTH001)"""

    rule_id = "PTH001"
    risk_level = "medium"
    auto_fixable = False

    def can_fix(self, vuln: Vulnerability, source_code: str) -> bool:
        return False

    def generate_fix(self, vuln: Vulnerability, source_code: str) -> Optional[str]:
        return None

    def get_fix_example(self, vuln: Vulnerability) -> str:
        return '''# 修复前 (不安全 - 路径遍历风险):
with open(user_filename, 'r') as f:
    content = f.read()

# 修复后 (安全 - 路径验证):
import os
from pathlib import Path

SAFE_DIR = Path("/app/uploads").resolve()

def safe_open(filename):
    """安全地打开文件，防止路径遍历"""
    # 规范化路径
    file_path = (SAFE_DIR / filename).resolve()
    
    # 确保路径在安全目录内
    if not str(file_path).startswith(str(SAFE_DIR)):
        raise ValueError("非法路径")
    
    return open(file_path, 'r')

content = safe_open(user_filename).read()'''


@register_fix_pattern
class XSSFixPattern(FixPattern):
    """XSS修复模式 (XSS001)"""

    rule_id = "XSS001"
    risk_level = "medium"
    auto_fixable = False

    def can_fix(self, vuln: Vulnerability, source_code: str) -> bool:
        return False

    def generate_fix(self, vuln: Vulnerability, source_code: str) -> Optional[str]:
        return None

    def get_fix_example(self, vuln: Vulnerability) -> str:
        return '''# 修复前 (不安全 - XSS 风险):
html = f"<div>{user_input}</div>"

# 修复后 (安全 - HTML 转义):
import html
safe_input = html.escape(user_input)
html_content = f"<div>{safe_input}</div>"

# Flask 中使用 Markup:
from markupsafe import escape
html_content = f"<div>{escape(user_input)}</div>"

# Jinja2 模板自动转义:
# {{ user_input }}  # 默认自动转义'''


@register_fix_pattern
class InsecureRandomFixPattern(FixPattern):
    """不安全随机数修复模式 (RND001)"""

    rule_id = "RND001"
    risk_level = "medium"
    auto_fixable = False

    def can_fix(self, vuln: Vulnerability, source_code: str) -> bool:
        return False

    def generate_fix(self, vuln: Vulnerability, source_code: str) -> Optional[str]:
        return None

    def get_fix_example(self, vuln: Vulnerability) -> str:
        return '''# 修复前 (不安全 - 使用random生成token):
import random
import string
token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

# 修复后 (安全 - 使用secrets模块):
import secrets

# 生成URL安全的token
token = secrets.token_urlsafe(32)

# 生成十六进制token
token = secrets.token_hex(32)

# 安全的随机选择
item = secrets.choice(items)

# 生成安全的随机整数
number = secrets.randbelow(100)'''


@register_fix_pattern
class InsecureHashFixPattern(FixPattern):
    """不安全哈希算法修复模式 (HSH001)"""

    rule_id = "HSH001"
    risk_level = "medium"
    auto_fixable = False

    def can_fix(self, vuln: Vulnerability, source_code: str) -> bool:
        return False

    def generate_fix(self, vuln: Vulnerability, source_code: str) -> Optional[str]:
        return None

    def get_fix_example(self, vuln: Vulnerability) -> str:
        return '''# 修复前 (不安全 - 使用MD5/SHA1哈希密码):
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# 修复后 (安全 - 使用bcrypt):
import bcrypt
# 哈希密码
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
# 验证密码
if bcrypt.checkpw(password.encode(), stored_hash):
    print("密码正确")

# 或使用 argon2 (更现代):
from argon2 import PasswordHasher
ph = PasswordHasher()
password_hash = ph.hash(password)
try:
    ph.verify(stored_hash, password)
except argon2.exceptions.VerifyMismatchError:
    print("密码错误")

# 或使用 passlib (多算法支持):
from passlib.hash import pbkdf2_sha256
password_hash = pbkdf2_sha256.hash(password)
if pbkdf2_sha256.verify(password, stored_hash):
    print("密码正确")'''


# ============================================================================
# 代码修复器
# ============================================================================


class CodeFixer:
    """
    代码修复器

    提供漏洞修复、diff生成等功能
    """

    def __init__(self):
        """初始化修复器"""
        self.fix_patterns: Dict[str, FixPattern] = {}
        self._load_fix_patterns()

    def _load_fix_patterns(self):
        """加载所有修复模式"""
        for rule_id, pattern_class in FIX_PATTERN_REGISTRY.items():
            self.fix_patterns[rule_id] = pattern_class()

    def get_fix_pattern(self, rule_id: str) -> Optional[FixPattern]:
        """获取指定规则的修复模式"""
        return self.fix_patterns.get(rule_id)

    def can_fix(self, vuln: Vulnerability, source_code: str) -> bool:
        """检查漏洞是否可以自动修复"""
        pattern = self.get_fix_pattern(vuln.rule_id)
        if pattern and pattern.auto_fixable:
            return pattern.can_fix(vuln, source_code)
        return False

    def generate_fix(
        self, vuln: Vulnerability, source_code: str
    ) -> Optional[str]:
        """
        生成修复后的代码

        Args:
            vuln: 漏洞对象
            source_code: 完整源代码

        Returns:
            修复后的源代码，如果无法修复返回None
        """
        pattern = self.get_fix_pattern(vuln.rule_id)
        if pattern:
            return pattern.generate_fix(vuln, source_code)
        return None

    def get_fix_example(self, vuln: Vulnerability) -> str:
        """
        获取修复示例

        Args:
            vuln: 漏洞对象

        Returns:
            修复示例代码
        """
        pattern = self.get_fix_pattern(vuln.rule_id)
        if pattern:
            return pattern.get_fix_example(vuln)
        return ""

    def generate_diff(
        self, vuln: Vulnerability, source_code: str, context_lines: int = 3
    ) -> str:
        """
        生成 unified diff 格式的修复差异

        Args:
            vuln: 漏洞对象
            source_code: 原始源代码
            context_lines: diff 上下文行数

        Returns:
            unified diff 格式的字符串
        """
        fixed_code = self.generate_fix(vuln, source_code)
        if not fixed_code:
            # 如果无法自动修复，生成基于修复示例的 diff
            return self._generate_example_diff(vuln)

        original_lines = source_code.splitlines(keepends=True)
        fixed_lines = fixed_code.splitlines(keepends=True)

        diff = difflib.unified_diff(
            original_lines,
            fixed_lines,
            fromfile=f"a/{vuln.file_path}",
            tofile=f"b/{vuln.file_path}",
            n=context_lines,
        )

        return "".join(diff)

    def _generate_example_diff(self, vuln: Vulnerability) -> str:
        """为无法自动修复的漏洞生成示例 diff"""
        example = self.get_fix_example(vuln)
        if example:
            return f"# 修复示例 (需手动应用):\n{example}"
        return ""

    def fix_vulnerability(
        self, vuln: Vulnerability, source_code: str, file_path: str
    ) -> FixResult:
        """
        尝试修复单个漏洞

        Args:
            vuln: 漏洞对象
            source_code: 原始源代码
            file_path: 文件路径

        Returns:
            修复结果
        """
        original_code = vuln.code_snippet
        diff = self.generate_diff(vuln, source_code)

        if not self.can_fix(vuln, source_code):
            return FixResult(
                vulnerability=vuln,
                file_path=file_path,
                original_code=original_code,
                fixed_code="",
                success=False,
                error="此漏洞类型不支持自动修复，请参考修复示例手动修复",
                applied=False,
                diff=diff,
            )

        fixed_code = self.generate_fix(vuln, source_code)
        if not fixed_code:
            return FixResult(
                vulnerability=vuln,
                file_path=file_path,
                original_code=original_code,
                fixed_code="",
                success=False,
                error="无法生成修复代码",
                applied=False,
                diff=diff,
            )

        return FixResult(
            vulnerability=vuln,
            file_path=file_path,
            original_code=original_code,
            fixed_code=fixed_code,
            success=True,
            error=None,
            applied=False,
            diff=diff,
        )

    def fix_file(
        self,
        file_path: str,
        vulnerabilities: List[Vulnerability],
        dry_run: bool = True,
        interactive: bool = False,
        confirm_callback=None,
    ) -> List[FixResult]:
        """
        修复文件中的多个漏洞

        Args:
            file_path: 文件路径
            vulnerabilities: 漏洞列表
            dry_run: 是否只预览不实际修改
            interactive: 是否交互式确认
            confirm_callback: 交互式确认回调函数，接受FixResult返回bool

        Returns:
            修复结果列表
        """
        results = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source_code = f.read()
        except Exception as e:
            for vuln in vulnerabilities:
                results.append(
                    FixResult(
                        vulnerability=vuln,
                        file_path=file_path,
                        original_code=vuln.code_snippet,
                        fixed_code="",
                        success=False,
                        error=f"无法读取文件: {e}",
                        applied=False,
                    )
                )
            return results

        # 按行号倒序排列，从后往前修复以避免行号偏移问题
        sorted_vulns = sorted(vulnerabilities, key=lambda v: v.line_number, reverse=True)

        current_source = source_code
        for vuln in sorted_vulns:
            fix_result = self.fix_vulnerability(vuln, current_source, file_path)
            results.append(fix_result)

            if fix_result.success and not dry_run:
                # 检查是否需要交互式确认
                if interactive and confirm_callback:
                    if not confirm_callback(fix_result):
                        fix_result.applied = False
                        continue

                current_source = fix_result.fixed_code
                fix_result.applied = True

        # 如果不是 dry_run 且有修复被应用，则写入文件
        if not dry_run and any(r.applied for r in results):
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(current_source)
            except Exception as e:
                for result in results:
                    if result.applied:
                        result.applied = False
                        result.error = f"写入文件失败: {e}"

        return results


def get_fixer() -> CodeFixer:
    """获取代码修复器实例"""
    return CodeFixer()
