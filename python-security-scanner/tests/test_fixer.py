"""
修复器模块单元测试
"""

import unittest
import sys
import os
import tempfile
import shutil
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from pysec.models import Vulnerability, FixResult
from pysec.fixer import (
    CodeFixer,
    FixPattern,
    get_fixer,
    FIX_PATTERN_REGISTRY,
    HardcodedSecretFixPattern,
    SQLInjectionFixPattern,
    CommandInjectionFixPattern,
)


class TestFixPatternRegistry(unittest.TestCase):
    """测试修复模式注册表"""

    def test_registry_not_empty(self):
        """测试注册表不为空"""
        self.assertGreater(len(FIX_PATTERN_REGISTRY), 0)

    def test_all_rules_have_patterns(self):
        """测试主要规则都有修复模式"""
        expected_rules = ["SEC001", "SQL001", "CMD001", "DNG001", "PTH001", "XSS001"]
        for rule_id in expected_rules:
            self.assertIn(rule_id, FIX_PATTERN_REGISTRY, f"规则 {rule_id} 没有修复模式")


class TestHardcodedSecretFixPattern(unittest.TestCase):
    """测试硬编码凭据修复模式"""

    def setUp(self):
        self.pattern = HardcodedSecretFixPattern()

    def test_can_fix_simple_assignment(self):
        """测试简单变量赋值可以修复"""
        vuln = Vulnerability(
            rule_id="SEC001",
            rule_name="硬编码敏感信息",
            severity="high",
            file_path="test.py",
            line_number=1,
            column=0,
            code_snippet='password = "secret123"',
            description="硬编码密码",
            suggestion="使用环境变量",
        )
        source = 'password = "secret123"\n'
        self.assertTrue(self.pattern.can_fix(vuln, source))

    def test_generate_fix(self):
        """测试生成修复代码"""
        vuln = Vulnerability(
            rule_id="SEC001",
            rule_name="硬编码敏感信息",
            severity="high",
            file_path="test.py",
            line_number=1,
            column=0,
            code_snippet='password = "secret123"',
            description="硬编码密码",
            suggestion="使用环境变量",
        )
        source = 'password = "secret123"\n'
        fixed = self.pattern.generate_fix(vuln, source)
        
        self.assertIsNotNone(fixed)
        self.assertIn("os.environ.get", fixed)
        self.assertIn("PASSWORD", fixed)

    def test_get_fix_example(self):
        """测试获取修复示例"""
        vuln = Vulnerability(
            rule_id="SEC001",
            rule_name="硬编码敏感信息",
            severity="high",
            file_path="test.py",
            line_number=1,
            column=0,
            code_snippet='password = "secret123"',
            description="硬编码密码",
            suggestion="使用环境变量",
        )
        example = self.pattern.get_fix_example(vuln)
        
        self.assertIn("修复前", example)
        self.assertIn("修复后", example)
        self.assertIn("os.environ.get", example)


class TestSQLInjectionFixPattern(unittest.TestCase):
    """测试SQL注入修复模式"""

    def setUp(self):
        self.pattern = SQLInjectionFixPattern()

    def test_not_auto_fixable(self):
        """测试SQL注入不可自动修复"""
        self.assertFalse(self.pattern.auto_fixable)

    def test_get_fix_example(self):
        """测试获取修复示例"""
        vuln = Vulnerability(
            rule_id="SQL001",
            rule_name="SQL注入",
            severity="high",
            file_path="test.py",
            line_number=1,
            column=0,
            code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
            description="SQL注入",
            suggestion="使用参数化查询",
        )
        example = self.pattern.get_fix_example(vuln)
        
        self.assertIn("参数化查询", example)
        self.assertIn("cursor.execute", example)


class TestCodeFixer(unittest.TestCase):
    """测试代码修复器"""

    def setUp(self):
        self.fixer = get_fixer()

    def test_get_fixer(self):
        """测试获取修复器实例"""
        fixer = get_fixer()
        self.assertIsInstance(fixer, CodeFixer)

    def test_load_fix_patterns(self):
        """测试加载修复模式"""
        self.assertGreater(len(self.fixer.fix_patterns), 0)

    def test_get_fix_pattern(self):
        """测试获取修复模式"""
        pattern = self.fixer.get_fix_pattern("SEC001")
        self.assertIsNotNone(pattern)
        self.assertIsInstance(pattern, HardcodedSecretFixPattern)

    def test_get_fix_pattern_not_found(self):
        """测试获取不存在的修复模式"""
        pattern = self.fixer.get_fix_pattern("NONEXISTENT")
        self.assertIsNone(pattern)

    def test_can_fix_sec001(self):
        """测试SEC001可修复"""
        vuln = Vulnerability(
            rule_id="SEC001",
            rule_name="硬编码敏感信息",
            severity="high",
            file_path="test.py",
            line_number=1,
            column=0,
            code_snippet='api_key = "sk-12345678"',
            description="硬编码密钥",
            suggestion="使用环境变量",
        )
        source = 'api_key = "sk-12345678"\n'
        self.assertTrue(self.fixer.can_fix(vuln, source))

    def test_cannot_fix_sql001(self):
        """测试SQL001不可自动修复"""
        vuln = Vulnerability(
            rule_id="SQL001",
            rule_name="SQL注入",
            severity="high",
            file_path="test.py",
            line_number=1,
            column=0,
            code_snippet='query = f"SELECT * FROM users"',
            description="SQL注入",
            suggestion="使用参数化查询",
        )
        source = 'query = f"SELECT * FROM users"\n'
        self.assertFalse(self.fixer.can_fix(vuln, source))

    def test_generate_diff(self):
        """测试生成diff"""
        vuln = Vulnerability(
            rule_id="SEC001",
            rule_name="硬编码敏感信息",
            severity="high",
            file_path="test.py",
            line_number=1,
            column=0,
            code_snippet='password = "secret"',
            description="硬编码密码",
            suggestion="使用环境变量",
        )
        source = 'password = "secret"\n'
        diff = self.fixer.generate_diff(vuln, source)
        
        self.assertIsInstance(diff, str)
        # diff 应该包含文件名
        self.assertIn("test.py", diff)


class TestFixVulnerability(unittest.TestCase):
    """测试修复漏洞功能"""

    def setUp(self):
        self.fixer = get_fixer()

    def test_fix_vulnerability_success(self):
        """测试成功修复漏洞"""
        vuln = Vulnerability(
            rule_id="SEC001",
            rule_name="硬编码敏感信息",
            severity="high",
            file_path="test.py",
            line_number=1,
            column=0,
            code_snippet='token = "abc123"',
            description="硬编码令牌",
            suggestion="使用环境变量",
        )
        source = 'token = "abc123"\n'
        result = self.fixer.fix_vulnerability(vuln, source, "test.py")
        
        self.assertIsInstance(result, FixResult)
        self.assertTrue(result.success)
        self.assertIn("os.environ.get", result.fixed_code)

    def test_fix_vulnerability_not_supported(self):
        """测试不支持的修复"""
        vuln = Vulnerability(
            rule_id="SQL001",
            rule_name="SQL注入",
            severity="high",
            file_path="test.py",
            line_number=1,
            column=0,
            code_snippet='query = f"SELECT * FROM users"',
            description="SQL注入",
            suggestion="使用参数化查询",
        )
        source = 'query = f"SELECT * FROM users"\n'
        result = self.fixer.fix_vulnerability(vuln, source, "test.py")
        
        self.assertIsInstance(result, FixResult)
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)


class TestFixFile(unittest.TestCase):
    """测试文件修复功能"""

    def setUp(self):
        self.fixer = get_fixer()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_fix_file_dry_run(self):
        """测试dry-run模式不修改文件"""
        # 创建测试文件
        test_file = Path(self.temp_dir) / "test.py"
        original_content = 'password = "secret123"\n'
        test_file.write_text(original_content, encoding="utf-8")
        
        vuln = Vulnerability(
            rule_id="SEC001",
            rule_name="硬编码敏感信息",
            severity="high",
            file_path=str(test_file),
            line_number=1,
            column=0,
            code_snippet='password = "secret123"',
            description="硬编码密码",
            suggestion="使用环境变量",
        )
        
        results = self.fixer.fix_file(str(test_file), [vuln], dry_run=True)
        
        # 检查结果
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].success)
        self.assertFalse(results[0].applied)  # dry-run 不应用修复
        
        # 检查文件未被修改
        self.assertEqual(test_file.read_text(encoding="utf-8"), original_content)

    def test_fix_file_apply(self):
        """测试实际应用修复"""
        # 创建测试文件
        test_file = Path(self.temp_dir) / "test.py"
        original_content = 'password = "secret123"\n'
        test_file.write_text(original_content, encoding="utf-8")
        
        vuln = Vulnerability(
            rule_id="SEC001",
            rule_name="硬编码敏感信息",
            severity="high",
            file_path=str(test_file),
            line_number=1,
            column=0,
            code_snippet='password = "secret123"',
            description="硬编码密码",
            suggestion="使用环境变量",
        )
        
        results = self.fixer.fix_file(str(test_file), [vuln], dry_run=False)
        
        # 检查结果
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].success)
        self.assertTrue(results[0].applied)
        
        # 检查文件已被修改
        new_content = test_file.read_text(encoding="utf-8")
        self.assertNotEqual(new_content, original_content)
        self.assertIn("os.environ.get", new_content)


class TestFixExamples(unittest.TestCase):
    """测试各规则的修复示例"""

    def setUp(self):
        self.fixer = get_fixer()

    def test_all_patterns_have_examples(self):
        """测试所有模式都有修复示例"""
        # 为每个规则创建带有合适 code_snippet 的测试漏洞
        test_cases = {
            "SEC001": 'password = "secret123"',
            "SQL001": 'query = f"SELECT * FROM users"',
            "CMD001": 'os.system(command)',
            "DNG001": 'result = eval(user_input)',
            "PTH001": 'open(user_filename)',
            "XSS001": 'html = f"<div>{user_input}</div>"',
        }
        
        for rule_id, code_snippet in test_cases.items():
            vuln = Vulnerability(
                rule_id=rule_id,
                rule_name="test",
                severity="high",
                file_path="test.py",
                line_number=1,
                column=0,
                code_snippet=code_snippet,
                description="test",
                suggestion="test",
            )
            example = self.fixer.get_fix_example(vuln)
            self.assertIsInstance(example, str, f"规则 {rule_id} 的修复示例不是字符串")
            self.assertGreater(len(example), 0, f"规则 {rule_id} 没有修复示例")


if __name__ == "__main__":
    unittest.main()
