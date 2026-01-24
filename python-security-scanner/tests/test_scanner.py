# PySecScanner 单元测试

import unittest
import sys
import os
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from pysec.models import Vulnerability, ScanResult, ScanConfig
from pysec.rules import list_rules, get_rule
from pysec.rules.base import RULE_REGISTRY
from pysec.scanner import ASTParser, FileScanner
from pysec.engine import RuleEngine, SecurityScanner
from pysec.reporter import TextReporter, MarkdownReporter, JSONReporter, get_reporter


class TestModels(unittest.TestCase):
    """测试数据模型"""

    def test_vulnerability_creation(self):
        """测试漏洞对象创建"""
        vuln = Vulnerability(
            rule_id="TEST001",
            rule_name="测试规则",
            severity="high",
            file_path="test.py",
            line_number=10,
            column=5,
            code_snippet="print('test')",
            description="测试描述",
            suggestion="测试建议",
        )
        self.assertEqual(vuln.rule_id, "TEST001")
        self.assertEqual(vuln.severity, "high")
        self.assertEqual(vuln.line_number, 10)

    def test_vulnerability_to_dict(self):
        """测试漏洞对象转字典"""
        vuln = Vulnerability(
            rule_id="TEST001",
            rule_name="测试规则",
            severity="high",
            file_path="test.py",
            line_number=10,
            column=5,
            code_snippet="print('test')",
            description="测试描述",
            suggestion="测试建议",
        )
        d = vuln.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["rule_id"], "TEST001")

    def test_scan_result_summary(self):
        """测试扫描结果统计"""
        vulns = [
            Vulnerability("R1", "N1", "critical", "f.py", 1, 0, "c", "d", "s"),
            Vulnerability("R2", "N2", "high", "f.py", 2, 0, "c", "d", "s"),
            Vulnerability("R3", "N3", "high", "f.py", 3, 0, "c", "d", "s"),
            Vulnerability("R4", "N4", "medium", "f.py", 4, 0, "c", "d", "s"),
        ]
        result = ScanResult(target="/test", vulnerabilities=vulns, files_scanned=1)
        summary = result.summary
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["high"], 2)
        self.assertEqual(summary["medium"], 1)
        self.assertEqual(summary["low"], 0)
        self.assertEqual(summary["total"], 4)


class TestRules(unittest.TestCase):
    """测试规则系统"""

    def test_rule_registry_not_empty(self):
        """测试规则注册表不为空"""
        rules = list_rules()
        self.assertGreater(len(rules), 0)

    def test_get_rule_by_id(self):
        """测试通过ID获取规则"""
        rule = get_rule("SQL001")
        self.assertIsNotNone(rule)

    def test_all_rules_have_required_attributes(self):
        """测试所有规则都有必要属性"""
        for rule_class in list_rules():
            instance = rule_class()
            self.assertTrue(hasattr(instance, "rule_id"))
            self.assertTrue(hasattr(instance, "rule_name"))
            self.assertTrue(hasattr(instance, "severity"))
            self.assertTrue(hasattr(instance, "description"))
            self.assertTrue(callable(getattr(instance, "check", None)))


class TestASTParser(unittest.TestCase):
    """测试AST解析器"""

    def test_parse_simple_code(self):
        """测试解析简单代码"""
        code = "x = 1 + 2"
        tree, error = ASTParser.parse_source(code)
        self.assertIsNotNone(tree)
        self.assertIsNone(error)

    def test_parse_invalid_syntax(self):
        """测试解析语法错误的代码"""
        code = "def broken("
        tree, error = ASTParser.parse_source(code)
        self.assertIsNone(tree)
        self.assertIsNotNone(error)


class TestFileScanner(unittest.TestCase):
    """测试文件扫描器"""

    def setUp(self):
        self.samples_dir = Path(__file__).parent / "samples"

    def test_scan_finds_python_files(self):
        """测试能找到Python文件"""
        if self.samples_dir.exists():
            scanner = FileScanner()
            files = list(scanner.scan_directory(str(self.samples_dir)))
            self.assertGreater(len(files), 0)
            for f in files:
                self.assertTrue(f.endswith(".py"))


class TestSecurityScanner(unittest.TestCase):
    """测试安全扫描器"""

    def setUp(self):
        self.samples_dir = Path(__file__).parent / "samples"
        self.scanner = SecurityScanner()

    def test_scan_vulnerable_code(self):
        """测试扫描漏洞代码"""
        vuln_file = self.samples_dir / "vulnerable_code.py"
        if vuln_file.exists():
            result = self.scanner.scan(str(vuln_file))
            # 应该发现多个漏洞
            self.assertGreater(len(result.vulnerabilities), 0)

    def test_scan_safe_code(self):
        """测试扫描安全代码"""
        safe_file = self.samples_dir / "safe_code.py"
        if safe_file.exists():
            result = self.scanner.scan(str(safe_file))
            # 安全代码应该检测到较少或没有漏洞
            # 注意：可能有一些误报，所以不断言为0
            self.assertLess(len(result.vulnerabilities), 10)

    def test_scan_code_snippet(self):
        """测试扫描代码片段"""
        code = "import os; os.system(user_input)"
        result = self.scanner.scan_code(code)
        # 应该检测到命令注入
        self.assertGreater(len(result.vulnerabilities), 0)


class TestReporters(unittest.TestCase):
    """测试报告生成器"""

    def setUp(self):
        self.vulns = [
            Vulnerability(
                rule_id="SQL001",
                rule_name="SQL注入",
                severity="high",
                file_path="test.py",
                line_number=10,
                column=5,
                code_snippet='query = f"SELECT * FROM {table}"',
                description="检测到SQL注入",
                suggestion="使用参数化查询",
            )
        ]
        self.result = ScanResult(target="/test/path", vulnerabilities=self.vulns, files_scanned=5)

    def test_text_reporter(self):
        """测试纯文本报告"""
        reporter = TextReporter()
        report = reporter.generate(self.result)
        self.assertIn("PySecScanner", report)
        self.assertIn("SQL注入", report)

    def test_markdown_reporter(self):
        """测试Markdown报告"""
        reporter = MarkdownReporter()
        report = reporter.generate(self.result)
        self.assertIn("# PySecScanner", report)
        self.assertIn("```python", report)

    def test_json_reporter(self):
        """测试JSON报告"""
        import json

        reporter = JSONReporter()
        report = reporter.generate(self.result)
        data = json.loads(report)
        self.assertIn("vulnerabilities", data)
        self.assertIn("summary", data)

    def test_get_reporter(self):
        """测试获取报告生成器"""
        text_reporter = get_reporter("text")
        md_reporter = get_reporter("markdown")
        json_reporter = get_reporter("json")

        self.assertIsInstance(text_reporter, TextReporter)
        self.assertIsInstance(md_reporter, MarkdownReporter)
        self.assertIsInstance(json_reporter, JSONReporter)


class TestRuleDetection(unittest.TestCase):
    """测试具体规则检测能力"""

    def setUp(self):
        self.scanner = SecurityScanner()

    def test_detect_sql_injection(self):
        """测试SQL注入检测"""
        code = """
query = "SELECT * FROM users WHERE id = '%s'" % user_id
cursor.execute(query)
"""
        result = self.scanner.scan_code(code)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        self.assertIn("SQL001", rule_ids)

    def test_detect_command_injection(self):
        """测试命令注入检测"""
        code = """
import os
os.system("ping " + user_input)
"""
        result = self.scanner.scan_code(code)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        self.assertIn("CMD001", rule_ids)

    def test_detect_hardcoded_secret(self):
        """测试硬编码密钥检测"""
        code = """
PASSWORD = "super_secret_123"
api_key = "sk-1234567890"
"""
        result = self.scanner.scan_code(code)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        self.assertIn("SEC001", rule_ids)

    def test_detect_dangerous_function(self):
        """测试危险函数检测"""
        code = """
result = eval(user_input)
exec(code_string)
"""
        result = self.scanner.scan_code(code)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        self.assertIn("DNG001", rule_ids)

    def test_detect_path_traversal(self):
        """测试路径遍历检测"""
        code = """
with open(user_filename, 'r') as f:
    content = f.read()
"""
        result = self.scanner.scan_code(code)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        self.assertIn("PTH001", rule_ids)


if __name__ == "__main__":
    unittest.main()
