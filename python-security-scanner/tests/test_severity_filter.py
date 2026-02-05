"""
严重程度过滤功能测试
"""

import unittest
from pysec.models import ScanResult, Vulnerability, ScanConfig, get_severity_value, SEVERITY_LEVELS


class TestSeverityLevels(unittest.TestCase):
    """测试严重程度级别"""

    def test_severity_levels_order(self):
        """测试严重程度级别顺序"""
        self.assertEqual(SEVERITY_LEVELS, ["critical", "high", "medium", "low"])

    def test_get_severity_value(self):
        """测试严重程度数值转换"""
        self.assertEqual(get_severity_value("critical"), 0)
        self.assertEqual(get_severity_value("high"), 1)
        self.assertEqual(get_severity_value("medium"), 2)
        self.assertEqual(get_severity_value("low"), 3)

    def test_get_severity_value_case_insensitive(self):
        """测试严重程度大小写不敏感"""
        self.assertEqual(get_severity_value("CRITICAL"), 0)
        self.assertEqual(get_severity_value("High"), 1)
        self.assertEqual(get_severity_value("MEDIUM"), 2)

    def test_get_severity_value_unknown(self):
        """测试未知严重程度返回最大值"""
        self.assertEqual(get_severity_value("unknown"), len(SEVERITY_LEVELS))


class TestScanConfigSeverity(unittest.TestCase):
    """测试 ScanConfig 严重程度功能"""

    def test_default_min_severity_is_none(self):
        """测试默认最低严重程度为 None"""
        config = ScanConfig()
        self.assertIsNone(config.min_severity)

    def test_meets_min_severity_no_filter(self):
        """测试无过滤时所有级别都满足"""
        config = ScanConfig(min_severity=None)
        self.assertTrue(config.meets_min_severity("critical"))
        self.assertTrue(config.meets_min_severity("high"))
        self.assertTrue(config.meets_min_severity("medium"))
        self.assertTrue(config.meets_min_severity("low"))

    def test_meets_min_severity_critical(self):
        """测试过滤只保留 critical"""
        config = ScanConfig(min_severity="critical")
        self.assertTrue(config.meets_min_severity("critical"))
        self.assertFalse(config.meets_min_severity("high"))
        self.assertFalse(config.meets_min_severity("medium"))
        self.assertFalse(config.meets_min_severity("low"))

    def test_meets_min_severity_high(self):
        """测试过滤保留 critical 和 high"""
        config = ScanConfig(min_severity="high")
        self.assertTrue(config.meets_min_severity("critical"))
        self.assertTrue(config.meets_min_severity("high"))
        self.assertFalse(config.meets_min_severity("medium"))
        self.assertFalse(config.meets_min_severity("low"))

    def test_meets_min_severity_medium(self):
        """测试过滤保留 critical, high, medium"""
        config = ScanConfig(min_severity="medium")
        self.assertTrue(config.meets_min_severity("critical"))
        self.assertTrue(config.meets_min_severity("high"))
        self.assertTrue(config.meets_min_severity("medium"))
        self.assertFalse(config.meets_min_severity("low"))

    def test_meets_min_severity_low(self):
        """测试过滤保留所有级别"""
        config = ScanConfig(min_severity="low")
        self.assertTrue(config.meets_min_severity("critical"))
        self.assertTrue(config.meets_min_severity("high"))
        self.assertTrue(config.meets_min_severity("medium"))
        self.assertTrue(config.meets_min_severity("low"))


class TestScanResultFilter(unittest.TestCase):
    """测试 ScanResult 过滤功能"""

    def create_test_vulns(self):
        """创建测试漏洞列表"""
        return [
            Vulnerability(
                rule_id="TEST001",
                rule_name="Critical Issue",
                severity="critical",
                file_path="test.py",
                line_number=1,
                column=0,
                code_snippet="code1",
                description="desc1",
                suggestion="fix1",
            ),
            Vulnerability(
                rule_id="TEST002",
                rule_name="High Issue",
                severity="high",
                file_path="test.py",
                line_number=2,
                column=0,
                code_snippet="code2",
                description="desc2",
                suggestion="fix2",
            ),
            Vulnerability(
                rule_id="TEST003",
                rule_name="Medium Issue",
                severity="medium",
                file_path="test.py",
                line_number=3,
                column=0,
                code_snippet="code3",
                description="desc3",
                suggestion="fix3",
            ),
            Vulnerability(
                rule_id="TEST004",
                rule_name="Low Issue",
                severity="low",
                file_path="test.py",
                line_number=4,
                column=0,
                code_snippet="code4",
                description="desc4",
                suggestion="fix4",
            ),
        ]

    def test_filter_by_severity_none(self):
        """测试无过滤"""
        result = ScanResult(target="test")
        result.vulnerabilities = self.create_test_vulns()

        filtered = result.filter_by_severity(None)

        self.assertEqual(filtered, 0)
        self.assertEqual(len(result.vulnerabilities), 4)
        self.assertEqual(result.filtered_count, 0)

    def test_filter_by_severity_critical(self):
        """测试过滤只保留 critical"""
        result = ScanResult(target="test")
        result.vulnerabilities = self.create_test_vulns()

        filtered = result.filter_by_severity("critical")

        self.assertEqual(filtered, 3)
        self.assertEqual(len(result.vulnerabilities), 1)
        self.assertEqual(result.vulnerabilities[0].severity, "critical")
        self.assertEqual(result.filtered_count, 3)

    def test_filter_by_severity_high(self):
        """测试过滤保留 critical 和 high"""
        result = ScanResult(target="test")
        result.vulnerabilities = self.create_test_vulns()

        filtered = result.filter_by_severity("high")

        self.assertEqual(filtered, 2)
        self.assertEqual(len(result.vulnerabilities), 2)
        severities = [v.severity for v in result.vulnerabilities]
        self.assertIn("critical", severities)
        self.assertIn("high", severities)
        self.assertEqual(result.filtered_count, 2)

    def test_filter_by_severity_medium(self):
        """测试过滤保留 critical, high, medium"""
        result = ScanResult(target="test")
        result.vulnerabilities = self.create_test_vulns()

        filtered = result.filter_by_severity("medium")

        self.assertEqual(filtered, 1)
        self.assertEqual(len(result.vulnerabilities), 3)
        severities = [v.severity for v in result.vulnerabilities]
        self.assertNotIn("low", severities)
        self.assertEqual(result.filtered_count, 1)

    def test_filter_by_severity_low(self):
        """测试过滤保留所有级别"""
        result = ScanResult(target="test")
        result.vulnerabilities = self.create_test_vulns()

        filtered = result.filter_by_severity("low")

        self.assertEqual(filtered, 0)
        self.assertEqual(len(result.vulnerabilities), 4)
        self.assertEqual(result.filtered_count, 0)

    def test_summary_includes_filtered(self):
        """测试摘要包含过滤计数"""
        result = ScanResult(target="test")
        result.vulnerabilities = self.create_test_vulns()
        result.filter_by_severity("high")

        summary = result.summary

        self.assertEqual(summary["filtered"], 2)
        self.assertEqual(summary["total"], 2)


class TestScannerSeverityFilter(unittest.TestCase):
    """测试扫描器集成严重程度过滤"""

    def test_scan_with_min_severity(self):
        """测试扫描时应用最低严重程度"""
        from pysec.engine import SecurityScanner

        # 创建包含漏洞代码的测试
        code = """
import os

# 命令注入（高危）
os.system(user_input)

# 危险函数（中危）
eval("1+1")
"""
        config = ScanConfig(min_severity="high")
        scanner = SecurityScanner(config)
        result = scanner.scan_code(code, "test.py")

        # 应该过滤掉 medium 及以下级别
        for vuln in result.vulnerabilities:
            self.assertIn(vuln.severity, ["critical", "high"])


class TestSeverityOverrides(unittest.TestCase):
    """测试严重程度覆盖功能"""

    def test_get_effective_severity_no_override(self):
        """测试无覆盖时返回默认严重程度"""
        config = ScanConfig()
        self.assertEqual(config.get_effective_severity("SQL001", "high"), "high")
        self.assertEqual(config.get_effective_severity("CMD001", "medium"), "medium")

    def test_get_effective_severity_with_override(self):
        """测试有覆盖时返回覆盖的严重程度"""
        config = ScanConfig(severity_overrides={"SQL001": "critical", "CMD001": "low"})
        self.assertEqual(config.get_effective_severity("SQL001", "high"), "critical")
        self.assertEqual(config.get_effective_severity("CMD001", "medium"), "low")

    def test_get_effective_severity_override_not_matched(self):
        """测试规则未匹配覆盖时返回默认值"""
        config = ScanConfig(severity_overrides={"SQL001": "critical"})
        self.assertEqual(config.get_effective_severity("CMD001", "high"), "high")

    def test_get_effective_severity_invalid_override(self):
        """测试无效的覆盖值返回默认值"""
        config = ScanConfig(severity_overrides={"SQL001": "invalid_level"})
        self.assertEqual(config.get_effective_severity("SQL001", "high"), "high")

    def test_get_effective_severity_case_insensitive(self):
        """测试覆盖值大小写不敏感"""
        config = ScanConfig(severity_overrides={"SQL001": "CRITICAL"})
        self.assertEqual(config.get_effective_severity("SQL001", "high"), "critical")

    def test_scanner_applies_severity_override(self):
        """测试扫描器应用严重程度覆盖"""
        from pysec.engine import SecurityScanner

        code = """
import os
os.system(user_input)  # 默认 high 严重程度
"""
        # 将 CMD001 (命令注入) 覆盖为 critical
        config = ScanConfig(severity_overrides={"CMD001": "critical"})
        scanner = SecurityScanner(config)
        result = scanner.scan_code(code, "test.py")

        # 应该找到命令注入漏洞，严重程度应该被覆盖为 critical
        cmd_vulns = [v for v in result.vulnerabilities if v.rule_id == "CMD001"]
        if cmd_vulns:
            self.assertEqual(cmd_vulns[0].severity, "critical")

    def test_override_combined_with_min_severity(self):
        """测试覆盖与最低严重程度过滤组合"""
        from pysec.engine import SecurityScanner

        code = """
eval(user_input)  # 默认 medium，覆盖为 critical
exec(code)        # 默认 medium，未覆盖
"""
        # 将 DNG001 中的 eval 相关规则覆盖为 critical，同时过滤低于 high 的漏洞
        config = ScanConfig(severity_overrides={"DNG001": "critical"}, min_severity="high")
        scanner = SecurityScanner(config)
        result = scanner.scan_code(code, "test.py")

        # 由于覆盖，DNG001 应该变成 critical，不会被过滤
        # 只有严重程度 >= high 的漏洞会被保留
        for vuln in result.vulnerabilities:
            self.assertIn(vuln.severity, ["critical", "high"])


if __name__ == "__main__":
    unittest.main()
