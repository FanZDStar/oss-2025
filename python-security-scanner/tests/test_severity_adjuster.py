"""
动态严重程度调整功能测试
"""

import unittest
from pysec.severity_adjuster import (
    SeverityAdjuster,
    ContextInfo,
    create_context_from_vulnerability,
    SENSITIVE_PATH_PATTERNS,
    LOW_SENSITIVITY_PATH_PATTERNS,
)
from pysec.models import Vulnerability


class TestContextInfo(unittest.TestCase):
    """测试上下文信息"""

    def test_context_creation(self):
        """测试上下文创建"""
        context = ContextInfo(
            file_path="src/auth/login.py",
            function_name="authenticate",
            class_name="AuthService",
            code_snippet="password = request.form['password']",
            line_number=10,
        )
        self.assertEqual(context.file_path, "src/auth/login.py")
        self.assertEqual(context.function_name, "authenticate")
        self.assertEqual(context.class_name, "AuthService")


class TestSeverityAdjuster(unittest.TestCase):
    """测试严重程度调整器"""

    def test_disabled_adjuster_returns_original(self):
        """测试禁用时返回原始严重程度"""
        adjuster = SeverityAdjuster(enabled=False)
        context = ContextInfo(file_path="tests/test_login.py")

        result = adjuster.adjust_severity("high", context)
        self.assertEqual(result, "high")

    def test_test_code_downgrades_severity(self):
        """测试代码会降低严重程度"""
        adjuster = SeverityAdjuster(enabled=True, downgrade_for_tests=True)

        # 测试目录
        context = ContextInfo(file_path="tests/test_auth.py")
        result = adjuster.adjust_severity("high", context)
        self.assertEqual(result, "medium")

        # test_ 前缀文件
        context = ContextInfo(file_path="test_utils.py")
        result = adjuster.adjust_severity("critical", context)
        self.assertEqual(result, "high")

        # _test 后缀文件
        context = ContextInfo(file_path="auth_test.py")
        result = adjuster.adjust_severity("high", context)
        self.assertEqual(result, "medium")

    def test_test_function_downgrades_severity(self):
        """测试代码会降低严重程度（在测试目录中）"""
        adjuster = SeverityAdjuster(
            enabled=True, downgrade_for_tests=True, upgrade_for_sensitive=False
        )
        context = ContextInfo(file_path="tests/test_app.py", function_name="test_something")

        result = adjuster.adjust_severity("high", context)
        self.assertEqual(result, "medium")

    def test_sensitive_path_upgrades_severity(self):
        """敏感路径会提升严重程度"""
        adjuster = SeverityAdjuster(enabled=True, upgrade_for_sensitive=True)

        # src 目录
        context = ContextInfo(file_path="src/api/handler.py")
        result = adjuster.adjust_severity("medium", context)
        self.assertEqual(result, "high")

        # api 目录
        context = ContextInfo(file_path="api/users.py")
        result = adjuster.adjust_severity("low", context)
        self.assertEqual(result, "medium")

    def test_sensitive_function_upgrades_severity(self):
        """敏感函数会提升严重程度"""
        adjuster = SeverityAdjuster(enabled=True, upgrade_for_sensitive=True)

        # auth 相关
        context = ContextInfo(file_path="app.py", function_name="authenticate_user")
        result = adjuster.adjust_severity("medium", context)
        self.assertEqual(result, "high")

        # password 相关
        context = ContextInfo(file_path="app.py", function_name="reset_password")
        result = adjuster.adjust_severity("medium", context)
        self.assertEqual(result, "high")

    def test_sensitive_class_upgrades_severity(self):
        """敏感类会提升严重程度"""
        adjuster = SeverityAdjuster(enabled=True, upgrade_for_sensitive=True)
        context = ContextInfo(file_path="app.py", class_name="PaymentService")

        result = adjuster.adjust_severity("medium", context)
        self.assertEqual(result, "high")

    def test_user_input_upgrades_severity(self):
        """涉及用户输入会提升严重程度"""
        adjuster = SeverityAdjuster(enabled=True, consider_user_input=True)

        # request.
        context = ContextInfo(file_path="app.py", code_snippet="data = request.form['input']")
        result = adjuster.adjust_severity("medium", context)
        self.assertEqual(result, "high")

        # user_input
        context = ContextInfo(file_path="app.py", code_snippet="os.system(user_input)")
        result = adjuster.adjust_severity("medium", context)
        self.assertEqual(result, "high")

    def test_combined_factors_stack(self):
        """多个因素会叠加"""
        adjuster = SeverityAdjuster(enabled=True)

        # 敏感路径 + 敏感函数 + 用户输入 = +3
        context = ContextInfo(
            file_path="src/api/auth.py",
            function_name="login_user",
            code_snippet="password = request.form['password']",
        )
        result = adjuster.adjust_severity("low", context)
        self.assertEqual(result, "critical")  # low -> medium -> high -> critical

    def test_severity_bounds(self):
        """严重程度不会超出范围"""
        adjuster = SeverityAdjuster(enabled=True)

        # 已经是 critical，再提升还是 critical
        context = ContextInfo(
            file_path="src/api/auth.py", function_name="login", code_snippet="request.form"
        )
        result = adjuster.adjust_severity("critical", context)
        self.assertEqual(result, "critical")

        # 已经是 low，在测试代码中还是 low
        context = ContextInfo(file_path="tests/test.py")
        result = adjuster.adjust_severity("low", context)
        self.assertEqual(result, "low")

    def test_test_code_cancels_upgrade(self):
        """测试代码会抵消部分提升"""
        adjuster = SeverityAdjuster(enabled=True)

        # 测试代码中的敏感函数：-1 (测试代码) + 1 (敏感函数 login) = 0
        context = ContextInfo(
            file_path="tests/test_auth.py", function_name="test_login"  # 包含 login
        )
        result = adjuster.adjust_severity("medium", context)
        # 测试代码 -1，但函数名包含 login 是敏感函数 +1，抵消后不变
        self.assertEqual(result, "medium")

    def test_get_adjustment_reasons(self):
        """测试获取调整原因"""
        adjuster = SeverityAdjuster(enabled=True)

        context = ContextInfo(
            file_path="src/api/auth.py",
            function_name="login",
            code_snippet="request.form['password']",
        )

        reasons = adjuster.get_adjustment_reasons(context)

        self.assertIn("敏感路径 (提升严重程度)", reasons)
        self.assertIn("敏感函数 (提升严重程度)", reasons)
        self.assertIn("涉及用户输入 (提升严重程度)", reasons)


class TestCreateContextFromVulnerability(unittest.TestCase):
    """测试从漏洞创建上下文"""

    def test_create_context_basic(self):
        """测试基本上下文创建"""
        vuln = Vulnerability(
            rule_id="SQL001",
            rule_name="SQL Injection",
            severity="high",
            file_path="app/db.py",
            line_number=10,
            column=5,
            code_snippet="execute(query + user_input)",
            description="SQL Injection detected",
            suggestion="Use parameterized queries",
        )

        context = create_context_from_vulnerability(vuln)

        self.assertEqual(context.file_path, "app/db.py")
        self.assertEqual(context.line_number, 10)
        self.assertEqual(context.code_snippet, "execute(query + user_input)")


class TestScannerIntegration(unittest.TestCase):
    """测试扫描器集成"""

    def test_scanner_with_dynamic_severity(self):
        """测试扫描器应用动态严重程度"""
        from pysec.engine import SecurityScanner
        from pysec.models import ScanConfig

        code = """
import os
os.system(user_input)
"""
        # 启用动态严重程度，代码涉及用户输入应提升
        config = ScanConfig(dynamic_severity=True)
        scanner = SecurityScanner(config)
        result = scanner.scan_code(code, "src/api/handler.py")

        # 检查是否有漏洞
        if result.vulnerabilities:
            # 由于是 src/api 路径 + 涉及 user_input，严重程度应该被提升
            for vuln in result.vulnerabilities:
                # 原始 CMD001 是 high，提升后应该是 critical
                if vuln.rule_id == "CMD001":
                    self.assertEqual(vuln.severity, "critical")

    def test_scanner_downgrades_in_test_code(self):
        """测试代码中的漏洞严重程度降低"""
        from pysec.engine import SecurityScanner
        from pysec.models import ScanConfig

        code = """
import os
os.system(cmd)
"""
        config = ScanConfig(dynamic_severity=True, downgrade_for_tests=True)
        scanner = SecurityScanner(config)
        result = scanner.scan_code(code, "tests/test_cmd.py")

        # 测试代码中的漏洞应该降级
        for vuln in result.vulnerabilities:
            if vuln.rule_id == "CMD001":
                # 原始 critical -> high（因为在测试代码中降级一级）
                self.assertEqual(vuln.severity, "high")


if __name__ == "__main__":
    unittest.main()
