"""
忽略规则功能测试
"""

import pytest
from pysec.ignore_handler import IgnoreHandler, IgnoreContext


class TestIgnoreHandler:
    """测试忽略规则处理器"""

    def test_inline_ignore_all(self):
        """测试行内忽略所有规则"""
        source = """
password = "secret123"  # pysec: ignore
"""
        context = IgnoreHandler.parse_source(source)
        assert context.should_ignore(2, "SEC001")
        assert context.should_ignore(2, "SQL001")
        assert not context.should_ignore(1, "SEC001")

    def test_inline_ignore_specific_rule(self):
        """测试行内忽略指定规则"""
        source = """
password = "secret123"  # pysec: ignore[SEC001]
eval(user_input)  # pysec: ignore[FUNC001, FUNC002]
"""
        context = IgnoreHandler.parse_source(source)
        # SEC001 应该被忽略
        assert context.should_ignore(2, "SEC001")
        # 其他规则不应该被忽略
        assert not context.should_ignore(2, "SQL001")
        # 多个规则
        assert context.should_ignore(3, "FUNC001")
        assert context.should_ignore(3, "FUNC002")
        assert not context.should_ignore(3, "SQL001")

    def test_file_level_ignore_all(self):
        """测试文件级别忽略所有规则"""
        source = """# pysec: ignore-file
password = "secret123"
eval(user_input)
"""
        context = IgnoreHandler.parse_source(source)
        assert context.should_ignore(2, "SEC001")
        assert context.should_ignore(3, "FUNC001")
        assert context.should_ignore(100, "SQL001")

    def test_file_level_ignore_specific_rules(self):
        """测试文件级别忽略指定规则"""
        source = """# pysec: ignore-file[SEC001, SQL001]
password = "secret123"
eval(user_input)
"""
        context = IgnoreHandler.parse_source(source)
        assert context.should_ignore(2, "SEC001")
        assert context.should_ignore(3, "SQL001")
        assert not context.should_ignore(2, "FUNC001")

    def test_block_disable_enable_all(self):
        """测试代码块忽略所有规则"""
        source = """
# pysec: disable
password = "secret123"
eval(user_input)
# pysec: enable
exec(code)
"""
        context = IgnoreHandler.parse_source(source)
        # 块内的代码应该被忽略
        assert context.should_ignore(3, "SEC001")
        assert context.should_ignore(4, "FUNC001")
        # 块外的代码不应该被忽略
        assert not context.should_ignore(6, "FUNC001")

    def test_block_disable_enable_specific_rules(self):
        """测试代码块忽略指定规则"""
        source = """
# pysec: disable[SQL001]
query = f"SELECT * FROM {table}"
password = "secret123"
# pysec: enable[SQL001]
query2 = f"SELECT * FROM {table2}"
"""
        context = IgnoreHandler.parse_source(source)
        # SQL001 在块内应该被忽略
        assert context.should_ignore(3, "SQL001")
        # SEC001 不受影响
        assert not context.should_ignore(4, "SEC001")
        # SQL001 在块外不应该被忽略
        assert not context.should_ignore(6, "SQL001")

    def test_unclosed_block_extends_to_eof(self):
        """测试未闭合的代码块延伸到文件末尾"""
        source = """
# pysec: disable
password = "secret123"
eval(user_input)
"""
        context = IgnoreHandler.parse_source(source)
        assert context.should_ignore(3, "SEC001")
        assert context.should_ignore(4, "FUNC001")

    def test_nested_blocks(self):
        """测试嵌套/多个规则的代码块"""
        source = """
# pysec: disable[SQL001]
query = f"SELECT * FROM {table}"
# pysec: disable[SEC001]
password = "secret123"
# pysec: enable
query2 = f"SELECT * FROM {table2}"
"""
        context = IgnoreHandler.parse_source(source)
        # SQL001 应该被忽略
        assert context.should_ignore(3, "SQL001")
        # SEC001 应该被忽略
        assert context.should_ignore(5, "SEC001")
        # enable 后都不再忽略
        assert not context.should_ignore(7, "SQL001")
        assert not context.should_ignore(7, "SEC001")

    def test_case_insensitive(self):
        """测试大小写不敏感"""
        source = """
password = "secret123"  # PYSEC: IGNORE[sec001]
# PySeC: Disable
eval(user_input)
# pySec: Enable
"""
        context = IgnoreHandler.parse_source(source)
        assert context.should_ignore(2, "SEC001")
        assert context.should_ignore(4, "FUNC001")
        assert not context.should_ignore(6, "FUNC001")

    def test_filter_vulnerabilities(self):
        """测试过滤漏洞列表"""
        from pysec.models import Vulnerability

        source = """
password = "secret123"  # pysec: ignore[SEC001]
eval(user_input)
"""
        vulnerabilities = [
            Vulnerability(
                rule_id="SEC001",
                rule_name="硬编码密码",
                severity="high",
                file_path="test.py",
                line_number=2,
                column=0,
                code_snippet='password = "secret123"',
                description="发现硬编码密码",
                suggestion="使用环境变量存储密码",
            ),
            Vulnerability(
                rule_id="FUNC001",
                rule_name="危险函数",
                severity="critical",
                file_path="test.py",
                line_number=3,
                column=0,
                code_snippet="eval(user_input)",
                description="发现危险函数调用",
                suggestion="避免使用 eval",
            ),
        ]

        filtered, ignored_count = IgnoreHandler.filter_vulnerabilities(
            vulnerabilities, source, "test.py"
        )

        assert ignored_count == 1
        assert len(filtered) == 1
        assert filtered[0].rule_id == "FUNC001"


class TestIgnoreContext:
    """测试 IgnoreContext 类"""

    def test_should_ignore_with_file_level(self):
        """测试文件级别忽略"""
        context = IgnoreContext(file_path="test.py", file_level_ignore_all=True)
        assert context.should_ignore(1, "ANY_RULE")
        assert context.should_ignore(100, "OTHER_RULE")

    def test_should_ignore_with_specific_file_rules(self):
        """测试指定规则的文件级别忽略"""
        context = IgnoreContext(file_path="test.py", file_level_ignore={"SQL001", "SEC001"})
        assert context.should_ignore(1, "SQL001")
        assert context.should_ignore(1, "SEC001")
        assert not context.should_ignore(1, "FUNC001")

    def test_should_ignore_with_line_ignores(self):
        """测试行级别忽略"""
        context = IgnoreContext(
            file_path="test.py",
            line_ignores={
                5: None,  # 忽略所有
                10: ["SQL001", "SEC001"],  # 忽略指定规则
            },
        )
        assert context.should_ignore(5, "ANY_RULE")
        assert context.should_ignore(10, "SQL001")
        assert context.should_ignore(10, "SEC001")
        assert not context.should_ignore(10, "FUNC001")
        assert not context.should_ignore(15, "SQL001")

    def test_should_ignore_with_block_ignores(self):
        """测试代码块忽略"""
        context = IgnoreContext(
            file_path="test.py",
            block_ignores=[
                (5, 10, None),  # 5-10行忽略所有
                (15, 20, ["SQL001"]),  # 15-20行忽略SQL001
            ],
        )
        # 块内
        assert context.should_ignore(7, "ANY_RULE")
        assert context.should_ignore(17, "SQL001")
        assert not context.should_ignore(17, "SEC001")
        # 块外
        assert not context.should_ignore(12, "SQL001")


class TestIntegration:
    """集成测试"""

    def test_scanner_with_ignore(self):
        """测试扫描器与忽略功能集成"""
        from pysec.engine import SecurityScanner

        source = """# pysec: ignore-file[SEC001]
password = "secret123"
eval(user_input)
"""
        scanner = SecurityScanner()
        result = scanner.scan_code(source, "test.py")

        # SEC001 应该被忽略，只有 FUNC001 被报告
        sec_vulns = [v for v in result.vulnerabilities if v.rule_id == "SEC001"]
        assert len(sec_vulns) == 0

        # 检查忽略计数
        assert result.ignored_count >= 1

    def test_mixed_ignore_directives(self):
        """测试混合使用多种忽略指令"""
        source = """# pysec: ignore-file[SQL001]
query = f"SELECT * FROM {table}"  # 文件级别忽略

password = "secret123"  # pysec: ignore
# 行级别忽略

# pysec: disable
eval(user_input)  # 块级别忽略
exec(code)
# pysec: enable

os.system(cmd)  # 不被忽略
"""
        context = IgnoreHandler.parse_source(source)

        # 文件级别
        assert context.should_ignore(2, "SQL001")
        assert not context.should_ignore(2, "SEC001")

        # 行级别
        assert context.should_ignore(4, "SEC001")
        assert context.should_ignore(4, "SQL001")

        # 块级别
        assert context.should_ignore(8, "FUNC001")
        assert context.should_ignore(9, "FUNC001")

        # 块外
        assert not context.should_ignore(12, "CMD001")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
