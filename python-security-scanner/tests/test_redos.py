"""
测试 ReDoS 检测规则
"""

import unittest
import ast
from pysec.rules.redos import ReDoSRule
from pysec.models import Vulnerability


class TestReDoSRule(unittest.TestCase):
    """测试正则表达式 DoS 检测规则"""

    def setUp(self):
        """初始化测试"""
        self.rule = ReDoSRule()

    def _check_code(self, code: str) -> list:
        """辅助方法：检查代码并返回漏洞列表"""
        tree = ast.parse(code)
        return self.rule.check(tree, "test.py", code)

    def test_nested_quantifiers_plus(self):
        """测试嵌套的 + 量词"""
        code = '''
import re
pattern = re.compile(r"(a+)+")
'''
        vulns = self._check_code(code)
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].rule_id, "REX001")
        self.assertIn("嵌套量词", vulns[0].description)

    def test_nested_quantifiers_star(self):
        """测试嵌套的 * 量词"""
        code = '''
import re
pattern = re.compile(r"(a*)*")
'''
        vulns = self._check_code(code)
        self.assertEqual(len(vulns), 1)
        self.assertIn("嵌套量词", vulns[0].description)

    def test_nested_quantifiers_mixed(self):
        """测试混合嵌套量词"""
        code = '''
import re
pattern = re.compile(r"(a+)*")
'''
        vulns = self._check_code(code)
        self.assertEqual(len(vulns), 1)

    def test_word_class_nesting(self):
        """测试字符类嵌套"""
        code = '''
import re
pattern1 = re.compile(r"(\\w+)+")
pattern2 = re.compile(r"(\\d+)+")
pattern3 = re.compile(r"([a-z]+)+")
'''
        vulns = self._check_code(code)
        self.assertEqual(len(vulns), 3)

    def test_overlapping_alternation_same(self):
        """测试完全相同的交替"""
        code = '''
import re
pattern = re.compile(r"(a|a)+")
'''
        vulns = self._check_code(code)
        self.assertEqual(len(vulns), 1)
        self.assertIn("重叠交替", vulns[0].description)

    def test_overlapping_alternation_prefix(self):
        """测试前缀重叠的交替"""
        code = '''
import re
pattern1 = re.compile(r"(a|ab)+")
pattern2 = re.compile(r"(test|tests)+")
'''
        vulns = self._check_code(code)
        self.assertEqual(len(vulns), 2)

    def test_bounded_quantifiers(self):
        """测试带数量限定的嵌套"""
        code = '''
import re
pattern1 = re.compile(r"(a{1,5})+")
pattern2 = re.compile(r"(a+){1,10}")
'''
        vulns = self._check_code(code)
        self.assertEqual(len(vulns), 2)

    def test_greedy_nesting(self):
        """测试贪婪匹配嵌套"""
        code = '''
import re
pattern1 = re.compile(r"(.*)+end")
pattern2 = re.compile(r"(.+)+$")
'''
        vulns = self._check_code(code)
        self.assertEqual(len(vulns), 2)

    def test_different_re_functions(self):
        """测试不同的 re 函数调用"""
        code = '''
import re
result1 = re.match(r"(a+)+", "test")
result2 = re.search(r"(\\d+)+", "123")
result3 = re.findall(r"(\\w+)+", "hello")
result4 = re.sub(r"(a*)*", "x", "aaa")
result5 = re.split(r"(,\\s*)+", "a,b,c")
'''
        vulns = self._check_code(code)
        self.assertEqual(len(vulns), 5)

    def test_from_import_syntax(self):
        """测试 from re import 语法"""
        code = '''
from re import compile, match
pattern = compile(r"(a+)+")
result = match(r"(\\d+)+", "123")
'''
        vulns = self._check_code(code)
        # 注意：compile 可能被 DNG001 检测为危险函数，这里只测试 ReDoS
        redos_vulns = [v for v in vulns if v.rule_id == "REX001"]
        self.assertGreaterEqual(len(redos_vulns), 2)

    def test_safe_patterns(self):
        """测试安全的正则表达式（不应该被检测到）"""
        code = '''
import re
# 简单量词 - 安全
pattern1 = re.compile(r"a+")
pattern2 = re.compile(r"\\w+")
pattern3 = re.compile(r"\\d{3}")

# 非嵌套交替 - 安全
pattern4 = re.compile(r"(cat|dog)")
pattern5 = re.compile(r"(apple|banana)")

# 锚点约束 - 安全
pattern6 = re.compile(r"^[a-z]+$")

# 非贪婪模式 - 安全
pattern7 = re.compile(r"a+?")
'''
        vulns = self._check_code(code)
        self.assertEqual(len(vulns), 0, "安全的正则表达式不应该被检测到")

    def test_real_world_email_vulnerable(self):
        """测试实际场景：有漏洞的邮箱验证"""
        code = '''
import re
def validate_email(email):
    # 危险：嵌套量词
    pattern = re.compile(r"^([a-zA-Z0-9])+@([a-zA-Z0-9])+\\.([a-zA-Z])+$")
    return pattern.match(email)
'''
        vulns = self._check_code(code)
        self.assertGreaterEqual(len(vulns), 1)

    def test_real_world_url_vulnerable(self):
        """测试实际场景：有漏洞的 URL 验证"""
        code = '''
import re
def validate_url(url):
    pattern = re.compile(r"(http|https)://(\\w+)+\\.(\\w+)+")
    return pattern.match(url)
'''
        vulns = self._check_code(code)
        self.assertGreaterEqual(len(vulns), 1)

    def test_vulnerability_severity(self):
        """测试漏洞严重程度"""
        code = '''
import re
pattern = re.compile(r"(a+)+")
'''
        vulns = self._check_code(code)
        self.assertEqual(vulns[0].severity, "medium")

    def test_vulnerability_suggestion(self):
        """测试修复建议"""
        code = '''
import re
pattern = re.compile(r"(a+)+")
'''
        vulns = self._check_code(code)
        self.assertIn("re2", vulns[0].suggestion)
        self.assertIn("嵌套量词", vulns[0].suggestion)

    def test_complex_nested_pattern(self):
        """测试复杂的嵌套模式"""
        code = '''
import re
# HTML 标签提取的典型 ReDoS 漏洞
pattern = re.compile(r"<(\\w+)>(.*)+</\\1>")
'''
        vulns = self._check_code(code)
        self.assertEqual(len(vulns), 1)

    def test_multiple_vulnerabilities_in_one_file(self):
        """测试一个文件中的多个漏洞"""
        code = '''
import re
pattern1 = re.compile(r"(a+)+")
pattern2 = re.compile(r"(b*)*")
pattern3 = re.compile(r"(c|c)+")
pattern4 = re.compile(r"(\\w+)+")
'''
        vulns = self._check_code(code)
        self.assertEqual(len(vulns), 4)


if __name__ == '__main__':
    unittest.main()
