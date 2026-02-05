"""
测试忽略注释功能
"""

import unittest
from pysec.ignore import IgnoreCommentParser


class TestIgnoreComments(unittest.TestCase):
    """测试忽略注释解析器"""

    def test_line_ignore_all(self):
        """测试行级忽略所有规则"""
        source = """
password = "secret123"  # pysec: ignore
api_key = "key456"
"""
        parser = IgnoreCommentParser(source)
        
        # 第2行应该被忽略（所有规则）
        self.assertTrue(parser.should_ignore(2, "SEC001"))
        self.assertTrue(parser.should_ignore(2, "SQL001"))
        
        # 第3行不应该被忽略
        self.assertFalse(parser.should_ignore(3, "SEC001"))

    def test_line_ignore_specific_rule(self):
        """测试行级忽略特定规则"""
        source = """
password = "secret123"  # pysec: ignore[SEC001]
"""
        parser = IgnoreCommentParser(source)
        
        # SEC001 应该被忽略
        self.assertTrue(parser.should_ignore(2, "SEC001"))
        
        # 其他规则不应该被忽略
        self.assertFalse(parser.should_ignore(2, "SQL001"))
        self.assertFalse(parser.should_ignore(2, "CMD001"))

    def test_line_ignore_multiple_rules(self):
        """测试行级忽略多个规则"""
        source = """
code = "test"  # pysec: ignore[SEC001, SQL001, CMD001]
"""
        parser = IgnoreCommentParser(source)
        
        # 这三个规则应该被忽略
        self.assertTrue(parser.should_ignore(2, "SEC001"))
        self.assertTrue(parser.should_ignore(2, "SQL001"))
        self.assertTrue(parser.should_ignore(2, "CMD001"))
        
        # 其他规则不应该被忽略
        self.assertFalse(parser.should_ignore(2, "DNG001"))

    def test_block_ignore(self):
        """测试代码块忽略"""
        source = """
eval("1 + 1")
# pysec: disable
eval("2 + 2")
exec("code")
password = "secret"
# pysec: enable
eval("3 + 3")
"""
        parser = IgnoreCommentParser(source)
        
        # 第2行不应该被忽略（disable之前）
        self.assertFalse(parser.should_ignore(2, "DNG001"))
        
        # 第3-6行应该被忽略（disable和enable之间）
        self.assertTrue(parser.should_ignore(3, "DNG001"))  # disable行本身
        self.assertTrue(parser.should_ignore(4, "DNG001"))
        self.assertTrue(parser.should_ignore(5, "DNG001"))
        self.assertTrue(parser.should_ignore(6, "SEC001"))
        self.assertTrue(parser.should_ignore(7, "DNG001"))  # enable行本身
        
        # 第8行不应该被忽略（enable之后）
        self.assertFalse(parser.should_ignore(8, "DNG001"))

    def test_case_insensitive(self):
        """测试大小写不敏感"""
        source = """
password1 = "test"  # PYSEC: IGNORE
password2 = "test"  # pysec: IGNORE
password3 = "test"  # PySec: Ignore
"""
        parser = IgnoreCommentParser(source)
        
        # 所有格式都应该被识别
        self.assertTrue(parser.should_ignore(2, "SEC001"))
        self.assertTrue(parser.should_ignore(3, "SEC001"))
        self.assertTrue(parser.should_ignore(4, "SEC001"))

    def test_whitespace_tolerance(self):
        """测试空格容错"""
        source = """
password1 = "test"  #pysec:ignore
password2 = "test"  # pysec: ignore
password3 = "test"  #  pysec:  ignore
"""
        parser = IgnoreCommentParser(source)
        
        # 所有格式都应该被识别
        self.assertTrue(parser.should_ignore(2, "SEC001"))
        self.assertTrue(parser.should_ignore(3, "SEC001"))
        self.assertTrue(parser.should_ignore(4, "SEC001"))

    def test_unclosed_disable_block(self):
        """测试未关闭的disable块（忽略到文件末尾）"""
        source = """
eval("1 + 1")
# pysec: disable
eval("2 + 2")
eval("3 + 3")
"""
        parser = IgnoreCommentParser(source)
        
        # 第2行不应该被忽略
        self.assertFalse(parser.should_ignore(2, "DNG001"))
        
        # 第3行及之后都应该被忽略
        self.assertTrue(parser.should_ignore(3, "DNG001"))
        self.assertTrue(parser.should_ignore(4, "DNG001"))
        self.assertTrue(parser.should_ignore(5, "DNG001"))

    def test_nested_disable_blocks(self):
        """测试嵌套的disable块（不支持真正的嵌套，后面的enable会关闭前面的disable）"""
        source = """
# pysec: disable
code1 = "test1"
# pysec: disable
code2 = "test2"
# pysec: enable
code3 = "test3"
"""
        parser = IgnoreCommentParser(source)
        
        # 第2-6行应该在第一个disable块中
        self.assertTrue(parser.should_ignore(2, "SEC001"))
        self.assertTrue(parser.should_ignore(3, "SEC001"))
        self.assertTrue(parser.should_ignore(4, "SEC001"))
        self.assertTrue(parser.should_ignore(5, "SEC001"))
        self.assertTrue(parser.should_ignore(6, "SEC001"))
        
        # 第7行在enable之后，不应该被忽略
        self.assertFalse(parser.should_ignore(7, "SEC001"))

    def test_get_ignore_stats(self):
        """测试获取忽略统计信息"""
        source = """
password1 = "test1"  # pysec: ignore
password2 = "test2"  # pysec: ignore[SEC001]
# pysec: disable
line4
line5
line6
# pysec: enable
line8
"""
        parser = IgnoreCommentParser(source)
        stats = parser.get_ignore_stats()
        
        # 2行行级忽略
        self.assertEqual(stats['line_ignores'], 2)
        
        # 1个代码块忽略
        self.assertEqual(stats['block_ignores'], 1)
        
        # 代码块忽略了5行（line 4-8，从disable到enable，包括两端）
        self.assertEqual(stats['total_ignored_lines'], 5)


if __name__ == '__main__':
    unittest.main()
