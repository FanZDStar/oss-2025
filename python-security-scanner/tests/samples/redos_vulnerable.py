"""
ReDoS (正则表达式拒绝服务) 漏洞测试样例

包含各种可能导致灾难性回溯的正则表达式模式
"""

import re


# ========== 测试1: 嵌套量词 - 最危险的模式 ==========

def test_nested_quantifiers():
    """嵌套量词会导致指数级时间复杂度"""
    
    # 危险：(a+)+ - 嵌套的 + 量词
    pattern1 = re.compile(r"(a+)+")
    
    # 危险：(a*)* - 嵌套的 * 量词
    pattern2 = re.compile(r"(a*)*")
    
    # 危险：(a+)* - 混合嵌套
    pattern3 = re.compile(r"(a+)*")
    
    # 危险：(a?)+ - 可选嵌套
    pattern4 = re.compile(r"(a?)+")
    
    # 危险：(\d+)+ - 数字嵌套量词
    pattern5 = re.compile(r"(\d+)+")
    
    return pattern1, pattern2, pattern3, pattern4, pattern5


# ========== 测试2: 重叠交替 ==========

def test_overlapping_alternation():
    """交替分支重叠会导致大量回溯"""
    
    # 危险：(a|a)+ - 完全相同的交替
    pattern1 = re.compile(r"(a|a)+")
    
    # 危险：(a|ab)+ - 一个是另一个的前缀
    pattern2 = re.compile(r"(a|ab)+")
    
    # 危险：(abc|ab)+ - 有公共前缀
    pattern3 = re.compile(r"(abc|ab)+")
    
    # 危险：(test|tests)+ - 重叠后缀
    pattern4 = re.compile(r"(test|tests)+")
    
    return pattern1, pattern2, pattern3, pattern4


# ========== 测试3: 危险的字符类嵌套 ==========

def test_character_class_nesting():
    """字符类和量词的嵌套"""
    
    # 危险：(\w+)+ - 单词字符嵌套
    pattern1 = re.compile(r"(\w+)+")
    
    # 危险：([a-z]+)+ - 字符范围嵌套
    pattern2 = re.compile(r"([a-z]+)+")
    
    # 危险：(.*)+end - 贪婪匹配嵌套
    pattern3 = re.compile(r"(.*)+end")
    
    # 危险：(.+)+$ - 任意字符嵌套到行尾
    pattern4 = re.compile(r"(.+)+$")
    
    return pattern1, pattern2, pattern3, pattern4


# ========== 测试4: 数量限定符嵌套 ==========

def test_bounded_quantifier_nesting():
    """带数量限定的嵌套量词"""
    
    # 危险：(a{1,5})+ - 限定范围的嵌套
    pattern1 = re.compile(r"(a{1,5})+")
    
    # 危险：(a+){1,10} - 嵌套到限定次数
    pattern2 = re.compile(r"(a+){1,10}")
    
    # 危险：(\d{2,4})* - 数字范围嵌套
    pattern3 = re.compile(r"(\d{2,4})*")
    
    return pattern1, pattern2, pattern3


# ========== 测试5: 实际场景中的ReDoS ==========

def validate_email_vulnerable(email):
    """危险：邮箱验证的 ReDoS 漏洞"""
    # 这个模式因为嵌套量词可能导致 ReDoS
    pattern = re.compile(r"^([a-zA-Z0-9])+@([a-zA-Z0-9])+\.([a-zA-Z])+$")
    return pattern.match(email)


def validate_url_vulnerable(url):
    """危险：URL 验证的 ReDoS 漏洞"""
    # 重叠的交替模式
    pattern = re.compile(r"(http|https)://(\w+)+\.(\w+)+")
    return pattern.match(url)


def parse_json_vulnerable(text):
    """危险：JSON 解析的 ReDoS 漏洞"""
    # 贪婪匹配嵌套
    pattern = re.compile(r'(\s*"[^"]*"\s*:\s*"[^"]*"\s*,?\s*)+')
    return pattern.findall(text)


def extract_tags_vulnerable(html):
    """危险：HTML 标签提取的 ReDoS 漏洞"""
    # .*+ 嵌套非常危险
    pattern = re.compile(r"<(\w+)>(.*)+</\1>")
    return pattern.findall(html)


# ========== 测试6: 使用 re 模块的不同函数 ==========

def test_different_re_functions():
    """测试不同的 re 函数调用"""
    
    # re.match()
    result1 = re.match(r"(a+)+b", "aaaaab")
    
    # re.search()
    result2 = re.search(r"(\d+)+", "12345")
    
    # re.findall()
    result3 = re.findall(r"(\w+)+", "hello world")
    
    # re.sub()
    result4 = re.sub(r"(a*)*", "x", "aaaa")
    
    # re.split()
    result5 = re.split(r"(,\s*)+", "a, b, c")
    
    return result1, result2, result3, result4, result5


# ========== 测试7: 安全的模式（不应该被检测到）==========

def test_safe_patterns():
    """这些模式是安全的，不应该被报告为 ReDoS"""
    
    # 安全：简单量词
    pattern1 = re.compile(r"a+")
    
    # 安全：非嵌套交替
    pattern2 = re.compile(r"(cat|dog)")
    
    # 安全：固定重复
    pattern3 = re.compile(r"a{3}")
    
    # 安全：非贪婪匹配
    pattern4 = re.compile(r"a+?")
    
    # 安全：简单字符类
    pattern5 = re.compile(r"\w+")
    
    # 安全：锚点约束
    pattern6 = re.compile(r"^[a-z]+$")
    
    return pattern1, pattern2, pattern3, pattern4, pattern5, pattern6


# ========== 测试8: from re import 语法 ==========

def test_import_from():
    """测试 from re import compile 的情况"""
    from re import compile, match, search
    
    # 应该被检测到
    pattern1 = compile(r"(a+)+")
    
    # 应该被检测到
    result1 = match(r"(\d+)+", "12345")
    
    # 应该被检测到
    result2 = search(r"(\w+)+", "hello")
    
    return pattern1, result1, result2


if __name__ == "__main__":
    print("ReDoS 测试样例文件")
    print("运行扫描器检测这些漏洞模式")
