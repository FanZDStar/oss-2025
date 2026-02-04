"""
忽略规则检查器
用于检测代码中的 pysec 忽略注释
"""

import re

class IgnoreChecker:
    """忽略规则检查器"""
    
    def __init__(self, source_code: str = ""):
        """
        初始化检查器
        
        Args:
            source_code: 源代码字符串
        """
        self.source_code = source_code
        self.lines = source_code.splitlines() if source_code else []
    
    def should_ignore_line(self, line_text: str, rule_id: str = None) -> bool:
        """
        检查一行代码是否应被忽略
        
        Args:
            line_text: 一行代码文本
            rule_id: 规则ID，如 'SQL001'
        
        Returns:
            bool: True表示应忽略
        """
        # 1. 检查通用忽略： # pysec: ignore
        if "# pysec: ignore" in line_text:
            # 如果没有指定规则ID，忽略所有
            if rule_id is None:
                return True
            # 如果注释是 # pysec: ignore（没有括号），也忽略所有规则
            if "ignore[" not in line_text:
                return True
        
        # 2. 检查指定规则忽略： # pysec: ignore[SQL001]
        if rule_id is not None and f"ignore[{rule_id}]" in line_text:
            return True
        
        return False
    
    def analyze_file_ignore(self):
        """
        分析整个文件的忽略情况
        
        Returns:
            dict: 包含文件忽略状态和代码块忽略信息
        """
        result = {
            "ignore_file": False,  # 文件级别忽略
            "disabled_blocks": [],  # 被禁用的代码块 [(start_line, end_line)]
        }
        
        current_block_start = None
        
        for i, line in enumerate(self.lines, 1):  # 行号从1开始
            line_stripped = line.strip()
            
            # 检查文件级别忽略（通常在文件开头）
            if i <= 5 and "# pysec: ignore-file" in line_stripped:
                result["ignore_file"] = True
            
            # 检查代码块开始
            if "# pysec: disable" in line_stripped:
                current_block_start = i
            
            # 检查代码块结束
            if "# pysec: enable" in line_stripped and current_block_start is not None:
                result["disabled_blocks"].append((current_block_start, i))
                current_block_start = None
        
        # 如果 disable 没有对应的 enable，忽略到文件末尾
        if current_block_start is not None:
            result["disabled_blocks"].append((current_block_start, len(self.lines)))
        
        return result
    
    def is_line_in_disabled_block(self, line_number: int, disabled_blocks: list) -> bool:
        """
        检查某一行是否在禁用的代码块中
        
        Args:
            line_number: 行号
            disabled_blocks: 从 analyze_file_ignore() 获取的禁用块列表
        
        Returns:
            bool: True表示在禁用块中
        """
        for start, end in disabled_blocks:
            if start <= line_number <= end:
                return True
        return False
    
    def should_ignore_vulnerability(self, vulnerability, source_code_lines=None):
        """
        判断一个漏洞是否应被忽略（核心函数）
        
        Args:
            vulnerability: 一个漏洞对象，它至少应该有 line（行号）和 rule_id（规则ID）
            source_code_lines: 源代码按行分割的列表。如果为None，则用 self.lines
        
        Returns:
            bool: True 表示应忽略，False 表示应报告
        """
        if source_code_lines is None:
            source_code_lines = self.lines
        
        line_number = vulnerability.get('line')  # 漏洞所在行号
        rule_id = vulnerability.get('rule_id')   # 触发的规则ID，如 'SQL001'
        
        if line_number is None or line_number > len(source_code_lines):
            # 行号无效，默认不忽略
            return False
        
        # 获取漏洞所在行的代码文本
        line_text = source_code_lines[line_number - 1]  # 列表索引从0开始，行号从1开始
        
        # 1. 先检查这一行是否因为任何原因被全局忽略（单行忽略或处于禁用块中）
        # 1.1 检查单行忽略
        if self.should_ignore_line(line_text, rule_id=None):
            # 如果有 # pysec: ignore（不带规则ID），忽略所有
            return True
        
        # 1.2 检查是否处于 # pysec: disable ... # pysec: enable 代码块中
        file_ignore_info = self.analyze_file_ignore()
        if self.is_line_in_disabled_block(line_number, file_ignore_info['disabled_blocks']):
            return True
        
        # 2. 检查指定规则忽略
        if rule_id and self.should_ignore_line(line_text, rule_id):
            # 如果有 # pysec: ignore[SQL001]，且当前漏洞正是 SQL001
            return True
        
        # 3. 如果以上都不是，则不忽略
        return False