"""
忽略规则注释处理模块

支持以下注释格式：
1. # pysec: ignore - 忽略该行所有规则
2. # pysec: ignore[SQL001] - 忽略该行指定规则
3. # pysec: ignore[SQL001,CMD001] - 忽略该行多个规则
4. # pysec: disable ... # pysec: enable - 忽略代码块
"""

import re
from typing import Set, Optional, Dict, List


class IgnoreCommentParser:
    """忽略注释解析器"""

    # 匹配 # pysec: ignore 或 # pysec: ignore[RULE001]
    IGNORE_PATTERN = re.compile(
        r'#\s*pysec:\s*ignore(?:\[([\w,\s]+)\])?',
        re.IGNORECASE
    )

    # 匹配 # pysec: disable
    DISABLE_PATTERN = re.compile(
        r'#\s*pysec:\s*disable',
        re.IGNORECASE
    )

    # 匹配 # pysec: enable
    ENABLE_PATTERN = re.compile(
        r'#\s*pysec:\s*enable',
        re.IGNORECASE
    )

    def __init__(self, source_code: str):
        """
        初始化解析器

        Args:
            source_code: 源代码内容
        """
        self.source_code = source_code
        self.lines = source_code.split('\n')
        self._parse_ignore_comments()

    def _parse_ignore_comments(self):
        """解析所有忽略注释"""
        # 行级忽略：{行号: set(规则ID) 或 None (表示忽略所有)}
        self.line_ignores: Dict[int, Optional[Set[str]]] = {}
        
        # 代码块忽略状态
        self.disabled_ranges: List[tuple] = []  # [(start_line, end_line), ...]
        
        disable_start = None
        
        for line_num, line in enumerate(self.lines, start=1):
            # 检查行级忽略
            ignore_match = self.IGNORE_PATTERN.search(line)
            if ignore_match:
                rules_str = ignore_match.group(1)
                if rules_str:
                    # 指定了规则ID
                    rule_ids = {r.strip() for r in rules_str.split(',') if r.strip()}
                    self.line_ignores[line_num] = rule_ids
                else:
                    # 忽略所有规则
                    self.line_ignores[line_num] = None

            # 检查代码块禁用
            if self.DISABLE_PATTERN.search(line):
                if disable_start is None:
                    disable_start = line_num
            
            # 检查代码块启用
            elif self.ENABLE_PATTERN.search(line):
                if disable_start is not None:
                    self.disabled_ranges.append((disable_start, line_num))
                    disable_start = None
        
        # 如果有未关闭的 disable，忽略到文件末尾
        if disable_start is not None:
            self.disabled_ranges.append((disable_start, len(self.lines)))

    def should_ignore(self, line_number: int, rule_id: str) -> bool:
        """
        检查指定行和规则是否应该被忽略

        Args:
            line_number: 行号（从1开始）
            rule_id: 规则ID，如 "SQL001"

        Returns:
            True 如果应该忽略，False 否则
        """
        # 检查是否在禁用的代码块中
        for start, end in self.disabled_ranges:
            if start <= line_number <= end:
                return True
        
        # 检查行级忽略
        if line_number in self.line_ignores:
            ignored_rules = self.line_ignores[line_number]
            # None 表示忽略所有规则
            if ignored_rules is None:
                return True
            # 检查特定规则是否被忽略
            if rule_id in ignored_rules:
                return True
        
        return False

    def get_ignore_stats(self) -> dict:
        """获取忽略统计信息"""
        return {
            'line_ignores': len(self.line_ignores),
            'block_ignores': len(self.disabled_ranges),
            'total_ignored_lines': sum(
                end - start + 1 for start, end in self.disabled_ranges
            )
        }


def should_ignore_vulnerability(source_code: str, line_number: int, rule_id: str) -> bool:
    """
    便捷函数：检查漏洞是否应该被忽略

    Args:
        source_code: 源代码内容
        line_number: 漏洞所在行号
        rule_id: 规则ID

    Returns:
        True 如果应该忽略，False 否则
    """
    parser = IgnoreCommentParser(source_code)
    return parser.should_ignore(line_number, rule_id)
