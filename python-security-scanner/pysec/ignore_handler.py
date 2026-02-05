"""
忽略规则处理模块

支持多种忽略注释格式：
- 行内忽略: # pysec: ignore 或 # pysec: ignore[RULE001]
- 代码块忽略: # pysec: disable ... # pysec: enable
- 文件级别忽略: # pysec: ignore-file 或 # pysec: ignore-file[RULE001]
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict, Tuple


@dataclass
class IgnoreDirective:
    """忽略指令数据类"""

    line_number: int  # 指令所在行号
    directive_type: str  # 指令类型: 'ignore', 'ignore-file', 'disable', 'enable'
    rule_ids: Optional[List[str]] = None  # 指定的规则ID列表，None表示所有规则

    def applies_to_rule(self, rule_id: str) -> bool:
        """判断该指令是否适用于指定规则"""
        if self.rule_ids is None:
            return True
        return rule_id in self.rule_ids


@dataclass
class IgnoreContext:
    """忽略上下文，包含文件的所有忽略信息"""

    file_path: str
    # 文件级别忽略的规则ID，None表示忽略所有
    file_level_ignore: Optional[Set[str]] = None
    file_level_ignore_all: bool = False
    # 行内忽略: {行号: [规则ID列表或None]}
    line_ignores: Dict[int, Optional[List[str]]] = field(default_factory=dict)
    # 代码块忽略: [(start_line, end_line, [规则ID列表或None])]
    block_ignores: List[Tuple[int, int, Optional[List[str]]]] = field(default_factory=list)
    # 统计信息
    ignored_count: int = 0

    def should_ignore(self, line_number: int, rule_id: str) -> bool:
        """
        判断指定行的指定规则是否应该被忽略

        Args:
            line_number: 行号
            rule_id: 规则ID

        Returns:
            是否应该忽略
        """
        # 检查文件级别忽略
        if self.file_level_ignore_all:
            return True
        if self.file_level_ignore and rule_id in self.file_level_ignore:
            return True

        # 检查行内忽略
        if line_number in self.line_ignores:
            rule_ids = self.line_ignores[line_number]
            if rule_ids is None:  # 忽略所有规则
                return True
            if rule_id in rule_ids:
                return True

        # 检查代码块忽略
        for start_line, end_line, rule_ids in self.block_ignores:
            if start_line <= line_number <= end_line:
                if rule_ids is None:  # 忽略所有规则
                    return True
                if rule_id in rule_ids:
                    return True

        return False


class IgnoreHandler:
    """忽略规则处理器"""

    # 正则表达式模式
    # 匹配: # pysec: ignore 或 # pysec: ignore[RULE001] 或 # pysec: ignore[RULE001, RULE002]
    INLINE_IGNORE_PATTERN = re.compile(r"#\s*pysec:\s*ignore(?:\[([^\]]+)\])?\s*$", re.IGNORECASE)

    # 匹配: # pysec: ignore-file 或 # pysec: ignore-file[RULE001]
    FILE_IGNORE_PATTERN = re.compile(
        r"#\s*pysec:\s*ignore-file(?:\[([^\]]+)\])?\s*$", re.IGNORECASE
    )

    # 匹配: # pysec: disable 或 # pysec: disable[RULE001]
    BLOCK_DISABLE_PATTERN = re.compile(r"#\s*pysec:\s*disable(?:\[([^\]]+)\])?\s*$", re.IGNORECASE)

    # 匹配: # pysec: enable 或 # pysec: enable[RULE001]
    BLOCK_ENABLE_PATTERN = re.compile(r"#\s*pysec:\s*enable(?:\[([^\]]+)\])?\s*$", re.IGNORECASE)

    @classmethod
    def parse_source(cls, source_code: str, file_path: str = "<string>") -> IgnoreContext:
        """
        解析源代码中的忽略指令

        Args:
            source_code: 源代码
            file_path: 文件路径

        Returns:
            IgnoreContext 对象
        """
        context = IgnoreContext(file_path=file_path)
        lines = source_code.split("\n")

        # 追踪当前活跃的 disable 块
        # 格式: {rule_id或None: start_line}
        active_disables: Dict[Optional[str], int] = {}

        for line_number, line in enumerate(lines, start=1):
            # 检查文件级别忽略（通常在文件开头）
            file_match = cls.FILE_IGNORE_PATTERN.search(line)
            if file_match:
                rule_ids = cls._parse_rule_ids(file_match.group(1))
                if rule_ids is None:
                    context.file_level_ignore_all = True
                else:
                    if context.file_level_ignore is None:
                        context.file_level_ignore = set()
                    context.file_level_ignore.update(rule_ids)
                continue

            # 检查代码块 disable
            disable_match = cls.BLOCK_DISABLE_PATTERN.search(line)
            if disable_match:
                rule_ids = cls._parse_rule_ids(disable_match.group(1))
                if rule_ids is None:
                    # 禁用所有规则
                    active_disables[None] = line_number
                else:
                    # 禁用指定规则
                    for rule_id in rule_ids:
                        active_disables[rule_id] = line_number
                continue

            # 检查代码块 enable
            enable_match = cls.BLOCK_ENABLE_PATTERN.search(line)
            if enable_match:
                rule_ids = cls._parse_rule_ids(enable_match.group(1))
                if rule_ids is None:
                    # 启用所有规则 - 关闭所有活跃的 disable 块
                    for key, start_line in list(active_disables.items()):
                        block_rule_ids = None if key is None else [key]
                        context.block_ignores.append(
                            (start_line + 1, line_number - 1, block_rule_ids)
                        )
                    active_disables.clear()
                else:
                    # 启用指定规则
                    for rule_id in rule_ids:
                        if rule_id in active_disables:
                            start_line = active_disables.pop(rule_id)
                            context.block_ignores.append(
                                (start_line + 1, line_number - 1, [rule_id])
                            )
                    # 如果有全局 disable，也需要检查
                    if None in active_disables:
                        start_line = active_disables.pop(None)
                        context.block_ignores.append((start_line + 1, line_number - 1, None))
                continue

            # 检查行内忽略
            inline_match = cls.INLINE_IGNORE_PATTERN.search(line)
            if inline_match:
                rule_ids = cls._parse_rule_ids(inline_match.group(1))
                context.line_ignores[line_number] = rule_ids
                continue

        # 处理未闭合的 disable 块（一直到文件末尾）
        total_lines = len(lines)
        for key, start_line in active_disables.items():
            block_rule_ids = None if key is None else [key]
            context.block_ignores.append((start_line + 1, total_lines, block_rule_ids))

        return context

    @classmethod
    def _parse_rule_ids(cls, rule_str: Optional[str]) -> Optional[List[str]]:
        """
        解析规则ID字符串

        Args:
            rule_str: 规则ID字符串，如 "SQL001" 或 "SQL001, CMD001"

        Returns:
            规则ID列表，如果为空则返回 None（表示所有规则）
        """
        if rule_str is None:
            return None

        # 分割并清理
        rule_ids = [rid.strip().upper() for rid in rule_str.split(",")]
        rule_ids = [rid for rid in rule_ids if rid]

        return rule_ids if rule_ids else None

    @classmethod
    def filter_vulnerabilities(
        cls, vulnerabilities: list, source_code: str, file_path: str
    ) -> Tuple[list, int]:
        """
        过滤漏洞列表，移除被忽略的漏洞

        Args:
            vulnerabilities: 漏洞列表
            source_code: 源代码
            file_path: 文件路径

        Returns:
            (过滤后的漏洞列表, 被忽略的漏洞数量)
        """
        if not vulnerabilities:
            return vulnerabilities, 0

        context = cls.parse_source(source_code, file_path)

        filtered = []
        ignored_count = 0

        for vuln in vulnerabilities:
            if context.should_ignore(vuln.line_number, vuln.rule_id):
                ignored_count += 1
            else:
                filtered.append(vuln)

        return filtered, ignored_count


def should_ignore_line(source_code: str, line_number: int, rule_id: str) -> bool:
    """
    便捷函数：判断指定行的指定规则是否应该被忽略

    Args:
        source_code: 源代码
        line_number: 行号
        rule_id: 规则ID

    Returns:
        是否应该忽略
    """
    context = IgnoreHandler.parse_source(source_code)
    return context.should_ignore(line_number, rule_id)
