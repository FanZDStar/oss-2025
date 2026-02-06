"""
检测规则模块

自动加载并注册所有检测规则
"""

from .base import BaseRule, RULE_REGISTRY, register_rule

# 导入所有规则模块，触发规则注册
from . import sql_injection
from . import command_injection
from . import hardcoded_secrets
from . import dangerous_functions
from . import path_traversal
from . import xss
from . import insecure_random
from . import insecure_hash

__all__ = [
    "BaseRule",
    "RULE_REGISTRY",
    "register_rule",
    "list_rules",
    "get_rule",
]


def list_rules():
    """获取所有已注册的规则类列表"""
    return list(RULE_REGISTRY.values())


def get_rule(rule_id: str):
    """
    根据规则ID获取规则类

    Args:
        rule_id: 规则ID（如 SQL001）

    Returns:
        规则类，如果不存在返回None
    """
    return RULE_REGISTRY.get(rule_id)
