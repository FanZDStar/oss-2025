"""
上下文敏感的严重程度调整器

根据代码上下文动态调整漏洞的严重程度
"""

import re
from typing import List, Optional
from dataclasses import dataclass


# 高敏感路径模式（生产代码）
SENSITIVE_PATH_PATTERNS = [
    r"src/",
    r"app/",
    r"api/",
    r"core/",
    r"services/",
    r"handlers/",
    r"views/",
    r"routes/",
]

# 低敏感路径模式（测试/开发代码）
LOW_SENSITIVITY_PATH_PATTERNS = [
    r"tests?/",
    r"test_.*\.py$",
    r".*_test\.py$",
    r"examples?/",
    r"samples?/",
    r"docs?/",
    r"fixtures?/",
    r"mocks?/",
    r"scripts/",
    r"tools/",
]

# 敏感函数名模式（涉及认证/授权/支付等）
SENSITIVE_FUNCTION_PATTERNS = [
    r"auth",
    r"login",
    r"password",
    r"token",
    r"secret",
    r"payment",
    r"credit",
    r"transaction",
    r"admin",
    r"security",
    r"encrypt",
    r"decrypt",
    r"session",
    r"cookie",
]

# 用户输入相关模式
USER_INPUT_PATTERNS = [
    r"request\.",
    r"user_input",
    r"user_data",
    r"input\s*\(",
    r"raw_input\s*\(",
    r"form\[",
    r"params\[",
    r"query\[",
    r"args\.",
    r"kwargs\.",
]


@dataclass
class ContextInfo:
    """代码上下文信息"""

    file_path: str
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    code_snippet: str = ""
    line_number: int = 0


class SeverityAdjuster:
    """
    上下文敏感的严重程度调整器

    根据代码上下文自动调整漏洞的严重程度：
    - 测试代码中的漏洞会降低严重程度
    - 敏感路径/函数中的漏洞会提升严重程度
    - 涉及用户输入的漏洞会提升严重程度
    """

    # 严重程度级别（从高到低）
    SEVERITY_ORDER = ["critical", "high", "medium", "low"]

    def __init__(
        self,
        enabled: bool = True,
        upgrade_for_sensitive: bool = True,
        downgrade_for_tests: bool = True,
        consider_user_input: bool = True,
    ):
        """
        初始化调整器

        Args:
            enabled: 是否启用动态调整
            upgrade_for_sensitive: 是否为敏感上下文提升严重程度
            downgrade_for_tests: 是否为测试代码降低严重程度
            consider_user_input: 是否考虑用户输入因素
        """
        self.enabled = enabled
        self.upgrade_for_sensitive = upgrade_for_sensitive
        self.downgrade_for_tests = downgrade_for_tests
        self.consider_user_input = consider_user_input

    def adjust_severity(self, base_severity: str, context: ContextInfo) -> str:
        """
        根据上下文调整严重程度

        Args:
            base_severity: 基础严重程度
            context: 代码上下文信息

        Returns:
            调整后的严重程度
        """
        if not self.enabled:
            return base_severity

        severity = base_severity.lower()
        adjustment = 0  # 正数提升，负数降低

        # 检查是否为测试代码
        if self.downgrade_for_tests and self._is_test_code(context):
            adjustment -= 1

        # 检查是否为敏感路径
        if self.upgrade_for_sensitive and self._is_sensitive_path(context):
            adjustment += 1

        # 检查是否涉及敏感函数
        if self.upgrade_for_sensitive and self._is_sensitive_function(context):
            adjustment += 1

        # 检查是否涉及用户输入
        if self.consider_user_input and self._involves_user_input(context):
            adjustment += 1

        # 应用调整
        return self._apply_adjustment(severity, adjustment)

    def _is_test_code(self, context: ContextInfo) -> bool:
        """判断是否为测试代码"""
        file_path = context.file_path.lower().replace("\\", "/")

        for pattern in LOW_SENSITIVITY_PATH_PATTERNS:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True

        # 检查函数名是否以 test 开头
        if context.function_name:
            func_name = context.function_name.lower()
            if func_name.startswith("test") or func_name.startswith("_test"):
                return True

        return False

    def _is_sensitive_path(self, context: ContextInfo) -> bool:
        """判断是否为敏感路径"""
        file_path = context.file_path.lower().replace("\\", "/")

        for pattern in SENSITIVE_PATH_PATTERNS:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True

        return False

    def _is_sensitive_function(self, context: ContextInfo) -> bool:
        """判断是否为敏感函数或类"""
        # 检查函数名
        if context.function_name:
            func_name = context.function_name.lower()
            for pattern in SENSITIVE_FUNCTION_PATTERNS:
                if re.search(pattern, func_name, re.IGNORECASE):
                    return True

        # 检查类名
        if context.class_name:
            class_name = context.class_name.lower()
            for pattern in SENSITIVE_FUNCTION_PATTERNS:
                if re.search(pattern, class_name, re.IGNORECASE):
                    return True

        return False

    def _involves_user_input(self, context: ContextInfo) -> bool:
        """判断是否涉及用户输入"""
        code = context.code_snippet.lower()

        for pattern in USER_INPUT_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                return True

        return False

    def _apply_adjustment(self, severity: str, adjustment: int) -> str:
        """应用调整量到严重程度"""
        if adjustment == 0:
            return severity

        try:
            current_index = self.SEVERITY_ORDER.index(severity)
        except ValueError:
            return severity

        # 计算新索引（负调整提升严重程度，正调整降低）
        # 因为列表是从高到低排序的
        new_index = current_index - adjustment

        # 限制在有效范围内
        new_index = max(0, min(len(self.SEVERITY_ORDER) - 1, new_index))

        return self.SEVERITY_ORDER[new_index]

    def get_adjustment_reasons(self, context: ContextInfo) -> List[str]:
        """
        获取调整原因列表

        Args:
            context: 代码上下文信息

        Returns:
            调整原因列表
        """
        reasons = []

        if self._is_test_code(context):
            reasons.append("测试代码 (降低严重程度)")

        if self._is_sensitive_path(context):
            reasons.append("敏感路径 (提升严重程度)")

        if self._is_sensitive_function(context):
            reasons.append("敏感函数 (提升严重程度)")

        if self._involves_user_input(context):
            reasons.append("涉及用户输入 (提升严重程度)")

        return reasons


def create_context_from_vulnerability(vuln, source_code: str = "") -> ContextInfo:
    """
    从漏洞对象创建上下文信息

    Args:
        vuln: Vulnerability 对象
        source_code: 完整源代码

    Returns:
        ContextInfo 对象
    """
    return ContextInfo(
        file_path=vuln.file_path,
        function_name=getattr(vuln, "function_name", None),
        class_name=getattr(vuln, "class_name", None),
        code_snippet=vuln.code_snippet,
        line_number=vuln.line_number,
    )
