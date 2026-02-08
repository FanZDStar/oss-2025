"""终端彩色输出工具

支持 ANSI 颜色代码的终端彩色输出，并提供 Windows 兼容性处理
"""

import os
import sys
import platform
from typing import Optional


# ANSI 颜色代码
class ANSIColors:
    """ANSI 转义序列颜色代码"""
    
    # 基础颜色
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    # 前景色
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # 亮色
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    # 背景色
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


class ColorSupport:
    """终端颜色支持检测"""
    
    _enabled: Optional[bool] = None
    _forced: Optional[bool] = None
    
    @classmethod
    def is_enabled(cls) -> bool:
        """检测终端是否支持颜色输出"""
        # 如果用户强制启用/禁用
        if cls._forced is not None:
            return cls._forced
        
        # 缓存检测结果
        if cls._enabled is not None:
            return cls._enabled
        
        # 检测是否支持颜色
        cls._enabled = cls._detect_color_support()
        return cls._enabled
    
    @classmethod
    def _detect_color_support(cls) -> bool:
        """自动检测终端颜色支持"""
        # 检查环境变量
        if os.getenv('NO_COLOR'):
            return False
        
        if os.getenv('FORCE_COLOR'):
            return True
        
        # 检查 TERM 环境变量
        term = os.getenv('TERM', '')
        if term == 'dumb':
            return False
        
        # 检查标准输出是否是终端
        if not hasattr(sys.stdout, 'isatty'):
            return False
        
        if not sys.stdout.isatty():
            return False
        
        # Windows 特殊处理
        if platform.system() == 'Windows':
            return cls._enable_windows_ansi_support()
        
        # Unix/Linux/macOS 默认支持
        return True
    
    @classmethod
    def _enable_windows_ansi_support(cls) -> bool:
        """启用 Windows 终端 ANSI 支持"""
        try:
            # Windows 10+ 支持 ANSI 转义序列
            import ctypes
            
            # 获取标准输出句柄
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            
            # 获取当前控制台模式
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            
            # 启用 ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004)
            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
            
            # 设置新模式
            success = kernel32.SetConsoleMode(handle, new_mode)
            return bool(success)
        
        except Exception:
            # 如果失败，检查是否是新版 Windows Terminal
            return os.getenv('WT_SESSION') is not None
    
    @classmethod
    def enable(cls):
        """强制启用颜色输出"""
        cls._forced = True
    
    @classmethod
    def disable(cls):
        """强制禁用颜色输出"""
        cls._forced = False
    
    @classmethod
    def reset(cls):
        """重置颜色设置（重新自动检测）"""
        cls._forced = None
        cls._enabled = None


def colorize(text: str, color: str, bold: bool = False) -> str:
    """
    为文本添加颜色
    
    Args:
        text: 要着色的文本
        color: ANSI 颜色代码
        bold: 是否加粗
    
    Returns:
        着色后的文本
    """
    if not ColorSupport.is_enabled():
        return text
    
    prefix = ANSIColors.BOLD + color if bold else color
    return f"{prefix}{text}{ANSIColors.RESET}"


def red(text: str, bold: bool = False) -> str:
    """红色文本（用于 CRITICAL）"""
    return colorize(text, ANSIColors.BRIGHT_RED, bold)


def orange(text: str, bold: bool = False) -> str:
    """橙色文本（用于 HIGH）"""
    return colorize(text, ANSIColors.YELLOW, bold)  # 使用黄色模拟橙色


def yellow(text: str, bold: bool = False) -> str:
    """黄色文本（用于 MEDIUM）"""
    return colorize(text, ANSIColors.BRIGHT_YELLOW, bold)


def green(text: str, bold: bool = False) -> str:
    """绿色文本（用于 LOW/SUCCESS）"""
    return colorize(text, ANSIColors.GREEN, bold)


def blue(text: str, bold: bool = False) -> str:
    """蓝色文本（用于信息）"""
    return colorize(text, ANSIColors.CYAN, bold)


def gray(text: str) -> str:
    """灰色文本（用于次要信息）"""
    return colorize(text, ANSIColors.BRIGHT_BLACK, False)


def bold(text: str) -> str:
    """加粗文本"""
    if not ColorSupport.is_enabled():
        return text
    return f"{ANSIColors.BOLD}{text}{ANSIColors.RESET}"


def severity_color(severity: str, text: str, bold: bool = True) -> str:
    """
    根据严重程度着色文本
    
    Args:
        severity: 严重程度（critical/high/medium/low）
        text: 要着色的文本
        bold: 是否加粗
    
    Returns:
        着色后的文本
    """
    severity_lower = severity.lower()
    
    if severity_lower == 'critical':
        return red(text, bold)
    elif severity_lower == 'high':
        return orange(text, bold)
    elif severity_lower == 'medium':
        return yellow(text, bold)
    elif severity_lower == 'low':
        return green(text, bold)
    else:
        return text


def severity_badge(severity: str) -> str:
    """
    生成带颜色的严重程度标记
    
    Args:
        severity: 严重程度
    
    Returns:
        带颜色的严重程度标记
    """
    severity_upper = severity.upper()
    
    if severity.lower() == 'critical':
        return red(f"[!!!] [{severity_upper}]", bold=True)
    elif severity.lower() == 'high':
        return orange(f"[!!] [{severity_upper}]", bold=True)
    elif severity.lower() == 'medium':
        return yellow(f"[!] [{severity_upper}]", bold=True)
    elif severity.lower() == 'low':
        return green(f"[·] [{severity_upper}]", bold=True)
    else:
        return f"[?] [{severity_upper}]"


def header(text: str) -> str:
    """生成标题（蓝色加粗）"""
    return blue(text, bold=True)


def success(text: str) -> str:
    """成功消息（绿色）"""
    return green(f"✓ {text}", bold=True)


def error(text: str) -> str:
    """错误消息（红色）"""
    return red(f"✗ {text}", bold=True)


def warning(text: str) -> str:
    """警告消息（黄色）"""
    return yellow(f"⚠ {text}", bold=True)


def info(text: str) -> str:
    """信息消息（蓝色）"""
    return blue(f"ℹ {text}")


# 导出常用函数
__all__ = [
    'ANSIColors',
    'ColorSupport',
    'colorize',
    'red',
    'orange',
    'yellow',
    'green',
    'blue',
    'gray',
    'bold',
    'severity_color',
    'severity_badge',
    'header',
    'success',
    'error',
    'warning',
    'info',
]
