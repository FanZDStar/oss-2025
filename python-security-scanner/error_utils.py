"""
错误处理工具模块

负责生成友好的错误消息、解决建议和格式化错误追踪信息。
"""
import sys
import traceback
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

class ErrorFormatter:
    """错误格式化器，用于生成用户友好的错误信息"""
    
    # 常见错误类型与友好提示的映射
    ERROR_MESSAGES = {
        FileNotFoundError: "文件或目录不存在",
        PermissionError: "没有权限访问该文件或目录",
        IsADirectoryError: "这是一个目录，而不是文件",
        SyntaxError: "Python代码存在语法错误",
        UnicodeDecodeError: "文件编码不是UTF-8，无法正确读取",
        ImportError: "导入模块失败",
        ValueError: "参数值不正确",
        TypeError: "参数类型不正确",
        KeyError: "访问了不存在的键",
        AttributeError: "对象没有这个属性",
        RuntimeError: "运行时发生错误",
        TimeoutError: "操作超时",
        MemoryError: "内存不足",
        KeyboardInterrupt: "用户中断了操作",
    }
    
    # 常见问题与解决建议的映射
    SOLUTIONS = {
        "FileNotFoundError": [
            "1. 检查文件路径是否正确，注意大小写",
            "2. 确认文件是否已被移动或删除",
            "3. 使用绝对路径而不是相对路径",
            "4. 检查当前工作目录是否正确",
        ],
        "PermissionError": [
            "1. 确认您有该文件的读取权限",
            "2. 如果是目录，确认您有进入目录的权限",
            "3. 在Windows上，尝试以管理员身份运行",
            "4. 检查文件是否被其他程序独占锁定",
        ],
        "SyntaxError": [
            "1. 检查代码中是否有拼写错误",
            "2. 确认括号、引号是否匹配",
            "3. 检查缩进是否正确（Python对缩进敏感）",
            "4. 使用Python解释器直接运行该文件，查看详细错误",
        ],
        "UnicodeDecodeError": [
            "1. 文件可能不是UTF-8编码，尝试使用其他编码（如gbk, latin-1）",
            "2. 使用文本编辑器（如VSCode, Notepad++）转换文件编码为UTF-8",
            "3. 检查文件中是否包含二进制内容",
            "4. 使用 `chardet` 库自动检测文件编码",
        ],
        "ImportError": [
            "1. 确认模块名称拼写是否正确",
            "2. 检查模块是否已安装（使用 `pip list`）",
            "3. 如果是本地模块，检查 `__init__.py` 文件是否存在",
            "4. 检查Python路径（sys.path）是否包含模块所在目录",
        ],
        "扫描速度慢": [
            "1. 使用 `--no-cache` 参数重新扫描，建立新的缓存",
            "2. 排除不需要扫描的大目录（如 `venv`, `.git`, `node_modules`）",
            "3. 使用 `--file-timeout` 参数限制单个文件的扫描时间",
            "4. 考虑分批扫描大型项目",
        ],
        "没有发现漏洞": [
            "1. 确认您扫描的是Python代码文件（.py后缀）",
            "2. 代码可能确实很安全，或者使用了规避模式",
            "3. 尝试扫描一些包含已知安全问题的测试文件",
            "4. 考虑调整或添加安全检测规则",
        ],
    }
    
    @classmethod
    def get_friendly_message(cls, exception: Exception) -> str:
        """
        获取用户友好的错误消息
        
        Args:
            exception: 异常对象
            
        Returns:
            友好的错误消息字符串
        """
        # 首先尝试从映射表中获取友好消息
        for error_type, friendly_msg in cls.ERROR_MESSAGES.items():
            if isinstance(exception, error_type):
                base_msg = f"{friendly_msg}"
                
                # 为特定错误添加详细信息
                if isinstance(exception, FileNotFoundError):
                    file_path = str(exception).split("'")[1] if "'" in str(exception) else "未知路径"
                    return f"{base_msg}: {file_path}"
                elif isinstance(exception, SyntaxError):
                    return f"{base_msg}（行 {exception.lineno}）：{exception.msg}"
                elif isinstance(exception, PermissionError):
                    file_path = str(exception).split("'")[1] if "'" in str(exception) else "未知路径"
                    return f"{base_msg}: {file_path}"
                else:
                    return f"{base_msg}: {str(exception)[:100]}"
        
        # 如果不在映射表中，返回通用的友好消息
        return f"处理过程中发生错误: {type(exception).__name__} - {str(exception)[:100]}"
    
    @classmethod
    def get_suggestions(cls, exception_type: str, context: Dict[str, Any] = None) -> List[str]:
        """
        获取针对特定错误的解决建议
        
        Args:
            exception_type: 异常类型名称
            context: 错误上下文信息
            
        Returns:
            解决建议列表
        """
        suggestions = []
        
        # 添加通用建议
        suggestions.append("通用建议:")
        suggestions.append("  • 检查命令参数是否正确")
        suggestions.append("  • 确保文件路径没有拼写错误")
        suggestions.append("  • 查看帮助信息: python main.py --help")
        
        # 添加针对特定错误的建议
        if exception_type in cls.SOLUTIONS:
            suggestions.append(f"针对 {exception_type} 的建议:")
            for solution in cls.SOLUTIONS[exception_type]:
                suggestions.append(f"  {solution}")
        
        # 根据上下文添加额外建议
        if context:
            if "file_path" in context:
                file_path = context["file_path"]
                if not os.path.exists(file_path):
                    suggestions.append("\n 路径检查:")
                    suggestions.append(f"  • 文件 '{file_path}' 不存在")
                    suggestions.append("  • 使用 `ls` 或 `dir` 命令查看当前目录内容")
            
            if "file_size" in context and context["file_size"] > 10 * 1024 * 1024:  # 10MB
                suggestions.append(" 大文件处理建议:")
                suggestions.append("  • 考虑排除此文件或使用 --file-timeout 参数")
                suggestions.append("  • 检查是否为必要的代码文件")
        
        return suggestions
    
    @classmethod
    def format_traceback(cls, exception: Exception, verbose_level: int = 0) -> str:
        """
        格式化错误追踪信息
        
        Args:
            exception: 异常对象
            verbose_level: 详细级别（0-3）
            
        Returns:
            格式化的错误追踪信息
        """
        if verbose_level <= 0:
            return ""
        
        tb_lines = []
        
        if verbose_level >= 1:
            # 基本追踪信息
            tb_lines.append("\n" + "═" * 60)
            tb_lines.append("错误追踪信息 (用于调试):")
            tb_lines.append("═" * 60)
            
            # 获取完整的traceback信息
            tb_text = traceback.format_exc()
            
            if verbose_level == 1:
                # 仅显示最后几行
                lines = tb_text.strip().split('\n')
                if len(lines) > 8:
                    tb_lines.extend(lines[-8:])
                else:
                    tb_lines.append(tb_text)
            
            elif verbose_level >= 2:
                # 显示完整traceback，并进行格式化
                lines = tb_text.strip().split('\n')
                for i, line in enumerate(lines):
                    if "File \"" in line and ", line" in line:
                        # 文件路径行，添加缩进和图标
                        tb_lines.append(f"  📄 {line}")
                    elif line.strip().startswith("^"):
                        # 错误指示行
                        tb_lines.append(f"     {line}")
                    else:
                        # 其他行
                        tb_lines.append(f"  {line}")
        
        if verbose_level >= 3:
            # 添加额外的调试信息
            tb_lines.append("\n" + "─" * 60)
            tb_lines.append("调试信息:")
            tb_lines.append("─" * 60)
            tb_lines.append(f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            tb_lines.append(f"  平台: {sys.platform}")
            tb_lines.append(f"  Python版本: {sys.version.split()[0]}")
            tb_lines.append(f"  工作目录: {os.getcwd()}")
            tb_lines.append(f"  系统编码: {sys.getdefaultencoding()}")
            
            # 环境变量信息（部分）
            env_vars = ["PATH", "PYTHONPATH", "HOME", "USER"]
            tb_lines.append(f"  相关环境变量:")
            for var in env_vars:
                if var in os.environ:
                    value = os.environ[var]
                    if len(value) > 100:
                        value = value[:100] + "..."
                    tb_lines.append(f"    {var}={value}")
        
        return "\n".join(tb_lines)
    
    @classmethod
    def create_error_report(cls, exception: Exception, context: Dict[str, Any] = None, 
                           verbose_level: int = 0) -> str:
        """
        创建完整的错误报告
        
        Args:
            exception: 异常对象
            context: 错误上下文
            verbose_level: 详细级别
            
        Returns:
            完整的错误报告字符串
        """
        report_lines = []
        
        # 1. 错误标题
        report_lines.append("PySec 扫描错误")
        report_lines.append("─" * 40)
        
        # 2. 友好的错误消息
        friendly_msg = cls.get_friendly_message(exception)
        report_lines.append(f"问题: {friendly_msg}")
        
        # 3. 解决建议
        suggestions = cls.get_suggestions(type(exception).__name__, context)
        report_lines.append("\n建议:")
        for suggestion in suggestions:
            report_lines.append(f"  {suggestion}")
        
        # 4. 格式化追踪信息
        traceback_info = cls.format_traceback(exception, verbose_level)
        if traceback_info:
            report_lines.append(traceback_info)
        
        # 5. 联系信息（可选）
        report_lines.append("\n" + "─" * 40)
        report_lines.append("如需进一步帮助:")
        report_lines.append("  • 查看完整文档")
        report_lines.append("  • 联系项目维护者")
        
        return "\n".join(report_lines)


def handle_scan_error(exception: Exception, file_path: str = None, 
                     verbose_level: int = 0) -> str:
    """
    处理扫描错误的便捷函数
    
    Args:
        exception: 异常对象
        file_path: 发生错误的文件路径（可选）
        verbose_level: 详细级别（0-3）
        
    Returns:
            格式化的错误信息
    """
    context = {}
    if file_path:
        context["file_path"] = file_path
        try:
            context["file_size"] = os.path.getsize(file_path)
        except:
            pass
    
    return ErrorFormatter.create_error_report(exception, context, verbose_level)