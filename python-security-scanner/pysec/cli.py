#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
命令行接口模块

提供友好的命令行交互体验，支持5.5友好的错误信息功能、3.3 SARIF格式支持,3.4增量扫描功能和6.5规则仓库功能
"""

import argparse
import sys
import os
import traceback
import time
from pathlib import Path
from datetime import datetime

from .engine import SecurityScanner
from .models import ScanConfig, ScanResult
from .reporter import get_reporter, REPORTER_REGISTRY
from .rules import list_rules, SecurityRule
from .config import Config
from .fixer import CodeFixer, get_fixer
from .progress import ProgressBar
from .colors import ColorSupport, header, bold, success, error, warning, info, severity_color, blue


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
        FileExistsError: "文件已存在",
        NotADirectoryError: "这不是一个目录",
    }
    
    # 常见问题与解决建议的映射
    SOLUTIONS = {
        "FileNotFoundError": [
            "1. 检查文件路径是否正确，注意大小写",
            "2. 确认文件是否已被移动或删除",
            "3. 使用绝对路径而不是相对路径",
            "4. 检查当前工作目录是否正确",
            "5. 使用 `ls` 或 `dir` 命令查看目录内容",
        ],
        "PermissionError": [
            "1. 确认您有该文件的读取权限",
            "2. 如果是目录，确认您有进入目录的权限",
            "3. 在Windows上，尝试以管理员身份运行",
            "4. 检查文件是否被其他程序独占锁定",
            "5. 使用 `chmod` 或文件属性对话框修改权限",
        ],
        "SyntaxError": [
            "1. 检查代码中是否有拼写错误",
            "2. 确认括号、引号是否匹配",
            "3. 检查缩进是否正确（Python对缩进敏感）",
            "4. 使用Python解释器直接运行该文件，查看详细错误",
            "5. 使用IDE或代码编辑器的语法检查功能",
        ],
        "UnicodeDecodeError": [
            "1. 文件可能不是UTF-8编码，尝试使用其他编码（如gbk, latin-1）",
            "2. 使用文本编辑器（如VSCode, Notepad++）转换文件编码为UTF-8",
            "3. 检查文件中是否包含二进制内容",
            "4. 使用 `chardet` 库自动检测文件编码",
            "5. 使用 `open(file, 'rb')` 以二进制模式读取",
        ],
        "ImportError": [
            "1. 确认模块名称拼写是否正确",
            "2. 检查模块是否已安装（使用 `pip list`）",
            "3. 如果是本地模块，检查 `__init__.py` 文件是否存在",
            "4. 检查Python路径（sys.path）是否包含模块所在目录",
            "5. 尝试重新安装依赖：`pip install -r requirements.txt`",
        ],
        "扫描速度慢": [
            "1. 使用 `--no-cache` 参数重新扫描，建立新的缓存",
            "2. 排除不需要扫描的大目录（如 `venv`, `.git`, `node_modules`）",
            "3. 使用 `--timeout` 参数限制总扫描时间",
            "4. 使用 `--file-timeout` 参数限制单个文件的扫描时间",
            "5. 考虑分批扫描大型项目",
        ],
        "没有发现漏洞": [
            "1. 确认您扫描的是Python代码文件（.py后缀）",
            "2. 代码可能确实很安全，或者使用了规避模式",
            "3. 尝试扫描一些包含已知安全问题的测试文件",
            "4. 考虑调整或添加安全检测规则",
            "5. 使用 `--rules` 参数指定特定的规则进行扫描",
        ],
        "Git相关错误": [
            "1. 确认当前目录是一个Git仓库",
            "2. 检查Git是否已正确安装和配置",
            "3. 确认 `--since` 参数指定的提交或分支存在",
            "4. 运行 `git status` 检查仓库状态",
            "5. 尝试使用 `--no-cache` 参数进行完整扫描",
        ],
    }
    
    @classmethod
    def get_friendly_message(cls, exception: Exception) -> str:
        """获取用户友好的错误消息"""
        # 首先尝试从映射表中获取友好消息
        for error_type, friendly_msg in cls.ERROR_MESSAGES.items():
            if isinstance(exception, error_type):
                base_msg = f"{friendly_msg}"
                
                # 为特定错误添加详细信息
                if isinstance(exception, FileNotFoundError):
                    file_path = str(exception).split("'")[1] if "'" in str(exception) else "未知路径"
                    return f"{base_msg}: {file_path}"
                elif isinstance(exception, SyntaxError):
                    return f"{base_msg}（行 {exception.lineno}）：{exception.msg}")
                elif isinstance(exception, PermissionError):
                    file_path = str(exception).split("'")[1] if "'" in str(exception) else "未知路径"
                    return f"{base_msg}: {file_path}"
                elif isinstance(exception, ImportError):
                    module_name = str(exception).split("'")[1] if "'" in str(exception) else "未知模块"
                    return f"{base_msg}: 无法导入模块 '{module_name}'"
                else:
                    error_str = str(exception)
                    if len(error_str) > 200:
                        error_str = error_str[:200] + "..."
                    return f"{base_msg}: {error_str}"
        
        # 如果不在映射表中，返回通用的友好消息
        error_str = str(exception)
        if len(error_str) > 200:
            error_str = error_str[:200] + "..."
        return f"处理过程中发生错误: {type(exception).__name__} - {error_str}"
    
    @classmethod
    def get_suggestions(cls, exception_type: str, context: dict = None) -> list:
        """获取针对特定错误的解决建议"""
        suggestions = []
        
        # 添加通用建议
        suggestions.append(" 通用建议:")
        suggestions.append("  • 检查命令参数是否正确")
        suggestions.append("  • 确保文件路径没有拼写错误")
        suggestions.append("  • 查看帮助信息: pysec scan --help")
        suggestions.append("  • 尝试使用 --verbose 参数获取更多信息")
        
        # 添加针对特定错误的建议
        if exception_type in cls.SOLUTIONS:
            suggestions.append(f"\n🔧 针对 {exception_type} 的建议:")
            for solution in cls.SOLUTIONS[exception_type]:
                suggestions.append(f"  {solution}")
        
        # 根据上下文添加额外建议
        if context:
            if "file_path" in context:
                file_path = context["file_path"]
                if not os.path.exists(file_path):
                    suggestions.append("\n 路径检查:")
                    suggestions.append(f"  • 文件 '{file_path}' 不存在")
                    suggestions.append(f"  • 当前工作目录: {os.getcwd()}")
            
            if "config_file" in context:
                suggestions.append("\n 配置文件检查:")
                suggestions.append(f"  • 配置文件: {context['config_file']}")
                suggestions.append("  • 确保配置文件格式正确（YAML或JSON）")
            
            if "git_error" in context:
                suggestions.append("\n Git相关问题:")
                suggestions.append("  • 确保当前目录是Git仓库")
                suggestions.append("  • 运行 `git status` 检查仓库状态")
                suggestions.append("  • 如果不需要Git功能，移除 --changed-only 或 --since 参数")
        
        return suggestions
    
    @classmethod
    def format_traceback(cls, exception: Exception, verbose_level: int = 0) -> str:
        """格式化错误追踪信息"""
        if verbose_level <= 0:
            return ""
        
        tb_lines = []
        
        if verbose_level >= 1:
            # 基本追踪信息
            tb_lines.append("\n" + "═" * 60)
            tb_lines.append(" 错误追踪信息 (用于调试):")
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
            tb_lines.append(" 调试信息:")
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
    def create_error_report(cls, exception: Exception, context: dict = None, 
                           verbose_level: int = 0) -> str:
        """创建完整的错误报告"""
        report_lines = []
        
        # 错误标题
        report_lines.append(" PySecScanner 错误报告")
        report_lines.append("─" * 50)
        
        # 友好的错误消息
        friendly_msg = cls.get_friendly_message(exception)
        report_lines.append(f"问题: {friendly_msg}")
        
        # 解决建议
        suggestions = cls.get_suggestions(type(exception).__name__, context)
        report_lines.append("\n建议:")
        for suggestion in suggestions:
            report_lines.append(f"  {suggestion}")
        
        # 格式化追踪信息
        traceback_info = cls.format_traceback(exception, verbose_level)
        if traceback_info:
            report_lines.append(traceback_info)
        
        # 联系信息和文档
        report_lines.append("\n" + "─" * 50)
        report_lines.append(" 如需进一步帮助:")
        report_lines.append("  • 运行 `pysec scan --help` 查看完整帮助")
        report_lines.append("  • 查看项目文档和示例")
        report_lines.append("  • 在GitHub Issues中报告问题")
        
        return "\n".join(report_lines)


def handle_command_error(exception: Exception, command: str = None, 
                        verbose_level: int = 0, context: dict = None) -> None:
    """
    处理命令行错误的便捷函数
    
    Args:
        exception: 异常对象
        command: 发生错误的命令（如'scan', 'rules'等）
        verbose_level: 详细级别（0-3）
        context: 错误上下文信息
    """
    if context is None:
        context = {}
    
    if command:
        context["command"] = command
    
    error_report = ErrorFormatter.create_error_report(exception, context, verbose_level)
    print(f"\n{error_report}", file=sys.stderr)


def create_parser() -> argparse.ArgumentParser:
    """创建命令行解析器"""
    parser = argparse.ArgumentParser(
        prog="pysec",
        description="PySecScanner - Python 代码安全漏洞静态分析工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  pysec scan ./myproject                    # 扫描目录
  pysec scan app.py                         # 扫描单个文件
  pysec scan ./src -o report.md -f markdown # 生成Markdown报告
  pysec scan ./src -f sarif                # 生成SARIF格式报告 (3.3任务)
  pysec scan ./src --exclude tests,docs     # 排除目录
  
  # 6.5规则仓库功能
  pysec rules install community/aws-rules   # 安装社区规则
  pysec rules install https://example.com/rule.py  # 从URL安装规则
  pysec rules install ./my_rule.py          # 从本地文件安装规则
  pysec rules list                          # 列出已安装规则
  pysec rules update                        # 更新所有规则
  pysec rules update community/aws-rules    # 更新指定规则
  pysec rules search sql                    # 搜索社区规则
  pysec rules uninstall community/aws-rules # 卸载规则
  
  # 其他命令
  pysec rules                               # 列出所有内置规则
  pysec rules --verbose                     # 显示规则详情
  pysec version                             # 显示版本信息
  # 3.4增量扫描功能
  pysec scan . --incremental               # 增量扫描，智能检测修改的文件
  pysec scan . --changed-only              # 仅扫描Git修改的文件
  pysec scan . --since HEAD~5              # 扫描最近5次提交修改的文件
  pysec scan . --since 1.day.ago           # 扫描最近1天修改的文件
  pysec scan . --full-scan                 # 强制完整扫描
  pysec scan . --clear-cache               # 清除增量扫描缓存
  
  # 其他命令
  pysec rules                              # 列出所有规则
  pysec rules --verbose                    # 显示规则详情

详细级别控制:
  -v         显示基础信息（默认）
  -vv        显示详细信息
  -vvv       显示调试信息（包括完整错误追踪）

错误处理改进:
  • 更清晰的错误消息（中文化）
  • 常见问题的解决建议
  • 调试模式支持 -vvv 参数
  • 格式化的错误追踪信息

SARIF格式支持 (3.3任务):
  • 支持生成符合SARIF 2.1.0标准的报告
  • 兼容GitHub Code Scanning和VS Code SARIF Viewer

规则仓库功能 (6.5任务):
  • 支持从外部加载规则（本地文件、URL、社区仓库）
  • 社区规则仓库，支持搜索和安装社区规则
  • 规则版本管理，支持更新检查
  • 规则自动更新，支持更新所有或指定规则包
增量扫描功能 (3.4任务):
  • 基于Git的增量扫描，只扫描修改过的文件
  • 文件修改时间缓存，避免重复扫描
  • 智能跳过未修改文件，直接使用缓存结果
  • 与完整扫描无缝切换
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    # scan 命令
    scan_parser = subparsers.add_parser("scan", help="扫描Python代码")
    scan_parser.add_argument("target", type=str, help="扫描目标（文件或目录路径）")
    scan_parser.add_argument("-o", "--output", type=str, default=None, help="输出报告文件路径")
    scan_parser.add_argument(
        "-f",
        "--format",
        type=str,
        # 添加 SARIF 格式支持 (3.3任务) 和 HTML 格式支持 (含统计仪表盘)
        choices=["text", "json", "markdown", "html", "sarif"],
        default="text",
        help="报告输出格式 (默认: text)，支持: text, json, markdown, html, sarif"
    )
    scan_parser.add_argument("-c", "--config", type=str, default=None, help="指定配置文件路径")
    scan_parser.add_argument(
        "--exclude", type=str, default=None, help="排除的目录，逗号分隔 (如: tests,docs,venv)"
    )
    scan_parser.add_argument(
        "--rules", type=str, default=None, help="启用的规则ID，逗号分隔 (如: SQL001,CMD001)"
    )
    scan_parser.add_argument(
        "--severity",
        type=str,
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="最低报告严重程度",
    )
    
    # 修改：将 -v 参数改为计数类型，支持 -v, -vv, -vvv
    scan_parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="详细输出级别：-v 基础信息，-vv 详细信息，-vvv 调试信息（包含完整错误追踪）"
    )
    
    scan_parser.add_argument("-q", "--quiet", action="store_true", help="静默模式，仅输出报告")
    
    # 3.4任务：添加增量扫描参数
    scan_parser.add_argument(
        "--incremental",
        action="store_true",
        help="启用增量扫描模式，只扫描修改过的文件（3.4任务）"
    )
    scan_parser.add_argument(
        "--changed-only",
        action="store_true",
        help="仅扫描Git修改的文件（等同于 --incremental --since HEAD）"
    )
    scan_parser.add_argument(
        "--since",
        type=str,
        default=None,
        help="扫描自指定时间以来修改的文件（如: HEAD~5, main, 1.day.ago, 2.hours.ago）"
    )
    scan_parser.add_argument(
        "--full-scan",
        action="store_true",
        help="强制完整扫描，忽略增量模式（3.4任务）"
    )
    scan_parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="清除增量扫描缓存（3.4任务）"
    )
    
    scan_parser.add_argument(
        "--no-cache",
        action="store_true",
        help="禁用 AST 缓存，强制重新解析所有文件",
    )
    # 超时控制参数（5.4任务添加）
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="总扫描超时时间（秒），例如：300 表示5分钟"
    )
    scan_parser.add_argument(
        "--file-timeout",
        type=int,
        default=None,
        help="单文件扫描超时时间（秒），例如：30 表示30秒"
    )
    # 修复功能参数
    scan_parser.add_argument(
        "--fix",
        action="store_true",
        help="自动修复可修复的安全问题（仅支持低风险修复）",
    )
    scan_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="仅显示修复预览，不实际修改文件（需配合 --fix 使用）",
    )
    scan_parser.add_argument(
        "--interactive",
        action="store_true",
        help="交互式确认每个修复操作（需配合 --fix 使用）",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="禁用彩色输出（适用于不支持 ANSI 颜色的终端）",
    )
    scan_parser.add_argument(
        "--no-progress",
        action="store_true",
        help="禁用进度条显示",
    )
    scan_parser.add_argument(
        "--no-history",
        action="store_true",
        help="禁用扫描历史记录（用于 HTML 报告趋势图）",
    )

    # rules 命令 (原有的列出规则命令)
    rules_parser = subparsers.add_parser("rules", help="列出所有检测规则")
    rules_parser.add_argument("--verbose", action="store_true", help="显示规则详细信息")
    rules_parser.add_argument(
        "--no-color",
        action="store_true",
        help="禁用彩色输出",
    )

    # 6.5任务：添加规则管理命令
    try:
        from .commands.rules import add_rules_parser
        add_rules_parser(subparsers)
    except ImportError as e:
        # 如果导入失败，可能是commands模块不存在，继续执行
        print(f" 无法加载规则管理命令: {e}", file=sys.stderr)

    # version 命令
    version_parser = subparsers.add_parser("version", help="显示版本信息")

    return parser


def cmd_scan(args):
    """执行扫描命令"""
    # 处理颜色输出设置
    if args.no_color:
        ColorSupport.disable()
    
    target = Path(args.target)

    # 详细级别输出
    if args.verbose >= 1 and not args.quiet:
        print("=" * 60)
        print("PySecScanner 详细模式启动")
        print(f"详细级别: {args.verbose}")
        print(f"目标路径: {target.absolute()}")
        if args.timeout:
            print(f"总超时时间: {args.timeout}秒")
        if args.file_timeout:
            print(f"单文件超时: {args.file_timeout}秒")
        if args.verbose >= 2:
            print(f"Python版本: {sys.version.split()[0]}")
            print(f"工作目录: {os.getcwd()}")
        print("=" * 60)

    # 验证目标路径
    if not target.exists():
        error_msg = f"错误: 目标路径不存在: {args.target}"
        if args.verbose >= 1:
            context = {
                "file_path": str(target.absolute()),
                "current_dir": os.getcwd(),
            }
            handle_command_error(FileNotFoundError(error_msg), "scan", args.verbose, context)
        else:
            print(error(f" 目标路径不存在: {args.target}"), file=sys.stderr)
            print(" 建议: 检查路径是否正确，或使用绝对路径", file=sys.stderr)
        return 1

    try:
        # 检查是否清除缓存
        if args.clear_cache:
            from .incremental import FileHashCache
            cache = FileHashCache()
            cache.clear_cache()
            if not args.quiet:
                print(" 已清除增量扫描缓存")
            return 0

        # 加载配置文件
        loaded_config = None

        # 优先使用 --config 指定的配置文件
        if args.config:
            config_file = Path(args.config)
            if not config_file.exists():
                error_msg = f"配置文件不存在: {args.config}"
                if args.verbose >= 1:
                    context = {"config_file": str(config_file.absolute())}
                    handle_command_error(FileNotFoundError(error_msg), "scan", args.verbose, context)
                else:
                    print(error(f" 配置文件不存在: {args.config}"), file=sys.stderr)
                return 1
            try:
                loaded_config = Config.load_from_file(config_file)
                if args.verbose >= 1 and not args.quiet:
                    print(f" 加载配置文件: {config_file}")
            except Exception as e:
                error_msg = f"加载配置文件失败: {e}"
                if args.verbose >= 1:
                    context = {"config_file": str(config_file.absolute())}
                    handle_command_error(e, "scan", args.verbose, context)
                else:
                    print(error(f" 加载配置文件失败: {e}"), file=sys.stderr)
                    print(" 建议: 检查配置文件格式（YAML或JSON）", file=sys.stderr)
                return 1
        else:
            # 自动发现配置文件
            config_file = Config.find_config_file(target if target.is_dir() else target.parent)
            if config_file:
                try:
                    loaded_config = Config.load_from_file(config_file)
                    if args.verbose >= 1 and not args.quiet:
                        print(f" 自动发现并加载配置文件: {config_file}")
                except Exception as e:
                    if args.verbose >= 1:
                        print(warning(f"  加载配置文件失败: {e}"))
                    # 配置文件加载失败不影响扫描继续

        # 构建 ScanConfig 配置对象
        scan_config = ScanConfig()
        
        # 设置详细级别
        if hasattr(scan_config, 'verbose_level'):
            scan_config.verbose_level = args.verbose
        elif hasattr(scan_config, 'verbose'):
            scan_config.verbose = (args.verbose > 0)

        # 从配置文件应用设置
        if loaded_config:
            if loaded_config.exclude_dirs:
                scan_config.exclude_patterns = loaded_config.exclude_dirs
            if loaded_config.rules_enabled:
                scan_config.enabled_rules = loaded_config.rules_enabled
            if loaded_config.rules_disabled:
                scan_config.disabled_rules = loaded_config.rules_disabled
            if loaded_config.severity_overrides:
                scan_config.severity_overrides = loaded_config.severity_overrides
            # 加载动态严重程度调整配置
            scan_config.dynamic_severity = loaded_config.dynamic_severity
            scan_config.upgrade_for_sensitive = loaded_config.upgrade_for_sensitive
            scan_config.downgrade_for_tests = loaded_config.downgrade_for_tests

        # 命令行参数覆盖配置文件
        if args.exclude:
            scan_config.exclude_patterns = args.exclude.split(",")

        if args.rules:
            scan_config.enabled_rules = args.rules.split(",")

        if args.severity:
            scan_config.min_severity = args.severity
        elif loaded_config and loaded_config.minimum_severity:
            scan_config.min_severity = loaded_config.minimum_severity

        # 设置超时参数（5.4任务添加）
        if hasattr(scan_config, 'timeout'):
            scan_config.timeout = args.timeout
        if hasattr(scan_config, 'file_timeout'):
            scan_config.file_timeout = args.file_timeout

        # 创建扫描器
        scanner_args = {"config": scan_config}
        
        # 如果扫描器支持详细级别参数，传递它
        if hasattr(SecurityScanner, '__init__'):
            import inspect
            sig = inspect.signature(SecurityScanner.__init__)
            if 'verbose_level' in sig.parameters:
                scanner_args["verbose_level"] = args.verbose
            elif 'verbose' in sig.parameters:
                scanner_args["verbose"] = (args.verbose > 0)
        
        scanner = SecurityScanner(**scanner_args)

        if not args.quiet:
            print("=" * 50)
            print(header("PySecScanner - Python 代码安全扫描器"))
            print("=" * 50)
            print(f"{bold('扫描目标:')} {target.absolute()}")
            print(f"{bold('启用规则:')} {len(scanner.get_rules())} 个")
            
            # 3.4任务：显示扫描模式
            scan_mode = "完整扫描"
            if args.full_scan:
                scan_mode = "强制完整扫描"
            elif args.incremental or args.changed_only or args.since:
                scan_mode = "增量扫描"
                if args.since:
                    scan_mode += f" (自 {args.since} 以来)"
                elif args.changed_only:
                    scan_mode += " (仅Git修改的文件)"
            print(f"{bold('扫描模式:')} {info(scan_mode)}")
            
            if args.verbose >= 1:
                if args.timeout:
                    print(f"{bold('总超时:')} {args.timeout}秒")
                if args.file_timeout:
                    print(f"{bold('文件超时:')} {args.file_timeout}秒")
                if scan_config.exclude_patterns:
                    print(f"{bold('排除目录:')} {', '.join(scan_config.exclude_patterns)}")
            print("-" * 50)

        # 执行扫描
        if args.verbose >= 1 and not args.quiet:
            print("开始扫描...")

        # 3.4任务：根据参数选择扫描模式
        if args.full_scan:
            # 强制完整扫描
            if not args.quiet:
                print(" 执行强制完整扫描")
            result = scanner.scan(str(target))
            
        elif args.incremental or args.changed_only or args.since:
            # 增量扫描模式
            if not args.quiet:
                mode_desc = "增量扫描"
                if args.since:
                    mode_desc = f"增量扫描 (自 {args.since} 以来)"
                elif args.changed_only:
                    mode_desc = "增量扫描 (仅Git修改的文件)"
                print(f" 执行{mode_desc}")
            
            # 确定since参数
            since_param = args.since
            if args.changed_only and not args.since:
                since_param = "HEAD"
            
            # 检查扫描器是否支持增量扫描
            if hasattr(scanner, 'scan_incremental'):
                try:
                    result = scanner.scan_incremental(str(target), since_param)
                except Exception as e:
                    if args.verbose >= 1:
                        print(f"  增量扫描失败: {e}")
                        print("  回退到完整扫描")
                    result = scanner.scan(str(target))
            elif hasattr(scanner, 'scan_changed') and args.changed_only:
                result = scanner.scan_changed(str(target))
            elif hasattr(scanner, 'scan_since') and args.since:
                result = scanner.scan_since(str(target), args.since)
            else:
                if not args.quiet:
                    print("  扫描器不支持增量扫描，回退到完整扫描")
                result = scanner.scan(str(target))
                
        else:
            # 默认完整扫描
            result = scanner.scan(str(target))

        if not args.quiet:
            # 3.4任务：显示增量扫描统计（如果可用）
            if hasattr(result, 'scan_stats'):
                stats = result.scan_stats
                if stats:
                    print(f" 增量扫描统计:")
                    print(f"   总文件数: {stats.get('total_files', 0)}")
                    print(f"   实际扫描: {stats.get('scanned_files', 0)}")
                    print(f"   缓存命中: {stats.get('cached_files', 0)}")
                    if 'cache_hit_rate' in stats:
                        print(f"   缓存命中率: {stats.get('cache_hit_rate', 0):.1%}")
            
            print(success(f" 扫描完成! 耗时: {result.duration:.2f} 秒"))
            print(f"{bold('扫描文件:')} {result.files_scanned} 个")
            
            # 根据漏洞数量使用不同颜色
            total_vulns = result.summary['total']
            if total_vulns == 0:
                print(f"{bold('发现漏洞:')} {success(f'{total_vulns} 个')}")
            elif total_vulns < 5:
                print(f"{bold('发现漏洞:')} {warning(f'{total_vulns} 个')}")
            else:
                print(f"{bold('发现漏洞:')} {error(f'{total_vulns} 个')}")
            
            if args.verbose >= 1:
                if result.summary['critical'] > 0:
                    print(f"{bold('严重漏洞:')} {error(str(result.summary['critical']))} 个")
                if result.summary['high'] > 0:
                    print(f"{bold('高危漏洞:')} {error(str(result.summary['high']))} 个")
                if result.summary['medium'] > 0:
                    print(f"{bold('中危漏洞:')} {warning(str(result.summary['medium']))} 个")
                if result.summary['low'] > 0:
                    print(f"{bold('低危漏洞:')} {info(str(result.summary['low']))} 个")
            
            print("-" * 50)

        # 处理修复功能
        fix_results = []
        if hasattr(args, "fix") and args.fix and result.vulnerabilities:
            fix_results = _handle_fix(
                result,
                dry_run=getattr(args, "dry_run", False),
                interactive=getattr(args, "interactive", False),
                quiet=args.quiet,
                verbose_level=args.verbose,
            )

        # 生成报告
        scan_history_data = []
        if args.format == "html" and not getattr(args, 'no_history', False):
            try:
                from .scan_history import ScanHistory
                history = ScanHistory()
                # 先保存当前扫描记录
                history.save(result)
                # 加载历史数据用于趋势图
                scan_history_data = history.get_recent(10)
            except Exception:
                pass  # 历史记录功能不影响报告生成
        reporter = get_reporter(args.format, scan_history=scan_history_data)
        report = reporter.generate(result)

        # 输出报告
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(report)
                if not args.quiet:
                    print(f" 报告已保存至: {args.output}")
            except Exception as e:
                error_msg = f"保存报告文件失败: {e}"
                if args.verbose >= 1:
                    context = {"file_path": args.output}
                    handle_command_error(e, "scan", args.verbose, context)
                else:
                    print(error(f" {error_msg}"), file=sys.stderr)
                return 1
        else:
            print(report)

        # 返回状态码（有漏洞时返回非0）
        if result.summary["critical"] > 0 or result.summary["high"] > 0:
            return 2  # 发现高危漏洞
        elif result.summary["total"] > 0:
            return 1  # 发现漏洞
        return 0

    except Exception as e:
        # 使用友好的错误处理
        context = {
            "file_path": str(target.absolute()),
            "command": "scan",
            "verbose_level": args.verbose,
        }
        handle_command_error(e, "scan", args.verbose, context)
        return 1


def _handle_fix(result, dry_run=False, interactive=False, quiet=False, verbose_level=0):
    """
    处理修复功能

    Args:
        result: 扫描结果
        dry_run: 是否只预览不实际修改
        interactive: 是否交互式确认
        quiet: 是否静默模式
        verbose_level: 详细级别

    Returns:
        修复结果列表
    """
    fixer = get_fixer()
    all_fix_results = []

    # 按文件分组漏洞
    vulns_by_file = {}
    for vuln in result.vulnerabilities:
        if vuln.file_path not in vulns_by_file:
            vulns_by_file[vuln.file_path] = []
        vulns_by_file[vuln.file_path].append(vuln)

    if not quiet:
        mode_str = "预览模式" if dry_run else "修复模式"
        print(f"\n{'='*50}")
        print(f"🔧 修复建议 ({mode_str})")
        print("=" * 50)

    def confirm_callback(fix_result):
        """交互式确认回调"""
        print(f"\n是否应用此修复? [{fix_result.vulnerability.rule_id}] "
              f"{fix_result.vulnerability.file_path}:{fix_result.vulnerability.line_number}")
        print(f"原始代码: {fix_result.original_code}")
        if fix_result.diff:
            print("修复预览:")
            print(fix_result.diff[:500] + "..." if len(fix_result.diff) > 500 else fix_result.diff)
        response = input("应用修复? (y/n): ").strip().lower()
        return response == 'y'

    for file_path, vulns in vulns_by_file.items():
        if not quiet:
            print(f"\n {file_path}")

        # 检查哪些漏洞可以修复
        fixable_vulns = []
        for vuln in vulns:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    source_code = f.read()
                if fixer.can_fix(vuln, source_code):
                    fixable_vulns.append(vuln)
            except Exception as e:
                if verbose_level >= 2:
                    print(f"    检查修复性时出错: {e}")

        if fixable_vulns:
            try:
                fix_results = fixer.fix_file(
                    file_path,
                    fixable_vulns,
                    dry_run=dry_run,
                    interactive=interactive,
                    confirm_callback=confirm_callback if interactive else None,
                )
                all_fix_results.extend(fix_results)

                for fr in fix_results:
                    status = " 已修复" if fr.applied else (" 预览" if fr.success else " 无法自动修复")
                    if not quiet:
                        print(f"  {status} [{fr.vulnerability.rule_id}] 第 {fr.vulnerability.line_number} 行")
                        if dry_run and fr.diff and verbose_level >= 2:
                            # 显示简短的 diff 预览
                            diff_lines = fr.diff.split('\n')[:10]
                            for line in diff_lines:
                                print(f"    {line}")
                            if len(fr.diff.split('\n')) > 10:
                                print("    ...")
            except Exception as e:
                if verbose_level >= 1:
                    print(f"  修复文件时出错: {e}")
                if verbose_level >= 3:
                    print(f"    错误追踪: {traceback.format_exc()}")

        # 显示不可自动修复的漏洞的修复示例
        non_fixable = [v for v in vulns if v not in fixable_vulns]
        for vuln in non_fixable:
            example = fixer.get_fix_example(vuln)
            if example and not quiet and verbose_level >= 1:
                print(f"   [{vuln.rule_id}] 第 {vuln.line_number} 行 - 需手动修复")
                if dry_run and verbose_level >= 2:  # 只在 dry-run 和详细模式下显示完整示例
                    print("    修复示例:")
                    for line in example.split('\n')[:8]:
                        print(f"      {line}")
                    print("      ...")

    # 输出修复统计
    if not quiet:
        applied = sum(1 for r in all_fix_results if r.applied)
        total_fixable = len(all_fix_results)
        print(f"\n修复统计: 已应用 {applied}/{total_fixable} 个自动修复")
        if dry_run:
            print("提示: 使用 --fix 而不带 --dry-run 以实际应用修复")

    return all_fix_results


def cmd_rules(args):
    """列出规则命令"""
    try:
        # 处理颜色输出设置
        if args.no_color:
            ColorSupport.disable()
        
        rules = list_rules()

        print("=" * 50)
        print(header("PySecScanner 检测规则列表"))
        print("=" * 50)
        print()

        if args.verbose:
            for rule in rules:
                instance = rule()
                print(f"{bold('规则ID:')} {blue(instance.rule_id, bold=True)}")
                print(f"{bold('名称:')}   {instance.rule_name}")
                print(f"{bold('严重程度:')} {severity_color(instance.severity, instance.severity.upper())}")
                print(f"{bold('描述:')} {instance.description}")
                print("-" * 40)
                print()
        else:
            print(f"{bold('规则ID'):<15} {bold('严重程度'):<15} {bold('名称')}")
            print("-" * 55)
            for rule in rules:
                instance = rule()
                rule_id = blue(instance.rule_id)
                severity_text = severity_color(instance.severity, instance.severity.upper())
                print(f"{rule_id:<25} {severity_text:<25} {instance.rule_name}")

        print()
        print(f"共 {bold(str(len(rules)))} 条规则")
        return 0
    except Exception as e:
        handle_command_error(e, "rules", 0)
        return 1


def cmd_version(args):
    """显示版本信息"""
    try:
        print("PySecScanner v1.0.0")
        print("Python 代码安全漏洞静态分析工具")
        print()
        print("Copyright (c) 2025")
        print("基于 AST 的静态代码分析")
        print()
        print("功能特性:")
        print("  • 支持多种安全漏洞检测规则")
        print("  • 支持缓存加速（5.2任务）")
        print("  • 支持内存优化（5.3任务）")
        print("  • 支持扫描超时控制（5.4任务）")
        print("  • 友好的错误信息和调试模式（5.5任务）")
        print("  • SARIF格式报告支持（3.3任务）")
        print("  • 规则仓库功能（6.5任务）")
        print("  • 增量扫描功能（3.4任务）")
        return 0
    except Exception as e:
        handle_command_error(e, "version", 0)
        return 1


def main():
    """主入口函数"""
    parser = create_parser()
    
    # 如果没有提供参数，显示帮助
    if len(sys.argv) == 1:
        parser.print_help()
        return 0
    
    try:
        args = parser.parse_args()
    except SystemExit:
        # argparse在--help时会调用sys.exit，我们直接退出
        return 0
    except Exception as e:
        # 解析参数时发生错误
        handle_command_error(e, None, 0, {"argparse_error": True})
        print("\n 使用 `pysec --help` 查看完整帮助信息")
        return 1
    
    if args.command is None:
        parser.print_help()
        return 0

    try:
        if args.command == "scan":
            return cmd_scan(args)
        elif args.command == "rules":
            return cmd_rules(args)
        elif args.command == "version":
            return cmd_version(args)
        else:
            # 6.5任务：处理规则管理命令
            # 检查是否是规则管理命令
            if args.command in ["install", "uninstall", "list", "update", "search", "info"]:
                try:
                    from .commands.rules import main as rules_main
                    return rules_main()
                except ImportError as e:
                    print(f"无法执行规则管理命令: {e}")
                    print("  请确保已正确安装规则仓库功能模块")
                    return 1
            else:
                parser.print_help()
                return 0
    except KeyboardInterrupt:
        print("\n\n操作被用户中断。")
        return 130
    except Exception as e:
        # 捕获并处理所有未捕获的异常
        verbose_level = getattr(args, 'verbose', 0) if hasattr(args, 'verbose') else 0
        handle_command_error(e, args.command if hasattr(args, 'command') else None, verbose_level)
        return 1


if __name__ == "__main__":
    sys.exit(main())