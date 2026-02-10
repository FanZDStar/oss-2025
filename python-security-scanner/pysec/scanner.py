"""
文件扫描器模块

负责文件遍历、AST解析等功能，支持缓存、超时控制和友好错误信息
"""

import ast
import os
import fnmatch
import time
import threading
import traceback
from pathlib import Path
from typing import Optional, Tuple, List, Generator, Dict, Any
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
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
        suggestions.append(" 通用建议:")
        suggestions.append("  • 检查命令参数是否正确")
        suggestions.append("  • 确保文件路径没有拼写错误")
        suggestions.append("  • 查看帮助信息: python main.py --help")
        
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
                    suggestions.append("  • 使用 `ls` 或 `dir` 命令查看当前目录内容")
            
            if "file_size" in context and context["file_size"] > 10 * 1024 * 1024:  # 10MB
                suggestions.append("\n 大文件处理建议:")
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
                        tb_lines.append(f"   {line}")
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


class ASTParser:
    """Python AST解析器"""

    @staticmethod
    def parse_file(file_path: str) -> Tuple[Optional[ast.AST], str, Optional[str]]:
        """
        解析Python文件

        Args:
            file_path: 文件路径

        Returns:
            (AST树, 源代码, 错误信息)
            如果解析成功，错误信息为None
            如果解析失败，AST树为None
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source_code = f.read()
        except UnicodeDecodeError:
            # 尝试其他编码
            try:
                with open(file_path, "r", encoding="latin-1") as f:
                    source_code = f.read()
            except Exception as e:
                return None, "", f"无法读取文件: {e}"
        except Exception as e:
            return None, "", f"读取文件错误: {e}"

        try:
            tree = ast.parse(source_code, filename=file_path)
            return tree, source_code, None
        except SyntaxError as e:
            return None, source_code, f"语法错误 (行 {e.lineno}): {e.msg}"
        except Exception as e:
            return None, source_code, f"解析错误: {e}"

    @staticmethod
    def parse_source(
        source_code: str, filename: str = "<string>"
    ) -> Tuple[Optional[ast.AST], Optional[str]]:
        """
        解析Python源代码字符串

        Args:
            source_code: 源代码字符串
            filename: 虚拟文件名（用于错误报告）

        Returns:
            (AST树, 错误信息)
        """
        try:
            tree = ast.parse(source_code, filename=filename)
            return tree, None
        except SyntaxError as e:
            return None, f"语法错误 (行 {e.lineno}): {e.msg}"
        except Exception as e:
            return None, f"解析错误: {e}"


class FileScanner:
    """文件扫描器"""

    # 默认排除的目录
    DEFAULT_EXCLUDE_DIRS = {
        "__pycache__",
        ".git",
        ".svn",
        ".hg",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".eggs",
        "*.egg-info",
        "venv",
        ".venv",
        "env",
        ".env",
        "node_modules",
        "build",
        "dist",
        ".idea",
        ".vscode",
    }

    # 默认排除的文件模式
    DEFAULT_EXCLUDE_FILES = {
        "*.pyc",
        "*.pyo",
        "*.pyd",
        "*.so",
        "*.dll",
        "*.egg",
        "*.whl",
    }

    def __init__(
        self,
        exclude_dirs: Optional[List[str]] = None,
        exclude_files: Optional[List[str]] = None,
        max_file_size: int = 1024 * 1024,  # 1MB
    ):
        """
        初始化文件扫描器

        Args:
            exclude_dirs: 额外排除的目录
            exclude_files: 额外排除的文件模式
            max_file_size: 最大文件大小（字节）
        """
        self.exclude_dirs = self.DEFAULT_EXCLUDE_DIRS.copy()
        if exclude_dirs:
            self.exclude_dirs.update(exclude_dirs)

        self.exclude_files = self.DEFAULT_EXCLUDE_FILES.copy()
        if exclude_files:
            self.exclude_files.update(exclude_files)

        self.max_file_size = max_file_size

    def scan_directory(self, directory: str) -> Generator[str, None, None]:
        """
        扫描目录，返回所有Python文件路径

        Args:
            directory: 目录路径

        Yields:
            Python文件的绝对路径
        """
        directory = os.path.abspath(directory)

        for root, dirs, files in os.walk(directory):
            # 过滤排除的目录（原地修改以阻止遍历）
            dirs[:] = [d for d in dirs if not self._should_exclude_dir(d)]

            for filename in files:
                if self._is_python_file(filename):
                    file_path = os.path.join(root, filename)

                    # 检查文件大小
                    if self._check_file_size(file_path):
                        yield file_path

    def scan_file(self, file_path: str) -> Optional[str]:
        """
        检查单个文件是否应该被扫描

        Args:
            file_path: 文件路径

        Returns:
            如果应该扫描，返回绝对路径；否则返回None
        """
        file_path = os.path.abspath(file_path)

        if not os.path.isfile(file_path):
            return None

        filename = os.path.basename(file_path)

        if not self._is_python_file(filename):
            return None

        if not self._check_file_size(file_path):
            return None

        return file_path

    def _is_python_file(self, filename: str) -> bool:
        """判断是否为Python文件"""
        if not filename.endswith(".py"):
            return False

        # 检查排除的文件模式
        for pattern in self.exclude_files:
            if fnmatch.fnmatch(filename, pattern):
                return False

        return True

    def _should_exclude_dir(self, dirname: str) -> bool:
        """判断是否应该排除目录"""
        for pattern in self.exclude_dirs:
            if fnmatch.fnmatch(dirname, pattern):
                return True
        return False

    def _check_file_size(self, file_path: str) -> bool:
        """检查文件大小是否在限制内"""
        try:
            size = os.path.getsize(file_path)
            return size <= self.max_file_size
        except OSError:
            return False


class Scanner:
    """
    综合扫描器

    整合文件扫描和AST解析功能，支持缓存、超时控制和友好错误信息
    """

    def __init__(self, use_cache: bool = True, 
                 timeout: int = None, 
                 file_timeout: int = None,
                 verbose_level: int = 0,
                 **kwargs):
        """
        初始化扫描器

        Args:
            use_cache: 是否启用 AST 缓存
            timeout: 总扫描超时时间（秒），None表示无限制
            file_timeout: 单文件扫描超时时间（秒），None表示无限制
            verbose_level: 详细级别（0-3），控制日志和错误信息的详细程度
            **kwargs: 传递给FileScanner的参数
        """
        self.file_scanner = FileScanner(**kwargs)
        self.ast_parser = ASTParser()
        self.use_cache = use_cache
        self.timeout = timeout
        self.file_timeout = file_timeout
        self.verbose_level = verbose_level
        self.start_time = None
        self._cache = None

        if use_cache:
            try:
                from .cache import ASTCache
                self._cache = ASTCache()
            except ImportError:
                self._cache = None
                
        # 超时相关状态
        self._timeout_triggered = False
        self._scanned_files = 0
        self._total_files = 0

    def _check_global_timeout(self) -> bool:
        """
        检查全局扫描是否超时

        Returns:
            bool: True表示已超时，False表示未超时
        """
        if self._timeout_triggered:
            return True
            
        if self.timeout is None or self.start_time is None:
            return False
            
        elapsed_time = time.time() - self.start_time
        if elapsed_time > self.timeout:
            self._timeout_triggered = True
            print(f"  扫描超时: 总扫描时间超过 {self.timeout} 秒，已扫描 {self._scanned_files} 个文件")
            return True
            
        return False
    
    def _parse_with_timeout(self, file_path: str):
        """
        带超时控制的文件解析

        Args:
            file_path: 文件路径

        Returns:
            解析结果或超时错误
        """
        if self.file_timeout is None:
            # 没有文件超时限制，直接解析
            return self.ast_parser.parse_file(file_path)
        
        # 使用线程池实现文件级超时控制
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self.ast_parser.parse_file, file_path)
            try:
                return future.result(timeout=self.file_timeout)
            except FutureTimeoutError:
                # 文件解析超时
                return None, "", f"文件解析超时（超过 {self.file_timeout} 秒）"
            except Exception as e:
                return None, "", f"解析错误: {e}"

    def _parse_file_with_cache(
        self, file_path: str
    ) -> Tuple[Optional[ast.AST], str, Optional[str]]:
        """
        解析文件，优先使用缓存，支持超时控制

        Args:
            file_path: 文件路径

        Returns:
            (AST树, 源代码, 错误信息)
        """
        # 检查全局超时
        if self._check_global_timeout():
            error_msg = f"扫描任务总时间超时（限制: {self.timeout}秒）"
            return None, "", error_msg
        
        # 尝试从缓存获取
        if self._cache and self.use_cache:
            cached = self._cache.get(file_path)
            if cached:
                return cached[0], cached[1], None

        # 缓存未命中，使用带超时的解析
        try:
            tree, source, error = self._parse_with_timeout(file_path)
        except Exception as e:
            # 捕获异常，生成友好的错误信息
            error = ErrorFormatter.get_friendly_message(e)
            return None, "", error
        
        # 如果解析成功且未超时，存入缓存
        if tree is not None and self._cache and self.use_cache and not error:
            self._cache.set(file_path, tree, source)

        return tree, source, error

    def scan_target(
        self, target: str
    ) -> Generator[Tuple[str, Optional[ast.AST], str, Optional[str]], None, None]:
        """
        扫描目标（文件或目录），支持超时控制

        Args:
            target: 目标路径（文件或目录）

        Yields:
            (文件路径, AST树, 源代码, 错误信息)
        """
        # 记录扫描开始时间
        self.start_time = time.time()
        self._timeout_triggered = False
        self._scanned_files = 0
        self._total_files = 0
        
        # 详细日志：开始扫描
        if self.verbose_level >= 1:
            print(f"\n 开始扫描: {target}")
            print(f"   详细级别: {self.verbose_level}")
            if self.timeout:
                print(f"   总时间限制: {self.timeout}秒")
            if self.file_timeout:
                print(f"   单文件时间限制: {self.file_timeout}秒")
        
        target = os.path.abspath(target)

        if os.path.isfile(target):
            # 单个文件
            file_path = self.file_scanner.scan_file(target)
            if file_path:
                self._total_files = 1
                
                # 详细日志：扫描单个文件
                if self.verbose_level >= 2:
                    print(f"\n   扫描文件: {os.path.basename(file_path)}")
                    print(f"     路径: {file_path}")
                
                # 检查全局超时
                if self._check_global_timeout():
                    error_msg = f"扫描任务总时间超时（限制: {self.timeout}秒）"
                    yield target, None, "", error_msg
                    return
                    
                tree, source, error = self._parse_file_with_cache(file_path)
                self._scanned_files = 1
                yield file_path, tree, source, error

        elif os.path.isdir(target):
            # 目录扫描
            file_count = 0
            file_paths = []
            
            # 先收集所有文件，用于统计
            for file_path in self.file_scanner.scan_directory(target):
                file_paths.append(file_path)
                file_count += 1
                
            self._total_files = file_count
            
            # 详细日志：目录信息
            if self.verbose_level >= 1:
                print(f"\n  在目录中找到 {file_count} 个Python文件")
                if self.verbose_level >= 2 and file_count > 0:
                    print(f"  开始逐个扫描...")
            
            # 逐个扫描文件，支持超时中断
            for file_path in file_paths:
                # 检查全局超时
                if self._check_global_timeout():
                    # 详细日志：超时中断
                    if self.verbose_level >= 1:
                        print(f" 扫描超时中断")
                        print(f"    已扫描 {self._scanned_files}/{self._total_files} 个文件")
                    break
                    
                # 详细日志：单个文件进度
                if self.verbose_level >= 2:
                    print(f"\n  [{self._scanned_files+1}/{self._total_files}] 扫描: {os.path.basename(file_path)}")
                
                tree, source, error = self._parse_file_with_cache(file_path)
                self._scanned_files += 1
                yield file_path, tree, source, error

        else:
            error_msg = f"目标路径不存在: {target}"
            yield target, None, "", error_msg

    def scan_files(
        self, file_paths: List[str]
    ) -> Generator[Tuple[str, Optional[ast.AST], str, Optional[str]], None, None]:
        """
        扫描指定的文件列表，支持超时控制

        Args:
            file_paths: 文件路径列表

        Yields:
            (文件路径, AST树, 源代码, 错误信息)
        """
        # 记录扫描开始时间
        self.start_time = time.time()
        self._timeout_triggered = False
        self._scanned_files = 0
        self._total_files = len(file_paths)
        
        for file_path in file_paths:
            # 检查全局超时
            if self._check_global_timeout():
                print(f"  已扫描 {self._scanned_files}/{self._total_files} 个文件")
                break
                
            abs_path = os.path.abspath(file_path)
            if os.path.isfile(abs_path):
                validated_path = self.file_scanner.scan_file(abs_path)
                if validated_path:
                    tree, source, error = self._parse_file_with_cache(validated_path)
                    self._scanned_files += 1
                    yield validated_path, tree, source, error
            else:
                yield abs_path, None, "", f"文件不存在: {abs_path}"

    def clear_cache(self):
        """清除 AST 缓存"""
        if self._cache:
            self._cache.clear()

    def get_cache_stats(self) -> dict:
        """获取缓存统计信息"""
        if self._cache:
            return self._cache.get_stats()
        return {"enabled": False}
    
    def get_scan_stats(self) -> dict:
        """
        获取扫描统计信息

        Returns:
            包含扫描统计信息的字典
        """
        stats = {
            "total_files": self._total_files,
            "scanned_files": self._scanned_files,
            "timeout_triggered": self._timeout_triggered,
            "elapsed_time": None,
            "timeout_exceeded": False
        }
        
        if self.start_time:
            elapsed = time.time() - self.start_time
            stats["elapsed_time"] = elapsed
            
            if self.timeout and elapsed > self.timeout:
                stats["timeout_exceeded"] = True
                stats["timeout_limit"] = self.timeout
                
        return stats
    
    def scan_target_with_timeout(
        self, target: str
    ) -> Generator[Tuple[str, Optional[ast.AST], str, Optional[str]], None, None]:
        """
        带超时控制的扫描目标方法（外部接口）

        Args:
            target: 目标路径（文件或目录）

        Yields:
            (文件路径, AST树, 源代码, 错误信息)
        """
        try:
            for result in self.scan_target(target):
                yield result
                
                # 检查是否已触发超时
                if self._timeout_triggered:
                    break
        except Exception as e:
            yield target, None, "", f"扫描异常: {e}"