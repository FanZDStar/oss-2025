"""
文件扫描器模块

负责文件遍历、AST解析等功能
"""

import ast
import os
import fnmatch
from pathlib import Path
from typing import Optional, Tuple, List, Generator


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

    整合文件扫描和AST解析功能
    """

    def __init__(self, **kwargs):
        """
        初始化扫描器

        Args:
            **kwargs: 传递给FileScanner的参数
        """
        self.file_scanner = FileScanner(**kwargs)
        self.ast_parser = ASTParser()

    def scan_target(
        self, target: str
    ) -> Generator[Tuple[str, Optional[ast.AST], str, Optional[str]], None, None]:
        """
        扫描目标（文件或目录）

        Args:
            target: 目标路径（文件或目录）

        Yields:
            (文件路径, AST树, 源代码, 错误信息)
        """
        target = os.path.abspath(target)

        if os.path.isfile(target):
            # 单个文件
            file_path = self.file_scanner.scan_file(target)
            if file_path:
                tree, source, error = self.ast_parser.parse_file(file_path)
                yield file_path, tree, source, error

        elif os.path.isdir(target):
            # 目录
            for file_path in self.file_scanner.scan_directory(target):
                tree, source, error = self.ast_parser.parse_file(file_path)
                yield file_path, tree, source, error

        else:
            yield target, None, "", f"目标不存在: {target}"
