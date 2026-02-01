"""
Git 工具模块

提供 Git 相关功能，用于支持增量扫描
"""

import os
import subprocess
from pathlib import Path
from typing import List, Optional


class GitHelper:
    """Git 帮助类

    提供与 Git 仓库交互的功能，用于增量扫描
    """

    def __init__(self, repo_path: str):
        """
        初始化 Git 帮助类

        Args:
            repo_path: Git 仓库路径
        """
        self.repo_path = Path(repo_path).resolve()

    def is_git_repo(self) -> bool:
        """
        检查指定路径是否为 Git 仓库

        Returns:
            如果是 Git 仓库返回 True，否则返回 False
        """
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def get_repo_root(self) -> Optional[str]:
        """
        获取 Git 仓库根目录

        Returns:
            仓库根目录的绝对路径，如果不是 Git 仓库返回 None
        """
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except (subprocess.SubprocessError, FileNotFoundError):
            return None

    def get_changed_files(self) -> List[str]:
        """
        获取自上次提交以来修改的 Python 文件

        包括：
        - 工作区修改的文件 (未暂存)
        - 暂存区修改的文件 (已 git add)
        - 新增但未追踪的文件

        Returns:
            修改的 Python 文件路径列表（绝对路径）
        """
        if not self.is_git_repo():
            return []

        repo_root = self.get_repo_root()
        if not repo_root:
            return []

        changed_files = set()

        # 获取工作区修改的文件（未暂存）
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only"],
                cwd=repo_root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        changed_files.add(line.strip())
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # 获取暂存区修改的文件（已 git add）
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "--cached"],
                cwd=repo_root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        changed_files.add(line.strip())
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # 获取未追踪的新文件
        try:
            result = subprocess.run(
                ["git", "ls-files", "--others", "--exclude-standard"],
                cwd=repo_root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        changed_files.add(line.strip())
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # 过滤出 Python 文件并转换为绝对路径
        python_files = []
        for file_path in changed_files:
            if file_path.endswith(".py"):
                abs_path = os.path.join(repo_root, file_path)
                if os.path.isfile(abs_path):
                    python_files.append(abs_path)

        return sorted(python_files)

    def has_changes(self) -> bool:
        """
        检查是否有任何修改的 Python 文件

        Returns:
            如果有修改的 Python 文件返回 True，否则返回 False
        """
        return len(self.get_changed_files()) > 0
