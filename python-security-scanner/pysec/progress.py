"""
进度条显示模块

扫描大型项目时在终端显示进度条，包括：
- 可视化进度条
- 当前扫描文件名
- 已扫描文件数/总文件数
- 预计剩余时间
"""

import os
import sys
import time
import shutil
from typing import Optional

from .colors import ColorSupport, ANSIColors


class ProgressBar:
    """终端进度条

    在扫描大型项目时显示实时进度信息，包括进度条、百分比、
    文件计数、当前文件名和预计剩余时间。

    使用示例::

        progress = ProgressBar(total=100)
        for i, file_path in enumerate(files):
            progress.update(i + 1, file_path)
        progress.finish()
    """

    # 进度条字符
    FILL_CHAR = "█"
    EMPTY_CHAR = "░"

    def __init__(self, total: int = 0, bar_width: int = 30, enabled: bool = True):
        """
        初始化进度条

        Args:
            total: 总文件数
            bar_width: 进度条宽度（字符数）
            enabled: 是否启用进度条显示
        """
        self.total = total
        self.bar_width = bar_width
        self.enabled = enabled and total > 0
        self.current = 0
        self.start_time = time.time()
        self._last_render_time = 0
        self._min_render_interval = 0.1  # 最小渲染间隔（秒），避免刷新过快

    def update(self, current: int, current_file: str = ""):
        """
        更新进度条

        Args:
            current: 当前已完成数量
            current_file: 当前正在处理的文件路径
        """
        if not self.enabled:
            return

        self.current = current
        now = time.time()

        # 限制渲染频率，但最后一个文件总是渲染
        if current < self.total and (now - self._last_render_time) < self._min_render_interval:
            return

        self._last_render_time = now
        self._render(current_file)

    def _render(self, current_file: str = ""):
        """渲染进度条到终端"""
        if self.total <= 0:
            return

        # 计算百分比
        percentage = min(self.current / self.total, 1.0)
        filled_width = int(self.bar_width * percentage)
        empty_width = self.bar_width - filled_width

        # 构建进度条
        bar = self.FILL_CHAR * filled_width + self.EMPTY_CHAR * empty_width

        # 计算预计剩余时间
        elapsed = time.time() - self.start_time
        eta_str = self._format_eta(elapsed, percentage)

        # 文件计数
        count_str = f"{self.current}/{self.total}"

        # 百分比
        pct_str = f"{percentage * 100:5.1f}%"

        # 截断文件名以适应终端宽度
        file_display = self._truncate_filename(current_file)

        # 着色
        if ColorSupport.is_enabled():
            if percentage < 0.5:
                bar_color = ANSIColors.CYAN
            elif percentage < 1.0:
                bar_color = ANSIColors.GREEN
            else:
                bar_color = ANSIColors.BRIGHT_GREEN
            bar_str = f"{bar_color}{bar}{ANSIColors.RESET}"
            pct_colored = f"{ANSIColors.BOLD}{pct_str}{ANSIColors.RESET}"
            count_colored = f"{ANSIColors.BRIGHT_CYAN}{count_str}{ANSIColors.RESET}"
            eta_colored = f"{ANSIColors.BRIGHT_BLACK}{eta_str}{ANSIColors.RESET}"
        else:
            bar_str = bar
            pct_colored = pct_str
            count_colored = count_str
            eta_colored = eta_str

        # 组装进度行
        progress_line = f"\r  {bar_str} {pct_colored} [{count_colored}] {eta_colored}"

        # 文件名行
        if file_display:
            file_line = f"\r  📄 {file_display}"
        else:
            file_line = ""

        # 获取终端宽度用于清除行
        try:
            term_width = shutil.get_terminal_size().columns
        except Exception:
            term_width = 80

        # 输出：先清除当前两行，再写入
        # 使用 \033[K 清除到行尾
        sys.stderr.write(f"\r\033[K{progress_line}\033[K")
        if file_line:
            sys.stderr.write(f"\n{file_line}\033[K\033[A")
        sys.stderr.flush()

    def _format_eta(self, elapsed: float, percentage: float) -> str:
        """
        格式化预计剩余时间

        Args:
            elapsed: 已经过的时间（秒）
            percentage: 当前完成百分比

        Returns:
            格式化的剩余时间字符串
        """
        if percentage <= 0 or elapsed < 0.5:
            return "ETA: --:--"

        total_estimated = elapsed / percentage
        remaining = total_estimated - elapsed

        if remaining < 0:
            remaining = 0

        if remaining < 60:
            return f"ETA: {remaining:.0f}s"
        elif remaining < 3600:
            mins = int(remaining // 60)
            secs = int(remaining % 60)
            return f"ETA: {mins}m{secs:02d}s"
        else:
            hours = int(remaining // 3600)
            mins = int((remaining % 3600) // 60)
            return f"ETA: {hours}h{mins:02d}m"

    def _truncate_filename(self, file_path: str, max_len: int = 50) -> str:
        """
        截断文件名以适应终端显示

        Args:
            file_path: 文件路径
            max_len: 最大显示长度

        Returns:
            截断后的文件名
        """
        if not file_path:
            return ""

        # 使用相对路径或文件名
        basename = os.path.basename(file_path)
        # 尝试获取父目录/文件名 的简短路径
        parent = os.path.basename(os.path.dirname(file_path))
        if parent:
            short_path = f"{parent}/{basename}"
        else:
            short_path = basename

        if len(short_path) <= max_len:
            return short_path

        # 截断过长的路径
        return "..." + short_path[-(max_len - 3):]

    def finish(self):
        """完成进度条，清除进度显示"""
        if not self.enabled:
            return

        elapsed = time.time() - self.start_time

        # 清除进度条行
        sys.stderr.write("\r\033[K")
        if self.total > 0:
            sys.stderr.write("\n\033[K\033[A")
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()
