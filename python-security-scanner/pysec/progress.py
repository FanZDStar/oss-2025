# progress.py
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    tqdm = None

import os
import sys
import time
import shutil
from typing import Iterable, Optional, Callable

# 颜色支持（复用旧版的颜色逻辑）
class ANSIColors:
    RESET = "\033[0m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    BRIGHT_GREEN = "\033[92;1m"
    BRIGHT_CYAN = "\033[96;1m"
    BRIGHT_BLACK = "\033[90;1m"
    BOLD = "\033[1m"

class ColorSupport:
    @staticmethod
    def is_enabled() -> bool:
        """判断是否启用颜色输出"""
        try:
            return os.isatty(1) and sys.stdout.encoding == "utf-8"
        except Exception:
            return False

class ScanProgressBar:
    """扫描进度条管理器（整合tqdm+旧版颜色/ETA功能）"""
    
    def __init__(self, total_files: int, disable: bool = False):
        """
        初始化进度条
        :param total_files: 总文件数
        :param disable: 是否禁用进度条（非交互终端时自动禁用）
        """
        self.total = total_files
        self.disable = disable or not self._is_interactive()
        self.pbar = None
        self.start_time = time.time()
    
    def _is_interactive(self) -> bool:
        """判断是否为交互式终端（避免非交互环境输出乱码）"""
        try:
            return os.isatty(1)  # 标准输出是否为终端
        except Exception:
            return False
    
    def _format_eta(self, elapsed: float, percentage: float) -> str:
        """格式化预计剩余时间（复用旧版逻辑）"""
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
        """截断文件名（复用旧版逻辑）"""
        if not file_path:
            return ""

        basename = os.path.basename(file_path)
        parent = os.path.basename(os.path.dirname(file_path))
        if parent:
            short_path = f"{parent}/{basename}"
        else:
            short_path = basename

        if len(short_path) <= max_len:
            return short_path

        return "..." + short_path[-(max_len - 3):]
    
    def start(self) -> None:
        """启动进度条（带颜色和ETA）"""
        if self.disable:
            return
        
        if not HAS_TQDM:
            # Fallback: 简单文本进度
            print(f"开始扫描 {self.total} 个文件...")
            return
        
        # 配置进度条样式（整合颜色和ETA）
        bar_format = "{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        if ColorSupport.is_enabled():
            bar_format = f"{ANSIColors.CYAN}{bar_format}{ANSIColors.RESET}"
        
        self.pbar = tqdm(
            total=self.total,
            desc="扫描进度",
            unit="文件",
            dynamic_ncols=True,
            bar_format=bar_format,
        )
    
    def update(self, current_file: str, step: int = 1) -> None:
        """更新进度条（显示截断后的文件名+ETA）"""
        if self.disable:
            return
        
        if not HAS_TQDM or not self.pbar:
            # Fallback: 简单文本进度
            return
        
        # 显示当前扫描的文件名（截断过长路径）
        display_name = self._truncate_filename(current_file)
        
        # 计算ETA
        elapsed = time.time() - self.start_time
        percentage = self.pbar.n / self.total if self.total > 0 else 0
        eta = self._format_eta(elapsed, percentage)
        
        # 更新进度条描述（带颜色）
        postfix = {"file": display_name, "ETA": eta}
        if ColorSupport.is_enabled():
            postfix = {
                "file": f"{ANSIColors.BRIGHT_CYAN}{display_name}{ANSIColors.RESET}",
                "ETA": f"{ANSIColors.BRIGHT_BLACK}{eta}{ANSIColors.RESET}"
            }
        
        self.pbar.set_postfix(postfix)
        self.pbar.update(step)
    
    def finish(self) -> None:
        """结束进度条"""
        if self.disable:
            return
        
        if not HAS_TQDM or not self.pbar:
            # Fallback: 简单文本完成提示
            print(f"扫描完成")
            return
            
        self.pbar.close()

# 便捷装饰器：为扫描函数添加进度条
def with_progress_bar(func: Callable) -> Callable:
    """
    装饰器：给文件扫描迭代器添加进度条
    使用示例：
    @with_progress_bar
    def scan_files(files):
        for file in files:
            yield scan_file(file)
    """
    def wrapper(files: Iterable[str], *args, **kwargs):
        # 统计总文件数
        file_list = list(files)
        total = len(file_list)
        
        # 初始化进度条
        progress = ScanProgressBar(total)
        progress.start()
        
        try:
            # 遍历文件并更新进度
            for file in file_list:
                yield func(file, *args, **kwargs)
                progress.update(file)
        finally:
            progress.finish()
    
    return wrapper

# 向后兼容别名
ProgressBar = ScanProgressBar

# 独立使用示例
if __name__ == "__main__":
    # 模拟扫描10个文件
    test_files = [f"test_{i}.py" for i in range(10)]
    
    progress = ScanProgressBar(len(test_files))
    progress.start()
    
    for file in test_files:
        # 模拟扫描耗时
        time.sleep(0.2)
        progress.update(file)
    
    progress.finish()