# progress.py
from tqdm import tqdm
import os
from typing import Iterable, Optional, Callable

class ScanProgressBar:
    """扫描进度条管理器"""
    
    def __init__(self, total_files: int, disable: bool = False):
        """
        初始化进度条
        :param total_files: 总文件数
        :param disable: 是否禁用进度条（非交互终端时自动禁用）
        """
        self.total = total_files
        self.disable = disable or not self._is_interactive()
        self.pbar = None
    
    def _is_interactive(self) -> bool:
        """判断是否为交互式终端（避免非交互环境输出乱码）"""
        try:
            return os.isatty(1)  # 标准输出是否为终端
        except Exception:
            return False
    
    def start(self) -> None:
        """启动进度条"""
        if self.disable:
            return
        
        # 配置进度条样式
        self.pbar = tqdm(
            total=self.total,
            desc="扫描进度",
            unit="文件",
            dynamic_ncols=True,  # 自适应终端宽度
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",
        )
    
    def update(self, current_file: str, step: int = 1) -> None:
        """
        更新进度条
        :param current_file: 当前扫描的文件名（显示在进度条右侧）
        :param step: 步进数（默认+1）
        """
        if self.disable or not self.pbar:
            return
        
        # 显示当前扫描的文件名（截断过长路径）
        display_name = os.path.basename(current_file)
        if len(display_name) > 30:
            display_name = f"...{display_name[-27:]}"
        
        # 更新进度条描述
        self.pbar.set_postfix(file=display_name)
        self.pbar.update(step)
    
    def finish(self) -> None:
        """结束进度条"""
        if self.disable or not self.pbar:
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

# 独立使用示例
if __name__ == "__main__":
    # 模拟扫描10个文件
    test_files = [f"test_{i}.py" for i in range(10)]
    
    progress = ScanProgressBar(len(test_files))
    progress.start()
    
    for file in test_files:
        # 模拟扫描耗时
        import time
        time.sleep(0.2)
        progress.update(file)
    
    progress.finish()