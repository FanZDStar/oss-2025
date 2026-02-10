"""
扫描统计迷你模块 - 轻量版漏洞统计+极简进度条
仅100+行代码，聚焦核心统计能力
"""

import os
import sys
import time
from typing import List, Dict, Tuple
from enum import Enum

# 漏洞等级枚举（极简版）
class VulnSeverity(Enum):
    CRITICAL = "致命"
    HIGH = "高风险"
    MEDIUM = "中风险"
    LOW = "低风险"

# 极简进度条（仅20行）
class MiniProgressBar:
    """迷你进度条 - 零依赖、极简实现"""
    def __init__(self, total: int):
        self.total = total
        self.current = 0
        self.start = time.time()

    def step(self, file_name: str = ""):
        """步进进度"""
        self.current += 1
        percent = (self.current / self.total) * 100
        elapsed = time.time() - self.start
        speed = self.current / elapsed if elapsed > 0 else 0
        
        # 进度条输出
        bar = f"[{'█'*int(percent/10)}{' '*(10-int(percent/10))}]"
        info = f"\r扫描中 {bar} {self.current}/{self.total} ({percent:.1f}%) | {speed:.1f} 文件/秒 | 当前: {file_name[:15]}"
        sys.stdout.write(info)
        sys.stdout.flush()
        
        if self.current >= self.total:
            print(f"\n✅ 扫描完成！总耗时: {elapsed:.2f} 秒")

# 核心统计功能
class ScanStats:
    """扫描统计工具"""
    def __init__(self):
        self.stats: Dict[str, int] = {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "files_scanned": 0
        }
        self.vuln_by_file: Dict[str, List[Tuple[int, str, str]]] = {}

    def add_vuln(self, file_path: str, line: int, severity: VulnSeverity, vuln_type: str):
        """添加漏洞统计"""
        self.stats["total"] += 1
        self.stats[severity.name.lower()] += 1
        
        if file_path not in self.vuln_by_file:
            self.vuln_by_file[file_path] = []
        self.vuln_by_file[file_path].append((line, severity.value, vuln_type))

    def add_scanned_file(self):
        """记录已扫描文件"""
        self.stats["files_scanned"] += 1

    def print_summary(self):
        """打印统计汇总"""
        print("\n📊 扫描统计汇总")
        print("-" * 30)
        print(f"扫描文件数: {self.stats['files_scanned']}")
        print(f"漏洞总数: {self.stats['total']}")
        print(f"├─ 致命漏洞: {self.stats['critical']}")
        print(f"├─ 高风险漏洞: {self.stats['high']}")
        print(f"├─ 中风险漏洞: {self.stats['medium']}")
        print(f"└─ 低风险漏洞: {self.stats['low']}")

    def print_file_detail(self):
        """打印按文件分类的漏洞详情"""
        print("\n📋 按文件漏洞详情")
        print("-" * 30)
        for file_path, vulns in self.vuln_by_file.items():
            if vulns:
                print(f"\n📄 {file_path}:")
                for line, severity, vuln_type in vulns:
                    print(f"  ⚠️  行{line} | {severity} | {vuln_type}")

# 便捷使用函数
def scan_demo(path: str = "./"):
    """扫描演示函数"""
    # 查找Python文件
    files = []
    for root, _, filenames in os.walk(path):
        for f in filenames:
            if f.endswith(".py") and "__pycache__" not in root:
                files.append(os.path.join(root, f))
    
    if not files:
        print("⚠️  未找到Python文件")
        return

    # 初始化工具
    stats = ScanStats()
    progress = MiniProgressBar(len(files))

    # 模拟扫描
    for file in files:
        progress.step(os.path.basename(file))
        stats.add_scanned_file()
        
        # 模拟漏洞检测
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.split("\n")
            
            # 检测硬编码密码
            for idx, line in enumerate(lines, 1):
                if "password=" in line.lower() and not line.startswith("#"):
                    stats.add_vuln(file, idx, VulnSeverity.HIGH, "硬编码凭据")
            
            # 检测危险函数
            if "eval(" in content:
                stats.add_vuln(file, lines.index([l for l in lines if "eval(" in l][0])+1, 
                              VulnSeverity.CRITICAL, "危险函数调用")

    # 输出统计结果
    stats.print_summary()
    stats.print_file_detail()

if __name__ == "__main__":
    # 运行演示（扫描当前目录）
    scan_demo()