"""
扫描忽略管理器 - 精准控制哪些内容不被扫描
全新功能：跳过指定文件/目录/漏洞类型，减少无效扫描结果
"""

import os
import fnmatch
from typing import List, Dict, Set
from dataclasses import dataclass, field

# 忽略规则模型
@dataclass
class IgnoreRules:
    dirs: Set[str] = field(default_factory=set)    # 忽略的目录
    files: Set[str] = field(default_factory=set)  # 忽略的文件（支持通配符）
    vuln_types: Set[str] = field(default_factory=set)  # 忽略的漏洞类型

# 核心忽略管理器
class ScanIgnoreManager:
    """扫描忽略规则管理器"""
    
    def __init__(self):
        self.rules = IgnoreRules()

    def load_ignore_file(self, file_path: str = ".scanignore"):
        """加载忽略配置文件（类似.gitignore）"""
        if not os.path.exists(file_path):
            return
        
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # 跳过注释和空行
                if not line or line.startswith("#"):
                    continue
                
                # 解析规则（按前缀分类）
                if line.startswith("dir:"):
                    self.rules.dirs.add(line[4:].strip())
                elif line.startswith("file:"):
                    self.rules.files.add(line[5:].strip())
                elif line.startswith("vuln:"):
                    self.rules.vuln_types.add(line[5:].strip().lower())

    def is_dir_ignored(self, dir_path: str) -> bool:
        """判断目录是否被忽略"""
        # 转换为相对路径，统一判断
        rel_dir = os.path.relpath(dir_path)
        for ignore_dir in self.rules.dirs:
            if ignore_dir in rel_dir or fnmatch.fnmatch(rel_dir, ignore_dir):
                return True
        return False

    def is_file_ignored(self, file_path: str) -> bool:
        """判断文件是否被忽略"""
        file_name = os.path.basename(file_path)
        rel_path = os.path.relpath(file_path)
        
        # 检查文件匹配
        for ignore_file in self.rules.files:
            if fnmatch.fnmatch(file_name, ignore_file) or fnmatch.fnmatch(rel_path, ignore_file):
                return True
        
        # 检查文件所在目录是否被忽略
        dir_path = os.path.dirname(file_path)
        return self.is_dir_ignored(dir_path)

    def is_vuln_ignored(self, vuln_type: str) -> bool:
        """判断漏洞类型是否被忽略"""
        return vuln_type.lower() in self.rules.vuln_types

    def add_ignore_rule(self, rule_type: str, value: str):
        """手动添加忽略规则"""
        if rule_type == "dir":
            self.rules.dirs.add(value)
        elif rule_type == "file":
            self.rules.files.add(value)
        elif rule_type == "vuln":
            self.rules.vuln_types.add(value.lower())

# 便捷使用示例
def demo_ignore():
    """忽略管理器演示"""
    # 创建管理器
    ignore_mgr = ScanIgnoreManager()
    
    # 手动添加忽略规则
    ignore_mgr.add_ignore_rule("dir", "tests")
    ignore_mgr.add_ignore_rule("file", "*_test.py")
    ignore_mgr.add_ignore_rule("vuln", "日志泄露")
    
    # 测试判断
    test_files = [
        "./tests/test_api.py",
        "./src/main.py",
        "./utils_test.py",
        "./src/log.py"
    ]
    
    print("🔍 忽略规则测试结果:")
    for file in test_files:
        ignored = ignore_mgr.is_file_ignored(file)
        status = "❌ 忽略" if ignored else "✅ 扫描"
        print(f"{status} | {file}")
    
    # 测试漏洞类型忽略
    vuln_types = ["SQL注入", "日志泄露", "硬编码凭据"]
    print("\n🔍 漏洞类型忽略测试:")
    for vuln in vuln_types:
        ignored = ignore_mgr.is_vuln_ignored(vuln)
        status = "❌ 忽略" if ignored else "✅ 检测"
        print(f"{status} | {vuln}")

if __name__ == "__main__":
    demo_ignore()