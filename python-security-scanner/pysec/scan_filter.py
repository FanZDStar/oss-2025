"""
扫描结果过滤器 - 精准筛选漏洞结果
全新轻量功能：按等级/类型/路径过滤，快速定位关键漏洞
"""

import re
from typing import List, Dict, Callable, Optional
from dataclasses import dataclass

# 极简漏洞数据模型
@dataclass
class VulnItem:
    file_path: str
    line: int
    severity: str  # critical/high/medium/low
    vuln_type: str
    description: str

# 核心过滤器类
class ScanResultFilter:
    """扫描结果精准过滤器"""
    
    def __init__(self, vuln_list: List[VulnItem]):
        self.vulns = vuln_list
        self.filtered_vulns = vuln_list

    def by_severity(self, severity: str) -> "ScanResultFilter":
        """按漏洞等级过滤"""
        self.filtered_vulns = [
            v for v in self.filtered_vulns 
            if v.severity.lower() == severity.lower()
        ]
        return self

    def by_severity_ge(self, min_severity: str) -> "ScanResultFilter":
        """按最低等级过滤（包含更高等级）"""
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        min_level = severity_order.get(min_severity.lower(), 1)
        
        self.filtered_vulns = [
            v for v in self.filtered_vulns 
            if severity_order.get(v.severity.lower(), 0) >= min_level
        ]
        return self

    def by_type(self, vuln_type: str, fuzzy: bool = True) -> "ScanResultFilter":
        """按漏洞类型过滤（支持模糊匹配）"""
        if fuzzy:
            self.filtered_vulns = [
                v for v in self.filtered_vulns 
                if vuln_type.lower() in v.vuln_type.lower()
            ]
        else:
            self.filtered_vulns = [
                v for v in self.filtered_vulns 
                if v.vuln_type.lower() == vuln_type.lower()
            ]
        return self

    def by_path(self, path_pattern: str) -> "ScanResultFilter":
        """按文件路径过滤（支持正则）"""
        pattern = re.compile(path_pattern, re.IGNORECASE)
        self.filtered_vulns = [
            v for v in self.filtered_vulns 
            if pattern.search(v.file_path)
        ]
        return self

    def get_result(self) -> List[VulnItem]:
        """获取过滤结果"""
        return self.filtered_vulns

    def print_result(self):
        """打印过滤结果"""
        print(f"\n🔍 过滤结果（共{len(self.filtered_vulns)}个漏洞）:")
        for idx, vuln in enumerate(self.filtered_vulns, 1):
            print(f"{idx}. [{vuln.severity.upper()}] {vuln.file_path}:{vuln.line}")
            print(f"   类型: {vuln.vuln_type} | 描述: {vuln.description[:50]}...")

# 便捷使用示例
def demo_filter():
    """过滤器演示"""
    # 模拟扫描结果
    demo_vulns = [
        VulnItem("./api.py", 15, "critical", "SQL注入", "SQL语句拼接存在注入风险"),
        VulnItem("./utils.py", 28, "high", "硬编码凭据", "代码中发现硬编码密码"),
        VulnItem("./api.py", 42, "medium", "不安全随机数", "使用random模块生成安全随机数"),
        VulnItem("./admin.py", 8, "high", "SQL注入", "未使用参数化查询"),
        VulnItem("./test.py", 5, "low", "日志泄露", "日志中包含敏感信息")
    ]

    # 创建过滤器
    filter = ScanResultFilter(demo_vulns)
    
    # 组合过滤：高等级 + SQL注入 + api相关文件
    filter.by_severity_ge("high").by_type("SQL注入").by_path(r"api\.py")
    
    # 输出结果
    filter.print_result()

if __name__ == "__main__":
    demo_filter()