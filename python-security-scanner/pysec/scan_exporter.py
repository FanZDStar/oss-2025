"""
扫描结果导出模块 - 支持多格式导出+简易进度条
轻量实用，专注扫描结果的多样化导出能力
"""

import os
import csv
import json
import time
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime

# 简易进度条（无任何依赖）
class SimpleProgressBar:
    """零依赖简易进度条"""
    def __init__(self, total: int, title: str = "处理进度"):
        self.total = total
        self.title = title
        self.current = 0
        self.start_time = time.time()
        self.bar_length = 30  # 进度条长度
    
    def update(self, step: int = 1, current_item: str = ""):
        """更新进度"""
        self.current = min(self.current + step, self.total)
        progress = self.current / self.total if self.total > 0 else 1.0
        
        # 计算进度条
        filled = int(self.bar_length * progress)
        bar = "█" * filled + "░" * (self.bar_length - filled)
        
        # 计算耗时和剩余时间
        elapsed = time.time() - self.start_time
        eta = (elapsed / progress) - elapsed if progress > 0 else 0
        
        # 格式化时间
        elapsed_str = self._format_time(elapsed)
        eta_str = self._format_time(eta)
        
        # 构建进度信息
        item_info = f" | 当前: {current_item[:20]}" if current_item else ""
        progress_info = (
            f"\r{self.title}: [{bar}] {self.current}/{self.total} "
            f"({progress*100:.1f}%) | 耗时: {elapsed_str} | 剩余: {eta_str}{item_info}"
        )
        
        # 输出进度
        print(progress_info, end="", flush=True)
        
        # 完成时换行
        if self.current >= self.total:
            print("\n✅ 处理完成！")
    
    @staticmethod
    def _format_time(seconds: float) -> str:
        """格式化时间为 分:秒"""
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes:02d}:{secs:02d}"

# 漏洞等级枚举
class VulnLevel(Enum):
    CRITICAL = "致命"
    HIGH = "高风险"
    MEDIUM = "中风险"
    LOW = "低风险"

# 扫描结果模型
@dataclass
class ScanItem:
    """单个扫描结果项"""
    file_path: str
    line_num: int
    vuln_level: VulnLevel
    vuln_type: str
    description: str
    fix_suggestion: str = ""
    scan_time: datetime = field(default_factory=datetime.now)

@dataclass
class ExportResult:
    """导出结果"""
    export_path: str
    total_items: int
    success_count: int
    fail_count: int
    export_time: datetime = field(default_factory=datetime.now)

# 多格式导出器
class MultiFormatExporter:
    """多格式扫描结果导出器"""
    
    def __init__(self):
        self.progress = None
        self.export_history: List[ExportResult] = []
    
    def _prepare_export_dir(self, export_path: str) -> str:
        """准备导出目录"""
        export_dir = os.path.dirname(export_path)
        if export_dir and not os.path.exists(export_dir):
            os.makedirs(export_dir)
        return export_path
    
    def export_json(self, items: List[ScanItem], export_path: str) -> ExportResult:
        """导出为JSON格式"""
        export_path = self._prepare_export_dir(export_path)
        self.progress = SimpleProgressBar(len(items), "JSON导出进度")
        
        success = 0
        fail = 0
        export_data = {
            "export_info": {
                "export_time": datetime.now().isoformat(),
                "total_items": len(items)
            },
            "scan_results": []
        }
        
        for idx, item in enumerate(items):
            try:
                item_dict = asdict(item)
                item_dict["vuln_level"] = item.vuln_level.value
                item_dict["scan_time"] = item.scan_time.isoformat()
                export_data["scan_results"].append(item_dict)
                success += 1
            except Exception as e:
                print(f"\n❌ 导出项 {idx+1} 失败: {str(e)}")
                fail += 1
            self.progress.update(current_item=os.path.basename(item.file_path))
        
        # 保存JSON文件
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)
        
        result = ExportResult(export_path, len(items), success, fail)
        self.export_history.append(result)
        print(f"\n📄 JSON文件已导出至: {export_path}")
        return result
    
    def export_csv(self, items: List[ScanItem], export_path: str) -> ExportResult:
        """导出为CSV格式（便于Excel打开）"""
        export_path = self._prepare_export_dir(export_path)
        self.progress = SimpleProgressBar(len(items), "CSV导出进度")
        
        success = 0
        fail = 0
        
        # 打开CSV文件
        with open(export_path, "w", encoding="utf-8-sig", newline="") as f:
            # 定义表头
            fieldnames = [
                "文件路径", "行号", "漏洞等级", "漏洞类型", 
                "漏洞描述", "修复建议", "扫描时间"
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            # 逐行导出
            for idx, item in enumerate(items):
                try:
                    writer.writerow({
                        "文件路径": item.file_path,
                        "行号": item.line_num,
                        "漏洞等级": item.vuln_level.value,
                        "漏洞类型": item.vuln_type,
                        "漏洞描述": item.description,
                        "修复建议": item.fix_suggestion,
                        "扫描时间": item.scan_time.strftime("%Y-%m-%d %H:%M:%S")
                    })
                    success += 1
                except Exception as e:
                    print(f"\n❌ 导出项 {idx+1} 失败: {str(e)}")
                    fail += 1
                self.progress.update(current_item=os.path.basename(item.file_path))
        
        result = ExportResult(export_path, len(items), success, fail)
        self.export_history.append(result)
        print(f"\n📄 CSV文件已导出至: {export_path}")
        return result
    
    def export_txt(self, items: List[ScanItem], export_path: str) -> ExportResult:
        """导出为易读的TXT格式"""
        export_path = self._prepare_export_dir(export_path)
        self.progress = SimpleProgressBar(len(items), "TXT导出进度")
        
        success = 0
        fail = 0
        
        with open(export_path, "w", encoding="utf-8") as f:
            # 写入导出信息
            f.write(f"===== 扫描结果导出报告 =====\n")
            f.write(f"导出时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"总扫描项: {len(items)}\n")
            f.write(f"============================\n\n")
            
            # 逐行写入扫描结果
            for idx, item in enumerate(items):
                try:
                    item_str = f"""
【{idx+1}/{len(items)}】
文件: {item.file_path}
行号: {item.line_num}
等级: {item.vuln_level.value}
类型: {item.vuln_type}
描述: {item.description}
建议: {item.fix_suggestion}
扫描时间: {item.scan_time.strftime('%Y-%m-%d %H:%M:%S')}
----------------------------------------
                    """.strip()
                    f.write(item_str + "\n\n")
                    success += 1
                except Exception as e:
                    print(f"\n❌ 导出项 {idx+1} 失败: {str(e)}")
                    fail += 1
                self.progress.update(current_item=os.path.basename(item.file_path))
        
        result = ExportResult(export_path, len(items), success, fail)
        self.export_history.append(result)
        print(f"\n📄 TXT文件已导出至: {export_path}")
        return result

# 便捷使用示例
def demo_export():
    """导出功能演示"""
    # 模拟扫描结果
    demo_items = [
        ScanItem(
            file_path="./test.py",
            line_num=10,
            vuln_level=VulnLevel.HIGH,
            vuln_type="硬编码凭据",
            description="代码中发现硬编码的密码",
            fix_suggestion="使用环境变量存储密码"
        ),
        ScanItem(
            file_path="./utils.py",
            line_num=25,
            vuln_level=VulnLevel.MEDIUM,
            vuln_type="不安全随机数",
            description="使用random模块生成安全相关随机数",
            fix_suggestion="替换为secrets模块"
        ),
        ScanItem(
            file_path="./api.py",
            line_num=58,
            vuln_level=VulnLevel.CRITICAL,
            vuln_type="SQL注入",
            description="SQL语句拼接存在注入风险",
            fix_suggestion="使用参数化查询"
        )
    ]
    
    # 创建导出器
    exporter = MultiFormatExporter()
    
    # 导出为不同格式
    exporter.export_json(demo_items, "./scan_result.json")
    exporter.export_csv(demo_items, "./scan_result.csv")
    exporter.export_txt(demo_items, "./scan_result.txt")
    
    # 打印导出历史
    print("\n📊 导出历史:")
    for hist in exporter.export_history:
        print(f"- {hist.export_path}: 成功{hist.success_count} | 失败{hist.fail_count}")

if __name__ == "__main__":
    # 运行演示
    demo_export()