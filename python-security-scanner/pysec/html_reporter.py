"""
HTML可视化报告模块 - 生成带样式的漏洞扫描报告
全新功能：替代纯文本报告，提供可视化、可交互的HTML报告
"""

import os
from typing import List, Dict
from dataclasses import dataclass, field
from datetime import datetime

# 漏洞数据模型（极简版）
@dataclass
class VulnData:
    file_path: str
    line: int
    severity: str  # critical/high/medium/low
    vuln_type: str
    description: str
    fix_suggestion: str = ""

# HTML报告生成器
class HTMLVulnReporter:
    """轻量级HTML漏洞报告生成器"""
    
    def __init__(self):
        # 严重程度对应样式（颜色标记）
        self.severity_styles = {
            "critical": "background: #dc2626; color: white",
            "high": "background: #f97316; color: white",
            "medium": "background: #f59e0b; color: white",
            "low": "background: #10b981; color: white"
        }
        self.report_template = self._get_template()

    def _get_template(self) -> str:
        """HTML模板（内置样式，零外部依赖）"""
        return """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>Python安全扫描报告 - {timestamp}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ text-align: center; padding: 10px; border-bottom: 2px solid #333; }}
        .summary {{ margin: 20px 0; padding: 15px; background: #f3f4f6; border-radius: 8px; }}
        .vuln-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .vuln-table th, .vuln-table td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        .vuln-table th {{ background: #2563eb; color: white; }}
        .vuln-table tr:hover {{ background: #f9fafb; }}
        .severity-badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .stats {{ display: flex; gap: 20px; flex-wrap: wrap; margin: 10px 0; }}
        .stat-item {{ padding: 10px; border-radius: 6px; color: white; min-width: 100px; text-align: center; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Python代码安全扫描报告</h1>
        <p>生成时间：{timestamp} | 扫描文件数：{file_count} | 漏洞总数：{vuln_count}</p>
    </div>
    
    <div class="summary">
        <h3>漏洞统计</h3>
        <div class="stats">
            <div class="stat-item" style="background: #dc2626;">致命漏洞：{critical}</div>
            <div class="stat-item" style="background: #f97316;">高风险漏洞：{high}</div>
            <div class="stat-item" style="background: #f59e0b;">中风险漏洞：{medium}</div>
            <div class="stat-item" style="background: #10b981;">低风险漏洞：{low}</div>
        </div>
    </div>

    <h3>漏洞详情</h3>
    <table class="vuln-table">
        <tr>
            <th>文件路径</th>
            <th>行号</th>
            <th>严重程度</th>
            <th>漏洞类型</th>
            <th>描述</th>
            <th>修复建议</th>
        </tr>
        {vuln_rows}
    </table>
</body>
</html>
        """

    def _generate_vuln_rows(self, vulns: List[VulnData]) -> str:
        """生成漏洞详情行"""
        rows = []
        for vuln in vulns:
            # 获取严重程度样式
            style = self.severity_styles.get(vuln.severity.lower(), "background: #6b7280; color: white")
            # 构建行HTML
            row = f"""
            <tr>
                <td>{vuln.file_path}</td>
                <td>{vuln.line}</td>
                <td><span class="severity-badge" style="{style}">{vuln.severity.upper()}</span></td>
                <td>{vuln.vuln_type}</td>
                <td>{vuln.description}</td>
                <td>{vuln.fix_suggestion or "无"}</td>
            </tr>
            """
            rows.append(row)
        return "\n".join(rows)

    def generate_report(self, vulns: List[VulnData], output_path: str = "scan_report.html"):
        """生成HTML报告"""
        # 统计漏洞数量
        stats = {
            "critical": len([v for v in vulns if v.severity.lower() == "critical"]),
            "high": len([v for v in vulns if v.severity.lower() == "high"]),
            "medium": len([v for v in vulns if v.severity.lower() == "medium"]),
            "low": len([v for v in vulns if v.severity.lower() == "low"]),
        }
        # 提取唯一文件数
        file_count = len(set([v.file_path for v in vulns]))
        
        # 填充模板
        html_content = self.report_template.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            file_count=file_count,
            vuln_count=len(vulns),
            critical=stats["critical"],
            high=stats["high"],
            medium=stats["medium"],
            low=stats["low"],
            vuln_rows=self._generate_vuln_rows(vulns)
        )
        
        # 保存报告
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        print(f"✅ HTML可视化报告已生成：{os.path.abspath(output_path)}")

# 便捷演示
if __name__ == "__main__":
    # 模拟漏洞数据
    demo_vulns = [
        VulnData("./api.py", 15, "critical", "SQL注入", "SQL语句拼接注入", "使用参数化查询"),
        VulnData("./utils.py", 28, "high", "硬编码凭据", "代码中硬编码密码", "使用环境变量"),
        VulnData("./api.py", 42, "medium", "不安全随机数", "使用random模块", "替换为secrets模块"),
    ]
    
    # 生成报告
    reporter = HTMLVulnReporter()
    reporter.generate_report(demo_vulns)