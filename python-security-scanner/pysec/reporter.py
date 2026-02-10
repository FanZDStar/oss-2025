"""
报告生成器模块

支持多种格式的扫描报告输出
"""

import json
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Type, Any, Optional
from pathlib import Path

try:
    from .models import ScanResult, Vulnerability
    from .colors import (
        header, bold, severity_badge, severity_color,
        green, blue, gray, success, ColorSupport
    )
    from .reporters.html_charts_reporter import HTMLChartsReporter
    from .reporters.sarif_reporter import SarifReporter
except ImportError:
    # 备用导入
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from models import ScanResult, Vulnerability
    from colors import (
        header, bold, severity_badge, severity_color,
        green, blue, gray, success, ColorSupport
    )
    from reporters.html_charts_reporter import HTMLChartsReporter
    from reporters.sarif_reporter import SarifReporter



class BaseReporter(ABC):
    """报告生成器基类"""

    @abstractmethod
    def generate(self, result: ScanResult) -> str:
        """
        生成报告

        Args:
            result: 扫描结果

        Returns:
            报告内容字符串
        """
        pass

    def save(self, result: ScanResult, file_path: str):
        """
        生成报告并保存到文件

        Args:
            result: 扫描结果
            file_path: 输出文件路径
        """
        content = self.generate(result)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)


class TextReporter(BaseReporter):
    """纯文本格式报告生成器"""

    SEVERITY_SYMBOLS = {
        "critical": "[!!!]",
        "high": "[!!]",
        "medium": "[!]",
        "low": "[.]",
    }

    def generate(self, result: ScanResult) -> str:
        lines = []

        # 标题
        lines.append("=" * 60)
        lines.append(header("PySecScanner 安全扫描报告"))
        lines.append("=" * 60)
        lines.append("")

        # 基本信息
        lines.append(f"{bold('扫描目标:')} {result.target}")
        lines.append(f"{bold('扫描时间:')} {result.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"{bold('扫描耗时:')} {result.duration:.2f} 秒")
        lines.append(f"{bold('扫描文件:')} {result.files_scanned} 个")
        lines.append("")

        # 统计摘要
        summary = result.summary
        lines.append("-" * 40)
        lines.append(header("漏洞统计"))
        lines.append("-" * 40)
        lines.append(f"  {severity_color('critical', '严重 (Critical):'):<25} {summary['critical']}")
        lines.append(f"  {severity_color('high', '高危 (High):'):<25} {summary['high']}")
        lines.append(f"  {severity_color('medium', '中危 (Medium):'):<25} {summary['medium']}")
        lines.append(f"  {severity_color('low', '低危 (Low):'):<25} {summary['low']}")
        lines.append(f"  {bold('总计:'):<25} {summary['total']}")
        if summary.get("ignored", 0) > 0:
            lines.append(f"  {gray('已忽略:'):<25} {summary['ignored']}")
        if summary.get("filtered", 0) > 0:
            lines.append(f"  {gray('已过滤:'):<25} {summary['filtered']}")
        lines.append("")

        # 漏洞详情
        if result.vulnerabilities:
            lines.append("-" * 40)
            lines.append(header("漏洞详情"))
            lines.append("-" * 40)
            lines.append("")

            # 按严重程度排序
            sorted_vulns = sorted(
                result.vulnerabilities,
                key=lambda v: ["critical", "high", "medium", "low"].index(v.severity),
            )

            for i, vuln in enumerate(sorted_vulns, 1):
                badge = severity_badge(vuln.severity)
                rule_id = blue(f"[{vuln.rule_id}]", bold=True)
                lines.append(f"{i}. {badge} {rule_id} {vuln.rule_name}")
                lines.append(f"   {bold('严重程度:')} {severity_color(vuln.severity, vuln.severity.upper())}")
                lines.append(f"   {bold('位置:')} {vuln.file_path}:{vuln.line_number}")
                lines.append(f"   {bold('描述:')} {vuln.description}")
                lines.append(f"   {bold('代码:')} {gray(vuln.code_snippet)}")
                lines.append(f"   {bold('建议:')} {vuln.suggestion}")
                lines.append("")
        else:
            lines.append(success("未发现安全漏洞"))
            lines.append("")

        # 错误信息
        if result.errors:
            lines.append("-" * 40)
            lines.append(header("扫描错误"))
            lines.append("-" * 40)
            for error in result.errors:
                lines.append(f"  - {gray(error)}")
            lines.append("")

        # 页脚
        lines.append("=" * 60)
        lines.append(f"报告由 {blue('PySecScanner v1.0.0', bold=True)} 生成")
        lines.append("=" * 60)

        return "\n".join(lines)


class MarkdownReporter(BaseReporter):
    """Markdown格式报告生成器"""

    SEVERITY_ICONS = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
    }

    def generate(self, result: ScanResult) -> str:
        lines = []

        # 标题
        lines.append("# PySecScanner 安全扫描报告")
        lines.append("")

        # 基本信息
        lines.append("## 扫描信息")
        lines.append("")
        lines.append("| 项目 | 内容 |")
        lines.append("|------|------|")
        lines.append(f"| 扫描目标 | `{result.target}` |")
        lines.append(f"| 扫描时间 | {result.scan_time.strftime('%Y-%m-%d %H:%M:%S')} |")
        lines.append(f"| 扫描耗时 | {result.duration:.2f} 秒 |")
        lines.append(f"| 扫描文件数 | {result.files_scanned} |")
        lines.append("")

        # 统计摘要
        summary = result.summary
        lines.append("## 漏洞统计")
        lines.append("")
        lines.append("| 严重程度 | 数量 |")
        lines.append("|----------|------|")
        lines.append(
            f"| {self.SEVERITY_ICONS['critical']} 严重 (Critical) | {summary['critical']} |"
        )
        lines.append(f"| {self.SEVERITY_ICONS['high']} 高危 (High) | {summary['high']} |")
        lines.append(f"| {self.SEVERITY_ICONS['medium']} 中危 (Medium) | {summary['medium']} |")
        lines.append(f"| {self.SEVERITY_ICONS['low']} 低危 (Low) | {summary['low']} |")
        lines.append(f"| **总计** | **{summary['total']}** |")
        if summary.get("ignored", 0) > 0:
            lines.append(f"|  已忽略 | {summary['ignored']} |")
        if summary.get("filtered", 0) > 0:
            lines.append(f"|  已过滤 | {summary['filtered']} |")
        lines.append("")

        # 漏洞详情
        if result.vulnerabilities:
            lines.append("## 漏洞详情")
            lines.append("")

            # 按严重程度排序
            sorted_vulns = sorted(
                result.vulnerabilities,
                key=lambda v: ["critical", "high", "medium", "low"].index(v.severity),
            )

            for i, vuln in enumerate(sorted_vulns, 1):
                icon = self.SEVERITY_ICONS.get(vuln.severity, "⚪")

                lines.append(f"### {i}. [{vuln.rule_id}] {vuln.rule_name}")
                lines.append("")
                lines.append(f"**严重程度:** {icon} {vuln.severity.upper()}")
                lines.append("")
                lines.append(f"**位置:** `{vuln.file_path}` 第 {vuln.line_number} 行")
                lines.append("")
                lines.append(f"**描述:** {vuln.description}")
                lines.append("")
                lines.append("**问题代码:**")
                lines.append("")
                lines.append("```python")
                lines.append(vuln.code_snippet)
                lines.append("```")
                lines.append("")
                lines.append(f"**修复建议:** {vuln.suggestion}")
                lines.append("")
                lines.append("---")
                lines.append("")
        else:
            lines.append("## 扫描结果")
            lines.append("")
            lines.append(" **未发现安全漏洞**")
            lines.append("")

        # 错误信息
        if result.errors:
            lines.append("## 扫描错误")
            lines.append("")
            for error in result.errors:
                lines.append(f"- {error}")
            lines.append("")

        # 页脚
        lines.append("---")
        lines.append("")
        lines.append(
            f"*报告由 PySecScanner v1.0.0 生成 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        )

        return "\n".join(lines)


class JSONReporter(BaseReporter):
    """JSON格式报告生成器"""

    def generate(self, result: ScanResult) -> str:
        data = {
            "target": result.target,
            "scan_time": result.scan_time.isoformat(),
            "duration": result.duration,
            "files_scanned": result.files_scanned,
            "summary": result.summary,
            "vulnerabilities": [vuln.to_dict() for vuln in result.vulnerabilities],
            "errors": result.errors,
        }
        return json.dumps(data, ensure_ascii=False, indent=2)


class HTMLReporter(BaseReporter):
    """HTML格式报告生成器（含统计仪表盘）"""

    SEVERITY_COLORS = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#28a745",
    }

    def __init__(self, scan_history=None):
        """
        初始化 HTML 报告生成器

        Args:
            scan_history: 可选的扫描历史记录列表（ScanSummary 对象），用于趋势图
        """
        self.scan_history = scan_history or []

    def _build_type_data(self, vulnerabilities):
        """按漏洞类型（rule_id）分组统计"""
        type_counts = {}
        for vuln in vulnerabilities:
            label = f"{vuln.rule_id}"
            type_counts[label] = type_counts.get(label, 0) + 1
        # 按数量降序排列
        sorted_items = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        return [item[0] for item in sorted_items], [item[1] for item in sorted_items]

    def _build_file_data(self, vulnerabilities, top_n=10):
        """按文件分组统计漏洞数量（取 Top N）"""
        import os
        file_counts = {}
        for vuln in vulnerabilities:
            # 使用文件名（不含完整路径）以节省空间
            basename = os.path.basename(vuln.file_path)
            file_counts[basename] = file_counts.get(basename, 0) + 1
        sorted_items = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
        return [item[0] for item in sorted_items], [item[1] for item in sorted_items]

    def _build_trend_data(self):
        """构建趋势数据（来自 scan_history）"""
        if not self.scan_history:
            return [], [], [], [], []
        labels = []
        critical_data = []
        high_data = []
        medium_data = []
        low_data = []
        for record in self.scan_history:
            # 如果是 ScanSummary 对象
            if hasattr(record, 'scan_time'):
                time_str = record.scan_time
                labels.append(time_str[:10] if len(time_str) >= 10 else time_str)
                critical_data.append(record.critical)
                high_data.append(record.high)
                medium_data.append(record.medium)
                low_data.append(record.low)
            # 如果是字典
            elif isinstance(record, dict):
                time_str = record.get('scan_time', '')
                labels.append(time_str[:10] if len(time_str) >= 10 else time_str)
                critical_data.append(record.get('critical', 0))
                high_data.append(record.get('high', 0))
                medium_data.append(record.get('medium', 0))
                low_data.append(record.get('low', 0))
        return labels, critical_data, high_data, medium_data, low_data

    def generate(self, result: ScanResult) -> str:
        summary = result.summary

        # 构建图表数据
        type_labels, type_values = self._build_type_data(result.vulnerabilities)
        file_labels, file_values = self._build_file_data(result.vulnerabilities)
        trend_labels, trend_critical, trend_high, trend_medium, trend_low = self._build_trend_data()

        # 生成漏洞HTML
        vulns_html = ""
        if result.vulnerabilities:
            sorted_vulns = sorted(
                result.vulnerabilities,
                key=lambda v: ["critical", "high", "medium", "low"].index(v.severity),
            )
            for vuln in sorted_vulns:
                color = self.SEVERITY_COLORS.get(vuln.severity, "#6c757d")
                vulns_html += f"""
                <div class="vuln-card">
                    <div class="vuln-header">
                        <span class="severity-badge" style="background-color: {color};">
                            {vuln.severity.upper()}
                        </span>
                        <strong>[{vuln.rule_id}] {vuln.rule_name}</strong>
                    </div>
                    <div class="vuln-body">
                        <p><strong>位置:</strong> <code>{vuln.file_path}:{vuln.line_number}</code></p>
                        <p><strong>描述:</strong> {vuln.description}</p>
                        <p><strong>问题代码:</strong></p>
                        <pre><code>{vuln.code_snippet}</code></pre>
                        <p><strong>修复建议:</strong> {vuln.suggestion}</p>
                    </div>
                </div>
                """
        else:
            vulns_html = '<div class="success-msg"> 未发现安全漏洞</div>'

        # 趋势图 HTML（仅在有历史数据时显示）
        trend_chart_html = ""
        if trend_labels:
            trend_chart_html = """
            <div class="chart-card">
                <h3>📈 扫描趋势对比</h3>
                <canvas id="trendChart"></canvas>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PySecScanner 安全扫描报告</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .container {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.15);
            padding: 40px;
        }}
        h1 {{
            color: #1a1a2e;
            border-bottom: 3px solid #667eea;
            padding-bottom: 12px;
            font-size: 1.8em;
        }}
        h2 {{
            color: #333;
            margin-top: 35px;
            font-size: 1.4em;
        }}
        .info-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .info-table th, .info-table td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }}
        .info-table th {{
            background: #f8f9fa;
            width: 150px;
            font-weight: 600;
            color: #555;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .summary-card {{
            text-align: center;
            padding: 20px;
            border-radius: 10px;
            color: white;
            transition: transform 0.2s;
        }}
        .summary-card:hover {{ transform: translateY(-3px); }}
        .summary-card.critical {{ background: linear-gradient(135deg, #dc3545, #c82333); }}
        .summary-card.high {{ background: linear-gradient(135deg, #fd7e14, #e8590c); }}
        .summary-card.medium {{ background: linear-gradient(135deg, #ffc107, #e0a800); color: #333; }}
        .summary-card.low {{ background: linear-gradient(135deg, #28a745, #1e7e34); }}
        .summary-card .count {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        /* Dashboard 图表区域 */
        .dashboard-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin: 25px 0;
        }}
        @media (max-width: 768px) {{
            .dashboard-grid {{ grid-template-columns: 1fr; }}
        }}
        .chart-card {{
            background: #fff;
            border: 1px solid #e9ecef;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        }}
        .chart-card h3 {{
            margin: 0 0 15px 0;
            color: #444;
            font-size: 1.05em;
            text-align: center;
        }}
        .chart-card canvas {{
            max-height: 300px;
        }}
        .vuln-card {{
            border: 1px solid #e9ecef;
            border-radius: 10px;
            margin: 15px 0;
            overflow: hidden;
            transition: box-shadow 0.2s;
        }}
        .vuln-card:hover {{ box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
        .vuln-header {{
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #e9ecef;
        }}
        .vuln-body {{
            padding: 15px 20px;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 3px 12px;
            border-radius: 20px;
            color: white;
            font-size: 0.8em;
            font-weight: 600;
            margin-right: 10px;
            letter-spacing: 0.5px;
        }}
        pre {{
            background: #1e1e2e;
            color: #cdd6f4;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.9em;
        }}
        code {{
            font-family: 'Fira Code', 'Cascadia Code', 'Consolas', monospace;
        }}
        .success-msg {{
            background: linear-gradient(135deg, #d4edda, #c3e6cb);
            color: #155724;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            font-size: 1.2em;
            font-weight: 500;
        }}
        .footer {{
            text-align: center;
            color: #888;
            margin-top: 35px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1> PySecScanner 安全扫描报告</h1>
        
        <h2> 扫描信息</h2>
        <table class="info-table">
            <tr><th>扫描目标</th><td><code>{result.target}</code></td></tr>
            <tr><th>扫描时间</th><td>{result.scan_time.strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
            <tr><th>扫描耗时</th><td>{result.duration:.2f} 秒</td></tr>
            <tr><th>扫描文件数</th><td>{result.files_scanned}</td></tr>
        </table>
        
        <h2> 漏洞统计</h2>
        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="count">{summary['critical']}</div>
                <div>严重</div>
            </div>
            <div class="summary-card high">
                <div class="count">{summary['high']}</div>
                <div>高危</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{summary['medium']}</div>
                <div>中危</div>
            </div>
            <div class="summary-card low">
                <div class="count">{summary['low']}</div>
                <div>低危</div>
            </div>
        </div>
        {f'<p style="text-align: center; color: #666;"> 已忽略 {summary["ignored"]} 个漏洞（通过 pysec: ignore 注释）</p>' if summary.get('ignored', 0) > 0 else ''}
        {f'<p style="text-align: center; color: #666;"> 已过滤 {summary["filtered"]} 个漏洞（低于最小严重程度）</p>' if summary.get('filtered', 0) > 0 else ''}
        
        <h2> 漏洞详情</h2>
        {vulns_html}

        <div class="footer">
            <p>报告由 PySecScanner v1.0.0 生成 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>

    <script>
    // === 严重程度分布环形图 ===
    new Chart(document.getElementById('severityChart'), {{
        type: 'doughnut',
        data: {{
            labels: ['严重 (Critical)', '高危 (High)', '中危 (Medium)', '低危 (Low)'],
            datasets: [{{
                data: [{summary['critical']}, {summary['high']}, {summary['medium']}, {summary['low']}],
                backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
                borderWidth: 2,
                borderColor: '#fff'
            }}]
        }},
        options: {{
            responsive: true,
            plugins: {{
                legend: {{ position: 'bottom', labels: {{ padding: 15 }} }}
            }},
            cutout: '55%'
        }}
    }});

    // === 漏洞类型分布柱状图 ===
    new Chart(document.getElementById('typeChart'), {{
        type: 'bar',
        data: {{
            labels: {json.dumps(type_labels, ensure_ascii=False)},
            datasets: [{{
                label: '漏洞数量',
                data: {json.dumps(type_values)},
                backgroundColor: 'rgba(102, 126, 234, 0.7)',
                borderColor: '#667eea',
                borderWidth: 1,
                borderRadius: 4
            }}]
        }},
        options: {{
            responsive: true,
            plugins: {{
                legend: {{ display: false }}
            }},
            scales: {{
                y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }},
                x: {{ ticks: {{ maxRotation: 45 }} }}
            }}
        }}
    }});

    // === 文件漏洞热力图（横向柱状图）===
    new Chart(document.getElementById('fileChart'), {{
        type: 'bar',
        data: {{
            labels: {json.dumps(file_labels, ensure_ascii=False)},
            datasets: [{{
                label: '漏洞数量',
                data: {json.dumps(file_values)},
                backgroundColor: (ctx) => {{
                    const max = Math.max(...{json.dumps(file_values)}, 1);
                    const ratio = ctx.raw / max;
                    const r = Math.round(40 + ratio * 180);
                    const g = Math.round(167 - ratio * 130);
                    const b = Math.round(69 - ratio * 30);
                    return `rgba(${{r}}, ${{g}}, ${{b}}, 0.8)`;
                }},
                borderRadius: 4
            }}]
        }},
        options: {{
            indexAxis: 'y',
            responsive: true,
            plugins: {{
                legend: {{ display: false }}
            }},
            scales: {{
                x: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }}
            }}
        }}
    }});

    // === 趋势对比折线图 ===
    {f"""
    if (document.getElementById('trendChart')) {{
        new Chart(document.getElementById('trendChart'), {{
            type: 'line',
            data: {{
                labels: {json.dumps(trend_labels, ensure_ascii=False)},
                datasets: [
                    {{
                        label: '严重',
                        data: {json.dumps(trend_critical)},
                        borderColor: '#dc3545',
                        backgroundColor: 'rgba(220,53,69,0.1)',
                        fill: true,
                        tension: 0.3
                    }},
                    {{
                        label: '高危',
                        data: {json.dumps(trend_high)},
                        borderColor: '#fd7e14',
                        backgroundColor: 'rgba(253,126,20,0.1)',
                        fill: true,
                        tension: 0.3
                    }},
                    {{
                        label: '中危',
                        data: {json.dumps(trend_medium)},
                        borderColor: '#ffc107',
                        backgroundColor: 'rgba(255,193,7,0.1)',
                        fill: true,
                        tension: 0.3
                    }},
                    {{
                        label: '低危',
                        data: {json.dumps(trend_low)},
                        borderColor: '#28a745',
                        backgroundColor: 'rgba(40,167,69,0.1)',
                        fill: true,
                        tension: 0.3
                    }}
                ]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }},
                scales: {{
                    y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }}
                }}
            }}
        }});
    }}
    """ if trend_labels else "// 无历史数据，跳过趋势图"}
    </script>
</body>
</html>"""

        return html


# 报告生成器注册表
try:
    from .reporters.sarif_reporter import SarifReporter
except ImportError:
    SarifReporter = None

REPORTER_REGISTRY: Dict[str, Type[BaseReporter]] = {
    "text": TextReporter,
    "markdown": MarkdownReporter,
    "md": MarkdownReporter,
    "json": JSONReporter,
    "html": HTMLChartsReporter,  # 3.5任务：使用带图表的HTML报告器
    "sarif": SarifReporter,  # 3.3任务：SARIF格式支持
}

def get_available_formats() -> list:
    """获取可用的报告格式列表"""
    return list(REPORTER_REGISTRY.keys())


def get_reporter(format_type: str, **kwargs) -> BaseReporter:
    """
    获取报告生成器实例

    Args:
        format_type: 报告格式 (text/markdown/json/html)
        **kwargs: 传递给报告生成器的额外参数（如 scan_history）

    Returns:
        报告生成器实例
    """
    reporter_class = REPORTER_REGISTRY.get(format_type.lower())
    if reporter_class is None:
        raise ValueError(f"不支持的报告格式: {format_type}")
    # 仅将 kwargs 传递给支持它们的报告生成器
    import inspect
    sig = inspect.signature(reporter_class.__init__)
    filtered_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}
    return reporter_class(**filtered_kwargs)

