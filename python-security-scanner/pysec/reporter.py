"""
报告生成器模块

支持多种格式的扫描报告输出
"""

import json
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Type

from .models import ScanResult, Vulnerability


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
        lines.append("PySecScanner 安全扫描报告")
        lines.append("=" * 60)
        lines.append("")

        # 基本信息
        lines.append(f"扫描目标: {result.target}")
        lines.append(f"扫描时间: {result.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"扫描耗时: {result.duration:.2f} 秒")
        lines.append(f"扫描文件: {result.files_scanned} 个")
        lines.append("")

        # 统计摘要
        summary = result.summary
        lines.append("-" * 40)
        lines.append("漏洞统计")
        lines.append("-" * 40)
        lines.append(f"  严重 (Critical): {summary['critical']}")
        lines.append(f"  高危 (High):     {summary['high']}")
        lines.append(f"  中危 (Medium):   {summary['medium']}")
        lines.append(f"  低危 (Low):      {summary['low']}")
        lines.append(f"  总计:            {summary['total']}")
        if summary.get("ignored", 0) > 0:
            lines.append(f"  已忽略:          {summary['ignored']}")
        if summary.get("filtered", 0) > 0:
            lines.append(f"  已过滤:          {summary['filtered']}")
        lines.append("")

        # 漏洞详情
        if result.vulnerabilities:
            lines.append("-" * 40)
            lines.append("漏洞详情")
            lines.append("-" * 40)
            lines.append("")

            # 按严重程度排序
            sorted_vulns = sorted(
                result.vulnerabilities,
                key=lambda v: ["critical", "high", "medium", "low"].index(v.severity),
            )

            for i, vuln in enumerate(sorted_vulns, 1):
                symbol = self.SEVERITY_SYMBOLS.get(vuln.severity, "[?]")
                lines.append(f"{i}. {symbol} [{vuln.rule_id}] {vuln.rule_name}")
                lines.append(f"   严重程度: {vuln.severity.upper()}")
                lines.append(f"   位置: {vuln.file_path}:{vuln.line_number}")
                lines.append(f"   描述: {vuln.description}")
                lines.append(f"   代码: {vuln.code_snippet}")
                lines.append(f"   建议: {vuln.suggestion}")
                lines.append("")
        else:
            lines.append("✓ 未发现安全漏洞")
            lines.append("")

        # 错误信息
        if result.errors:
            lines.append("-" * 40)
            lines.append("扫描错误")
            lines.append("-" * 40)
            for error in result.errors:
                lines.append(f"  - {error}")
            lines.append("")

        # 页脚
        lines.append("=" * 60)
        lines.append(f"报告由 PySecScanner v1.0.0 生成")
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
            lines.append(f"| ⏭️ 已忽略 | {summary['ignored']} |")
        if summary.get("filtered", 0) > 0:
            lines.append(f"| 🔽 已过滤 | {summary['filtered']} |")
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
            lines.append("✅ **未发现安全漏洞**")
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
    """HTML格式报告生成器"""

    SEVERITY_COLORS = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#28a745",
    }

    def generate(self, result: ScanResult) -> str:
        summary = result.summary

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
            vulns_html = '<div class="success-msg">✅ 未发现安全漏洞</div>'

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PySecScanner 安全扫描报告</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
        }}
        .info-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .info-table th, .info-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        .info-table th {{
            background: #f8f9fa;
            width: 150px;
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
            border-radius: 8px;
            color: white;
        }}
        .summary-card.critical {{ background: {self.SEVERITY_COLORS['critical']}; }}
        .summary-card.high {{ background: {self.SEVERITY_COLORS['high']}; }}
        .summary-card.medium {{ background: {self.SEVERITY_COLORS['medium']}; color: #333; }}
        .summary-card.low {{ background: {self.SEVERITY_COLORS['low']}; }}
        .summary-card .count {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        .vuln-card {{
            border: 1px solid #ddd;
            border-radius: 8px;
            margin: 15px 0;
            overflow: hidden;
        }}
        .vuln-header {{
            background: #f8f9fa;
            padding: 15px;
            border-bottom: 1px solid #ddd;
        }}
        .vuln-body {{
            padding: 15px;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            color: white;
            font-size: 0.8em;
            margin-right: 10px;
        }}
        pre {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }}
        code {{
            font-family: 'Fira Code', 'Consolas', monospace;
        }}
        .success-msg {{
            background: #d4edda;
            color: #155724;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            font-size: 1.2em;
        }}
        .footer {{
            text-align: center;
            color: #666;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ PySecScanner 安全扫描报告</h1>
        
        <h2>📋 扫描信息</h2>
        <table class="info-table">
            <tr><th>扫描目标</th><td><code>{result.target}</code></td></tr>
            <tr><th>扫描时间</th><td>{result.scan_time.strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
            <tr><th>扫描耗时</th><td>{result.duration:.2f} 秒</td></tr>
            <tr><th>扫描文件数</th><td>{result.files_scanned}</td></tr>
        </table>
        
        <h2>📊 漏洞统计</h2>
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
        {f'<p style="text-align: center; color: #666;">⏭️ 已忽略 {summary["ignored"]} 个漏洞（通过 pysec: ignore 注释）</p>' if summary.get('ignored', 0) > 0 else ''}
        {f'<p style="text-align: center; color: #666;">🔽 已过滤 {summary["filtered"]} 个漏洞（低于最小严重程度）</p>' if summary.get('filtered', 0) > 0 else ''}
        
        <h2>🔍 漏洞详情</h2>
        {vulns_html}
        
        <div class="footer">
            <p>报告由 PySecScanner v1.0.0 生成 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""

        return html


# 报告生成器注册表
REPORTER_REGISTRY: Dict[str, Type[BaseReporter]] = {
    "text": TextReporter,
    "markdown": MarkdownReporter,
    "md": MarkdownReporter,
    "json": JSONReporter,
    "html": HTMLReporter,
}


def get_reporter(format_type: str) -> BaseReporter:
    """
    获取报告生成器实例

    Args:
        format_type: 报告格式 (text/markdown/json/html)

    Returns:
        报告生成器实例
    """
    reporter_class = REPORTER_REGISTRY.get(format_type.lower())
    if reporter_class is None:
        raise ValueError(f"不支持的报告格式: {format_type}")
    return reporter_class()
