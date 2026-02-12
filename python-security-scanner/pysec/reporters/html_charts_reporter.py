#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
HTML图表报告器

生成包含图表的HTML报告，支持3.5统计仪表盘功能
"""

import os
import json
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

try:
    from ..charts import ChartDataGenerator, TrendAnalyzer, generate_chart_data, save_scan_history
except ImportError:
    # 备用导入
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from charts import ChartDataGenerator, TrendAnalyzer, generate_chart_data, save_scan_history


class HTMLChartsReporter:
    """HTML图表报告器"""
    
    def __init__(self, include_charts: bool = True, save_history: bool = True):
        """
        初始化HTML图表报告器
        
        Args:
            include_charts: 是否包含图表
            save_history: 是否保存历史记录
        """
        self.include_charts = include_charts
        self.save_history = save_history
    
    def generate(self, scan_result: Any, output_file: Optional[str] = None) -> str:
        """
        生成HTML报告
        
        Args:
            scan_result: 扫描结果
            output_file: 输出文件路径
            
        Returns:
            HTML报告字符串
        """
        # 生成图表数据
        if self.include_charts:
            chart_generator = ChartDataGenerator(scan_result)
            charts_data = chart_generator.generate_all_charts()
            
            # 保存历史记录
            if self.save_history:
                try:
                    save_scan_history(scan_result)
                except Exception as e:
                    print(f"警告: 保存历史记录失败: {e}")
        else:
            charts_data = {}
        
        # 生成趋势图数据
        try:
            trend_analyzer = TrendAnalyzer()
            trend_chart = trend_analyzer.generate_trend_chart_data()
            severity_trend_chart = trend_analyzer.generate_severity_trend_chart()
        except Exception as e:
            trend_chart = {"enabled": False, "message": f"生成趋势图失败: {e}"}
            severity_trend_chart = {"enabled": False}
        
        # 生成HTML
        html_content = self._generate_html(scan_result, charts_data, trend_chart, severity_trend_chart)
        
        # 写入文件
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"HTML报告已保存: {output_file}")
        
        return html_content
    
    def _generate_html(self, scan_result: Any, charts_data: Dict[str, Any], 
                      trend_chart: Dict[str, Any], severity_trend_chart: Dict[str, Any]) -> str:
        """生成HTML内容"""
        
        # 基本统计信息
        total_vulns = len(scan_result.vulnerabilities) if hasattr(scan_result, 'vulnerabilities') else 0
        files_scanned = scan_result.files_scanned if hasattr(scan_result, 'files_scanned') else 0
        scan_duration = round(scan_result.duration, 2) if hasattr(scan_result, 'duration') else 0
        
        # 严重程度统计
        severity_stats = scan_result.summary if hasattr(scan_result, 'summary') else {}
        
        # 生成时间
        scan_time = scan_result.scan_time if hasattr(scan_result, 'scan_time') else datetime.now()
        if isinstance(scan_time, str):
            display_time = scan_time
        else:
            display_time = scan_time.strftime("%Y-%m-%d %H:%M:%S")
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PySecScanner 安全扫描报告 - 3.5统计仪表盘</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f7fa;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .header h1 i {{
            font-size: 2rem;
        }}
        
        .header .subtitle {{
            font-size: 1.1rem;
            opacity: 0.9;
        }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .card {{
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }}
        
        .card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }}
        
        .card h3 {{
            font-size: 1.2rem;
            color: #666;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .card .value {{
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }}
        
        .card-danger {{ border-left: 4px solid #ef4444; }}
        .card-warning {{ border-left: 4px solid #f59e0b; }}
        .card-success {{ border-left: 4px solid #10b981; }}
        .card-info {{ border-left: 4px solid #3b82f6; }}
        
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }}
        
        .chart-container {{
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }}
        
        .chart-container h3 {{
            font-size: 1.3rem;
            margin-bottom: 1rem;
            color: #374151;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .chart-wrapper {{
            position: relative;
            height: 300px;
            width: 100%;
        }}
        
        .heatmap-container {{
            margin-top: 1rem;
        }}
        
        .heatmap-item {{
            display: flex;
            align-items: center;
            padding: 0.5rem;
            border-radius: 4px;
            margin-bottom: 0.5rem;
            transition: background-color 0.2s;
        }}
        
        .heatmap-item:hover {{
            background-color: #f3f4f6;
        }}
        
        .heatmap-color {{
            width: 20px;
            height: 20px;
            border-radius: 4px;
            margin-right: 1rem;
        }}
        
        .heatmap-label {{
            flex: 1;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
        }}
        
        .heatmap-count {{
            font-weight: bold;
            color: #374151;
        }}
        
        .vulnerability-list {{
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            margin-bottom: 2rem;
        }}
        
        .vulnerability-list h3 {{
            font-size: 1.3rem;
            margin-bottom: 1rem;
            color: #374151;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th {{
            background-color: #f9fafb;
            padding: 0.75rem;
            text-align: left;
            font-weight: 600;
            color: #374151;
            border-bottom: 1px solid #e5e7eb;
        }}
        
        td {{
            padding: 0.75rem;
            border-bottom: 1px solid #e5e7eb;
        }}
        
        tr:hover {{
            background-color: #f9fafb;
        }}
        
        .severity-critical {{
            background-color: #fee2e2;
            color: #dc2626;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        
        .severity-high {{
            background-color: #ffedd5;
            color: #f97316;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        
        .severity-medium {{
            background-color: #fef3c7;
            color: #f59e0b;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        
        .severity-low {{
            background-color: #d1fae5;
            color: #10b981;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        
        .footer {{
            text-align: center;
            color: #6b7280;
            padding: 2rem;
            font-size: 0.9rem;
        }}
        
        .no-data {{
            text-align: center;
            padding: 3rem;
            color: #6b7280;
        }}
        
        .no-data i {{
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }}
        
        @media (max-width: 768px) {{
            .charts-grid {{
                grid-template-columns: 1fr;
            }}
            
            .header h1 {{
                font-size: 2rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- 头部 -->
        <div class="header">
            <h1> PySecScanner 安全扫描报告</h1>
            <div class="subtitle">
                扫描时间: {display_time} | 版本: 3.5统计仪表盘
            </div>
        </div>
        
        <!-- 摘要卡片 -->
        <div class="summary-cards">
            <div class="card card-danger">
                <h3> 总漏洞数</h3>
                <div class="value">{total_vulns}</div>
                <div>扫描文件: {files_scanned} 个</div>
            </div>
            
            <div class="card card-warning">
                <h3> 严重漏洞</h3>
                <div class="value">{severity_stats.get('critical', 0)}</div>
                <div>高危: {severity_stats.get('high', 0)} 个</div>
            </div>
            
            <div class="card card-success">
                <h3> 扫描统计</h3>
                <div class="value">{scan_duration}s</div>
                <div>耗时</div>
            </div>
            
            <div class="card card-info">
                <h3> 图表报告</h3>
                <div class="value">3.5</div>
                <div>统计仪表盘</div>
            </div>
        </div>
        
        <!-- 图表区域 -->
        <div class="charts-grid">
            <!-- 漏洞类型分布饼图 -->
            <div class="chart-container">
                <h3> 漏洞类型分布</h3>
                <div class="chart-wrapper">
                    <canvas id="vulnerabilityTypeChart"></canvas>
                </div>
            </div>
            
            <!-- 严重程度分布柱状图 -->
            <div class="chart-container">
                <h3> 严重程度分布</h3>
                <div class="chart-wrapper">
                    <canvas id="severityBarChart"></canvas>
                </div>
            </div>
            
            <!-- 趋势对比图 -->
            <div class="chart-container">
                <h3> 扫描趋势对比</h3>
                <div class="chart-wrapper">
                    <canvas id="trendLineChart"></canvas>
                </div>
            </div>
            
            <!-- 严重程度趋势图 -->
            <div class="chart-container">
                <h3> 严重程度趋势</h3>
                <div class="chart-wrapper">
                    <canvas id="severityTrendChart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- 文件漏洞热力图 -->
        <div class="chart-container" style="grid-column: span 2;">
            <h3> 文件漏洞热力图</h3>
            <div id="heatmap" class="heatmap-container">
                <!-- 热力图将通过JavaScript动态生成 -->
            </div>
        </div>
        
        <!-- 漏洞列表 -->
        <div class="vulnerability-list">
            <h3> 漏洞详情列表</h3>
            {"".join(self._generate_vulnerability_table(scan_result))}
        </div>
        
        <!-- 页脚 -->
        <div class="footer">
            <p>PySecScanner v1.0.0 | 基于AST的Python代码安全扫描工具 | 3.5统计仪表盘功能</p>
            <p>报告生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
    
    <script>
        // 图表数据
        const chartData = {json.dumps(charts_data, ensure_ascii=False)};
        const trendChartData = {json.dumps(trend_chart, ensure_ascii=False)};
        const severityTrendChartData = {json.dumps(severity_trend_chart, ensure_ascii=False)};
        
        // 生成热力图
        function generateHeatmap() {{
            const heatmap = document.getElementById('heatmap');
            if (!chartData.heatmap || !chartData.heatmap.enabled) {{
                heatmap.innerHTML = '<div class="no-data">暂无文件漏洞数据</div>';
                return;
            }}
            
            const items = chartData.heatmap.data;
            let html = '';
            
            items.forEach(item => {{
                const widthPercent = Math.min(100, (item.intensity / 100) * 100);
                html += `
                <div class="heatmap-item">
                    <div class="heatmap-color" style="background-color: ${{item.color}}"></div>
                    <div class="heatmap-label" style="flex: 1">
                        <div style="font-weight: bold">${{item.file_name}}</div>
                        <div style="font-size: 0.8rem; color: #6b7280">${{item.file_path}}</div>
                    </div>
                    <div class="heatmap-count">${{item.count}} 个漏洞</div>
                </div>
                `;
            }});
            
            heatmap.innerHTML = html;
        }}
        
        // 初始化漏洞类型饼图
        function initVulnerabilityTypeChart() {{
            const ctx = document.getElementById('vulnerabilityTypeChart').getContext('2d');
            
            if (!chartData.pie_chart || !chartData.pie_chart.enabled) {{
                new Chart(ctx, {{
                    type: 'doughnut',
                    data: {{
                        labels: ['暂无数据'],
                        datasets: [{{
                            data: [1],
                            backgroundColor: ['#e5e7eb']
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{ display: false }},
                            title: {{
                                display: true,
                                text: '暂无漏洞数据'
                            }}
                        }}
                    }}
                }});
                return;
            }}
            
            const pieData = chartData.pie_chart.data;
            new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: pieData.map(item => `${{item.label}} (${{item.percentage}}%)`),
                    datasets: [{{
                        data: pieData.map(item => item.value),
                        backgroundColor: pieData.map(item => item.color),
                        borderWidth: 2,
                        borderColor: '#fff'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'right',
                            labels: {{
                                padding: 20,
                                usePointStyle: true,
                                pointStyle: 'circle'
                            }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    const label = context.label || '';
                                    const value = context.raw || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = Math.round((value / total) * 100);
                                    return `${{label}}: ${{value}} 个 (${{percentage}}%)`;
                                }}
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        // 初始化严重程度柱状图
        function initSeverityBarChart() {{
            const ctx = document.getElementById('severityBarChart').getContext('2d');
            
            if (!chartData.bar_chart || !chartData.bar_chart.enabled) {{
                new Chart(ctx, {{
                    type: 'bar',
                    data: {{
                        labels: ['暂无数据'],
                        datasets: [{{
                            data: [0],
                            backgroundColor: '#e5e7eb'
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{ display: false }}
                        }}
                    }}
                }});
                return;
            }}
            
            const barData = chartData.bar_chart.data;
            new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: barData.map(item => item.severity),
                    datasets: [{{
                        label: '漏洞数量',
                        data: barData.map(item => item.count),
                        backgroundColor: barData.map(item => item.color),
                        borderColor: barData.map(item => item.color),
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{
                                precision: 0
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{ display: false }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    return `${{context.dataset.label}}: ${{context.raw}} 个`;
                                }}
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        // 初始化趋势对比图
        function initTrendChart() {{
            const ctx = document.getElementById('trendLineChart').getContext('2d');
            
            if (!trendChartData.enabled) {{
                new Chart(ctx, {{
                    type: 'line',
                    data: {{
                        labels: ['暂无历史数据'],
                        datasets: [{{
                            data: [0],
                            borderColor: '#e5e7eb',
                            borderWidth: 2
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{ display: false }},
                            title: {{
                                display: true,
                                text: trendChartData.message || '暂无趋势数据'
                            }}
                        }}
                    }}
                }});
                return;
            }}
            
            new Chart(ctx, {{
                type: 'line',
                data: {{
                    labels: trendChartData.labels,
                    datasets: trendChartData.datasets.map(dataset => ({{
                        label: dataset.label,
                        data: dataset.data,
                        borderColor: dataset.borderColor,
                        backgroundColor: dataset.color + '20',
                        borderWidth: 3,
                        tension: 0.2,
                        fill: false
                    }}))
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {{
                        intersect: false,
                        mode: 'index'
                    }},
                    plugins: {{
                        tooltip: {{
                            mode: 'index',
                            intersect: false
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{
                                precision: 0
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        // 初始化严重程度趋势图
        function initSeverityTrendChart() {{
            const ctx = document.getElementById('severityTrendChart').getContext('2d');
            
            if (!severityTrendChartData.enabled) {{
                new Chart(ctx, {{
                    type: 'line',
                    data: {{
                        labels: ['暂无历史数据'],
                        datasets: [{{
                            data: [0],
                            borderColor: '#e5e7eb',
                            borderWidth: 2
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{ display: false }}
                        }}
                    }}
                }});
                return;
            }}
            
            new Chart(ctx, {{
                type: 'line',
                data: {{
                    labels: severityTrendChartData.labels,
                    datasets: severityTrendChartData.datasets.map(dataset => ({{
                        label: dataset.label,
                        data: dataset.data,
                        borderColor: dataset.borderColor,
                        backgroundColor: dataset.color + '20',
                        borderWidth: 3,
                        tension: 0.2,
                        fill: false
                    }}))
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {{
                        intersect: false,
                        mode: 'index'
                    }},
                    plugins: {{
                        tooltip: {{
                            mode: 'index',
                            intersect: false
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{
                                precision: 0
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        // 页面加载完成后初始化图表
        document.addEventListener('DOMContentLoaded', function() {{
            generateHeatmap();
            initVulnerabilityTypeChart();
            initSeverityBarChart();
            initTrendChart();
            initSeverityTrendChart();
        }});
    </script>
</body>
</html>
"""
        return html
    
    def _generate_vulnerability_table(self, scan_result: Any) -> str:
        """生成漏洞表格"""
        if not hasattr(scan_result, 'vulnerabilities') or not scan_result.vulnerabilities:
            return ['<div class="no-data"><p> 未发现安全漏洞</p></div>']
        
        table_html = ['<table>']
        table_html.append('''
        <thead>
            <tr>
                <th>规则ID</th>
                <th>严重程度</th>
                <th>文件位置</th>
                <th>描述</th>
            </tr>
        </thead>
        <tbody>
        ''')
        
        for vuln in scan_result.vulnerabilities[:50]:  # 最多显示50个
            severity = getattr(vuln, 'severity', 'medium').lower()
            severity_class = f'severity-{severity}'
            severity_display = severity.capitalize()
            
            # 文件位置
            file_path = getattr(vuln, 'file_path', '未知文件')
            line_number = getattr(vuln, 'line_number', '?')
            file_location = f'{file_path}:{line_number}'
            
            # 截断过长的描述
            description = getattr(vuln, 'description', '')
            if len(description) > 100:
                description = description[:100] + '...'
            
            table_html.append(f'''
            <tr>
                <td><strong>{getattr(vuln, 'rule_id', 'N/A')}</strong></td>
                <td><span class="{severity_class}">{severity_display}</span></td>
                <td><code>{file_location}</code></td>
                <td>{description}</td>
            </tr>
            ''')
        
        table_html.append('</tbody></table>')
        
        if len(scan_result.vulnerabilities) > 50:
            table_html.append(f'<p style="margin-top: 1rem; color: #6b7280;">... 还有 {len(scan_result.vulnerabilities) - 50} 个漏洞未显示</p>')
        
        return table_html


# 便捷函数
def generate_html_with_charts(scan_result: Any, output_file: Optional[str] = None) -> str:
    """生成带图表的HTML报告的便捷函数"""
    reporter = HTMLChartsReporter()
    return reporter.generate(scan_result, output_file)