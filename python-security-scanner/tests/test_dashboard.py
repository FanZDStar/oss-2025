# PySecScanner 统计仪表盘测试

import unittest
import sys
import os
import json
import tempfile
from pathlib import Path
from datetime import datetime

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from pysec.models import Vulnerability, ScanResult
from pysec.reporter import HTMLReporter, get_reporter
from pysec.scan_history import ScanHistory, ScanSummary


def _create_test_result():
    """创建测试用的扫描结果"""
    result = ScanResult(target="/test/project")
    result.files_scanned = 10
    result.duration = 1.5

    vulns = [
        Vulnerability(
            rule_id="SQL001", rule_name="SQL注入",
            severity="critical", file_path="/test/app.py",
            line_number=10, column=0,
            code_snippet="cursor.execute(query)", description="SQL注入风险",
            suggestion="使用参数化查询"
        ),
        Vulnerability(
            rule_id="SQL001", rule_name="SQL注入",
            severity="high", file_path="/test/db.py",
            line_number=20, column=0,
            code_snippet="cursor.execute(q)", description="SQL注入风险",
            suggestion="使用参数化查询"
        ),
        Vulnerability(
            rule_id="CMD001", rule_name="命令注入",
            severity="high", file_path="/test/app.py",
            line_number=15, column=0,
            code_snippet="os.system(cmd)", description="命令注入风险",
            suggestion="使用subprocess"
        ),
        Vulnerability(
            rule_id="SEC001", rule_name="硬编码密钥",
            severity="medium", file_path="/test/config.py",
            line_number=5, column=0,
            code_snippet='password = "123"', description="硬编码密钥",
            suggestion="使用环境变量"
        ),
        Vulnerability(
            rule_id="PTH001", rule_name="路径遍历",
            severity="low", file_path="/test/app.py",
            line_number=30, column=0,
            code_snippet="open(user_path)", description="路径遍历风险",
            suggestion="验证路径"
        ),
    ]
    for v in vulns:
        result.add_vulnerability(v)
    return result


class TestHTMLDashboard(unittest.TestCase):
    """测试 HTML 统计仪表盘"""

    def setUp(self):
        self.result = _create_test_result()

    def test_html_report_contains_chartjs(self):
        """HTML 报告包含 Chart.js CDN 引用"""
        reporter = HTMLReporter()
        html = reporter.generate(self.result)
        self.assertIn("chart.js", html.lower())
        self.assertIn("cdn.jsdelivr.net", html)

    def test_html_report_contains_severity_chart(self):
        """HTML 报告包含严重程度分布环形图"""
        reporter = HTMLReporter()
        html = reporter.generate(self.result)
        self.assertIn("severityChart", html)
        self.assertIn("doughnut", html)

    def test_html_report_contains_type_chart(self):
        """HTML 报告包含漏洞类型分布柱状图"""
        reporter = HTMLReporter()
        html = reporter.generate(self.result)
        self.assertIn("typeChart", html)
        self.assertIn("SQL001", html)
        self.assertIn("CMD001", html)

    def test_html_report_contains_file_heatmap(self):
        """HTML 报告包含文件漏洞热力图"""
        reporter = HTMLReporter()
        html = reporter.generate(self.result)
        self.assertIn("fileChart", html)
        self.assertIn("app.py", html)

    def test_html_report_contains_trend_chart_with_history(self):
        """有历史数据时 HTML 报告包含趋势对比图"""
        history = [
            ScanSummary(
                scan_time="2026-02-09T10:00:00",
                target="/test", files_scanned=5, duration=1.0,
                total=10, critical=2, high=3, medium=3, low=2
            ),
            ScanSummary(
                scan_time="2026-02-10T10:00:00",
                target="/test", files_scanned=8, duration=1.5,
                total=8, critical=1, high=2, medium=3, low=2
            ),
        ]
        reporter = HTMLReporter(scan_history=history)
        html = reporter.generate(self.result)
        self.assertIn("trendChart", html)
        self.assertIn("2026-02-09", html)
        self.assertIn("2026-02-10", html)

    def test_html_report_no_trend_chart_without_history(self):
        """无历史数据时不渲染趋势图 canvas"""
        reporter = HTMLReporter()
        html = reporter.generate(self.result)
        self.assertNotIn("trendChart", html)

    def test_html_report_no_vulns(self):
        """无漏洞时图表不崩溃"""
        empty_result = ScanResult(target="/test/clean")
        empty_result.files_scanned = 5
        empty_result.duration = 0.5
        reporter = HTMLReporter()
        html = reporter.generate(empty_result)
        self.assertIn("severityChart", html)
        self.assertIn("未发现安全漏洞", html)

    def test_get_reporter_html(self):
        """get_reporter 支持 html 格式"""
        reporter = get_reporter("html")
        self.assertIsInstance(reporter, HTMLReporter)

    def test_get_reporter_html_with_history(self):
        """get_reporter 支持传递 scan_history"""
        history = [ScanSummary(
            scan_time="2026-02-10T10:00:00",
            target="/test", files_scanned=5, duration=1.0,
            total=5, critical=1, high=1, medium=2, low=1
        )]
        reporter = get_reporter("html", scan_history=history)
        self.assertIsInstance(reporter, HTMLReporter)
        self.assertEqual(len(reporter.scan_history), 1)


class TestScanHistory(unittest.TestCase):
    """测试扫描历史模块"""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.history_file = os.path.join(self.tmp_dir, ".pysec_history.json")
        self.history = ScanHistory(history_file=self.history_file)

    def tearDown(self):
        if os.path.exists(self.history_file):
            os.remove(self.history_file)
        os.rmdir(self.tmp_dir)

    def test_save_and_load(self):
        """保存并加载扫描历史"""
        result = _create_test_result()
        self.history.save(result)

        records = self.history.load()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].target, "/test/project")
        self.assertEqual(records[0].total, 5)
        self.assertEqual(records[0].critical, 1)
        self.assertEqual(records[0].high, 2)
        self.assertEqual(records[0].medium, 1)
        self.assertEqual(records[0].low, 1)

    def test_multiple_saves(self):
        """多次保存累积记录"""
        result = _create_test_result()
        self.history.save(result)
        self.history.save(result)
        self.history.save(result)

        records = self.history.load()
        self.assertEqual(len(records), 3)

    def test_get_recent(self):
        """获取最近 N 条记录"""
        result = _create_test_result()
        for _ in range(15):
            self.history.save(result)

        recent = self.history.get_recent(5)
        self.assertEqual(len(recent), 5)

        all_records = self.history.get_recent(20)
        self.assertEqual(len(all_records), 15)

    def test_load_empty(self):
        """文件不存在时返回空列表"""
        records = self.history.load()
        self.assertEqual(records, [])

    def test_corrupted_file(self):
        """损坏的文件不崩溃"""
        with open(self.history_file, "w") as f:
            f.write("not json at all {{{")
        records = self.history.load()
        self.assertEqual(records, [])

    def test_scan_summary_from_dict(self):
        """ScanSummary 从字典创建"""
        data = {
            "scan_time": "2026-02-10T10:00:00",
            "target": "/test",
            "files_scanned": 5,
            "duration": 1.0,
            "total": 10,
            "critical": 2,
            "high": 3,
            "medium": 3,
            "low": 2,
        }
        summary = ScanSummary.from_dict(data)
        self.assertEqual(summary.total, 10)
        self.assertEqual(summary.critical, 2)
        self.assertEqual(summary.target, "/test")


if __name__ == "__main__":
    unittest.main()
