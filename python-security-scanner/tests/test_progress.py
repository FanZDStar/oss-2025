"""
进度条模块测试
"""

import io
import sys
import time
import unittest
from unittest.mock import patch

from pysec.progress import ProgressBar
from pysec.colors import ColorSupport


class TestProgressBar(unittest.TestCase):
    """进度条测试"""

    def setUp(self):
        """每个测试前禁用颜色，确保输出可预测"""
        ColorSupport.disable()

    def tearDown(self):
        """每个测试后重置颜色设置"""
        ColorSupport.reset()

    def test_init_default(self):
        """测试默认初始化"""
        pb = ProgressBar(total=10)
        self.assertEqual(pb.total, 10)
        self.assertEqual(pb.current, 0)
        self.assertTrue(pb.enabled)

    def test_init_disabled(self):
        """测试禁用状态"""
        pb = ProgressBar(total=10, enabled=False)
        self.assertFalse(pb.enabled)

    def test_init_zero_total(self):
        """总数为0时自动禁用"""
        pb = ProgressBar(total=0)
        self.assertFalse(pb.enabled)

    def test_update_disabled(self):
        """禁用时 update 不崩溃"""
        pb = ProgressBar(total=10, enabled=False)
        pb.update(5, "test.py")  # 应该不做任何事

    def test_update_progress(self):
        """测试进度更新"""
        pb = ProgressBar(total=5)
        # 捕获 stderr 输出
        with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
            pb.update(1, "file1.py")
            pb.update(3, "file3.py")
            pb.update(5, "file5.py")
        self.assertEqual(pb.current, 5)

    def test_finish_clears_output(self):
        """测试 finish 清除进度条"""
        pb = ProgressBar(total=3)
        with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
            pb.update(3, "done.py")
            pb.finish()
            output = mock_stderr.getvalue()
        # 应该包含清除转义序列
        self.assertIn("\r", output)

    def test_finish_disabled(self):
        """禁用时 finish 不崩溃"""
        pb = ProgressBar(total=10, enabled=False)
        pb.finish()  # 应该不做任何事

    def test_truncate_filename_short(self):
        """短文件名不截断"""
        pb = ProgressBar(total=1)
        result = pb._truncate_filename("/path/to/file.py")
        self.assertEqual(result, "to/file.py")

    def test_truncate_filename_long(self):
        """长文件名被截断"""
        pb = ProgressBar(total=1)
        long_path = "/very/long/path/that/exceeds/the/maximum/display/length/configuration/file.py"
        result = pb._truncate_filename(long_path, max_len=20)
        self.assertTrue(len(result) <= 20)
        self.assertTrue(result.startswith("..."))

    def test_truncate_filename_empty(self):
        """空文件名返回空字符串"""
        pb = ProgressBar(total=1)
        result = pb._truncate_filename("")
        self.assertEqual(result, "")

    def test_format_eta_initial(self):
        """初始阶段显示 --:--"""
        pb = ProgressBar(total=10)
        result = pb._format_eta(0.1, 0.0)
        self.assertIn("--:--", result)

    def test_format_eta_seconds(self):
        """秒级别 ETA"""
        pb = ProgressBar(total=10)
        result = pb._format_eta(5.0, 0.5)
        self.assertIn("ETA:", result)
        self.assertIn("s", result)

    def test_format_eta_minutes(self):
        """分钟级别 ETA"""
        pb = ProgressBar(total=10)
        result = pb._format_eta(60.0, 0.1)
        self.assertIn("m", result)

    def test_render_with_color_enabled(self):
        """测试彩色模式渲染"""
        ColorSupport.enable()
        pb = ProgressBar(total=10)
        with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
            pb.update(5, "test.py")
            output = mock_stderr.getvalue()
        # 应该包含 ANSI 转义序列
        self.assertIn("\033[", output)


class TestProgressBarIntegration(unittest.TestCase):
    """进度条集成测试"""

    def test_scan_with_progress_callback(self):
        """测试 SecurityScanner.scan 的 progress_callback"""
        from pysec.engine import SecurityScanner
        from pysec.models import ScanConfig
        import tempfile
        import os

        # 创建临时目录和测试文件
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(3):
                filepath = os.path.join(tmpdir, f"test{i}.py")
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(f"# test file {i}\nx = {i}\n")

            # 记录回调调用
            callback_calls = []

            def mock_callback(current, total, file_path):
                callback_calls.append((current, total, file_path))

            scanner = SecurityScanner(config=ScanConfig())
            result = scanner.scan(tmpdir, progress_callback=mock_callback)

            # 验证回调被调用
            self.assertGreater(len(callback_calls), 0)
            # 验证 current 递增
            currents = [c[0] for c in callback_calls]
            self.assertEqual(currents, sorted(currents))
            # 验证 total 一致
            totals = set(c[1] for c in callback_calls)
            self.assertEqual(len(totals), 1)

    def test_scan_without_progress_callback(self):
        """测试无 progress_callback 时正常工作"""
        from pysec.engine import SecurityScanner
        from pysec.models import ScanConfig
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test.py")
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("x = 1\n")

            scanner = SecurityScanner(config=ScanConfig())
            result = scanner.scan(tmpdir)
            self.assertEqual(result.files_scanned, 1)


if __name__ == "__main__":
    unittest.main()
