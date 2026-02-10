"""
CLI解析器模块 - 提供直观的命令行接口
对应报告"命令行友好"特性，统一处理命令行参数
"""

import argparse
import sys
from typing import Optional, Dict

class ScanCLIParser:
    """扫描工具命令行参数解析器"""
    def __init__(self):
        self.parser = self._build_parser()

    def _build_parser(self) -> argparse.ArgumentParser:
        """构建命令行参数解析器"""
        parser = argparse.ArgumentParser(
            prog="pysecscanner",
            description="Python代码安全漏洞静态分析工具",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="示例:\n  pysec scan ./src\n  pysec scan ./src -o report.html -f html\n  pysec rules --verbose"
        )

        # 子命令
        subparsers = parser.add_subparsers(dest="command", required=True)

        # 1. scan子命令（核心扫描）
        scan_parser = subparsers.add_parser("scan", help="扫描Python代码漏洞")
        scan_parser.add_argument("path", help="扫描路径（文件/目录）")
        scan_parser.add_argument("-o", "--output", help="报告输出路径")
        scan_parser.add_argument("-f", "--format", choices=["text", "json", "markdown", "html"], 
                                 default="text", help="报告格式")
        scan_parser.add_argument("--exclude", help="排除目录/文件（逗号分隔）")
        scan_parser.add_argument("--severity", choices=["critical", "high", "medium", "low"],
                                 help="仅显示指定严重程度及以上的漏洞")
        scan_parser.add_argument("--changed-only", action="store_true",
                                 help="仅扫描Git变动文件（增量扫描）")
        scan_parser.add_argument("--fix", action="store_true", help="自动修复低风险漏洞")
        scan_parser.add_argument("--dry-run", action="store_true", help="预览修复不实际修改")
        scan_parser.add_argument("--no-cache", action="store_true", help="禁用AST缓存")

        # 2. rules子命令（查看规则）
        rules_parser = subparsers.add_parser("rules", help="查看所有检测规则")
        rules_parser.add_argument("--verbose", action="store_true", help="显示规则详细描述")
        rules_parser.add_argument("--enabled", action="store_true", help="仅显示启用的规则")

        # 3. config子命令（查看配置）
        config_parser = subparsers.add_parser("config", help="查看当前配置")
        config_parser.add_argument("--path", help="指定配置文件路径")

        return parser

    def parse_args(self) -> Dict:
        """解析命令行参数（返回字典便于使用）"""
        if len(sys.argv) == 1:
            self.parser.print_help()
            sys.exit(0)
        
        args = self.parser.parse_args()
        return vars(args)

# 演示
if __name__ == "__main__":
    cli = ScanCLIParser()
    args = cli.parse_args()
    print("📜 解析的命令行参数:")
    for key, value in args.items():
        print(f"  {key}: {value}")