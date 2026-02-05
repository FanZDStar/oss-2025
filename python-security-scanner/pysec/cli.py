"""
命令行接口模块

提供友好的命令行交互体验
"""

import argparse
import sys
import os
from pathlib import Path

from .engine import SecurityScanner
from .models import ScanConfig
from .reporter import get_reporter, REPORTER_REGISTRY
from .rules import list_rules
from .config import Config


def create_parser() -> argparse.ArgumentParser:
    """创建命令行解析器"""
    parser = argparse.ArgumentParser(
        prog="pysec",
        description="PySecScanner - Python 代码安全漏洞静态分析工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  pysec scan ./myproject                    # 扫描目录
  pysec scan app.py                         # 扫描单个文件
  pysec scan ./src -o report.md -f markdown # 生成Markdown报告
  pysec scan ./src -f json                  # JSON格式输出
  pysec scan ./src --exclude tests,docs     # 排除目录
  pysec scan . --changed-only               # 仅扫描Git修改的文件
  pysec scan . --since HEAD~5               # 扫描最近5次提交修改的文件
  pysec scan . --since main                 # 扫描结main分支不同的文件
  pysec rules                               # 列出所有规则
  pysec rules --verbose                     # 显示规则详情
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    # scan 命令
    scan_parser = subparsers.add_parser("scan", help="扫描Python代码")
    scan_parser.add_argument("target", type=str, help="扫描目标（文件或目录路径）")
    scan_parser.add_argument("-o", "--output", type=str, default=None, help="输出报告文件路径")
    scan_parser.add_argument(
        "-f",
        "--format",
        type=str,
        choices=list(REPORTER_REGISTRY.keys()),
        default="text",
        help="报告输出格式 (默认: text)",
    )
    scan_parser.add_argument("-c", "--config", type=str, default=None, help="指定配置文件路径")
    scan_parser.add_argument(
        "--exclude", type=str, default=None, help="排除的目录，逗号分隔 (如: tests,docs,venv)"
    )
    scan_parser.add_argument(
        "--rules", type=str, default=None, help="启用的规则ID，逗号分隔 (如: SQL001,CMD001)"
    )
    scan_parser.add_argument(
        "--severity",
        type=str,
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="最低报告严重程度",
    )
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="显示详细扫描过程")
    scan_parser.add_argument("-q", "--quiet", action="store_true", help="静默模式，仅输出报告")
    scan_parser.add_argument(
        "--changed-only",
        action="store_true",
        help="仅扫描自上次提交以来修改的文件（需在Git仓库中使用）",
    )
    scan_parser.add_argument(
        "--since",
        type=str,
        default=None,
        help="扫描自指定提交/分支以来修改的文件（如: HEAD~5, main, abc123）",
    )
    scan_parser.add_argument(
        "--no-cache",
        action="store_true",
        help="禁用 AST 缓存，强制重新解析所有文件",
    )

    # rules 命令
    rules_parser = subparsers.add_parser("rules", help="列出所有检测规则")
    rules_parser.add_argument("--verbose", action="store_true", help="显示规则详细信息")

    # version 命令
    subparsers.add_parser("version", help="显示版本信息")

    return parser


def cmd_scan(args):
    """执行扫描命令"""
    target = Path(args.target)

    # 验证目标路径
    if not target.exists():
        print(f"错误: 目标路径不存在: {args.target}", file=sys.stderr)
        return 1

    # 加载配置文件
    loaded_config = None

    # 优先使用 --config 指定的配置文件
    if args.config:
        config_file = Path(args.config)
        if not config_file.exists():
            print(f"错误: 配置文件不存在: {args.config}", file=sys.stderr)
            return 1
        try:
            loaded_config = Config.load_from_file(config_file)
            if not args.quiet:
                print(f"加载配置文件: {config_file}")
        except Exception as e:
            print(f"错误: 加载配置文件失败: {e}", file=sys.stderr)
            return 1
    else:
        # 自动发现配置文件
        config_file = Config.find_config_file(target if target.is_dir() else target.parent)
        if config_file:
            try:
                loaded_config = Config.load_from_file(config_file)
                if not args.quiet:
                    print(f"加载配置文件: {config_file}")
            except Exception as e:
                print(f"警告: 加载配置文件失败: {e}", file=sys.stderr)

    # 构建 ScanConfig 配置对象
    scan_config = ScanConfig()

    # 从配置文件应用设置
    if loaded_config:
        if loaded_config.exclude_dirs:
            scan_config.exclude_patterns = loaded_config.exclude_dirs
        if loaded_config.rules_enabled:
            scan_config.enabled_rules = loaded_config.rules_enabled
        if loaded_config.rules_disabled:
            scan_config.disabled_rules = loaded_config.rules_disabled
        if loaded_config.severity_overrides:
            scan_config.severity_overrides = loaded_config.severity_overrides

    # 命令行参数覆盖配置文件
    if args.exclude:
        scan_config.exclude_patterns = args.exclude.split(",")

    if args.rules:
        scan_config.enabled_rules = args.rules.split(",")

    if args.severity:
        scan_config.min_severity = args.severity
    elif loaded_config and loaded_config.minimum_severity:
        scan_config.min_severity = loaded_config.minimum_severity

    if args.verbose:
        scan_config.verbose = True

    # 创建扫描器
    scanner = SecurityScanner(scan_config)

    if not args.quiet:
        print("=" * 50)
        print("PySecScanner - Python 代码安全扫描器")
        print("=" * 50)
        print(f"扫描目标: {target.absolute()}")
        print(f"启用规则: {len(scanner.get_rules())} 个")
        if hasattr(args, "changed_only") and args.changed_only:
            print("扫描模式: 增量扫描（仅扫描Git修改的文件）")
        elif hasattr(args, "since") and args.since:
            print(f"扫描模式: 增量扫描（自 {args.since} 以来修改的文件）")
        print("-" * 50)

    # 执行扫描
    if args.verbose and not args.quiet:
        print("开始扫描...")

    # 根据参数选择扫描模式
    if hasattr(args, "since") and args.since:
        # 使用 --since 参数的增量扫描
        result = scanner.scan_since(str(target), args.since)
        # 检查是否有错误
        if result.errors:
            for error in result.errors:
                if "Git 仓库" in error or "Git 引用" in error:
                    print(f"错误: {error}", file=sys.stderr)
                    return 1
        if result.files_scanned == 0 and not result.errors:
            if not args.quiet:
                print(f"没有检测到自 {args.since} 以来修改的 Python 文件")
            return 0
    elif hasattr(args, "changed_only") and args.changed_only:
        result = scanner.scan_changed(str(target))
        # 检查是否有错误（如不是Git仓库）
        if result.errors and any("Git 仓库" in e for e in result.errors):
            print(f"错误: {result.errors[0]}", file=sys.stderr)
            return 1
        if result.files_scanned == 0 and not result.errors:
            if not args.quiet:
                print("没有检测到修改的 Python 文件")
            return 0
    else:
        result = scanner.scan(str(target))

    if not args.quiet:
        print(f"扫描完成! 耗时: {result.duration:.2f} 秒")
        print(f"扫描文件: {result.files_scanned} 个")
        print(f"发现漏洞: {result.summary['total']} 个")
        print("-" * 50)

    # 生成报告
    reporter = get_reporter(args.format)
    report = reporter.generate(result)

    # 输出报告
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        if not args.quiet:
            print(f"报告已保存至: {args.output}")
    else:
        print(report)

    # 返回状态码（有漏洞时返回非0）
    if result.summary["critical"] > 0 or result.summary["high"] > 0:
        return 2  # 发现高危漏洞
    elif result.summary["total"] > 0:
        return 1  # 发现漏洞
    return 0


def cmd_rules(args):
    """列出规则命令"""
    rules = list_rules()

    print("=" * 50)
    print("PySecScanner 检测规则列表")
    print("=" * 50)
    print()

    if args.verbose:
        for rule in rules:
            instance = rule()
            print(f"规则ID: {instance.rule_id}")
            print(f"名称:   {instance.rule_name}")
            print(f"严重程度: {instance.severity.upper()}")
            print(f"描述: {instance.description}")
            print("-" * 40)
            print()
    else:
        print(f"{'规则ID':<10} {'严重程度':<10} {'名称':<30}")
        print("-" * 55)
        for rule in rules:
            instance = rule()
            print(
                f"{instance.rule_id:<10} {instance.severity.upper():<10} {instance.rule_name:<30}"
            )

    print()
    print(f"共 {len(rules)} 条规则")
    return 0


def cmd_version(args):
    """显示版本信息"""
    print("PySecScanner v1.0.0")
    print("Python 代码安全漏洞静态分析工具")
    print()
    print("Copyright (c) 2025")
    print("基于 AST 的静态代码分析")
    return 0


def main():
    """主入口函数"""
    parser = create_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "rules":
        return cmd_rules(args)
    elif args.command == "version":
        return cmd_version(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
