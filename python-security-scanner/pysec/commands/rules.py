#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
规则管理命令

支持：
- pysec rules install <package>    安装规则
- pysec rules uninstall <package>  卸载规则
- pysec rules list                 列出已安装规则
- pysec rules update [package]     更新规则
- pysec rules search <query>       搜索社区规则
"""

import argparse
import sys
from typing import List, Optional
from pathlib import Path

try:
    from ..rule_repository import get_repository
    from ..colors import (
        bold, success, error, warning, info, blue, green, yellow, red
    )
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from rule_repository import get_repository
    from colors import (
        bold, success, error, warning, info, blue, green, yellow, red
    )


def cmd_rules_install(args) -> int:
    """安装规则命令"""
    try:
        repo = get_repository()
        
        if args.package.startswith("http://") or args.package.startswith("https://"):
            # 从URL安装
            print(f" 从URL安装规则: {args.package}")
            success = repo.install_from_url(args.package)
        elif args.package.startswith("community/"):
            # 从社区安装
            print(f" 从社区安装规则: {args.package}")
            success = repo.install_from_community(args.package)
        elif Path(args.package).exists():
            # 从文件安装
            print(f" 从文件安装规则: {args.package}")
            success = repo.install_from_file(args.package)
        else:
            # 尝试从社区安装
            print(f" 尝试从社区安装规则: {args.package}")
            success = repo.install_from_community(args.package)
        
        if success:
            print(success("规则安装成功"))
            return 0
        else:
            print(error(" 规则安装失败"))
            return 1
            
    except Exception as e:
        print(error(f" 安装规则时发生错误: {e}"))
        return 1


def cmd_rules_uninstall(args) -> int:
    """卸载规则命令"""
    try:
        repo = get_repository()
        
        if repo.uninstall_package(args.package):
            print(success(f" 已卸载规则包: {args.package}"))
            return 0
        else:
            print(error(f" 卸载规则包失败: {args.package}"))
            return 1
            
    except Exception as e:
        print(error(f" 卸载规则时发生错误: {e}"))
        return 1


def cmd_rules_list(args) -> int:
    """列出已安装规则命令"""
    try:
        repo = get_repository()
        packages = repo.list_installed()
        
        if not packages:
            print(" 没有已安装的规则包")
            return 0
        
        print("=" * 80)
        print(bold(" 已安装的规则包"))
        print("=" * 80)
        
        for i, pkg in enumerate(packages, 1):
            print(f"\n{i}. {bold(pkg['name'])} v{pkg['version']}")
            print(f"   描述: {pkg['description']}")
            print(f"   作者: {pkg.get('author', '未知')}")
            print(f"   规则数: {pkg.get('rules_count', 0)}")
            print(f"   安装时间: {pkg.get('installed_at', '未知')}")
            print(f"   许可证: {pkg.get('license', 'MIT')}")
        
        print("\n" + "=" * 80)
        print(f"共 {len(packages)} 个规则包")
        
        return 0
        
    except Exception as e:
        print(error(f" 列出规则时发生错误: {e}"))
        return 1


def cmd_rules_update(args) -> int:
    """更新规则命令"""
    try:
        repo = get_repository()
        
        if args.package:
            # 更新指定包
            print(f" 检查更新: {args.package}")
            updates = repo.check_for_updates(args.package)
            
            if updates["available"]:
                print(" 发现以下更新:")
                for update in updates["available"]:
                    print(f"  {update['package']}: {update['current_version']} → {update['latest_version']}")
                
                if not args.dry_run:
                    print(f" 开始更新: {args.package}")
                    if repo.update_package(args.package):
                        print(success(f" 更新成功: {args.package}"))
                    else:
                        print(error(f" 更新失败: {args.package}"))
                else:
                    print(" 干运行模式，不实际更新")
            else:
                print(f" {args.package} 已是最新版本")
                
        else:
            # 更新所有包
            print(" 检查所有规则包更新...")
            updates = repo.check_for_updates()
            
            if updates["available"]:
                print(" 发现以下更新:")
                for update in updates["available"]:
                    print(f"  {update['package']}: {update['current_version']} → {update['latest_version']}")
                
                if not args.dry_run:
                    print("\n 开始更新所有包...")
                    results = repo.update_all()
                    
                    print("\n 更新结果:")
                    success_count = sum(1 for r in results.values() if r)
                    fail_count = len(results) - success_count
                    
                    if success_count > 0:
                        print(success(f" 成功更新: {success_count} 个包"))
                    if fail_count > 0:
                        print(error(f" 更新失败: {fail_count} 个包"))
                else:
                    print(" 干运行模式，不实际更新")
            else:
                print("所有规则包已是最新版本")
        
        return 0
        
    except Exception as e:
        print(error(f" 更新规则时发生错误: {e}"))
        return 1


def cmd_rules_search(args) -> int:
    """搜索社区规则命令"""
    try:
        repo = get_repository()
        results = repo.search_community(args.query)
        
        if not results:
            print(f"未找到包含 '{args.query}' 的规则")
            return 0
        
        print("=" * 80)
        print(bold(f" 搜索结果: '{args.query}'"))
        print("=" * 80)
        
        for i, rule in enumerate(results, 1):
            print(f"\n{i}. {bold(rule['name'])} v{rule['version']}")
            print(f"   描述: {rule['description']}")
            print(f"   作者: {rule.get('author', '未知')}")
            print(f"   下载量: {rule.get('downloads', 0)}")
            print(f"   评分: {'⭐' * int(rule.get('rating', 0))} ({rule.get('rating', 0)})")
        
        print("\n" + "=" * 80)
        print(f"找到 {len(results)} 个规则包")
        print("\n 使用以下命令安装:")
        for rule in results[:3]:  # 显示前3个的安装命令
            print(f"  pysec rules install {rule['name']}")
        
        return 0
        
    except Exception as e:
        print(error(f" 搜索规则时发生错误: {e}"))
        return 1


def cmd_rules_info(args) -> int:
    """显示规则包信息命令"""
    try:
        repo = get_repository()
        package = repo.get_installed_package(args.package)
        
        if not package:
            print(error(f" 规则包未安装: {args.package}"))
            
            # 尝试在社区搜索
            print(f" 在社区中搜索: {args.package}")
            results = repo.search_community(args.package)
            
            if results:
                print(f"\n 社区中找到的规则包:")
                for rule in results[:3]:
                    print(f"  {rule['name']} - {rule['description']}")
                print(f"\n 使用以下命令安装: pysec rules install {args.package}")
            return 1
        
        print("=" * 80)
        print(bold(f" 规则包信息: {package.name}"))
        print("=" * 80)
        
        print(f"名称: {bold(package.name)}")
        print(f"版本: v{package.version}")
        print(f"描述: {package.description}")
        print(f"作者: {package.author}")
        print(f"许可证: {package.license}")
        print(f"安装时间: {package.installed_at}")
        print(f"更新时间: {package.updated_at}")
        print(f"规则数量: {len(package.rules)}")
        
        if package.dependencies:
            print(f"依赖: {', '.join(package.dependencies)}")
        
        if package.rules:
            print(f"\n📋 包含的规则:")
            for rule_id in package.get_rule_ids()[:10]:  # 最多显示10个
                print(f"  - {rule_id}")
            if len(package.rules) > 10:
                print(f"  - ... 还有 {len(package.rules) - 10} 个规则")
        
        print("\n" + "=" * 80)
        
        return 0
        
    except Exception as e:
        print(error(f" 获取规则信息时发生错误: {e}"))
        return 1


def add_rules_parser(subparsers):
    """添加规则管理命令到解析器"""
    rules_parser = subparsers.add_parser("rules", help="规则包管理命令")
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command", help="规则子命令")
    
    # install 命令
    install_parser = rules_subparsers.add_parser("install", help="安装规则包")
    install_parser.add_argument("package", help="规则包名称、URL或文件路径")
    install_parser.set_defaults(func=cmd_rules_install)
    
    # uninstall 命令
    uninstall_parser = rules_subparsers.add_parser("uninstall", help="卸载规则包")
    uninstall_parser.add_argument("package", help="规则包名称")
    uninstall_parser.set_defaults(func=cmd_rules_uninstall)
    
    # list 命令
    list_parser = rules_subparsers.add_parser("list", help="列出已安装的规则包")
    list_parser.set_defaults(func=cmd_rules_list)
    
    # update 命令
    update_parser = rules_subparsers.add_parser("update", help="更新规则包")
    update_parser.add_argument("package", nargs="?", help="规则包名称（可选，默认更新所有）")
    update_parser.add_argument("--dry-run", action="store_true", help="干运行模式，只显示更新但不实际更新")
    update_parser.set_defaults(func=cmd_rules_update)
    
    # search 命令
    search_parser = rules_subparsers.add_parser("search", help="搜索社区规则")
    search_parser.add_argument("query", help="搜索关键词")
    search_parser.set_defaults(func=cmd_rules_search)
    
    # info 命令
    info_parser = rules_subparsers.add_parser("info", help="显示规则包信息")
    info_parser.add_argument("package", help="规则包名称")
    info_parser.set_defaults(func=cmd_rules_info)
    
    return rules_parser


def main(args=None):
    """主入口函数"""
    if args is None:
        args = sys.argv[1:]
    
    parser = argparse.ArgumentParser(prog="pysec rules", description="PySecScanner 规则包管理")
    subparsers = parser.add_subparsers(dest="command", help="命令")
    
    add_rules_parser(subparsers)
    
    if len(args) == 0:
        parser.print_help()
        return 0
    
    parsed_args = parser.parse_args(args)
    
    if hasattr(parsed_args, "func"):
        return parsed_args.func(parsed_args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())