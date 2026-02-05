"""
规则引擎模块

负责规则的加载、调度和执行
"""

import time
from datetime import datetime
from typing import List, Optional, Tuple

from .models import Vulnerability, ScanResult, ScanConfig
from .scanner import Scanner
from .rules import RULE_REGISTRY
from .rules.base import BaseRule
from .ignore_handler import IgnoreHandler


class RuleEngine:
    """
    规则引擎

    负责规则的加载、调度和执行
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        """
        初始化规则引擎

        Args:
            config: 扫描配置
        """
        self.config = config or ScanConfig()
        self.rules: List[BaseRule] = []
        self._load_rules()

    def _load_rules(self):
        """加载所有检测规则"""
        for rule_id, rule_class in RULE_REGISTRY.items():
            if self.config.should_scan_rule(rule_id):
                try:
                    self.rules.append(rule_class())
                except Exception as e:
                    print(f"加载规则 {rule_id} 失败: {e}")

    def get_loaded_rules(self) -> List[dict]:
        """获取已加载的规则信息"""
        return [
            {
                "id": rule.rule_id,
                "name": rule.rule_name,
                "severity": rule.severity,
                "description": rule.description,
            }
            for rule in self.rules
        ]

    def scan_ast(
        self, ast_tree, file_path: str, source_code: str
    ) -> Tuple[List[Vulnerability], int]:
        """
        对单个文件的AST执行所有规则检测

        Args:
            ast_tree: AST语法树
            file_path: 文件路径
            source_code: 源代码

        Returns:
            (发现的漏洞列表, 被忽略的漏洞数量)
        """
        vulnerabilities = []

        for rule in self.rules:
            try:
                results = rule.check(ast_tree, file_path, source_code)
                if results:
                    vulnerabilities.extend(results)
            except Exception as e:
                if self.config.verbose:
                    print(f"规则 {rule.rule_id} 执行出错: {e}")

        # 过滤被忽略的漏洞
        filtered_vulns, ignored_count = IgnoreHandler.filter_vulnerabilities(
            vulnerabilities, source_code, file_path
        )

        return filtered_vulns, ignored_count

    def scan_source(
        self, source_code: str, filename: str = "<string>"
    ) -> Tuple[List[Vulnerability], int]:
        """
        扫描源代码字符串

        Args:
            source_code: 源代码
            filename: 虚拟文件名

        Returns:
            (发现的漏洞列表, 被忽略的漏洞数量)
        """
        import ast

        try:
            tree = ast.parse(source_code, filename=filename)
            return self.scan_ast(tree, filename, source_code)
        except SyntaxError as e:
            if self.config.verbose:
                print(f"解析错误: {e}")
            return [], 0


class SecurityScanner:
    """
    安全扫描器

    提供完整的扫描功能，整合文件扫描、AST解析和规则检测
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        """
        初始化安全扫描器

        Args:
            config: 扫描配置
        """
        self.config = config or ScanConfig()
        self.scanner = Scanner()
        self.engine = RuleEngine(self.config)

    def scan(self, target: str) -> ScanResult:
        """
        扫描目标（文件或目录）

        Args:
            target: 目标路径

        Returns:
            扫描结果
        """
        start_time = time.time()
        result = ScanResult(target=target, scan_time=datetime.now())

        files_scanned = 0
        total_ignored = 0

        for file_path, ast_tree, source_code, error in self.scanner.scan_target(target):
            files_scanned += 1

            if error:
                result.add_error(f"{file_path}: {error}")
                if self.config.verbose:
                    print(f"[错误] {file_path}: {error}")
                continue

            if ast_tree is None:
                continue

            # 执行规则检测（包含忽略过滤）
            vulnerabilities, ignored_count = self.engine.scan_ast(ast_tree, file_path, source_code)
            total_ignored += ignored_count

            for vuln in vulnerabilities:
                result.add_vulnerability(vuln)

            if self.config.verbose:
                if vulnerabilities:
                    msg = f"[扫描] {file_path}: 发现 {len(vulnerabilities)} 个问题"
                    if ignored_count > 0:
                        msg += f" (忽略 {ignored_count} 个)"
                    print(msg)
                else:
                    msg = f"[扫描] {file_path}: 通过"
                    if ignored_count > 0:
                        msg += f" (忽略 {ignored_count} 个)"
                    print(msg)

        result.files_scanned = files_scanned
        result.ignored_count = total_ignored
        result.duration = time.time() - start_time

        # 应用严重程度过滤
        if self.config.min_severity:
            result.filter_by_severity(self.config.min_severity)

        return result

    def scan_file(self, file_path: str) -> ScanResult:
        """
        扫描单个文件

        Args:
            file_path: 文件路径

        Returns:
            扫描结果
        """
        return self.scan(file_path)

    def scan_directory(self, directory: str) -> ScanResult:
        """
        扫描目录

        Args:
            directory: 目录路径

        Returns:
            扫描结果
        """
        return self.scan(directory)

    def scan_code(self, source_code: str, filename: str = "<string>") -> ScanResult:
        """
        扫描代码字符串

        Args:
            source_code: 源代码
            filename: 虚拟文件名

        Returns:
            扫描结果
        """
        start_time = time.time()
        result = ScanResult(target=filename, scan_time=datetime.now())

        vulnerabilities, ignored_count = self.engine.scan_source(source_code, filename)

        for vuln in vulnerabilities:
            result.add_vulnerability(vuln)

        result.files_scanned = 1
        result.ignored_count = ignored_count
        result.duration = time.time() - start_time

        # 应用严重程度过滤
        if self.config.min_severity:
            result.filter_by_severity(self.config.min_severity)

        return result

    def scan_changed(self, target: str) -> ScanResult:
        """
        仅扫描 Git 仓库中自上次提交以来修改的 Python 文件

        Args:
            target: Git 仓库路径

        Returns:
            扫描结果
        """
        from .git_utils import GitHelper

        start_time = time.time()
        result = ScanResult(target=target, scan_time=datetime.now())

        git_helper = GitHelper(target)

        if not git_helper.is_git_repo():
            result.add_error("当前目录不是 Git 仓库")
            result.duration = time.time() - start_time
            return result

        changed_files = git_helper.get_changed_files()

        if not changed_files:
            result.duration = time.time() - start_time
            return result

        files_scanned = 0
        total_ignored = 0

        for file_path, ast_tree, source_code, error in self.scanner.scan_files(changed_files):
            files_scanned += 1

            if error:
                result.add_error(f"{file_path}: {error}")
                if self.config.verbose:
                    print(f"[错误] {file_path}: {error}")
                continue

            if ast_tree is None:
                continue

            # 执行规则检测（包含忽略过滤）
            vulnerabilities, ignored_count = self.engine.scan_ast(ast_tree, file_path, source_code)
            total_ignored += ignored_count

            for vuln in vulnerabilities:
                result.add_vulnerability(vuln)

            if self.config.verbose:
                if vulnerabilities:
                    msg = f"[扫描] {file_path}: 发现 {len(vulnerabilities)} 个问题"
                    if ignored_count > 0:
                        msg += f" (忽略 {ignored_count} 个)"
                    print(msg)
                else:
                    msg = f"[扫描] {file_path}: 通过"
                    if ignored_count > 0:
                        msg += f" (忽略 {ignored_count} 个)"
                    print(msg)

        result.files_scanned = files_scanned
        result.ignored_count = total_ignored
        result.duration = time.time() - start_time

        # 应用严重程度过滤
        if self.config.min_severity:
            result.filter_by_severity(self.config.min_severity)

        return result

    def scan_since(self, target: str, since_ref: str) -> ScanResult:
        """
        扫描自指定提交/分支以来修改的 Python 文件

        Args:
            target: Git 仓库路径
            since_ref: 基准提交/分支（如 HEAD~5, main, abc123）

        Returns:
            扫描结果
        """
        from .git_utils import GitHelper

        start_time = time.time()
        result = ScanResult(target=target, scan_time=datetime.now())

        git_helper = GitHelper(target)

        if not git_helper.is_git_repo():
            result.add_error("当前目录不是 Git 仓库")
            result.duration = time.time() - start_time
            return result

        if not git_helper.is_valid_ref(since_ref):
            result.add_error(f"无效的 Git 引用: {since_ref}")
            result.duration = time.time() - start_time
            return result

        changed_files = git_helper.get_files_changed_since(since_ref)

        if not changed_files:
            result.duration = time.time() - start_time
            return result

        files_scanned = 0
        total_ignored = 0

        for file_path, ast_tree, source_code, error in self.scanner.scan_files(changed_files):
            files_scanned += 1

            if error:
                result.add_error(f"{file_path}: {error}")
                if self.config.verbose:
                    print(f"[错误] {file_path}: {error}")
                continue

            if ast_tree is None:
                continue

            # 执行规则检测（包含忽略过滤）
            vulnerabilities, ignored_count = self.engine.scan_ast(ast_tree, file_path, source_code)
            total_ignored += ignored_count

            for vuln in vulnerabilities:
                result.add_vulnerability(vuln)

            if self.config.verbose:
                if vulnerabilities:
                    msg = f"[扫描] {file_path}: 发现 {len(vulnerabilities)} 个问题"
                    if ignored_count > 0:
                        msg += f" (忽略 {ignored_count} 个)"
                    print(msg)
                else:
                    msg = f"[扫描] {file_path}: 通过"
                    if ignored_count > 0:
                        msg += f" (忽略 {ignored_count} 个)"
                    print(msg)

        result.files_scanned = files_scanned
        result.ignored_count = total_ignored
        result.duration = time.time() - start_time

        # 应用严重程度过滤
        if self.config.min_severity:
            result.filter_by_severity(self.config.min_severity)

        return result

    def get_rules(self) -> List[dict]:
        """获取所有已加载的规则"""
        return self.engine.get_loaded_rules()
