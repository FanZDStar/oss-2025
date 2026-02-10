#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
规则仓库管理器

支持从外部加载规则、社区规则仓库、规则版本管理和自动更新
"""

import os
import json
import yaml
import re
import shutil
import tempfile
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union
import urllib.request
import urllib.parse
from urllib.error import URLError, HTTPError
import subprocess
import sys
import importlib.util
import importlib.machinery


class RuleRepositoryError(Exception):
    """规则仓库异常"""
    pass


class RulePackage:
    """规则包"""
    
    def __init__(self, name: str, version: str = "1.0.0", 
                 description: str = "", rules: List[Dict] = None,
                 dependencies: List[str] = None, author: str = "",
                 license: str = "MIT"):
        """
        初始化规则包
        
        Args:
            name: 规则包名称
            version: 版本号
            description: 描述
            rules: 规则列表
            dependencies: 依赖
            author: 作者
            license: 许可证
        """
        self.name = name
        self.version = version
        self.description = description
        self.rules = rules or []
        self.dependencies = dependencies or []
        self.author = author
        self.license = license
        self.installed_at = datetime.now()
        self.updated_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "rules_count": len(self.rules),
            "dependencies": self.dependencies,
            "author": self.author,
            "license": self.license,
            "installed_at": self.installed_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RulePackage':
        """从字典创建规则包"""
        package = cls(
            name=data.get("name", ""),
            version=data.get("version", "1.0.0"),
            description=data.get("description", ""),
            rules=data.get("rules", []),
            dependencies=data.get("dependencies", []),
            author=data.get("author", ""),
            license=data.get("license", "MIT")
        )
        if "installed_at" in data:
            package.installed_at = datetime.fromisoformat(data["installed_at"].replace('Z', '+00:00'))
        if "updated_at" in data:
            package.updated_at = datetime.fromisoformat(data["updated_at"].replace('Z', '+00:00'))
        return package
    
    def get_rule_ids(self) -> List[str]:
        """获取所有规则ID"""
        return [rule.get("id", f"UNKNOWN_{i}") for i, rule in enumerate(self.rules)]


class RuleRepository:
    """规则仓库管理器"""
    
    def __init__(self, rules_dir: str = None, 
                 config_file: str = ".pysec_rules.json"):
        """
        初始化规则仓库
        
        Args:
            rules_dir: 规则安装目录
            config_file: 配置文件路径
        """
        if rules_dir is None:
            rules_dir = os.path.join(os.path.expanduser("~"), ".pysec", "rules")
        
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        
        self.config_file = Path(config_file)
        self.installed_packages: Dict[str, RulePackage] = {}
        self.community_repositories = [
            "https://github.com/PySecScanner/community-rules"
        ]
        
        self._load_config()
    
    def _load_config(self):
        """加载配置"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                for pkg_name, pkg_data in data.get("installed_packages", {}).items():
                    self.installed_packages[pkg_name] = RulePackage.from_dict(pkg_data)
            except Exception as e:
                print(f" 加载规则配置失败: {e}")
                self.installed_packages = {}
    
    def _save_config(self):
        """保存配置"""
        config_data = {
            "rules_dir": str(self.rules_dir),
            "installed_packages": {
                name: pkg.to_dict() for name, pkg in self.installed_packages.items()
            },
            "last_updated": datetime.now().isoformat()
        }
        
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f" 保存规则配置失败: {e}")
    
    def install_from_file(self, file_path: str) -> bool:
        """
        从本地文件安装规则
        
        Args:
            file_path: 规则文件路径
            
        Returns:
            是否安装成功
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                print(f" 文件不存在: {file_path}")
                return False
            
            # 根据文件类型加载
            if file_path.suffix in ['.py', '.py3']:
                return self._install_python_rule(file_path)
            elif file_path.suffix in ['.json', '.yaml', '.yml']:
                return self._install_package_file(file_path)
            else:
                print(f" 不支持的文件格式: {file_path.suffix}")
                return False
                
        except Exception as e:
            print(f" 安装规则失败: {e}")
            return False
    
    def _install_python_rule(self, file_path: Path) -> bool:
        """安装Python规则文件"""
        try:
            # 读取文件内容
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 提取规则元数据
            rule_name = file_path.stem
            rule_id_match = re.search(r'rule_id\s*=\s*["\']([^"\']+)["\']', content)
            rule_id = rule_id_match.group(1) if rule_id_match else f"CUSTOM_{rule_name.upper()}"
            
            # 创建目标路径
            target_dir = self.rules_dir / "custom"
            target_dir.mkdir(exist_ok=True)
            target_path = target_dir / f"{rule_name}.py"
            
            # 复制文件
            shutil.copy2(file_path, target_path)
            
            # 添加到已安装包
            package_name = f"custom-{rule_name}"
            if package_name not in self.installed_packages:
                package = RulePackage(
                    name=package_name,
                    version="1.0.0",
                    description=f"自定义规则: {rule_name}",
                    author="user",
                    license="Custom"
                )
                self.installed_packages[package_name] = package
            
            print(f" 已安装规则: {rule_id}")
            self._save_config()
            return True
            
        except Exception as e:
            print(f" 安装Python规则失败: {e}")
            return False
    
    def _install_package_file(self, file_path: Path) -> bool:
        """安装规则包文件（JSON/YAML）"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.suffix == '.json':
                    data = json.load(f)
                else:  # YAML
                    data = yaml.safe_load(f)
            
            # 创建规则包
            package = RulePackage.from_dict(data)
            
            # 保存规则文件
            package_dir = self.rules_dir / package.name
            package_dir.mkdir(exist_ok=True)
            
            # 保存每个规则
            for rule_data in data.get("rules", []):
                rule_id = rule_data.get("id", "unknown")
                rule_file = package_dir / f"{rule_id}.py"
                
                # 生成Python规则代码
                rule_code = self._generate_rule_code(rule_data)
                with open(rule_file, 'w', encoding='utf-8') as f:
                    f.write(rule_code)
            
            # 保存元数据
            meta_file = package_dir / "metadata.json"
            with open(meta_file, 'w', encoding='utf-8') as f:
                json.dump(package.to_dict(), f, indent=2, ensure_ascii=False)
            
            # 添加到已安装
            self.installed_packages[package.name] = package
            self._save_config()
            
            print(f" 已安装规则包: {package.name} v{package.version}")
            print(f"   包含 {len(package.rules)} 个规则")
            return True
            
        except Exception as e:
            print(f" 安装规则包失败: {e}")
            return False
    
    def _generate_rule_code(self, rule_data: Dict[str, Any]) -> str:
        """生成Python规则代码"""
        rule_id = rule_data.get("id", "UNKNOWN")
        rule_name = rule_data.get("name", "Unknown Rule")
        severity = rule_data.get("severity", "medium")
        description = rule_data.get("description", "")
        pattern = rule_data.get("pattern", "")
        suggestion = rule_data.get("suggestion", "")
        
        return f'''"""
{rule_name}

{description}
"""

import ast
from pysec.rules.base import BaseRule


class {rule_id.replace('-', '_').replace('.', '_')}(BaseRule):
    """{rule_name}"""
    
    rule_id = "{rule_id}"
    rule_name = "{rule_name}"
    severity = "{severity}"
    description = "{description}"
    
    def detect(self, node: ast.AST) -> bool:
        """检测逻辑"""
        # TODO: 实现具体的检测逻辑
        # 这里只是一个示例
        {pattern if pattern else "# 实现检测逻辑"}
        return False
    
    def get_suggestion(self) -> str:
        """获取修复建议"""
        return "{suggestion}"


# 导出规则
RULE_CLASS = {rule_id.replace('-', '_').replace('.', '_')}
'''
    
    def install_from_url(self, url: str) -> bool:
        """
        从URL安装规则
        
        Args:
            url: 规则文件URL
            
        Returns:
            是否安装成功
        """
        try:
            # 下载文件
            response = urllib.request.urlopen(url, timeout=30)
            content = response.read().decode('utf-8')
            
            # 保存到临时文件
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            
            # 安装
            result = self.install_from_file(tmp_path)
            
            # 清理临时文件
            os.unlink(tmp_path)
            
            return result
            
        except Exception as e:
            print(f" 从URL安装规则失败: {e}")
            return False
    
    def install_from_community(self, package_name: str) -> bool:
        """
        从社区仓库安装规则
        
        Args:
            package_name: 规则包名称
            
        Returns:
            是否安装成功
        """
        print(f" 从社区仓库安装: {package_name}")
        
        # 这里实现从社区仓库下载
        # 示例：假设社区仓库是GitHub仓库
        for repo_url in self.community_repositories:
            try:
                # 构建规则文件URL
                rule_url = f"{repo_url}/raw/main/rules/{package_name}.py"
                return self.install_from_url(rule_url)
            except Exception as e:
                continue
        
        print(f" 未找到规则包: {package_name}")
        return False
    
    def list_installed(self) -> List[Dict[str, Any]]:
        """
        列出已安装的规则包
        
        Returns:
            已安装规则包列表
        """
        packages = []
        for name, package in self.installed_packages.items():
            packages.append(package.to_dict())
        
        return packages
    
    def get_installed_package(self, package_name: str) -> Optional[RulePackage]:
        """
        获取已安装的规则包
        
        Args:
            package_name: 规则包名称
            
        Returns:
            规则包对象，如果不存在返回None
        """
        return self.installed_packages.get(package_name)
    
    def uninstall_package(self, package_name: str) -> bool:
        """
        卸载规则包
        
        Args:
            package_name: 规则包名称
            
        Returns:
            是否卸载成功
        """
        if package_name not in self.installed_packages:
            print(f" 规则包未安装: {package_name}")
            return False
        
        try:
            # 删除规则目录
            package_dir = self.rules_dir / package_name
            if package_dir.exists():
                shutil.rmtree(package_dir)
            
            # 从配置中移除
            del self.installed_packages[package_name]
            self._save_config()
            
            print(f"已卸载规则包: {package_name}")
            return True
            
        except Exception as e:
            print(f"卸载规则包失败: {e}")
            return False
    
    def check_for_updates(self, package_name: str = None) -> Dict[str, Any]:
        """
        检查更新
        
        Args:
            package_name: 规则包名称，如果为None则检查所有
            
        Returns:
            更新信息
        """
        updates = {
            "available": [],
            "latest_versions": {},
            "last_checked": datetime.now().isoformat()
        }
        
        packages_to_check = []
        if package_name:
            if package_name in self.installed_packages:
                packages_to_check.append(package_name)
        else:
            packages_to_check = list(self.installed_packages.keys())
        
        for pkg_name in packages_to_check:
            package = self.installed_packages[pkg_name]
            
            # 这里实现检查更新逻辑
            # 示例：模拟检查
            current_version = package.version
            latest_version = self._get_latest_version(pkg_name)
            
            if latest_version and latest_version != current_version:
                updates["available"].append({
                    "package": pkg_name,
                    "current_version": current_version,
                    "latest_version": latest_version
                })
            
            updates["latest_versions"][pkg_name] = latest_version or current_version
        
        return updates
    
    def _get_latest_version(self, package_name: str) -> Optional[str]:
        """获取最新版本（模拟实现）"""
        # 这里应该从社区仓库获取最新版本
        # 现在返回模拟数据
        if package_name.startswith("community/"):
            return "1.1.0"
        return None
    
    def update_package(self, package_name: str) -> bool:
        """
        更新规则包
        
        Args:
            package_name: 规则包名称
            
        Returns:
            是否更新成功
        """
        if package_name not in self.installed_packages:
            print(f" 规则包未安装: {package_name}")
            return False
        
        print(f" 更新规则包: {package_name}")
        
        # 先卸载旧版本
        self.uninstall_package(package_name)
        
        # 重新安装
        if package_name.startswith("community/"):
            return self.install_from_community(package_name)
        else:
            print(f" 无法更新非社区规则包: {package_name}")
            return False
    
    def update_all(self) -> Dict[str, bool]:
        """
        更新所有规则包
        
        Returns:
            更新结果字典
        """
        results = {}
        
        for package_name in self.installed_packages.keys():
            if package_name.startswith("community/"):
                results[package_name] = self.update_package(package_name)
        
        return results
    
    def search_community(self, query: str) -> List[Dict[str, Any]]:
        """
        搜索社区规则
        
        Args:
            query: 搜索关键词
            
        Returns:
            搜索结果列表
        """
        # 这里实现社区规则搜索
        # 现在返回模拟数据
        mock_rules = [
            {
                "name": "community/aws-rules",
                "version": "1.0.0",
                "description": "AWS相关安全规则",
                "author": "PySecScanner Team",
                "downloads": 1500,
                "rating": 4.8
            },
            {
                "name": "community/docker-rules",
                "version": "1.2.0",
                "description": "Docker安全最佳实践规则",
                "author": "Security Expert",
                "downloads": 1200,
                "rating": 4.7
            },
            {
                "name": "community/web-rules",
                "version": "2.0.1",
                "description": "Web应用安全规则（SQL注入、XSS等）",
                "author": "Web Security Team",
                "downloads": 2100,
                "rating": 4.9
            }
        ]
        
        if query:
            return [rule for rule in mock_rules if query.lower() in rule["name"].lower() or 
                    query.lower() in rule["description"].lower()]
        else:
            return mock_rules
    
    def load_all_rules(self) -> List[Any]:
        """
        加载所有已安装的规则
        
        Returns:
            规则类列表
        """
        rules = []
        
        # 加载内置规则
        try:
            from ..rules import RULE_REGISTRY
            for rule_class in RULE_REGISTRY.values():
                rules.append(rule_class)
        except ImportError:
            pass
        
        # 加载自定义规则
        custom_dir = self.rules_dir / "custom"
        if custom_dir.exists():
            for py_file in custom_dir.glob("*.py"):
                try:
                    rule_class = self._load_rule_from_file(py_file)
                    if rule_class:
                        rules.append(rule_class)
                except Exception as e:
                    print(f"  加载规则文件失败 {py_file}: {e}")
        
        # 加载规则包
        for package_dir in self.rules_dir.iterdir():
            if package_dir.is_dir() and package_dir.name != "custom":
                for py_file in package_dir.glob("*.py"):
                    try:
                        rule_class = self._load_rule_from_file(py_file)
                        if rule_class:
                            rules.append(rule_class)
                    except Exception as e:
                        print(f" 加载规则文件失败 {py_file}: {e}")
        
        return rules
    
    def _load_rule_from_file(self, file_path: Path) -> Optional[Any]:
        """从文件加载规则类"""
        try:
            # 动态导入模块
            spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # 查找RULE_CLASS变量
                if hasattr(module, 'RULE_CLASS'):
                    return getattr(module, 'RULE_CLASS')
                
                # 或者查找BaseRule的子类
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and attr.__module__ == module.__name__ and
                        hasattr(attr, 'rule_id') and hasattr(attr, 'rule_name')):
                        return attr
        except Exception as e:
            print(f" 加载规则类失败 {file_path}: {e}")
        
        return None


# 全局规则仓库实例
_global_repository = None

def get_repository() -> RuleRepository:
    """获取全局规则仓库实例"""
    global _global_repository
    if _global_repository is None:
        _global_repository = RuleRepository()
    return _global_repository