"""
配置管理器模块 - 解析.pysecrc/pyproject.toml配置文件
对应报告"配置文件支持"特性，统一管理扫描规则/排除项/输出格式
"""

import os
import yaml
from typing import Dict, List, Optional
from dataclasses import dataclass, field

@dataclass
class ScanConfig:
    """扫描配置模型"""
    enabled_rules: List[str] = field(default_factory=list)
    disabled_rules: List[str] = field(default_factory=list)
    exclude_dirs: List[str] = field(default_factory=list)
    exclude_files: List[str] = field(default_factory=list)
    min_severity: str = "low"
    output_format: str = "text"
    use_cache: bool = True

class ConfigManager:
    """配置文件解析器"""
    def __init__(self, config_path: Optional[str] = None):
        self.config = ScanConfig()
        self._load_config(config_path)

    def _load_config(self, config_path: Optional[str]):
        """加载配置文件（.pysecrc优先，其次pyproject.toml）"""
        # 自动查找配置文件
        if not config_path:
            if os.path.exists(".pysecrc"):
                config_path = ".pysecrc"
            elif os.path.exists("pyproject.toml"):
                config_path = "pyproject.toml"
            else:
                return

        # 解析YAML格式（.pysecrc）
        if config_path.endswith(".pysecrc"):
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            self._parse_yaml_config(data)
        
        # 解析toml格式（pyproject.toml）
        elif config_path.endswith(".toml"):
            import tomllib  # Python 3.11+ 内置
            with open(config_path, "rb") as f:
                data = tomllib.load(f)
            self._parse_toml_config(data.get("tool", {}).get("pysec", {}))

    def _parse_yaml_config(self, data: Dict):
        """解析YAML配置"""
        self.config.enabled_rules = data.get("rules", {}).get("enabled", [])
        self.config.disabled_rules = data.get("rules", {}).get("disabled", [])
        self.config.exclude_dirs = data.get("exclude", {}).get("dirs", [])
        self.config.exclude_files = data.get("exclude", {}).get("files", [])
        self.config.min_severity = data.get("severity", {}).get("minimum", "low")
        self.config.output_format = data.get("output", {}).get("format", "text")

    def _parse_toml_config(self, data: Dict):
        """解析pyproject.toml中的pysec配置"""
        self.config = ScanConfig(**data)

    def get_config(self) -> ScanConfig:
        """获取解析后的配置"""
        return self.config

# 演示
if __name__ == "__main__":
    config = ConfigManager().get_config()
    print(f"启用的规则: {config.enabled_rules}")
    print(f"排除目录: {config.exclude_dirs}")
    print(f"最低严重程度: {config.min_severity}")