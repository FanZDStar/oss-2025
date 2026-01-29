"""配置文件加载和管理模块。

此模块负责加载和解析 PySecScanner 的配置文件，
支持 .pysecrc (YAML/TOML) 格式。
"""

from pathlib import Path
from typing import Optional, Dict, Any, List
import sys
import yaml

# Python 3.11+ 使用内置的 tomllib，之前版本使用 tomli
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None  # type: ignore


class Config:
    """配置管理类。

    负责加载和解析 PySecScanner 的配置文件。
    """

    def __init__(self):
        """初始化配置对象。"""
        self.rules_enabled: List[str] = []
        self.rules_disabled: List[str] = []
        self.exclude_dirs: List[str] = []
        self.exclude_files: List[str] = []
        self.minimum_severity: str = "info"
        self.output_format: str = "markdown"
        self.output_color: bool = True

    @classmethod
    def load_from_yaml(cls, file_path: Path) -> "Config":
        """从 YAML 文件加载配置。

        Args:
            file_path: YAML 配置文件路径

        Returns:
            Config: 配置对象

        Raises:
            FileNotFoundError: 配置文件不存在
            yaml.YAMLError: YAML 文件格式错误
        """
        if not file_path.exists():
            raise FileNotFoundError(f"配置文件不存在: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if data is None:
            data = {}

        config = cls()
        config._parse_config(data)
        return config

    @classmethod
    def load_from_toml(cls, file_path: Path) -> "Config":
        """从 TOML 文件加载配置。

        Args:
            file_path: TOML 配置文件路径

        Returns:
            Config: 配置对象

        Raises:
            FileNotFoundError: 配置文件不存在
            ImportError: tomli/tomllib 库未安装
            tomllib.TOMLDecodeError: TOML 文件格式错误
        """
        if tomllib is None:
            raise ImportError("需要安装 tomli 库以支持 TOML 格式（Python < 3.11）")

        if not file_path.exists():
            raise FileNotFoundError(f"配置文件不存在: {file_path}")

        with open(file_path, "rb") as f:
            data = tomllib.load(f)

        config = cls()
        config._parse_config(data)
        return config

    @classmethod
    def load_from_file(cls, file_path: Path) -> "Config":
        """自动检测文件格式并加载配置。

        Args:
            file_path: 配置文件路径

        Returns:
            Config: 配置对象

        Raises:
            ValueError: 不支持的文件格式
        """
        suffix = file_path.suffix.lower()
        if suffix in [".yaml", ".yml"] or file_path.name == ".pysecrc":
            return cls.load_from_yaml(file_path)
        elif suffix == ".toml":
            # 如果是 pyproject.toml，使用专门的方法
            if file_path.name == "pyproject.toml":
                return cls.load_from_pyproject(file_path)
            return cls.load_from_toml(file_path)
        else:
            raise ValueError(f"不支持的配置文件格式: {suffix}")

    @classmethod
    def load_from_pyproject(cls, file_path: Path) -> "Config":
        """从 pyproject.toml 的 [tool.pysec] 节加载配置。

        Args:
            file_path: pyproject.toml 文件路径

        Returns:
            Config: 配置对象

        Raises:
            FileNotFoundError: pyproject.toml 不存在
            ValueError: 未找到 [tool.pysec] 配置节
        """
        if tomllib is None:
            raise ImportError("需要安装 tomli 库以支持 TOML 格式（Python < 3.11）")

        if not file_path.exists():
            raise FileNotFoundError(f"pyproject.toml 不存在: {file_path}")

        with open(file_path, "rb") as f:
            data = tomllib.load(f)

        # 提取 tool.pysec 配置节
        if "tool" not in data or "pysec" not in data["tool"]:
            raise ValueError("pyproject.toml 中未找到 [tool.pysec] 配置节")

        pysec_config = data["tool"]["pysec"]
        config = cls()
        config._parse_config(pysec_config)
        return config

    def _parse_config(self, data: Dict[str, Any]) -> None:
        """解析配置数据。

        Args:
            data: 配置数据字典
        """
        # 解析规则配置
        if "rules" in data:
            rules_config = data["rules"]
            self.rules_enabled = rules_config.get("enabled", [])
            self.rules_disabled = rules_config.get("disabled", [])

        # 解析排除配置
        if "exclude" in data:
            exclude_config = data["exclude"]
            self.exclude_dirs = exclude_config.get("dirs", [])
            self.exclude_files = exclude_config.get("files", [])

        # 解析严重程度配置
        if "severity" in data:
            severity_config = data["severity"]
            self.minimum_severity = severity_config.get("minimum", "info")

        # 解析输出配置
        if "output" in data:
            output_config = data["output"]
            self.output_format = output_config.get("format", "markdown")
            self.output_color = output_config.get("color", True)

    @classmethod
    def find_config_file(cls, start_dir: Path) -> Optional[Path]:
        """从指定目录向上查找配置文件。

        查找顺序：.pysecrc -> pyproject.toml

        Args:
            start_dir: 起始搜索目录

        Returns:
            Optional[Path]: 找到的配置文件路径，未找到返回 None
        """
        current_dir = start_dir.resolve()

        # 向上查找，直到根目录
        while True:
            # 优先查找 .pysecrc
            config_path = current_dir / ".pysecrc"
            if config_path.exists():
                return config_path

            # 查找 pyproject.toml 并检查是否包含 [tool.pysec]
            pyproject_path = current_dir / "pyproject.toml"
            if pyproject_path.exists():
                try:
                    # 快速检查是否包含 [tool.pysec] 配置节
                    if tomllib is not None:
                        with open(pyproject_path, "rb") as f:
                            data = tomllib.load(f)
                            if "tool" in data and "pysec" in data["tool"]:
                                return pyproject_path
                except Exception:
                    pass  # 忽略解析错误，继续查找

            # 检查是否到达根目录
            parent = current_dir.parent
            if parent == current_dir:
                break
            current_dir = parent

        return None

    def to_dict(self) -> Dict[str, Any]:
        """将配置转换为字典格式。

        Returns:
            Dict[str, Any]: 配置字典
        """
        return {
            "rules": {
                "enabled": self.rules_enabled,
                "disabled": self.rules_disabled,
            },
            "exclude": {
                "dirs": self.exclude_dirs,
                "files": self.exclude_files,
            },
            "severity": {
                "minimum": self.minimum_severity,
            },
            "output": {
                "format": self.output_format,
                "color": self.output_color,
            },
        }
