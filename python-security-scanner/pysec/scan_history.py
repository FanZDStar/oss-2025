"""
扫描历史记录模块

管理多次扫描的历史记录，用于生成趋势对比图表
"""

import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Optional


@dataclass
class ScanSummary:
    """单次扫描的摘要信息"""

    scan_time: str  # ISO 格式时间
    target: str  # 扫描目标
    files_scanned: int  # 文件数
    duration: float  # 耗时（秒）
    total: int  # 漏洞总数
    critical: int  # 严重
    high: int  # 高危
    medium: int  # 中危
    low: int  # 低危

    def to_dict(self) -> dict:
        """转换为字典"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanSummary":
        """从字典创建"""
        return cls(
            scan_time=data.get("scan_time", ""),
            target=data.get("target", ""),
            files_scanned=data.get("files_scanned", 0),
            duration=data.get("duration", 0.0),
            total=data.get("total", 0),
            critical=data.get("critical", 0),
            high=data.get("high", 0),
            medium=data.get("medium", 0),
            low=data.get("low", 0),
        )


class ScanHistory:
    """
    扫描历史管理器

    将扫描摘要信息存储到 JSON 文件中，支持读取历史记录
    用于趋势对比图表的数据来源
    """

    DEFAULT_FILE = ".pysec_history.json"

    def __init__(self, history_file: Optional[str] = None):
        """
        初始化扫描历史管理器

        Args:
            history_file: 历史记录文件路径，默认为当前目录下 .pysec_history.json
        """
        self.history_file = history_file or self.DEFAULT_FILE

    def save(self, result) -> ScanSummary:
        """
        保存扫描结果摘要到历史记录

        Args:
            result: ScanResult 扫描结果对象

        Returns:
            保存的 ScanSummary 对象
        """
        summary_data = result.summary
        scan_summary = ScanSummary(
            scan_time=result.scan_time.isoformat(),
            target=result.target,
            files_scanned=result.files_scanned,
            duration=round(result.duration, 2),
            total=summary_data["total"],
            critical=summary_data["critical"],
            high=summary_data["high"],
            medium=summary_data["medium"],
            low=summary_data["low"],
        )

        # 读取现有历史记录
        history = self._load_raw()
        history.append(scan_summary.to_dict())

        # 写入文件
        with open(self.history_file, "w", encoding="utf-8") as f:
            json.dump(history, f, ensure_ascii=False, indent=2)

        return scan_summary

    def load(self) -> List[ScanSummary]:
        """
        加载所有历史记录

        Returns:
            ScanSummary 列表
        """
        raw = self._load_raw()
        return [ScanSummary.from_dict(item) for item in raw]

    def get_recent(self, n: int = 10) -> List[ScanSummary]:
        """
        获取最近 N 次扫描记录

        Args:
            n: 返回的记录数量

        Returns:
            最近 N 条 ScanSummary 列表
        """
        records = self.load()
        return records[-n:] if len(records) > n else records

    def _load_raw(self) -> list:
        """加载原始 JSON 数据"""
        if not os.path.exists(self.history_file):
            return []
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except (json.JSONDecodeError, IOError):
            return []
