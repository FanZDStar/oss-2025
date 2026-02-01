"""
AST 缓存模块

提供 AST 解析结果缓存功能，加速重复扫描
"""

import hashlib
import json
import os
import pickle
import time
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import ast


class ASTCache:
    """AST 缓存管理器

    基于文件哈希缓存 AST 解析结果，避免重复解析
    """

    # 默认缓存目录
    DEFAULT_CACHE_DIR = ".pysec_cache"

    # 缓存版本（当缓存格式变化时更新）
    CACHE_VERSION = 1

    # 默认缓存过期时间（秒）- 7 天
    DEFAULT_EXPIRY = 7 * 24 * 60 * 60

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        expiry_seconds: int = DEFAULT_EXPIRY,
        enabled: bool = True,
    ):
        """
        初始化 AST 缓存

        Args:
            cache_dir: 缓存目录路径，默认为当前目录下的 .pysec_cache
            expiry_seconds: 缓存过期时间（秒）
            enabled: 是否启用缓存
        """
        self.cache_dir = Path(cache_dir) if cache_dir else Path(self.DEFAULT_CACHE_DIR)
        self.expiry_seconds = expiry_seconds
        self.enabled = enabled
        self._memory_cache: Dict[str, Tuple[ast.AST, str, float]] = {}

        if self.enabled:
            self._ensure_cache_dir()

    def _ensure_cache_dir(self):
        """确保缓存目录存在"""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            self.enabled = False

    def _get_file_hash(self, file_path: str) -> str:
        """
        计算文件内容的哈希值

        Args:
            file_path: 文件路径

        Returns:
            文件内容的 MD5 哈希值
        """
        try:
            with open(file_path, "rb") as f:
                content = f.read()
                return hashlib.md5(content).hexdigest()
        except (IOError, OSError):
            return ""

    def _get_cache_key(self, file_path: str, file_hash: str) -> str:
        """
        生成缓存键

        Args:
            file_path: 文件路径
            file_hash: 文件哈希

        Returns:
            缓存键
        """
        path_hash = hashlib.md5(file_path.encode()).hexdigest()[:8]
        return f"{path_hash}_{file_hash}"

    def _get_cache_file_path(self, cache_key: str) -> Path:
        """
        获取缓存文件路径

        Args:
            cache_key: 缓存键

        Returns:
            缓存文件路径
        """
        return self.cache_dir / f"{cache_key}.cache"

    def get(self, file_path: str) -> Optional[Tuple[ast.AST, str]]:
        """
        获取缓存的 AST

        Args:
            file_path: 源文件路径

        Returns:
            (AST 树, 源代码) 元组，如果缓存不存在或已过期返回 None
        """
        if not self.enabled:
            return None

        file_hash = self._get_file_hash(file_path)
        if not file_hash:
            return None

        cache_key = self._get_cache_key(file_path, file_hash)

        # 首先检查内存缓存
        if cache_key in self._memory_cache:
            ast_tree, source_code, cache_time = self._memory_cache[cache_key]
            if time.time() - cache_time < self.expiry_seconds:
                return ast_tree, source_code

        # 检查磁盘缓存
        cache_file = self._get_cache_file_path(cache_key)
        if cache_file.exists():
            try:
                with open(cache_file, "rb") as f:
                    cached_data = pickle.load(f)

                # 验证缓存版本
                if cached_data.get("version") != self.CACHE_VERSION:
                    return None

                # 验证缓存是否过期
                cache_time = cached_data.get("time", 0)
                if time.time() - cache_time > self.expiry_seconds:
                    self._remove_cache_file(cache_file)
                    return None

                ast_tree = cached_data.get("ast")
                source_code = cached_data.get("source", "")

                # 更新内存缓存
                self._memory_cache[cache_key] = (ast_tree, source_code, cache_time)

                return ast_tree, source_code

            except (pickle.PickleError, IOError, OSError, KeyError):
                self._remove_cache_file(cache_file)
                return None

        return None

    def set(self, file_path: str, ast_tree: ast.AST, source_code: str):
        """
        缓存 AST 解析结果

        Args:
            file_path: 源文件路径
            ast_tree: AST 树
            source_code: 源代码
        """
        if not self.enabled:
            return

        file_hash = self._get_file_hash(file_path)
        if not file_hash:
            return

        cache_key = self._get_cache_key(file_path, file_hash)
        current_time = time.time()

        # 更新内存缓存
        self._memory_cache[cache_key] = (ast_tree, source_code, current_time)

        # 写入磁盘缓存
        cache_file = self._get_cache_file_path(cache_key)
        try:
            cached_data = {
                "version": self.CACHE_VERSION,
                "time": current_time,
                "ast": ast_tree,
                "source": source_code,
                "file_path": file_path,
            }
            with open(cache_file, "wb") as f:
                pickle.dump(cached_data, f)
        except (pickle.PickleError, IOError, OSError):
            pass

    def _remove_cache_file(self, cache_file: Path):
        """删除缓存文件"""
        try:
            cache_file.unlink()
        except OSError:
            pass

    def clear(self):
        """清除所有缓存"""
        self._memory_cache.clear()

        if self.cache_dir.exists():
            try:
                for cache_file in self.cache_dir.glob("*.cache"):
                    self._remove_cache_file(cache_file)
            except OSError:
                pass

    def get_stats(self) -> Dict[str, Any]:
        """
        获取缓存统计信息

        Returns:
            缓存统计字典
        """
        memory_count = len(self._memory_cache)
        disk_count = 0
        disk_size = 0

        if self.cache_dir.exists():
            try:
                for cache_file in self.cache_dir.glob("*.cache"):
                    disk_count += 1
                    disk_size += cache_file.stat().st_size
            except OSError:
                pass

        return {
            "enabled": self.enabled,
            "memory_entries": memory_count,
            "disk_entries": disk_count,
            "disk_size_bytes": disk_size,
            "cache_dir": str(self.cache_dir),
        }
