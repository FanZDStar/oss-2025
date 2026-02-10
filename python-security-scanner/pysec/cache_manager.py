"""
AST缓存管理器 - 缓存已解析的AST树，加速重复扫描
对应报告"AST缓存"特性，避免重复解析相同文件
"""

import os
import pickle
import hashlib
from typing import Dict, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ASTCacheItem:
    """AST缓存项"""
    ast_tree: object
    file_hash: str
    create_time: datetime = field(default_factory=datetime.now)

class ASTCacheManager:
    """AST解析结果缓存管理器"""
    def __init__(self, cache_dir: str = ".pysec_cache"):
        self.cache_dir = cache_dir
        self.cache: Dict[str, ASTCacheItem] = {}
        self._init_cache_dir()
        self._load_cache()

    def _init_cache_dir(self):
        """初始化缓存目录"""
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)

    def _get_file_hash(self, file_path: str) -> str:
        """计算文件内容哈希（判断是否修改）"""
        with open(file_path, "rb") as f:
            content = f.read()
        return hashlib.md5(content).hexdigest()

    def _load_cache(self):
        """加载本地缓存"""
        cache_file = os.path.join(self.cache_dir, "ast_cache.pkl")
        if os.path.exists(cache_file):
            with open(cache_file, "rb") as f:
                self.cache = pickle.load(f)

    def _save_cache(self):
        """保存缓存到本地"""
        cache_file = os.path.join(self.cache_dir, "ast_cache.pkl")
        with open(cache_file, "wb") as f:
            pickle.dump(self.cache, f)

    def get_cached_ast(self, file_path: str) -> Optional[object]:
        """获取缓存的AST树（文件未修改则返回）"""
        file_hash = self._get_file_hash(file_path)
        cache_key = os.path.abspath(file_path)
        
        # 缓存不存在/文件已修改 → 返回None
        if cache_key not in self.cache or self.cache[cache_key].file_hash != file_hash:
            return None
        return self.cache[cache_key].ast_tree

    def set_cached_ast(self, file_path: str, ast_tree: object):
        """缓存AST树"""
        cache_key = os.path.abspath(file_path)
        self.cache[cache_key] = ASTCacheItem(
            ast_tree=ast_tree,
            file_hash=self._get_file_hash(file_path)
        )
        self._save_cache()

    def clear_expired_cache(self, hours: int = 24):
        """清理过期缓存（默认24小时）"""
        now = datetime.now()
        expired_keys = []
        for key, item in self.cache.items():
            delta = now - item.create_time
            if delta.total_seconds() > hours * 3600:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.cache[key]
        self._save_cache()
        print(f"🗑️  清理过期缓存: {len(expired_keys)} 项")

# 演示
if __name__ == "__main__":
    import ast
    cache = ASTCacheManager()
    
    # 缓存AST
    test_file = "./test.py"
    if os.path.exists(test_file):
        tree = ast.parse(open(test_file).read())
        cache.set_cached_ast(test_file, tree)
        
        # 获取缓存
        cached_tree = cache.get_cached_ast(test_file)
        print(f"✅ 缓存命中: {cached_tree is not None}")
        
        # 清理过期缓存
        cache.clear_expired_cache()