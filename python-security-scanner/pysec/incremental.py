#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
增量扫描模块

实现基于Git和文件修改时间的增量扫描功能：
1. 基于Git的增量扫描
2. 文件修改时间缓存
3. 智能跳过未修改文件
"""

import os
import json
import hashlib
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Set, Dict, Tuple, Optional, Generator
import subprocess
import sqlite3
from dataclasses import dataclass, asdict


@dataclass
class FileChangeInfo:
    """文件变更信息"""
    file_path: str
    last_modified: float
    hash: str
    last_scanned: float
    scan_result: Optional[dict] = None


class FileHashCache:
    """文件哈希缓存，用于检测文件是否修改"""
    
    def __init__(self, cache_file: str = ".pysec_file_cache.json"):
        """
        初始化文件哈希缓存
        
        Args:
            cache_file: 缓存文件路径
        """
        self.cache_file = cache_file
        self.cache: Dict[str, FileChangeInfo] = {}
        self._load_cache()
    
    def _load_cache(self):
        """从文件加载缓存"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for file_path, file_data in data.items():
                        self.cache[file_path] = FileChangeInfo(
                            file_path=file_data['file_path'],
                            last_modified=file_data['last_modified'],
                            hash=file_data['hash'],
                            last_scanned=file_data['last_scanned'],
                            scan_result=file_data.get('scan_result')
                        )
                print(f" 加载文件缓存: {len(self.cache)} 个文件")
            except Exception as e:
                print(f"  加载缓存失败: {e}")
                self.cache = {}
    
    def _save_cache(self):
        """保存缓存到文件"""
        try:
            cache_data = {}
            for file_path, info in self.cache.items():
                cache_data[file_path] = asdict(info)
            
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"  保存缓存失败: {e}")
    
    def calculate_file_hash(self, file_path: str) -> str:
        """
        计算文件哈希值
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件的MD5哈希值
        """
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            print(f"  计算文件哈希失败 {file_path}: {e}")
            return ""
    
    def has_file_changed(self, file_path: str) -> Tuple[bool, Optional[FileChangeInfo]]:
        """
        检查文件是否发生变化
        
        Args:
            file_path: 文件路径
            
        Returns:
            (是否变化, 缓存信息)
        """
        if not os.path.exists(file_path):
            return True, None
        
        try:
            current_mtime = os.path.getmtime(file_path)
            current_hash = self.calculate_file_hash(file_path)
            
            if file_path in self.cache:
                cached_info = self.cache[file_path]
                # 检查修改时间
                if current_mtime != cached_info.last_modified:
                    return True, cached_info
                # 检查文件内容哈希
                if current_hash and current_hash != cached_info.hash:
                    return True, cached_info
                # 文件未变化
                return False, cached_info
            else:
                # 新文件
                return True, None
        except Exception as e:
            print(f"  检查文件变化失败 {file_path}: {e}")
            return True, None
    
    def update_cache(self, file_path: str, scan_result: dict = None):
        """
        更新文件缓存
        
        Args:
            file_path: 文件路径
            scan_result: 扫描结果
        """
        try:
            if os.path.exists(file_path):
                current_mtime = os.path.getmtime(file_path)
                current_hash = self.calculate_file_hash(file_path)
                
                self.cache[file_path] = FileChangeInfo(
                    file_path=file_path,
                    last_modified=current_mtime,
                    hash=current_hash,
                    last_scanned=time.time(),
                    scan_result=scan_result
                )
                self._save_cache()
        except Exception as e:
            print(f" 更新缓存失败 {file_path}: {e}")
    
    def get_cached_result(self, file_path: str) -> Optional[dict]:
        """
        获取缓存的扫描结果
        
        Args:
            file_path: 文件路径
            
        Returns:
            缓存的扫描结果，如果不存在则返回None
        """
        if file_path in self.cache:
            return self.cache[file_path].scan_result
        return None
    
    def clear_cache(self):
        """清除所有缓存"""
        self.cache = {}
        if os.path.exists(self.cache_file):
            os.remove(self.cache_file)
        print(" 已清除文件缓存")


class GitIncrementalScanner:
    """基于Git的增量扫描器"""
    
    def __init__(self, repo_path: str = "."):
        """
        初始化Git增量扫描器
        
        Args:
            repo_path: Git仓库路径
        """
        self.repo_path = os.path.abspath(repo_path)
        self.hash_cache = FileHashCache()
        
    def is_git_repo(self) -> bool:
        """检查当前目录是否是Git仓库"""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def get_git_modified_files(self, since: str = None) -> List[str]:
        """
        获取自指定时间以来修改的文件
        
        Args:
            since: 时间点（如：HEAD~1, 1.day.ago, 2024-01-01）
            
        Returns:
            修改的文件路径列表
        """
        if not self.is_git_repo():
            print("  当前目录不是Git仓库")
            return []
        
        try:
            cmd = ["git", "diff", "--name-only"]
            if since:
                cmd.extend([since, "HEAD"])
            else:
                cmd.append("HEAD")
            
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                files = [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]
                # 只保留Python文件
                python_files = [f for f in files if f.endswith('.py')]
                return python_files
            else:
                print(f"  Git命令失败: {result.stderr}")
                return []
        except Exception as e:
            print(f"  获取Git修改文件失败: {e}")
            return []
    
    def get_git_untracked_files(self) -> List[str]:
        """
        获取未跟踪的文件
        
        Returns:
            未跟踪的文件路径列表
        """
        if not self.is_git_repo():
            return []
        
        try:
            result = subprocess.run(
                ["git", "ls-files", "--others", "--exclude-standard"],
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                files = [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]
                # 只保留Python文件
                python_files = [f for f in files if f.endswith('.py')]
                return python_files
            else:
                return []
        except Exception:
            return []
    
    def get_modified_since_commit(self, commit_ref: str) -> List[str]:
        """
        获取自指定提交以来修改的文件
        
        Args:
            commit_ref: 提交引用（如：HEAD~5, abc123, main）
            
        Returns:
            修改的文件路径列表
        """
        if not self.is_git_repo():
            return []
        
        try:
            # 检查提交是否存在
            check_cmd = ["git", "rev-parse", "--verify", commit_ref]
            check_result = subprocess.run(
                check_cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            if check_result.returncode != 0:
                print(f"  Git提交不存在: {commit_ref}")
                return []
            
            # 获取修改的文件
            cmd = ["git", "diff", "--name-only", commit_ref, "HEAD"]
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                files = [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]
                python_files = [f for f in files if f.endswith('.py')]
                return python_files
            else:
                return []
        except Exception as e:
            print(f"  获取提交修改文件失败: {e}")
            return []
    
    def get_staged_files(self) -> List[str]:
        """
        获取已暂存的文件
        
        Returns:
            已暂存的文件路径列表
        """
        if not self.is_git_repo():
            return []
        
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "--cached"],
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                files = [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]
                python_files = [f for f in files if f.endswith('.py')]
                return python_files
            else:
                return []
        except Exception:
            return []
    
    def get_all_modified_files(self, since: str = None) -> List[str]:
        """
        获取所有需要扫描的修改文件（包括未跟踪、已暂存、已修改）
        
        Args:
            since: 时间点或提交
            
        Returns:
            需要扫描的文件路径列表
        """
        all_files = set()
        
        # 1. 获取Git修改的文件
        if since and since != "HEAD":
            git_files = self.get_modified_since_commit(since)
        else:
            git_files = self.get_git_modified_files(since)
        
        all_files.update(git_files)
        
        # 2. 获取未跟踪的文件
        untracked_files = self.get_git_untracked_files()
        all_files.update(untracked_files)
        
        # 3. 获取已暂存的文件
        staged_files = self.get_staged_files()
        all_files.update(staged_files)
        
        # 转换为绝对路径
        abs_files = []
        for file in all_files:
            abs_path = os.path.join(self.repo_path, file)
            if os.path.exists(abs_path):
                abs_files.append(abs_path)
        
        return sorted(abs_files)
    
    def scan_with_cache(self, files: List[str], scanner_func) -> Dict:
        """
        使用缓存进行增量扫描
        
        Args:
            files: 要扫描的文件列表
            scanner_func: 扫描函数，接受文件路径返回扫描结果
            
        Returns:
            扫描结果
        """
        results = {
            'total_files': len(files),
            'scanned_files': 0,
            'cached_files': 0,
            'modified_files': 0,
            'results': [],
            'cache_hits': []
        }
        
        for file_path in files:
            # 检查文件是否变化
            has_changed, cached_info = self.hash_cache.has_file_changed(file_path)
            
            if not has_changed and cached_info and cached_info.scan_result:
                # 使用缓存结果
                results['cached_files'] += 1
                results['cache_hits'].append({
                    'file': file_path,
                    'result': cached_info.scan_result
                })
                print(f"   [缓存] {os.path.basename(file_path)}")
            else:
                # 执行扫描
                results['modified_files'] += 1
                print(f"   [扫描] {os.path.basename(file_path)}")
                
                try:
                    scan_result = scanner_func(file_path)
                    # 更新缓存
                    self.hash_cache.update_cache(file_path, scan_result)
                    results['results'].append({
                        'file': file_path,
                        'result': scan_result
                    })
                except Exception as e:
                    print(f"   扫描失败 {file_path}: {e}")
            
            results['scanned_files'] += 1
        
        return results


class TimeBasedIncrementalScanner:
    """基于时间的增量扫描器"""
    
    def __init__(self, cache_dir: str = ".pysec_time_cache"):
        """
        初始化时间增量扫描器
        
        Args:
            cache_dir: 缓存目录
        """
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        self.cache_file = os.path.join(cache_dir, "file_times.json")
        self.file_times = self._load_file_times()
    
    def _load_file_times(self) -> Dict[str, float]:
        """从文件加载修改时间"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}
    
    def _save_file_times(self):
        """保存修改时间到文件"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.file_times, f)
        except Exception as e:
            print(f"  保存文件时间失败: {e}")
    
    def get_files_modified_since(self, directory: str, 
                                 since_seconds: int = 3600) -> List[str]:
        """
        获取指定时间以来修改的文件
        
        Args:
            directory: 目录路径
            since_seconds: 多少秒之前
            
        Returns:
            修改的文件路径列表
        """
        now = time.time()
        time_threshold = now - since_seconds
        modified_files = []
        
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    try:
                        mtime = os.path.getmtime(file_path)
                        
                        # 检查是否超过时间阈值
                        if mtime > time_threshold:
                            modified_files.append(file_path)
                        
                        # 更新缓存
                        self.file_times[file_path] = mtime
                    except OSError:
                        continue
        
        # 保存更新时间
        self._save_file_times()
        
        return modified_files
    
    def get_files_modified_since_timestamp(self, directory: str, 
                                          since_timestamp: float) -> List[str]:
        """
        获取自指定时间戳以来修改的文件
        
        Args:
            directory: 目录路径
            since_timestamp: 时间戳
            
        Returns:
            修改的文件路径列表
        """
        modified_files = []
        
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    try:
                        mtime = os.path.getmtime(file_path)
                        
                        if mtime > since_timestamp:
                            modified_files.append(file_path)
                        
                        # 更新缓存
                        self.file_times[file_path] = mtime
                    except OSError:
                        continue
        
        # 保存更新时间
        self._save_file_times()
        
        return modified_files


def incremental_scan(directory: str = ".", 
                    since: str = None,
                    use_git: bool = True,
                    scanner_func = None) -> Dict:
    """
    增量扫描的便捷函数
    
    Args:
        directory: 扫描目录
        since: 时间点（如：1.day.ago, HEAD~5, 2024-01-01）
        use_git: 是否使用Git检测
        scanner_func: 扫描函数
        
    Returns:
        扫描结果
    """
    scanner = GitIncrementalScanner(directory)
    files_to_scan = []
    
    if use_git and scanner.is_git_repo():
        print(" 使用Git增量扫描模式")
        files_to_scan = scanner.get_all_modified_files(since)
    else:
        print(" 使用时间增量扫描模式")
        time_scanner = TimeBasedIncrementalScanner()
        if since and since.endswith('.day.ago'):
            try:
                days = int(since.split('.')[0])
                since_seconds = days * 24 * 3600
                files_to_scan = time_scanner.get_files_modified_since(
                    directory, since_seconds
                )
            except ValueError:
                files_to_scan = []
        else:
            # 默认扫描1小时内修改的文件
            files_to_scan = time_scanner.get_files_modified_since(directory, 3600)
    
    if not files_to_scan:
        print(" 没有发现需要扫描的修改文件")
        return {
            'total_files': 0,
            'scanned_files': 0,
            'modified_files': 0,
            'files': []
        }
    
    print(f" 发现 {len(files_to_scan)} 个需要扫描的文件")
    return scanner.scan_with_cache(files_to_scan, scanner_func)