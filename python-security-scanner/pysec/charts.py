#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
图表数据生成器模块

为HTML报告生成各种图表数据：
1. 漏洞类型分布饼图
2. 严重程度分布柱状图
3. 文件漏洞热力图
4. 趋势对比图
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter, defaultdict
from pathlib import Path
import hashlib
import time


class ChartDataGenerator:
    """图表数据生成器"""
    
    def __init__(self, scan_result: Any = None):
        """
        初始化图表数据生成器
        
        Args:
            scan_result: 扫描结果对象
        """
        self.scan_result = scan_result
        self.charts_data = {}
        
    def generate_vulnerability_type_pie_chart(self) -> Dict[str, Any]:
        """
        生成漏洞类型分布饼图数据
        
        Returns:
            饼图数据字典
        """
        if not self.scan_result or not hasattr(self.scan_result, 'vulnerabilities'):
            return {
                "enabled": False,
                "type": "pie",
                "title": "漏洞类型分布",
                "data": []
            }
        
        # 统计漏洞类型
        rule_counter = Counter()
        for vuln in self.scan_result.vulnerabilities:
            rule_counter[vuln.rule_id] += 1
        
        # 生成饼图数据
        pie_data = []
        colors = [
            "#FF6384", "#36A2EB", "#FFCE56", "#4BC0C0", "#9966FF",
            "#FF9F40", "#FF6384", "#C9CBCF", "#4BC0C0", "#FF6384"
        ]
        
        for i, (rule_id, count) in enumerate(rule_counter.most_common()):
            color_index = i % len(colors)
            pie_data.append({
                "label": f"{rule_id}",
                "value": count,
                "color": colors[color_index],
                "percentage": round(count / len(self.scan_result.vulnerabilities) * 100, 1)
            })
        
        return {
            "enabled": True,
            "type": "pie",
            "title": "漏洞类型分布",
            "subtitle": f"共 {len(self.scan_result.vulnerabilities)} 个漏洞",
            "data": pie_data,
            "total": len(self.scan_result.vulnerabilities)
        }
    
    def generate_severity_bar_chart(self) -> Dict[str, Any]:
        """
        生成严重程度分布柱状图数据
        
        Returns:
            柱状图数据字典
        """
        if not self.scan_result or not hasattr(self.scan_result, 'vulnerabilities'):
            return {
                "enabled": False,
                "type": "bar",
                "title": "严重程度分布",
                "data": []
            }
        
        # 统计严重程度
        severity_order = ["critical", "high", "medium", "low"]
        severity_data = {level: 0 for level in severity_order}
        
        for vuln in self.scan_result.vulnerabilities:
            severity = getattr(vuln, 'severity', 'medium').lower()
            if severity in severity_data:
                severity_data[severity] += 1
        
        # 生成柱状图数据
        bar_data = []
        severity_colors = {
            "critical": "#DC2626",  # 红色
            "high": "#F97316",      # 橙色
            "medium": "#F59E0B",    # 黄色
            "low": "#10B981"        # 绿色
        }
        
        for severity in severity_order:
            count = severity_data[severity]
            bar_data.append({
                "severity": severity.capitalize(),
                "count": count,
                "color": severity_colors.get(severity, "#6B7280")
            })
        
        return {
            "enabled": True,
            "type": "bar",
            "title": "严重程度分布",
            "subtitle": f"按严重程度分类",
            "data": bar_data,
            "severity_order": severity_order
        }
    
    def generate_file_heatmap_data(self, top_n: int = 20) -> Dict[str, Any]:
        """
        生成文件漏洞热力图数据
        
        Args:
            top_n: 显示前N个文件
            
        Returns:
            热力图数据字典
        """
        if not self.scan_result or not hasattr(self.scan_result, 'vulnerabilities'):
            return {
                "enabled": False,
                "type": "heatmap",
                "title": "文件漏洞热力图",
                "data": []
            }
        
        # 按文件统计漏洞
        file_vuln_count = Counter()
        for vuln in self.scan_result.vulnerabilities:
            if hasattr(vuln, 'file_path'):
                file_vuln_count[vuln.file_path] += 1
        
        # 生成热力图数据
        heatmap_data = []
        
        # 对文件进行排序，取前N个
        sorted_files = file_vuln_count.most_common(top_n)
        
        # 计算颜色强度范围
        if sorted_files:
            max_count = sorted_files[0][1]
            min_count = sorted_files[-1][1] if len(sorted_files) > 1 else 0
            
            for file_path, count in sorted_files:
                # 计算颜色强度 (0-100)
                if max_count > min_count:
                    intensity = int(((count - min_count) / (max_count - min_count)) * 100)
                else:
                    intensity = 100 if count > 0 else 0
                
                # 根据强度生成颜色
                if intensity >= 80:
                    color = "#DC2626"  # 深红
                elif intensity >= 60:
                    color = "#F97316"  # 橙色
                elif intensity >= 40:
                    color = "#F59E0B"  # 黄色
                elif intensity >= 20:
                    color = "#10B981"  # 绿色
                else:
                    color = "#6B7280"  # 灰色
                
                # 获取文件名
                file_name = os.path.basename(file_path)
                
                heatmap_data.append({
                    "file_path": file_path,
                    "file_name": file_name,
                    "count": count,
                    "intensity": intensity,
                    "color": color
                })
        
        return {
            "enabled": True,
            "type": "heatmap",
            "title": "文件漏洞热力图",
            "subtitle": f"显示漏洞最多的 {len(heatmap_data)} 个文件",
            "data": heatmap_data,
            "max_count": sorted_files[0][1] if sorted_files else 0
        }
    
    def generate_scan_summary_stats(self) -> Dict[str, Any]:
        """
        生成扫描摘要统计
        
        Returns:
            统计信息字典
        """
        if not self.scan_result:
            return {}
        
        stats = {
            "total_vulnerabilities": 0,
            "files_scanned": 0,
            "scan_duration": 0,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity_stats": {}
        }
        
        if hasattr(self.scan_result, 'vulnerabilities'):
            stats["total_vulnerabilities"] = len(self.scan_result.vulnerabilities)
        
        if hasattr(self.scan_result, 'files_scanned'):
            stats["files_scanned"] = self.scan_result.files_scanned
        
        if hasattr(self.scan_result, 'duration'):
            stats["scan_duration"] = round(self.scan_result.duration, 2)
        
        if hasattr(self.scan_result, 'summary'):
            stats.update(self.scan_result.summary)
        
        return stats
    
    def generate_all_charts(self) -> Dict[str, Any]:
        """
        生成所有图表数据
        
        Returns:
            包含所有图表数据的字典
        """
        return {
            "pie_chart": self.generate_vulnerability_type_pie_chart(),
            "bar_chart": self.generate_severity_bar_chart(),
            "heatmap": self.generate_file_heatmap_data(),
            "stats": self.generate_scan_summary_stats(),
            "timestamp": datetime.now().isoformat()
        }


class TrendAnalyzer:
    """趋势分析器，用于生成趋势对比图"""
    
    def __init__(self, history_dir: str = ".pysec_history"):
        """
        初始化趋势分析器
        
        Args:
            history_dir: 历史数据存储目录
        """
        self.history_dir = history_dir
        os.makedirs(history_dir, exist_ok=True)
    
    def save_scan_result(self, scan_result: Any, name: str = None) -> str:
        """
        保存扫描结果到历史记录
        
        Args:
            scan_result: 扫描结果
            name: 保存名称（可选）
            
        Returns:
            保存的文件路径
        """
        if not name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            name = f"scan_{timestamp}"
        
        # 创建数据字典
        data = {
            "name": name,
            "timestamp": datetime.now().isoformat(),
            "stats": {
                "total_vulnerabilities": len(scan_result.vulnerabilities) if hasattr(scan_result, 'vulnerabilities') else 0,
                "files_scanned": scan_result.files_scanned if hasattr(scan_result, 'files_scanned') else 0,
                "duration": scan_result.duration if hasattr(scan_result, 'duration') else 0
            }
        }
        
        # 添加漏洞统计
        if hasattr(scan_result, 'vulnerabilities'):
            # 按规则统计
            rule_counter = Counter()
            for vuln in scan_result.vulnerabilities:
                rule_counter[vuln.rule_id] += 1
            data["rule_stats"] = dict(rule_counter)
            
            # 按严重程度统计
            severity_counter = Counter()
            for vuln in scan_result.vulnerabilities:
                severity_counter[getattr(vuln, 'severity', 'medium')] += 1
            data["severity_stats"] = dict(severity_counter)
        
        # 保存到文件
        filename = os.path.join(self.history_dir, f"{name}.json")
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return filename
    
    def get_history_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        获取历史扫描记录
        
        Args:
            limit: 返回的记录数量限制
            
        Returns:
            历史扫描记录列表
        """
        if not os.path.exists(self.history_dir):
            return []
        
        scans = []
        for filename in os.listdir(self.history_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.history_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    scans.append(data)
                except Exception:
                    continue
        
        # 按时间戳排序，最新的在前面
        scans.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return scans[:limit]
    
    def generate_trend_chart_data(self, scans: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        生成趋势对比图数据
        
        Args:
            scans: 扫描记录列表，如果为None则从历史目录加载
            
        Returns:
            趋势图数据字典
        """
        if scans is None:
            scans = self.get_history_scans(limit=5)
        
        if not scans:
            return {
                "enabled": False,
                "type": "line",
                "title": "扫描趋势对比",
                "message": "暂无历史扫描数据"
            }
        
        # 准备数据
        labels = []
        vulnerability_data = []
        file_data = []
        
        for scan in scans:
            # 使用扫描名称或时间戳作为标签
            name = scan.get('name', '')
            if not name:
                timestamp = scan.get('timestamp', '')
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        name = dt.strftime("%m-%d %H:%M")
                    except Exception:
                        name = timestamp[:16]
                else:
                    name = "未知"
            
            labels.append(name)
            
            # 漏洞总数
            stats = scan.get('stats', {})
            vulnerability_data.append(stats.get('total_vulnerabilities', 0))
            file_data.append(stats.get('files_scanned', 0))
        
        return {
            "enabled": True,
            "type": "line",
            "title": "扫描趋势对比",
            "subtitle": f"最近 {len(scans)} 次扫描",
            "labels": labels,
            "datasets": [
                {
                    "label": "漏洞数量",
                    "data": vulnerability_data,
                    "color": "#EF4444",  # 红色
                    "borderColor": "#EF4444"
                },
                {
                    "label": "扫描文件数",
                    "data": file_data,
                    "color": "#3B82F6",  # 蓝色
                    "borderColor": "#3B82F6"
                }
            ]
        }
    
    def generate_severity_trend_chart(self) -> Dict[str, Any]:
        """
        生成严重程度趋势图
        
        Returns:
            严重程度趋势图数据
        """
        scans = self.get_history_scans(limit=5)
        
        if not scans:
            return {
                "enabled": False,
                "type": "line",
                "title": "严重程度趋势",
                "message": "暂无历史扫描数据"
            }
        
        # 准备数据
        labels = []
        critical_data = []
        high_data = []
        medium_data = []
        low_data = []
        
        for scan in scans:
            # 标签
            name = scan.get('name', '')
            if not name:
                timestamp = scan.get('timestamp', '')
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        name = dt.strftime("%m-%d")
                    except Exception:
                        name = timestamp[:10]
                else:
                    name = "未知"
            
            labels.append(name)
            
            # 严重程度数据
            severity_stats = scan.get('severity_stats', {})
            critical_data.append(severity_stats.get('critical', 0))
            high_data.append(severity_stats.get('high', 0))
            medium_data.append(severity_stats.get('medium', 0))
            low_data.append(severity_stats.get('low', 0))
        
        return {
            "enabled": True,
            "type": "line",
            "title": "严重程度趋势",
            "subtitle": f"最近 {len(scans)} 次扫描",
            "labels": labels,
            "datasets": [
                {
                    "label": "严重",
                    "data": critical_data,
                    "color": "#DC2626",  # 红色
                    "borderColor": "#DC2626"
                },
                {
                    "label": "高危",
                    "data": high_data,
                    "color": "#F97316",  # 橙色
                    "borderColor": "#F97316"
                },
                {
                    "label": "中危",
                    "data": medium_data,
                    "color": "#F59E0B",  # 黄色
                    "borderColor": "#F59E0B"
                },
                {
                    "label": "低危",
                    "data": low_data,
                    "color": "#10B981",  # 绿色
                    "borderColor": "#10B981"
                }
            ]
        }
    
    def clear_history(self) -> bool:
        """
        清除历史数据
        
        Returns:
            是否成功清除
        """
        try:
            if os.path.exists(self.history_dir):
                for filename in os.listdir(self.history_dir):
                    filepath = os.path.join(self.history_dir, filename)
                    if os.path.isfile(filepath):
                        os.remove(filepath)
                return True
        except Exception:
            pass
        return False


# 便捷函数
def generate_chart_data(scan_result: Any) -> Dict[str, Any]:
    """生成图表数据的便捷函数"""
    generator = ChartDataGenerator(scan_result)
    return generator.generate_all_charts()


def save_scan_history(scan_result: Any, name: str = None) -> str:
    """保存扫描结果到历史记录的便捷函数"""
    analyzer = TrendAnalyzer()
    return analyzer.save_scan_result(scan_result, name)


def get_trend_chart_data() -> Dict[str, Any]:
    """获取趋势图数据的便捷函数"""
    analyzer = TrendAnalyzer()
    return analyzer.generate_trend_chart_data()