#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
SARIF 格式报告器

生成符合 SARIF 2.1.0 标准的报告，支持 GitHub Code Scanning 和 VS Code SARIF Viewer。
参考: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
import os
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import asdict

try:
    from ..models import ScanResult, Vulnerability
    from ..rules import list_rules, SecurityRule
except ImportError:
    # 备用导入方式
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from models import ScanResult, Vulnerability
    from rules import list_rules, SecurityRule


class SarifReporter:
    """SARIF 2.1.0 格式报告生成器"""
    
    # SARIF 版本
    SARIF_VERSION = "2.1.0"
    
    # SARIF 模式 URL
    SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
    
    def __init__(self):
        """初始化 SARIF 报告器"""
        self.tool_name = "PySecScanner"
        self.tool_version = "1.0.0"
        self.sarif_schema = self.SCHEMA_URL
        
    def _generate_run_automation_details(self) -> Dict[str, Any]:
        """生成运行自动化详情（用于 CI/CD 集成）"""
        return {
            "id": f"{self.tool_name}/scan/{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "description": {
                "text": f"Security scan by {self.tool_name}"
            },
            "correlationGuid": str(uuid.uuid4())
        }
    
    def _generate_tool_component(self) -> Dict[str, Any]:
        """生成工具组件定义"""
        # 获取所有规则
        rule_classes = list_rules()
        rules = []
        
        for rule_class in rule_classes:
            try:
                rule_instance = rule_class()
                rule_def = self._create_rule_definition(rule_instance)
                rules.append(rule_def)
            except Exception as e:
                # 如果规则实例化失败，创建一个基本定义
                rule_name = rule_class.__name__ if hasattr(rule_class, '__name__') else "UnknownRule"
                rules.append({
                    "id": rule_name,
                    "name": rule_name,
                    "shortDescription": {
                        "text": f"Security rule: {rule_name}"
                    },
                    "fullDescription": {
                        "text": f"Security detection rule"
                    },
                    "defaultConfiguration": {
                        "level": "warning"
                    }
                })
        
        return {
            "name": self.tool_name,
            "version": self.tool_version,
            "semanticVersion": "1.0.0",
            "language": "en-US",
            "informationUri": "https://github.com/FanZDStar/oss-2025",
            "rules": rules,
            "taxa": []  # 可以添加分类法（如CWE, OWASP等）
        }
    
    def _create_rule_definition(self, rule: SecurityRule) -> Dict[str, Any]:
        """为单个规则创建 SARIF 规则定义"""
        rule_id = getattr(rule, 'rule_id', rule.__class__.__name__)
        rule_name = getattr(rule, 'rule_name', rule_id)
        description = getattr(rule, 'description', f"Security rule: {rule_id}")
        severity = getattr(rule, 'severity', 'medium').lower()
        
        # 将严重程度映射到 SARIF 级别
        severity_to_level = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'note'
        }
        level = severity_to_level.get(severity, 'warning')
        
        # 构建规则定义
        rule_def = {
            "id": rule_id,
            "name": rule_name,
            "shortDescription": {
                "text": description[:100] + "..." if len(description) > 100 else description
            },
            "fullDescription": {
                "text": description
            },
            "defaultConfiguration": {
                "level": level
            },
            "properties": {
                "security-severity": severity,
                "precision": "high",
                "tags": ["security", "python"]
            }
        }
        
        # 添加帮助信息（如果可用）
        if hasattr(rule, 'help_uri') and rule.help_uri:
            rule_def["helpUri"] = rule.help_uri
            
        if hasattr(rule, 'help_text') and rule.help_text:
            rule_def["help"] = {
                "text": rule.help_text,
                "markdown": rule.help_text
            }
            
        # 添加 CWE 分类（如果可用）
        if hasattr(rule, 'cwe_id') and rule.cwe_id:
            rule_def["properties"]["cwe"] = rule.cwe_id
            rule_def["properties"]["tags"].append(f"CWE-{rule.cwe_id}")
            
        # 添加 OWASP 分类（如果可用）
        if hasattr(rule, 'owasp_category') and rule.owasp_category:
            rule_def["properties"]["owasp"] = rule.owasp_category
            rule_def["properties"]["tags"].append(f"OWASP-{rule.owasp_category}")
        
        return rule_def
    
    def _create_result(self, vuln: Vulnerability, rule_index: int, 
                      file_uri: str, working_directory: str) -> Dict[str, Any]:
        """为单个漏洞创建 SARIF 结果"""
        # 计算指纹（用于去重）
        fingerprint_input = f"{vuln.file_path}:{vuln.line_number}:{vuln.rule_id}:{vuln.description}"
        fingerprint = hashlib.md5(fingerprint_input.encode()).hexdigest()
        
        # 构建结果对象
        result = {
            "ruleId": vuln.rule_id,
            "ruleIndex": rule_index,
            "message": {
                "text": vuln.description
            },
            "level": self._get_sarif_level(vuln.severity),
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_uri,
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": vuln.line_number,
                        "startColumn": 1,
                        "endLine": vuln.line_number,
                        "endColumn": 100  # 估计的结束列
                    }
                }
            }],
            "partialFingerprints": {
                "primaryLocationLineHash": fingerprint
            },
            "properties": {
                "accuracy": "high",
                "security-severity": vuln.severity.lower()
            }
        }
        
        # 添加代码片段
        if hasattr(vuln, 'code_snippet') and vuln.code_snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": vuln.code_snippet
            }
            
        # 添加修复建议（如果可用）
        if hasattr(vuln, 'suggestion') and vuln.suggestion:
            result["fixes"] = [{
                "description": {
                    "text": vuln.suggestion
                },
                "artifactChanges": [{
                    "artifactLocation": {
                        "uri": file_uri,
                        "uriBaseId": "%SRCROOT%"
                    },
                    "replacements": []
                }]
            }]
            
        return result
    
    def _get_sarif_level(self, severity: str) -> str:
        """将严重程度转换为 SARIF 级别"""
        mapping = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'note'
        }
        return mapping.get(severity.lower(), 'warning')
    
    def _get_rule_index_map(self, rules: List[Dict]) -> Dict[str, int]:
        """创建规则ID到索引的映射"""
        return {rule['id']: i for i, rule in enumerate(rules)}
    
    def generate(self, result: ScanResult, output_file: Optional[str] = None) -> str:
        """
        生成 SARIF 格式报告
        
        Args:
            result: 扫描结果
            output_file: 输出文件路径（可选）
            
        Returns:
            SARIF JSON 字符串
        """
        # 获取工作目录（用于相对路径转换）
        working_dir = os.getcwd()
        
        # 构建 SARIF 数据结构
        tool_component = self._generate_tool_component()
        rule_index_map = self._get_rule_index_map(tool_component['rules'])
        
        # 收集所有结果
        sarif_results = []
        for vuln in result.vulnerabilities:
            try:
                # 将文件路径转换为相对URI
                file_path = Path(vuln.file_path)
                if file_path.is_absolute():
                    try:
                        file_uri = file_path.relative_to(working_dir).as_posix()
                    except ValueError:
                        file_uri = file_path.as_posix()
                else:
                    file_uri = file_path.as_posix()
                
                # 确保URI使用正斜杠
                file_uri = file_uri.replace('\\', '/')
                
                # 获取规则索引
                rule_index = rule_index_map.get(vuln.rule_id, 0)
                
                # 创建结果
                sarif_result = self._create_result(vuln, rule_index, file_uri, working_dir)
                sarif_results.append(sarif_result)
            except Exception as e:
                # 跳过无法处理的漏洞
                print(f"警告: 无法处理漏洞 {vuln.rule_id}: {e}")
                continue
        
        # 构建完整的 SARIF 对象
        sarif_data = {
            "$schema": self.sarif_schema,
            "version": self.SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": tool_component
                },
                "automationDetails": self._generate_run_automation_details(),
                "results": sarif_results,
                "columnKind": "utf16CodeUnits",
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "uri": f"file://{working_dir}/",
                        "description": {
                            "text": "The root directory of the scanned source code"
                        }
                    }
                },
                "properties": {
                    "scanTimestamp": datetime.now().isoformat(),
                    "filesScanned": result.files_scanned,
                    "totalVulnerabilities": result.summary['total'],
                    "scanDuration": result.duration
                }
            }]
        }
        
        # 转换为 JSON
        sarif_json = json.dumps(sarif_data, indent=2, ensure_ascii=False)
        
        # 写入文件（如果指定了输出文件）
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(sarif_json)
            print(f"SARIF 报告已保存到: {output_file}")
            
        return sarif_json


# 便捷函数
def generate_sarif(result: ScanResult, output_file: Optional[str] = None) -> str:
    """生成 SARIF 报告的便捷函数"""
    reporter = SarifReporter()
    return reporter.generate(result, output_file)