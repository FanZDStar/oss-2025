"""
规则验证器模块 - 校验自定义漏洞检测规则的合法性
全新功能：确保用户编写的自定义规则符合规范，避免扫描引擎崩溃
"""

import re
import ast
import json
import os
import sys
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

# 规则校验错误类型
class ValidationErrorType(Enum):
    SYNTAX_ERROR = "语法错误"
    MISSING_FIELD = "缺失必填字段"
    INVALID_VALUE = "值格式非法"
    DUPLICATE_RULE_ID = "规则ID重复"
    INVALID_SEVERITY = "严重程度非法"
    INVALID_CODE = "检测代码逻辑错误"
    FILE_NOT_FOUND = "规则文件不存在"

# 校验结果模型
@dataclass
class ValidationError:
    error_type: ValidationErrorType
    rule_id: str
    message: str
    line: int = 0
    column: int = 0

@dataclass
class ValidationResult:
    is_valid: bool = True
    errors: List[ValidationError] = field(default_factory=list)
    valid_rules: int = 0
    total_rules: int = 0

    def add_error(self, error: ValidationError):
        """添加错误并标记为无效"""
        self.is_valid = False
        self.errors.append(error)

# 核心规则验证器
class RuleValidator:
    """自定义检测规则合法性验证器"""
    
    # 规则必填字段
    REQUIRED_FIELDS = ["rule_id", "rule_name", "severity", "description", "check_function"]
    # 合法的严重程度
    VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"]
    # 规则ID格式正则（如 SQL001、CMD001）
    RULE_ID_PATTERN = re.compile(r"^[A-Z]{3}\d{3}$")

    def __init__(self):
        self.result = ValidationResult()
        self.rule_ids: List[str] = []  # 记录已存在的规则ID，防止重复

    def validate_rule_file(self, file_path: str) -> ValidationResult:
        """验证单个规则文件"""
        # 重置校验结果
        self.result = ValidationResult()
        
        # 检查文件是否存在
        if not os.path.exists(file_path):
            self.result.add_error(ValidationError(
                error_type=ValidationErrorType.FILE_NOT_FOUND,
                rule_id="",
                message=f"规则文件不存在: {file_path}"
            ))
            return self.result

        # 读取文件内容
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            lines = content.split("\n")
            self.result.total_rules = 1  # 单个文件默认1个规则
            
        except Exception as e:
            self.result.add_error(ValidationError(
                error_type=ValidationErrorType.FILE_NOT_FOUND,
                rule_id="",
                message=f"读取规则文件失败: {str(e)}"
            ))
            return self.result

        # 解析规则（支持Python类/JSON两种格式）
        if file_path.endswith(".py"):
            self._validate_python_rule(content, lines, file_path)
        elif file_path.endswith(".json"):
            self._validate_json_rule(content, lines, file_path)
        else:
            self.result.add_error(ValidationError(
                error_type=ValidationErrorType.INVALID_VALUE,
                rule_id="",
                message=f"不支持的规则文件格式: {os.path.splitext(file_path)[1]}"
            ))

        return self.result

    def validate_rules_dir(self, dir_path: str) -> ValidationResult:
        """验证目录下所有规则文件"""
        self.result = ValidationResult()
        self.rule_ids = []

        if not os.path.isdir(dir_path):
            self.result.add_error(ValidationError(
                error_type=ValidationErrorType.FILE_NOT_FOUND,
                rule_id="",
                message=f"规则目录不存在: {dir_path}"
            ))
            return self.result

        # 遍历目录下的规则文件
        for filename in os.listdir(dir_path):
            if filename.endswith((".py", ".json")) and not filename.startswith("_"):
                file_path = os.path.join(dir_path, filename)
                file_result = self.validate_rule_file(file_path)
                
                # 合并结果
                self.result.is_valid &= file_result.is_valid
                self.result.errors.extend(file_result.errors)
                self.result.valid_rules += 1 if file_result.is_valid else 0
                self.result.total_rules += 1

        return self.result

    def _validate_python_rule(self, content: str, lines: List[str], file_path: str):
        """验证Python格式的规则"""
        # 1. 检查语法是否合法
        try:
            ast.parse(content)
        except SyntaxError as e:
            self.result.add_error(ValidationError(
                error_type=ValidationErrorType.SYNTAX_ERROR,
                rule_id="",
                message=f"Python语法错误: {e.msg}",
                line=e.lineno,
                column=e.offset
            ))
            return

        # 2. 提取规则类信息（简单解析）
        rule_id = ""
        severity = ""
        
        # 查找规则ID和严重程度
        for idx, line in enumerate(lines, 1):
            line = line.strip()
            if line.startswith("rule_id = "):
                rule_id = line.split("=", 1)[1].strip().strip("'\"")
            elif line.startswith("severity = "):
                severity = line.split("=", 1)[1].strip().strip("'\"").lower()

        # 3. 验证必填字段
        if not rule_id:
            self.result.add_error(ValidationError(
                error_type=ValidationErrorType.MISSING_FIELD,
                rule_id="",
                message="缺失必填字段: rule_id",
                line=idx if 'rule_id' in locals() else 0
            ))
        else:
            # 验证规则ID格式
            if not self.RULE_ID_PATTERN.match(rule_id):
                self.result.add_error(ValidationError(
                    error_type=ValidationErrorType.INVALID_VALUE,
                    rule_id=rule_id,
                    message=f"规则ID格式非法（应为3字母+3数字，如SQL001）: {rule_id}"
                ))
            
            # 检查规则ID是否重复
            if rule_id in self.rule_ids:
                self.result.add_error(ValidationError(
                    error_type=ValidationErrorType.DUPLICATE_RULE_ID,
                    rule_id=rule_id,
                    message=f"规则ID重复: {rule_id}"
                ))
            else:
                self.rule_ids.append(rule_id)

        # 4. 验证严重程度
        if not severity:
            self.result.add_error(ValidationError(
                error_type=ValidationErrorType.MISSING_FIELD,
                rule_id=rule_id,
                message="缺失必填字段: severity"
            ))
        elif severity not in self.VALID_SEVERITIES:
            self.result.add_error(ValidationError(
                error_type=ValidationErrorType.INVALID_SEVERITY,
                rule_id=rule_id,
                message=f"非法的严重程度: {severity}（合法值：{', '.join(self.VALID_SEVERITIES)}）"
            ))

        # 5. 验证check_function是否存在
        if "def check(" not in content and "def check_function(" not in content:
            self.result.add_error(ValidationError(
                error_type=ValidationErrorType.MISSING_FIELD,
                rule_id=rule_id,
                message="缺失检测函数: check 或 check_function"
            ))

        # 验证通过
        if self.result.is_valid:
            self.result.valid_rules += 1

    def _validate_json_rule(self, content: str, lines: List[str], file_path: str):
        """验证JSON格式的规则"""
        # 1. 解析JSON
        try:
            rule_data = json.loads(content)
        except json.JSONDecodeError as e:
            self.result.add_error(ValidationError(
                error_type=ValidationErrorType.SYNTAX_ERROR,
                rule_id="",
                message=f"JSON解析错误: {e.msg}",
                line=e.lineno,
                column=e.colno
            ))
            return

        # 2. 检查必填字段
        rule_id = rule_data.get("rule_id", "")
        for field_name in self.REQUIRED_FIELDS:
            if field_name not in rule_data:
                self.result.add_error(ValidationError(
                    error_type=ValidationErrorType.MISSING_FIELD,
                    rule_id=rule_id,
                    message=f"缺失必填字段: {field_name}"
                ))

        # 3. 验证规则ID
        if rule_id:
            if not self.RULE_ID_PATTERN.match(rule_id):
                self.result.add_error(ValidationError(
                    error_type=ValidationErrorType.INVALID_VALUE,
                    rule_id=rule_id,
                    message=f"规则ID格式非法: {rule_id}"
                ))
            if rule_id in self.rule_ids:
                self.result.add_error(ValidationError(
                    error_type=ValidationErrorType.DUPLICATE_RULE_ID,
                    rule_id=rule_id,
                    message=f"规则ID重复: {rule_id}"
                ))
            else:
                self.rule_ids.append(rule_id)

        # 4. 验证严重程度
        severity = rule_data.get("severity", "").lower()
        if severity and severity not in self.VALID_SEVERITIES:
            self.result.add_error(ValidationError(
                error_type=ValidationErrorType.INVALID_SEVERITY,
                rule_id=rule_id,
                message=f"非法的严重程度: {severity}"
            ))

        # 验证通过
        if self.result.is_valid:
            self.result.valid_rules += 1

    def print_validation_report(self, result: ValidationResult):
        """打印校验报告"""
        print("\n📋 规则校验报告")
        print("=" * 50)
        print(f"总规则数: {result.total_rules}")
        print(f"有效规则数: {result.valid_rules}")
        print(f"校验结果: {'✅ 通过' if result.is_valid else '❌ 失败'}")
        
        if result.errors:
            print("\n❌ 校验错误列表:")
            for idx, error in enumerate(result.errors, 1):
                print(f"{idx}. [{error.error_type.value}] {error.rule_id or '未知规则'}: {error.message}")
                if error.line > 0:
                    print(f"   位置: 第{error.line}行，第{error.column}列")

# 便捷使用函数
def validate_rules(path: str):
    """便捷校验函数"""
    validator = RuleValidator()
    
    if os.path.isfile(path):
        result = validator.validate_rule_file(path)
    elif os.path.isdir(path):
        result = validator.validate_rules_dir(path)
    else:
        print(f"❌ 路径不存在: {path}")
        return
    
    validator.print_validation_report(result)
    return result

# 命令行入口
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("使用方法: python rule_validator.py <规则文件/目录路径>")
        print("示例1: python rule_validator.py ./custom_rule.py")
        print("示例2: python rule_validator.py ./rules/")
        sys.exit(1)
    
    validate_rules(sys.argv[1])