# Rule Development Guide

[English](#english) | [中文](#中文)

---

## English

### Table of Contents

- [Overview](#overview)
- [Rule Structure](#rule-structure)
- [Step-by-Step Tutorial](#step-by-step-tutorial)
- [Best Practices](#best-practices)
- [Testing Rules](#testing-rules)
- [Advanced Techniques](#advanced-techniques)
- [Common Patterns](#common-patterns)
- [Examples](#examples)

---

### Overview

PySecScanner uses a plugin-based rule system that makes it easy to add new security checks. Each rule is a Python class that:

1. Inherits from `BaseRule`
2. Registers itself using the `@register_rule` decorator
3. Implements pattern detection logic in the `check()` method
4. Returns a list of `Vulnerability` objects

**Rule Lifecycle:**
```
1. Rule class is imported
2. @register_rule decorator adds it to RULE_REGISTRY
3. Scanner loads all registered rules
4. For each file:
   - Parse Python code to AST
   - Run each rule's check() method
   - Collect vulnerabilities
5. Generate report
```

---

### Rule Structure

#### Minimal Rule Template

```python
import ast
from typing import List
from pysec.rules.base import BaseRule, register_rule
from pysec.models import Vulnerability


@register_rule
class MyCustomRule(BaseRule):
    """
    Detects custom security pattern
    """
    
    # Required Class Attributes
    rule_id = "CUS001"              # Unique ID (3-4 letters + 3 digits)
    rule_name = "Custom Rule Name"  # Human-readable name
    severity = "medium"             # critical, high, medium, low
    description = "Detailed description of what this rule checks"
    
    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        """
        Performs vulnerability detection
        
        Args:
            ast_tree: Parsed Abstract Syntax Tree
            file_path: Path to file being scanned
            source_code: Original source code
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        # Your detection logic here
        for node in ast.walk(ast_tree):
            if self._is_vulnerable(node):
                vuln = self._create_vulnerability(
                    file_path=file_path,
                    line_number=node.lineno,
                    code_snippet=self._get_code_snippet(source_code, node.lineno),
                    suggestion="How to fix this issue"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_vulnerable(self, node: ast.AST) -> bool:
        """
        Helper method to check if a node is vulnerable
        """
        # Detection logic
        return False
```

#### Required Attributes

| Attribute | Type | Format | Description | Example |
|-----------|------|--------|-------------|---------|
| `rule_id` | `str` | `[A-Z]{3,4}\d{3}` | Unique identifier | `"SQL001"`, `"CUSTOM001"` |
| `rule_name` | `str` | Free text | Human-readable name | `"SQL Injection Detection"` |
| `severity` | `str` | `critical\|high\|medium\|low` | Default severity level | `"high"` |
| `description` | `str` | Free text | Detailed description | `"Detects SQL injection..."` |

---

### Step-by-Step Tutorial

#### Step 1: Create Rule File

Create a new file in `pysec/rules/`:

```bash
# For a custom rule
touch pysec/rules/my_custom_rule.py
```

#### Step 2: Import Required Modules

```python
"""
My Custom Security Rule
Detects [describe the security issue]
"""

import ast
from typing import List

from .base import BaseRule, register_rule
from ..models import Vulnerability
```

#### Step 3: Define Rule Class

```python
@register_rule
class MyCustomRule(BaseRule):
    rule_id = "CUS001"
    rule_name = "My Custom Security Check"
    severity = "medium"
    description = "Detects insecure pattern XYZ"
    
    def check(self, ast_tree, file_path, source_code):
        vulnerabilities = []
        # Will implement detection logic
        return vulnerabilities
```

#### Step 4: Implement Detection Logic

Use AST to analyze code patterns:

```python
def check(self, ast_tree, file_path, source_code):
    vulnerabilities = []
    
    # Walk through all nodes in the AST
    for node in ast.walk(ast_tree):
        # Check for function calls
        if isinstance(node, ast.Call):
            # Get function name
            func_name = self._get_function_name(node)
            
            # Check if it's a dangerous function
            if func_name == "dangerous_function":
                vuln = self._create_vulnerability(
                    file_path=file_path,
                    line_number=node.lineno,
                    code_snippet=self._get_code_snippet(source_code, node.lineno),
                    suggestion="Use safe_function() instead"
                )
                vulnerabilities.append(vuln)
    
    return vulnerabilities

def _get_function_name(self, node: ast.Call) -> str:
    """Extract function name from Call node"""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""
```

#### Step 5: Add Helper Methods

```python
def _is_string_concat(self, node: ast.AST) -> bool:
    """Check if node uses string concatenation"""
    return isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)

def _contains_user_input(self, node: ast.AST) -> bool:
    """Check if expression contains user input variables"""
    user_input_vars = {"request", "input", "argv", "params"}
    
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in user_input_vars:
            return True
    return False
```

#### Step 6: Import in `__init__.py`

Add your rule to `pysec/rules/__init__.py`:

```python
# ... existing imports ...
from . import my_custom_rule  # Add this line
```

---

### Best Practices

#### 1. Use Specific Node Types

Instead of checking all nodes:
```python
# ❌ Slow - checks every node
for node in ast.walk(ast_tree):
    if isinstance(node, ast.Call):
        # ...
```

Better approach:
```python
# ✅ Fast - only Walk calls
for node in ast.walk(ast_tree):
    if isinstance(node, ast.Call):
        self._check_call(node, file_path, source_code, vulnerabilities)
```

#### 2. Provide Clear Suggestions

```python
# ❌ Vague
suggestion="Don't use this function"

# ✅ Specific and actionable
suggestion="""Replace with parameterized query:
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
Or use ORM methods:
    User.objects.get(id=user_id)"""
```

#### 3. Handle Edge Cases

```python
def _get_function_name(self, node: ast.Call) -> str:
    """Safely extract function name"""
    try:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # module.function or object.method
            return node.func.attr
        elif isinstance(node.func, ast.Subscript):
            # dict["key"]() - callable dict value
            return ""
    except AttributeError:
        return ""
    return ""
```

#### 4. Use Constants for Configuration

```python
@register_rule
class InsecureHashRule(BaseRule):
    rule_id = "HSH001"
    rule_name = "Insecure Hash Algorithm"
    severity = "medium"
    description = "Detects use of weak hash algorithms"
    
    # Configuration
    WEAK_ALGORITHMS = {"md5", "sha1", "md4", "sha"}
    SECURE_ALTERNATIVES = {"sha256", "sha512", "sha3_256", "blake2b"}
    
    def check(self, ast_tree, file_path, source_code):
        # Use self.WEAK_ALGORITHMS in detection logic
        pass
```

#### 5. Consider Context

Check if the code is in a test file or safe context:

```python
def check(self, ast_tree, file_path, source_code):
    # Skip test files
    if self._is_test_file(file_path):
        return []
    
    # Your detection logic
    vulnerabilities = []
    # ...
    return vulnerabilities

def _is_test_file(self, file_path: str) -> bool:
    """Check if file is a test file"""
    path_lower = file_path.lower()
    return (
        "test_" in path_lower or
        "_test." in path_lower or
        "/tests/" in path_lower
    )
```

---

### Testing Rules

####  Create Test Cases

Create test file in `tests/test_my_rule.py`:

```python
import pytest
from pysec import SecurityScanner


def test_detect_my_vulnerability():
    """Test that rule detects the vulnerability """
    code = """
import my_module

# This should be detected
result = dangerous_function(user_input)
"""
    
    scanner = SecurityScanner()
    result = scanner.scan_code(code, "test.py")
    
    # Should find 1 vulnerability
    assert len(result.vulnerabilities) == 1
    
    vuln = result.vulnerabilities[0]
    assert vuln.rule_id == "CUS001"
    assert vuln.severity == "medium"
    assert vuln.line_number == 5  # Line with dangerous_function


def test_no_false_positive():
    """Test that rule doesn't flag safe code"""
    code = """
import my_module

# This should NOT be detected
result = safe_function(user_input)
"""
    
    scanner = SecurityScanner()
    result = scanner.scan_code(code, "test.py")
    
    # Should find 0 vulnerabilities
    assert len(result.vulnerabilities) == 0
```

#### Create Sample Files

Create vulnerable example in `tests/samples/my_rule_vulnerable.py`:

```python
"""
Sample file with vulnerabilities for testing CUS001 rule
"""

import my_module

# CUS001: Should be detected
result1 = dangerous_function(user_input)

# CUS001: Should be detected with different syntax
result2 = my_module.dangerous_function(request.GET["param"])

# Safe code - should NOT be detected
result3 = safe_function(user_input)
```

#### Run Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test
pytest tests/test_my_rule.py -v

# Run with coverage
pytest tests/ --cov=pysec.rules
```

---

### Advanced Techniques

#### 1. Multi-Pattern Detection

Combine multiple AST patterns:

```python
def check(self, ast_tree, file_path, source_code):
    vulnerabilities = []
    
    # Pattern 1: Function calls
    vulnerabilities.extend(self._check_function_calls(ast_tree, file_path, source_code))
    
    # Pattern 2: String operations
    vulnerabilities.extend(self._check_string_operations(ast_tree, file_path, source_code))
    
    # Pattern 3: Attribute access
    vulnerabilities.extend(self._check_attribute_access(ast_tree, file_path, source_code))
    
    return vulnerabilities
```

#### 2. Context-Aware Detection

Track context while walking AST:

```python
def check(self, ast_tree, file_path, source_code):
    vulnerabilities = []
    
    # Find all function definitions
    for node in ast.walk(ast_tree):
        if isinstance(node, ast.FunctionDef):
            # Analyze function context
            context = {
                "function_name": node.name,
                "is_async": isinstance(node, ast.AsyncFunctionDef),
                "decorators": [d.id for d in node.decorator_list if isinstance(d, ast.Name)]
            }
            
            # Check function body with context
            for inner_node in ast.walk(node):
                if self._is_vulnerable_in_context(inner_node, context):
                    vuln = self._create_vulnerability(...)
                    vulnerabilities.append(vuln)
    
    return vulnerabilities
```

#### 3. Module Import Tracking

Track imported modules and their usage:

```python
def check(self, ast_tree, file_path, source_code):
    # Track imports
    imports = self._get_imports(ast_tree)
    
    vulnerabilities = []
    
    for node in ast.walk(ast_tree):
        if isinstance(node, ast.Call):
            func_name = self._get_full_function_name(node, imports)
            
            # Check against known vulnerable functions
            if func_name in self.VULNERABLE_FUNCTIONS:
                vuln = self._create_vulnerability(...)
                vulnerabilities.append(vuln)
    
    return vulnerabilities

def _get_imports(self, ast_tree: ast.AST) -> dict:
    """Build map of imported names to modules"""
    imports = {}
    
    for node in ast.walk(ast_tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name
                imports[name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                name = alias.asname or alias.name
                imports[name] = f"{module}.{alias.name}"
    
    return imports
```

#### 4. Data Flow Analysis (Simple)

Track variable assignments:

```python
def check(self, ast_tree, file_path, source_code):
    vulnerabilities = []
    
    # Track variable sources
    var_sources = {}  # {var_name: "user_input" | "safe" | "unknown"}
    
    for node in ast.walk(ast_tree):
        # Track assignments
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_sources[target.id] = self._classify_value(node.value)
        
        # Check usage in dangerous contexts
        elif isinstance(node, ast.Call):
            if self._is_dangerous_function(node):
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        if var_sources.get(arg.id) == "user_input":
                            vuln = self._create_vulnerability(...)
                            vulnerabilities.append(vuln)
    
    return vulnerabilities
```

---

### Common Patterns

#### Detecting Function Calls

```python
def _is_dangerous_call(self, node: ast.AST) -> bool:
    """Check if node is a call to dangerous function"""
    if not isinstance(node, ast.Call):
        return False
    
    # Direct call: dangerous_func()
    if isinstance(node.func, ast.Name):
        return node.func.id in self.DANGEROUS_FUNCTIONS
    
    # Method call: obj.dangerous_method()
    if isinstance(node.func, ast.Attribute):
        return node.func.attr in self.DANGEROUS_METHODS
    
    # Module call: module.dangerous()
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        module_name = node.func.value.id
        func_name = node.func.attr
        full_name = f"{module_name}.{func_name}"
        return full_name in self.DANGEROUS_QUALIFIED_NAMES
    
    return False
```

#### Detecting String Concatenation

```python
def _uses_string_concat(self, node: ast.AST) -> bool:
    """Check if node uses + operator for strings"""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        # Check if either operand is a string
        return self._is_string_expr(node.left) or self._is_string_expr(node.right)
    return False

def _is_string_expr(self, node: ast.AST) -> bool:
    """Check if expression is or returns a string"""
    if isinstance(node, ast.Str):  # String literal
        return True
    if isinstance(node, ast.JoinedStr):  # f-string
        return True
    # Add more checks as needed
    return False
```

#### Detecting Format Strings

```python
def _is_format_string(self, node: ast.AST) -> bool:
    """Check if node is .format() or % formatting"""
    # str.format()
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
    
    # % formatting
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        if self._is_string_expr(node.left):
            return True
    
    # f-strings
    if isinstance(node, ast.JoinedStr):
        return True
    
    return False
```

#### Detecting Tainted Variables

```python
def _is_user_input(self, node: ast.AST) -> bool:
    """Check if node represents user input"""
    USER_INPUT_PATTERNS = {
        # Variable names
        "request", "input", "user_input", "argv", "params",
        # Function/method calls
        "input()", "sys.argv", "request.GET", "request.POST",
        "request.args", "request.form", "request.json"
    }
    
    # Check variable names
    if isinstance(node, ast.Name):
        return node.id in USER_INPUT_PATTERNS
    
    # Check attribute access
    if isinstance(node, ast.Attribute):
        # request.GET, request.POST, etc.
        if isinstance(node.value, ast.Name):
            if node.value.id == "request":
                return node.attr in ("GET", "POST", "args", "form", "json", "data")
    
    # Check function calls
    if isinstance(node, ast.Call):
        func_name = self._get_function_name(node)
        return func_name == "input"
    
    return False
```

---

### Examples

#### Example 1: Detect Print Statements

```python
@register_rule
class PrintStatementRule(BaseRule):
    """Detects print() statements (potential information leak)"""
    
    rule_id = "PRINT001"
    rule_name = "Print Statement Detected"
    severity = "low"
    description = "Print statements may leak sensitive information to logs"
    
    def check(self, ast_tree, file_path, source_code):
        vulnerabilities = []
        
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                # Check if it's print()
                if isinstance(node.func, ast.Name) and node.func.id == "print":
                    vuln = self._create_vulnerability(
                        file_path=file_path,
                        line_number=node.lineno,
                        code_snippet=self._get_code_snippet(source_code, node.lineno),
                        suggestion="Use logging module instead: logger.info(...)"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
```

#### Example 2: Detect Hardcoded IPs

```python
import re

@register_rule
class HardcodedIPRule(BaseRule):
    """Detects hardcoded IP addresses"""
    
    rule_id = "IP001"
    rule_name = "Hardcoded IP Address"
    severity = "medium"
    description = "Hardcoded IP addresses reduce portability"
    
    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    def check(self, ast_tree, file_path, source_code):
        vulnerabilities = []
        
        for node in ast.walk(ast_tree):
            # Check string literals
            if isinstance(node, ast.Str):
                if self.IP_PATTERN.search(node.s):
                    # Ignore localhost
                    if node.s not in ("127.0.0.1", "0.0.0.0", "localhost"):
                        vuln = self._create_vulnerability(
                            file_path=file_path,
                            line_number=node.lineno,
                            code_snippet=self._get_code_snippet(source_code, node.lineno),
                            suggestion="Use environment variable or configuration file"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
```

#### Example 3: Detect Assert in Production

```python
@register_rule
class AssertInProdRule(BaseRule):
    """Detects assert statements (disabled with -O flag)"""
    
    rule_id = "ASSERT001"
    rule_name = "Assert Statement in Production Code"
    severity = "medium"
    description = "Assert statements are removed when Python runs with -O flag"
    
    def check(self, ast_tree, file_path, source_code):
        # Skip test files
        if self._is_test_file(file_path):
            return []
        
        vulnerabilities = []
        
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Assert):
                vuln = self._create_vulnerability(
                    file_path=file_path,
                    line_number=node.lineno,
                    code_snippet=self._get_code_snippet(source_code, node.lineno),
                    suggestion="Use proper error handling with if/raise instead"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_test_file(self, file_path: str) -> bool:
        """Check if file is a test file"""
        path_lower = file_path.lower()
        return ("test_" in path_lower or
                "_test." in path_lower or
                "/tests/" in path_lower)
```

---

## 中文

### 目录

- [概述](#概述)
- [规则结构](#规则结构)
- [分步教程](#分步教程)
- [最佳实践](#最佳实践-1)
- [测试规则](#测试规则)
- [高级技巧](#高级技巧)
- [常见模式](#常见模式-1)
- [示例](#示例-1)

---

### 概述

PySecScanner 使用基于插件的规则系统,便于添加新的安全检查。每个规则都是一个 Python 类,它:

1. 继承自 `BaseRule`
2. 使用 `@register_rule` 装饰器注册自己
3. 在 `check()` 方法中实现模式检测逻辑
4. 返回 `Vulnerability` 对象列表

**规则生命周期:**
```
1. 导入规则类
2. @register_rule 装饰器将其添加到 RULE_REGISTRY
3. 扫描器加载所有已注册的规则
4. 对于每个文件:
   - 将 Python 代码解析为 AST
   - 运行每个规则的 check() 方法
   - 收集漏洞
5. 生成报告
```

---

### 规则结构

#### 最小规则模板

```python
import ast
from typing import List
from pysec.rules.base import BaseRule, register_rule
from pysec.models import Vulnerability


@register_rule
class MyCustomRule(BaseRule):
    """
    检测自定义安全模式
    """
    
    # 必需的类属性
    rule_id = "CUS001"              # 唯一 ID(3-4 字母 + 3 数字)
    rule_name = "自定义规则名称"     # 可读的名称
    severity = "medium"             # critical, high, medium, low
    description = "此规则检查什么的详细描述"
    
    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        """
        执行漏洞检测
        
        Args:
            ast_tree: 解析的抽象语法树
            file_path: 正在扫描的文件路径
            source_code: 原始源代码
            
        Returns:
            检测到的漏洞列表
        """
        vulnerabilities = []
        
        # 你的检测逻辑在这里
        for node in ast.walk(ast_tree):
            if self._is_vulnerable(node):
                vuln = self._create_vulnerability(
                    file_path=file_path,
                    line_number=node.lineno,
                    code_snippet=self._get_code_snippet(source_code, node.lineno),
                    suggestion="如何修复此问题"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_vulnerable(self, node: ast.AST) -> bool:
        """
        辅助方法检查节点是否存在漏洞
        """
        # 检测逻辑
        return False
```

#### 必需属性

| 属性 | 类型 | 格式 | 描述 | 示例 |
|------|------|------|------|------|
| `rule_id` | `str` | `[A-Z]{3,4}\d{3}` | 唯一标识符 | `"SQL001"`, `"CUSTOM001"` |
| `rule_name` | `str` | 自由文本 | 可读的名称 | `"SQL 注入检测"` |
| `severity` | `str` | `critical\|high\|medium\|low` | 默认严重级别 | `"high"` |
| `description` | `str` | 自由文本 | 详细描述 | `"检测 SQL 注入..."` |

---

### 分步教程

#### 步骤 1: 创建规则文件

在 `pysec/rules/` 中创建新文件:

```bash
# 对于自定义规则
touch pysec/rules/my_custom_rule.py
```

#### 步骤 2: 导入所需模块

```python
"""
我的自定义安全规则
检测[描述安全问题]
"""

import ast
from typing import List

from .base import BaseRule, register_rule
from ..models import Vulnerability
```

#### 步骤 3: 定义规则类

```python
@register_rule
class MyCustomRule(BaseRule):
    rule_id = "CUS001"
    rule_name = "我的自定义安全检查"
    severity = "medium"
    description = "检测不安全的模式 XYZ"
    
    def check(self, ast_tree, file_path, source_code):
        vulnerabilities = []
        # 将实现检测逻辑
        return vulnerabilities
```

#### 步骤 4: 实现检测逻辑

使用 AST 分析代码模式:

```python
def check(self, ast_tree, file_path, source_code):
    vulnerabilities = []
    
    # 遍历 AST 中的所有节点
    for node in ast.walk(ast_tree):
        # 检查函数调用
        if isinstance(node, ast.Call):
            # 获取函数名
            func_name = self._get_function_name(node)
            
            # 检查是否是危险函数
            if func_name == "dangerous_function":
                vuln = self._create_vulnerability(
                    file_path=file_path,
                    line_number=node.lineno,
                    code_snippet=self._get_code_snippet(source_code, node.lineno),
                    suggestion="改用 safe_function()"
                )
                vulnerabilities.append(vuln)
    
    return vulnerabilities

def _get_function_name(self, node: ast.Call) -> str:
    """从 Call 节点提取函数名"""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""
```

#### 步骤 5: 添加辅助方法

```python
def _is_string_concat(self, node: ast.AST) -> bool:
    """检查节点是否使用字符串拼接"""
    return isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)

def _contains_user_input(self, node: ast.AST) -> bool:
    """检查表达式是否包含用户输入变量"""
    user_input_vars = {"request", "input", "argv", "params"}
    
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in user_input_vars:
            return True
    return False
```

#### 步骤 6: 在 `__init__.py` 中导入

将你的规则添加到 `pysec/rules/__init__.py`:

```python
# ... 现有导入 ...
from . import my_custom_rule  # 添加这一行
```

---

### 最佳实践

#### 1. 使用特定节点类型

不要检查所有节点:
```python
# ❌ 慢 - 检查每个节点
for node in ast.walk(ast_tree):
    if isinstance(node, ast.Call):
        # ...
```

更好的方法:
```python
# ✅ 快 - 仅遍历调用
for node in ast.walk(ast_tree):
    if isinstance(node, ast.Call):
        self._check_call(node, file_path, source_code, vulnerabilities)
```

#### 2. 提供清晰的建议

```python
# ❌ 模糊
suggestion="不要使用这个函数"

# ✅ 具体且可操作
suggestion="""替换为参数化查询:
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
或使用 ORM 方法:
    User.objects.get(id=user_id)"""
```

#### 3. 处理边缘情况

```python
def _get_function_name(self, node: ast.Call) -> str:
    """安全地提取函数名"""
    try:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # module.function 或 object.method
            return node.func.attr
        elif isinstance(node.func, ast.Subscript):
            # dict["key"]() - 可调用的字典值
            return ""
    except AttributeError:
        return ""
    return ""
```

#### 4. 使用常量进行配置

```python
@register_rule
class InsecureHashRule(BaseRule):
    rule_id = "HSH001"
    rule_name = "不安全的哈希算法"
    severity = "medium"
    description = "检测弱哈希算法的使用"
    
    # 配置
    WEAK_ALGORITHMS = {"md5", "sha1", "md4", "sha"}
    SECURE_ALTERNATIVES = {"sha256", "sha512", "sha3_256", "blake2b"}
    
    def check(self, ast_tree, file_path, source_code):
        # 在检测逻辑中使用 self.WEAK_ALGORITHMS
        pass
```

#### 5. 考虑上下文

检查代码是否在测试文件或安全上下文中:

```python
def check(self, ast_tree, file_path, source_code):
    # 跳过测试文件
    if self._is_test_file(file_path):
        return []
    
    # 你的检测逻辑
    vulnerabilities = []
    # ...
    return vulnerabilities

def _is_test_file(self, file_path: str) -> bool:
    """检查文件是否为测试文件"""
    path_lower = file_path.lower()
    return (
        "test_" in path_lower or
        "_test." in path_lower or
        "/tests/" in path_lower
    )
```

---

### 测试规则

#### 创建测试用例

在 `tests/test_my_rule.py` 中创建测试文件:

```python
import pytest
from pysec import SecurityScanner


def test_detect_my_vulnerability():
    """测试规则检测漏洞"""
    code = """
import my_module

# 这应该被检测到
result = dangerous_function(user_input)
"""
    
    scanner = SecurityScanner()
    result = scanner.scan_code(code, "test.py")
    
    # 应该找到 1 个漏洞
    assert len(result.vulnerabilities) == 1
    
    vuln = result.vulnerabilities[0]
    assert vuln.rule_id == "CUS001"
    assert vuln.severity == "medium"
    assert vuln.line_number == 5  # dangerous_function 所在行


def test_no_false_positive():
    """测试规则不会误报安全代码"""
    code = """
import my_module

# 这不应该被检测到
result = safe_function(user_input)
"""
    
    scanner = SecurityScanner()
    result = scanner.scan_code(code, "test.py")
    
    # 应该找到 0 个漏洞
    assert len(result.vulnerabilities) == 0
```

#### 创建示例文件

在 `tests/samples/my_rule_vulnerable.py` 中创建漏洞示例:

```python
"""
测试 CUS001 规则的漏洞样本文件
"""

import my_module

# CUS001: 应该被检测到
result1 = dangerous_function(user_input)

# CUS001: 应该被检测到(不同语法)
result2 = my_module.dangerous_function(request.GET["param"])

# 安全代码 - 不应该被检测到
result3 = safe_function(user_input)
```

#### 运行测试

```bash
# 运行所有测试
pytest tests/ -v

# 运行特定测试
pytest tests/test_my_rule.py -v

# 运行并生成覆盖率
pytest tests/ --cov=pysec.rules
```

---

### 高级技巧

*(其余部分与英文版本相同,重点展示代码示例)*

---

### 常见模式

#### 检测函数调用

```python
def _is_dangerous_call(self, node: ast.AST) -> bool:
    """检查节点是否是对危险函数的调用"""
    if not isinstance(node, ast.Call):
        return False
    
    # 直接调用: dangerous_func()
    if isinstance(node.func, ast.Name):
        return node.func.id in self.DANGEROUS_FUNCTIONS
    
    # 方法调用: obj.dangerous_method()
    if isinstance(node.func, ast.Attribute):
        return node.func.attr in self.DANGEROUS_METHODS
    
    # 模块调用: module.dangerous()
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        module_name = node.func.value.id
        func_name = node.func.attr
        full_name = f"{module_name}.{func_name}"
        return full_name in self.DANGEROUS_QUALIFIED_NAMES
    
    return False
```

---

### 示例

#### 示例 1: 检测 Print 语句

```python
@register_rule
class PrintStatementRule(BaseRule):
    """检测 print() 语句(潜在信息泄露)"""
    
    rule_id = "PRINT001"
    rule_name = "检测到 Print 语句"
    severity = "low"
    description = "Print 语句可能将敏感信息泄露到日志中"
    
    def check(self, ast_tree, file_path, source_code):
        vulnerabilities = []
        
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                # 检查是否是 print()
                if isinstance(node.func, ast.Name) and node.func.id == "print":
                    vuln = self._create_vulnerability(
                        file_path=file_path,
                        line_number=node.lineno,
                        code_snippet=self._get_code_snippet(source_code, node.lineno),
                        suggestion="改用 logging 模块: logger.info(...)"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
```

---

**Last Updated:** 2026-02-09
