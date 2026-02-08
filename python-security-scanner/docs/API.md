# PySecScanner API Documentation

[English](#english) | [中文](#中文)

---

## English

### Table of Contents

- [Core Modules](#core-modules)
  - [SecurityScanner](#securityscanner)
  - [ScanConfig](#scanconfig)
  - [ScanResult](#scanresult)
  - [Vulnerability](#vulnerability)
- [Scanner Module](#scanner-module)
- [Rule System](#rule-system)
  - [BaseRule](#baserule)
  - [Rule Registry](#rule-registry)
- [Reporter Module](#reporter-module)
- [Fixer Module](#fixer-module)
- [Configuration](#configuration)
- [Utilities](#utilities)

---

### Core Modules

#### SecurityScanner

The main entry point for security scanning operations.

**Location:** `pysec.engine.SecurityScanner`

**Constructor:**
```python
SecurityScanner(config: Optional[ScanConfig] = None)
```

**Parameters:**
- `config` (Optional[ScanConfig]): Scanner configuration. If not provided, uses default settings.

**Methods:**

##### `scan(target: str) -> ScanResult`

Scans a file or directory for security vulnerabilities.

**Parameters:**
- `target` (str): Path to file or directory to scan

**Returns:**
- `ScanResult`: Scan results containing vulnerabilities and statistics

**Example:**
```python
from pysec import SecurityScanner

scanner = SecurityScanner()
result = scanner.scan("./myproject")
print(f"Found {len(result.vulnerabilities)} vulnerabilities")
```

##### `scan_file(file_path: str) -> ScanResult`

Scans a single Python file.

**Parameters:**
- `file_path` (str): Path to Python file

**Returns:**
- `ScanResult`: Scan results

##### `scan_directory(directory: str) -> ScanResult`

Scans all Python files in a directory recursively.

**Parameters:**
- `directory` (str): Directory path

**Returns:**
- `ScanResult`: Scan results

##### `scan_code(source_code: str, filename: str = "<string>") -> ScanResult`

Scans Python source code directly.

**Parameters:**
- `source_code` (str): Python source code
- `filename` (str, optional): Filename for reporting. Default: `"<string>"`

**Returns:**
- `ScanResult`: Scan results

**Example:**
```python
code = """
import os
os.system("ls " + user_input)  # CMD001: Command Injection
"""
result = scanner.scan_code(code, "example.py")
```

##### `scan_changed(target: str) -> ScanResult`

Scans only files modified in Git working directory.

**Parameters:**
- `target` (str): Repository path

**Returns:**
- `ScanResult`: Scan results for modified files

**Example:**
```python
# Scan only uncommitted changes
result = scanner.scan_changed("./myproject")
```

##### `scan_since(target: str, since_ref: str) -> ScanResult`

Scans files modified since a specific Git reference.

**Parameters:**
- `target` (str): Repository path
- `since_ref` (str): Git reference (commit hash, branch name, tag)

**Returns:**
- `ScanResult`: Scan results for modified files

**Example:**
```python
# Scan changes since main branch
result = scanner.scan_since("./myproject", "main")

# Scan last 5 commits
result = scanner.scan_since("./myproject", "HEAD~5")
```

##### `get_rules() -> List[dict]`

Gets information about all loaded rules.

**Returns:**
- `List[dict]`: List of rule information dictionaries

**Example:**
```python
rules = scanner.get_rules()
for rule in rules:
    print(f"{rule['rule_id']}: {rule['rule_name']} ({rule['severity']})")
```

---

#### ScanConfig

Configuration object for scanner behavior.

**Location:** `pysec.models.ScanConfig`

**Constructor:**
```python
ScanConfig(
    exclude_dirs: Optional[List[str]] = None,
    exclude_files: Optional[List[str]] = None,
    enabled_rules: Optional[List[str]] = None,
    disabled_rules: Optional[List[str]] = None,
    min_severity: Optional[str] = None,
    severity_overrides: Optional[Dict[str, str]] = None,
    use_cache: bool = True,
    cache_dir: str = ".pysec_cache"
)
```

**Attributes:**

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `exclude_dirs` | `List[str]` | `None` | Directories to exclude from scanning |
| `exclude_files` | `List[str]` | `None` | File patterns to exclude |
| `enabled_rules` | `List[str]` | `None` | Only run these rules (if set) |
| `disabled_rules` | `List[str]` | `None` | Skip these rules |
| `min_severity` | `str` | `None` | Minimum severity level ("low", "medium", "high", "critical") |
| `severity_overrides` | `Dict[str, str]` | `None` | Override severity for specific rules |
| `use_cache` | `bool` | `True` | Enable AST caching |
| `cache_dir` | `str` | `".pysec_cache"` | Cache directory path |

**Example:**
```python
from pysec import SecurityScanner, ScanConfig

config = ScanConfig(
    exclude_dirs=["tests", "venv", "__pycache__"],
    exclude_files=["*_test.py", "test_*.py"],
    min_severity="high",
    severity_overrides={
        "SEC001": "critical"  # Upgrade hardcoded secrets to critical
    },
    disabled_rules=["RND001"]  # Skip insecure random check
)

scanner = SecurityScanner(config)
result = scanner.scan("./myproject")
```

**Methods:**

##### `meets_min_severity(severity: str) -> bool`

Checks if a severity level meets the minimum threshold.

**Parameters:**
- `severity` (str): Severity level to check

**Returns:**
- `bool`: True if meets minimum, False otherwise

---

#### ScanResult

Container for scan results.

**Location:** `pysec.models.ScanResult`

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `vulnerabilities` | `List[Vulnerability]` | List of detected vulnerabilities |
| `stats` | `dict` | Statistics about the scan |
| `file_count` | `int` | Number of files scanned |
| `scan_time` | `float` | Time taken for scan (seconds) |
| `target` | `str` | Scan target path |

**Methods:**

##### `summary() -> dict`

Generates a summary of scan results.

**Returns:**
- `dict`: Summary with counts by severity

**Example:**
```python
result = scanner.scan("./myproject")
summary = result.summary()
print(f"Critical: {summary['critical']}")
print(f"High: {summary['high']}")
print(f"Medium: {summary['medium']}")
print(f"Low: {summary['low']}")
print(f"Total: {summary['total']}")
```

##### `to_dict() -> dict`

Converts scan result to dictionary.

**Returns:**
- `dict`: JSON-serializable dictionary

---

#### Vulnerability

Represents a detected security vulnerability.

**Location:** `pysec.models.Vulnerability`

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `rule_id` | `str` | Rule identifier (e.g., "SQL001") |
| `rule_name` | `str` | Human-readable rule name |
| `severity` | `str` | Severity level ("critical", "high", "medium", "low") |
| `description` | `str` | Rule description |
| `file_path` | `str` | Path to file containing vulnerability |
| `line_number` | `int` | Line number where vulnerability was found |
| `code_snippet` | `str` | Code snippet showing the issue |
| `suggestion` | `str` | Suggestion for fixing the vulnerability |

**Methods:**

##### `to_dict() -> dict`

Converts vulnerability to dictionary.

**Returns:**
- `dict`: JSON-serializable dictionary

**Example:**
```python
for vuln in result.vulnerabilities:
    print(f"""
    Rule: {vuln.rule_id} - {vuln.rule_name}
    Severity: {vuln.severity}
    Location: {vuln.file_path}:{vuln.line_number}
    Description: {vuln.description}
    Code: {vuln.code_snippet}
    Fix: {vuln.suggestion}
    """)
```

---

### Scanner Module

#### Scanner

Low-level file scanning utilities.

**Location:** `pysec.scanner.Scanner`

**Methods:**

##### `find_python_files(directory: str, exclude_dirs: List[str] = None, exclude_files: List[str] = None) -> List[str]`

Finds all Python files in a directory.

**Parameters:**
- `directory` (str): Directory to search
- `exclude_dirs` (List[str], optional): Directories to exclude
- `exclude_files` (List[str], optional): File patterns to exclude

**Returns:**
- `List[str]`: List of Python file paths

#### ASTParser

AST parsing with caching support.

**Location:** `pysec.scanner.ASTParser`

**Methods:**

##### `parse(source_code: str, file_path: str) -> Optional[ast.AST]`

Parses Python source code into AST.

**Parameters:**
- `source_code` (str): Python source code
- `file_path` (str): File path for caching/error reporting

**Returns:**
- `Optional[ast.AST]`: Parsed AST or None if parsing fails

---

### Rule System

#### BaseRule

Base class for all detection rules.

**Location:** `pysec.rules.base.BaseRule`

**Class Attributes:**

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `rule_id` | `str` | Yes | Unique rule identifier |
| `rule_name` | `str` | Yes | Human-readable rule name |
| `severity` | `str` | Yes | Default severity level |
| `description` | `str` | Yes | Rule description |

**Methods:**

##### `check(ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]`

Performs vulnerability detection.

**Parameters:**
- `ast_tree` (ast.AST): Parsed AST
- `file_path` (str): File being scanned
- `source_code` (str): Original source code

**Returns:**
- `List[Vulnerability]`: List of detected vulnerabilities

**Helper Methods:**

##### `_create_vulnerability(file_path: str, line_number: int, code_snippet: str, suggestion: str = "") -> Vulnerability`

Creates a vulnerability instance.

##### `_get_code_snippet(source_code: str, line_number: int, context_lines: int = 2) -> str`

Extracts code snippet around a line.

**Example - Creating a Custom Rule:**
```python
import ast
from pysec.rules.base import BaseRule, register_rule
from pysec.models import Vulnerability
from typing import List

@register_rule
class DetectPrintStatement(BaseRule):
    rule_id = "PRINT001"
    rule_name = "Print Statement Detected"
    severity = "low"
    description = "Detects print() statements that may leak information"

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "print":
                    vuln = self._create_vulnerability(
                        file_path=file_path,
                        line_number=node.lineno,
                        code_snippet=self._get_code_snippet(source_code, node.lineno),
                        suggestion="Use proper logging instead of print()"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
```

#### Rule Registry

##### `register_rule(rule_class: Type[BaseRule])`

Decorator to register a rule class.

**Example:**
```python
@register_rule
class MyRule(BaseRule):
    # ...
```

##### `list_rules() -> List[Type[BaseRule]]`

Gets all registered rule classes.

**Returns:**
- `List[Type[BaseRule]]`: List of rule classes

##### `get_rule(rule_id: str) -> Optional[Type[BaseRule]]`

Gets a specific rule by ID.

**Parameters:**
- `rule_id` (str): Rule identifier

**Returns:**
- `Optional[Type[BaseRule]]`: Rule class or None

---

### Reporter Module

#### Available Reporters

**Location:** `pysec.reporter`

##### `get_reporter(format_type: str) -> BaseReporter`

Gets a reporter instance.

**Parameters:**
- `format_type` (str): Report format ("text", "markdown", "json", "html")

**Returns:**
- `BaseReporter`: Reporter instance

**Example:**
```python
from pysec.reporter import get_reporter

# Generate Markdown report
reporter = get_reporter("markdown")
report_content = reporter.generate(scan_result)

# Save to file
with open("report.md", "w", encoding="utf-8") as f:
    f.write(report_content)
```

#### Report Formats

| Format | Class | Description |
|--------|-------|-------------|
| `text` | `TextReporter` | Console-friendly colored text |
| `markdown` | `MarkdownReporter` | Markdown format with tables |
| `json` | `JSONReporter` | JSON format for automation |
| `html` | `HTMLReporter` | Styled HTML with syntax highlighting |

---

### Fixer Module

#### CodeFixer

Automatic vulnerability fixing.

**Location:** `pysec.fixer.CodeFixer`

**Methods:**

##### `get_fixer(rule_id: str) -> Optional[BaseFixPattern]`

Gets fixer for a specific rule.

**Parameters:**
- `rule_id` (str): Rule identifier

**Returns:**
- `Optional[BaseFixPattern]`: Fixer instance or None

##### `can_fix(vuln: Vulnerability) -> bool`

Checks if a vulnerability can be auto-fixed.

**Parameters:**
- `vuln` (Vulnerability): Vulnerability to check

**Returns:**
- `bool`: True if fixable

##### `fix_vulnerability(vuln: Vulnerability, source_code: str, dry_run: bool = False) -> FixResult`

Fixes a single vulnerability.

**Parameters:**
- `vuln` (Vulnerability): Vulnerability to fix
- `source_code` (str): Original source code
- `dry_run` (bool): If True, only preview changes

**Returns:**
- `FixResult`: Fix result with status and modified code

##### `fix_file(file_path: str, vulnerabilities: List[Vulnerability], dry_run: bool = False) -> List[FixResult]`

Fixes all auto-fixable vulnerabilities in a file.

**Parameters:**
- `file_path` (str): File path
- `vulnerabilities` (List[Vulnerability]): Vulnerabilities to fix
- `dry_run` (bool): If True, only preview changes

**Returns:**
- `List[FixResult]`: List of fix results

**Example:**
```python
from pysec.fixer import CodeFixer, get_fixer

fixer = CodeFixer()
result = scanner.scan("app.py")

for vuln in result.vulnerabilities:
    if fixer.can_fix(vuln):
        with open(vuln.file_path, "r") as f:
            source_code = f.read()
        
        fix_result = fixer.fix_vulnerability(vuln, source_code, dry_run=True)
        
        if fix_result.success:
            print(f"Can fix {vuln.rule_id}:")
            print(fix_result.diff)
```

---

### Configuration

#### Config

Configuration file loading.

**Location:** `pysec.config.Config`

**Methods:**

##### `load_config(config_path: Optional[str] = None) -> dict`

Loads configuration from file.

**Parameters:**
- `config_path` (Optional[str]): Path to config file. Auto-detects if None.

**Returns:**
- `dict`: Configuration dictionary

**Supported Files:**
- `.pysecrc` (YAML)
- `pyproject.toml` (under `[tool.pysec]`)

---

### Utilities

#### Git Utilities

**Location:** `pysec.git_utils`

##### `get_changed_files(repo_path: str) -> List[str]`

Gets files changed in working directory.

##### `get_files_changed_since(repo_path: str, since_ref: str) -> List[str]`

Gets files changed since a Git reference.

#### Cache

**Location:** `pysec.cache.ASTCache`

##### `get(file_path: str, source_hash: str) -> Optional[ast.AST]`

Retrieves cached AST.

##### `set(file_path: str, source_hash: str, ast_tree: ast.AST)`

Stores AST in cache.

---

## 中文

### 目录

- [核心模块](#核心模块)
  - [SecurityScanner](#securityscanner-1)
  - [ScanConfig](#scanconfig-1)
  - [ScanResult](#scanresult-1)
  - [Vulnerability](#vulnerability-1)
- [扫描器模块](#扫描器模块)
- [规则系统](#规则系统)
  - [BaseRule](#baserule-1)
  - [规则注册表](#规则注册表)
- [报告模块](#报告模块)
- [修复模块](#修复模块)
- [配置](#配置)
- [工具](#工具)

---

### 核心模块

#### SecurityScanner

安全扫描操作的主要入口点。

**位置:** `pysec.engine.SecurityScanner`

**构造函数:**
```python
SecurityScanner(config: Optional[ScanConfig] = None)
```

**参数:**
- `config` (Optional[ScanConfig]): 扫描器配置。如果未提供，使用默认设置。

**方法:**

##### `scan(target: str) -> ScanResult`

扫描文件或目录以查找安全漏洞。

**参数:**
- `target` (str): 要扫描的文件或目录路径

**返回:**
- `ScanResult`: 包含漏洞和统计信息的扫描结果

**示例:**
```python
from pysec import SecurityScanner

scanner = SecurityScanner()
result = scanner.scan("./myproject")
print(f"发现 {len(result.vulnerabilities)} 个漏洞")
```

##### `scan_file(file_path: str) -> ScanResult`

扫描单个 Python 文件。

**参数:**
- `file_path` (str): Python 文件路径

**返回:**
- `ScanResult`: 扫描结果

##### `scan_directory(directory: str) -> ScanResult`

递归扫描目录中的所有 Python 文件。

**参数:**
- `directory` (str): 目录路径

**返回:**
- `ScanResult`: 扫描结果

##### `scan_code(source_code: str, filename: str = "<string>") -> ScanResult`

直接扫描 Python 源代码。

**参数:**
- `source_code` (str): Python 源代码
- `filename` (str, 可选): 用于报告的文件名。默认: `"<string>"`

**返回:**
- `ScanResult`: 扫描结果

**示例:**
```python
code = """
import os
os.system("ls " + user_input)  # CMD001: 命令注入
"""
result = scanner.scan_code(code, "example.py")
```

##### `scan_changed(target: str) -> ScanResult`

仅扫描 Git 工作目录中修改的文件。

**参数:**
- `target` (str): 仓库路径

**返回:**
- `ScanResult`: 修改文件的扫描结果

**示例:**
```python
# 仅扫描未提交的更改
result = scanner.scan_changed("./myproject")
```

##### `scan_since(target: str, since_ref: str) -> ScanResult`

扫描自特定 Git 引用以来修改的文件。

**参数:**
- `target` (str): 仓库路径
- `since_ref` (str): Git 引用(提交哈希、分支名、标签)

**返回:**
- `ScanResult`: 修改文件的扫描结果

**示例:**
```python
# 扫描自 main 分支以来的更改
result = scanner.scan_since("./myproject", "main")

# 扫描最近 5 次提交
result = scanner.scan_since("./myproject", "HEAD~5")
```

##### `get_rules() -> List[dict]`

获取所有已加载规则的信息。

**返回:**
- `List[dict]`: 规则信息字典列表

**示例:**
```python
rules = scanner.get_rules()
for rule in rules:
    print(f"{rule['rule_id']}: {rule['rule_name']} ({rule['severity']})")
```

---

#### ScanConfig

扫描器行为的配置对象。

**位置:** `pysec.models.ScanConfig`

**构造函数:**
```python
ScanConfig(
    exclude_dirs: Optional[List[str]] = None,
    exclude_files: Optional[List[str]] = None,
    enabled_rules: Optional[List[str]] = None,
    disabled_rules: Optional[List[str]] = None,
    min_severity: Optional[str] = None,
    severity_overrides: Optional[Dict[str, str]] = None,
    use_cache: bool = True,
    cache_dir: str = ".pysec_cache"
)
```

**属性:**

| 属性 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `exclude_dirs` | `List[str]` | `None` | 要从扫描中排除的目录 |
| `exclude_files` | `List[str]` | `None` | 要排除的文件模式 |
| `enabled_rules` | `List[str]` | `None` | 仅运行这些规则(如果设置) |
| `disabled_rules` | `List[str]` | `None` | 跳过这些规则 |
| `min_severity` | `str` | `None` | 最低严重级别("low", "medium", "high", "critical") |
| `severity_overrides` | `Dict[str, str]` | `None` | 覆盖特定规则的严重性 |
| `use_cache` | `bool` | `True` | 启用 AST 缓存 |
| `cache_dir` | `str` | `".pysec_cache"` | 缓存目录路径 |

**示例:**
```python
from pysec import SecurityScanner, ScanConfig

config = ScanConfig(
    exclude_dirs=["tests", "venv", "__pycache__"],
    exclude_files=["*_test.py", "test_*.py"],
    min_severity="high",
    severity_overrides={
        "SEC001": "critical"  # 将硬编码凭据升级为严重级别
    },
    disabled_rules=["RND001"]  # 跳过不安全随机数检查
)

scanner = SecurityScanner(config)
result = scanner.scan("./myproject")
```

**方法:**

##### `meets_min_severity(severity: str) -> bool`

检查严重级别是否满足最低阈值。

**参数:**
- `severity` (str): 要检查的严重级别

**返回:**
- `bool`: 如果满足最低要求则为 True，否则为 False

---

#### ScanResult

扫描结果的容器。

**位置:** `pysec.models.ScanResult`

**属性:**

| 属性 | 类型 | 描述 |
|------|------|------|
| `vulnerabilities` | `List[Vulnerability]` | 检测到的漏洞列表 |
| `stats` | `dict` | 关于扫描的统计信息 |
| `file_count` | `int` | 扫描的文件数 |
| `scan_time` | `float` | 扫描耗时(秒) |
| `target` | `str` | 扫描目标路径 |

**方法:**

##### `summary() -> dict`

生成扫描结果摘要。

**返回:**
- `dict`: 按严重程度分类的计数摘要

**示例:**
```python
result = scanner.scan("./myproject")
summary = result.summary()
print(f"严重: {summary['critical']}")
print(f"高危: {summary['high']}")
print(f"中危: {summary['medium']}")
print(f"低危: {summary['low']}")
print(f"总计: {summary['total']}")
```

##### `to_dict() -> dict`

将扫描结果转换为字典。

**返回:**
- `dict`: JSON 可序列化字典

---

#### Vulnerability

表示检测到的安全漏洞。

**位置:** `pysec.models.Vulnerability`

**属性:**

| 属性 | 类型 | 描述 |
|------|------|------|
| `rule_id` | `str` | 规则标识符(例如 "SQL001") |
| `rule_name` | `str` | 可读的规则名称 |
| `severity` | `str` | 严重级别("critical", "high", "medium", "low") |
| `description` | `str` | 规则描述 |
| `file_path` | `str` | 包含漏洞的文件路径 |
| `line_number` | `int` | 发现漏洞的行号 |
| `code_snippet` | `str` | 显示问题的代码片段 |
| `suggestion` | `str` | 修复漏洞的建议 |

**方法:**

##### `to_dict() -> dict`

将漏洞转换为字典。

**返回:**
- `dict`: JSON 可序列化字典

**示例:**
```python
for vuln in result.vulnerabilities:
    print(f"""
    规则: {vuln.rule_id} - {vuln.rule_name}
    严重性: {vuln.severity}
    位置: {vuln.file_path}:{vuln.line_number}
    描述: {vuln.description}
    代码: {vuln.code_snippet}
    修复: {vuln.suggestion}
    """)
```

---

### 扫描器模块

#### Scanner

底层文件扫描工具。

**位置:** `pysec.scanner.Scanner`

**方法:**

##### `find_python_files(directory: str, exclude_dirs: List[str] = None, exclude_files: List[str] = None) -> List[str]`

查找目录中的所有 Python 文件。

**参数:**
- `directory` (str): 要搜索的目录
- `exclude_dirs` (List[str], 可选): 要排除的目录
- `exclude_files` (List[str], 可选): 要排除的文件模式

**返回:**
- `List[str]`: Python 文件路径列表

#### ASTParser

支持缓存的 AST 解析。

**位置:** `pysec.scanner.ASTParser`

**方法:**

##### `parse(source_code: str, file_path: str) -> Optional[ast.AST]`

将 Python 源代码解析为 AST。

**参数:**
- `source_code` (str): Python 源代码
- `file_path` (str): 用于缓存/错误报告的文件路径

**返回:**
- `Optional[ast.AST]`: 解析的 AST，如果解析失败则为 None

---

### 规则系统

#### BaseRule

所有检测规则的基类。

**位置:** `pysec.rules.base.BaseRule`

**类属性:**

| 属性 | 类型 | 必需 | 描述 |
|------|------|------|------|
| `rule_id` | `str` | 是 | 唯一规则标识符 |
| `rule_name` | `str` | 是 | 可读的规则名称 |
| `severity` | `str` | 是 | 默认严重级别 |
| `description` | `str` | 是 | 规则描述 |

**方法:**

##### `check(ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]`

执行漏洞检测。

**参数:**
- `ast_tree` (ast.AST): 解析的 AST
- `file_path` (str): 正在扫描的文件
- `source_code` (str): 原始源代码

**返回:**
- `List[Vulnerability]`: 检测到的漏洞列表

**辅助方法:**

##### `_create_vulnerability(file_path: str, line_number: int, code_snippet: str, suggestion: str = "") -> Vulnerability`

创建漏洞实例。

##### `_get_code_snippet(source_code: str, line_number: int, context_lines: int = 2) -> str`

提取某行周围的代码片段。

**示例 - 创建自定义规则:**
```python
import ast
from pysec.rules.base import BaseRule, register_rule
from pysec.models import Vulnerability
from typing import List

@register_rule
class DetectPrintStatement(BaseRule):
    rule_id = "PRINT001"
    rule_name = "检测到 Print 语句"
    severity = "low"
    description = "检测可能泄露信息的 print() 语句"

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "print":
                    vuln = self._create_vulnerability(
                        file_path=file_path,
                        line_number=node.lineno,
                        code_snippet=self._get_code_snippet(source_code, node.lineno),
                        suggestion="使用适当的日志记录而不是 print()"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
```

#### 规则注册表

##### `register_rule(rule_class: Type[BaseRule])`

注册规则类的装饰器。

**示例:**
```python
@register_rule
class MyRule(BaseRule):
    # ...
```

##### `list_rules() -> List[Type[BaseRule]]`

获取所有已注册的规则类。

**返回:**
- `List[Type[BaseRule]]`: 规则类列表

##### `get_rule(rule_id: str) -> Optional[Type[BaseRule]]`

根据 ID 获取特定规则。

**参数:**
- `rule_id` (str): 规则标识符

**返回:**
- `Optional[Type[BaseRule]]`: 规则类或 None

---

### 报告模块

#### 可用的报告器

**位置:** `pysec.reporter`

##### `get_reporter(format_type: str) -> BaseReporter`

获取报告器实例。

**参数:**
- `format_type` (str): 报告格式("text", "markdown", "json", "html")

**返回:**
- `BaseReporter`: 报告器实例

**示例:**
```python
from pysec.reporter import get_reporter

# 生成 Markdown 报告
reporter = get_reporter("markdown")
report_content = reporter.generate(scan_result)

# 保存到文件
with open("report.md", "w", encoding="utf-8") as f:
    f.write(report_content)
```

#### 报告格式

| 格式 | 类 | 描述 |
|------|---|------|
| `text` | `TextReporter` | 控制台友好的彩色文本 |
| `markdown` | `MarkdownReporter` | 带表格的 Markdown 格式 |
| `json` | `JSONReporter` | 用于自动化的 JSON 格式 |
| `html` | `HTMLReporter` | 带语法高亮的样式化 HTML |

---

### 修复模块

#### CodeFixer

自动漏洞修复。

**位置:** `pysec.fixer.CodeFixer`

**方法:**

##### `get_fixer(rule_id: str) -> Optional[BaseFixPattern]`

获取特定规则的修复器。

**参数:**
- `rule_id` (str): 规则标识符

**返回:**
- `Optional[BaseFixPattern]`: 修复器实例或 None

##### `can_fix(vuln: Vulnerability) -> bool`

检查漏洞是否可以自动修复。

**参数:**
- `vuln` (Vulnerability): 要检查的漏洞

**返回:**
- `bool`: 如果可修复则为 True

##### `fix_vulnerability(vuln: Vulnerability, source_code: str, dry_run: bool = False) -> FixResult`

修复单个漏洞。

**参数:**
- `vuln` (Vulnerability): 要修复的漏洞
- `source_code` (str): 原始源代码
- `dry_run` (bool): 如果为 True，仅预览更改

**返回:**
- `FixResult`: 包含状态和修改代码的修复结果

##### `fix_file(file_path: str, vulnerabilities: List[Vulnerability], dry_run: bool = False) -> List[FixResult]`

修复文件中所有可自动修复的漏洞。

**参数:**
- `file_path` (str): 文件路径
- `vulnerabilities` (List[Vulnerability]): 要修复的漏洞
- `dry_run` (bool): 如果为 True，仅预览更改

**返回:**
- `List[FixResult]`: 修复结果列表

**示例:**
```python
from pysec.fixer import CodeFixer, get_fixer

fixer = CodeFixer()
result = scanner.scan("app.py")

for vuln in result.vulnerabilities:
    if fixer.can_fix(vuln):
        with open(vuln.file_path, "r") as f:
            source_code = f.read()
        
        fix_result = fixer.fix_vulnerability(vuln, source_code, dry_run=True)
        
        if fix_result.success:
            print(f"可以修复 {vuln.rule_id}:")
            print(fix_result.diff)
```

---

### 配置

#### Config

配置文件加载。

**位置:** `pysec.config.Config`

**方法:**

##### `load_config(config_path: Optional[str] = None) -> dict`

从文件加载配置。

**参数:**
- `config_path` (Optional[str]): 配置文件路径。如果为 None 则自动检测。

**返回:**
- `dict`: 配置字典

**支持的文件:**
- `.pysecrc` (YAML)
- `pyproject.toml` (在 `[tool.pysec]` 下)

---

### 工具

#### Git 工具

**位置:** `pysec.git_utils`

##### `get_changed_files(repo_path: str) -> List[str]`

获取工作目录中更改的文件。

##### `get_files_changed_since(repo_path: str, since_ref: str) -> List[str]`

获取自 Git 引用以来更改的文件。

#### 缓存

**位置:** `pysec.cache.ASTCache`

##### `get(file_path: str, source_hash: str) -> Optional[ast.AST]`

检索缓存的 AST。

##### `set(file_path: str, source_hash: str, ast_tree: ast.AST)`

在缓存中存储 AST。

---

**Last Updated:** 2026-02-09
