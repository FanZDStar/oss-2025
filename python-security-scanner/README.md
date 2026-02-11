# PySecScanner

> Python Security Vulnerability Static Analysis Tool  
> Python 代码安全漏洞静态分析工具

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-121%20passed-brightgreen.svg)](tests/)

[English](#english) | [中文](#中文)

---

## English

### 📖 Introduction

PySecScanner is a lightweight Python static code security scanner based on Abstract Syntax Tree (AST) analysis. It helps developers discover potential security vulnerabilities in Python code, supports automatic fixing, and provides multiple report formats.

**Key Features:**

- 🔍 **Deep AST Analysis** - Precise code analysis based on Abstract Syntax Tree
- 🛡️ **23+ Security Rules** - Covers SQL injection, command injection, hardcoded secrets, framework-specific vulnerabilities, etc.
- 🔧 **Auto-Fix** - Automatic fixing for low-risk vulnerabilities with diff preview
- 📊 **Multi-Format Reports** - Support for Text, Markdown, JSON, HTML, and other formats
- 🔌 **Extensible Architecture** - Plugin-based rule system for easy extension
- ⚡ **Zero External Dependencies** - Uses only Python standard library, ready to use out-of-the-box
- 🖥️ **CLI Friendly** - Intuitive command-line interface with color output
- 📝 **Configuration Support** - Support for `.pysecrc` and `pyproject.toml` configuration files
- 🚀 **Incremental Scanning** - Git incremental scanning, scans only modified files
- 💾 **AST Caching** - Caches parsing results for faster repeated scans
- 🎨 **Color Terminal** - Colored output with severity-based highlighting
- 🔕 **Ignore Directives** - Support for inline and block-level ignore comments

### 🚀 Quick Start

#### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/python-security-scanner.git
cd python-security-scanner

# Install (optional, can run directly)
pip install -e .

# Or install from PyPI (upcoming)
pip install pysecscanner
```

#### Basic Usage

```bash
# Scan directory
python main.py scan ./your_project

# Scan single file
python main.py scan app.py

# Generate Markdown report
python main.py scan ./src -o report.md -f markdown

# Generate HTML report
python main.py scan ./src -o report.html -f html

# Exclude specific directories
python main.py scan ./src --exclude tests,docs,venv

# Filter by minimum severity
python main.py scan ./src --severity high

# Disable colored output
python main.py scan ./src --no-color
```

#### Incremental Scanning (Git)

```bash
# Scan only modified files (Git working directory)
python main.py scan . --changed-only

# Scan files modified since specific commit
python main.py scan . --since HEAD~5

# Scan differences from branch
python main.py scan . --since main
```

#### Auto-Fix

```bash
# Preview fixes without applying
python main.py scan ./src --fix --dry-run

# Apply fixes automatically
python main.py scan ./src --fix

# Interactive confirmation for each fix
python main.py scan ./src --fix --interactive
```

#### Using as Module

```python
from pysec import SecurityScanner

# Create scanner
scanner = SecurityScanner()

# Scan directory
result = scanner.scan("./your_project")

# View results
print(f"Found {len(result.vulnerabilities)} vulnerabilities")
for vuln in result.vulnerabilities:
    print(f"[{vuln.severity}] {vuln.rule_name}: {vuln.file_path}:{vuln.line_number}")

# Incremental scan (modified files only)
result = scanner.scan_changed("./your_project")

# Scan changes since specific commit
result = scanner.scan_since("./your_project", "main")
```

### 🛡️ Detection Rules

#### Core Security Rules

| Rule ID | Name              | Severity | Description                                       |
| ------- | ----------------- | -------- | ------------------------------------------------- |
| SQL001  | SQL Injection     | High     | Detects unsafe SQL string concatenation/formatting |
| CMD001  | Command Injection | Critical | Detects dangerous os.system, subprocess calls      |
| SEC001  | Hardcoded Secrets | High     | Detects hardcoded passwords, keys in code          |
| DNG001  | Dangerous Functions | Critical | Detects eval, exec, pickle and other risky functions |
| PTH001  | Path Traversal    | High     | Detects file operations that may lead to directory traversal |
| XSS001  | XSS Vulnerability | High     | Detects code that may cause cross-site scripting   |

#### Additional Security Rules

| Rule ID | Name              | Severity | Description                                       |
| ------- | ----------------- | -------- | ------------------------------------------------- |
| RND001  | Insecure Random   | Medium   | Detects use of random module for security purposes |
| HSH001  | Insecure Hash     | Medium   | Detects MD5/SHA1 used for password hashing         |
| SSL001  | SSL/TLS Config    | High     | Detects verify=False and insecure SSL contexts     |
| LOG001  | Sensitive Log Info| Medium   | Detects logging of passwords, tokens, etc.         |
| SSRF001 | SSRF Vulnerability| High     | Detects server-side request forgery vulnerabilities |
| XXE001  | XXE Vulnerability | High     | Detects XML external entity injection risks        |
| REX001  | ReDoS Pattern    | Medium   | Detects regex patterns vulnerable to ReDoS attacks |

#### Framework-Specific Rules

**Django Security (DJG001-DJG005)**
- Debug mode in production
- Hardcoded SECRET_KEY
- Insecure ALLOWED_HOSTS
- SQL query safety
- Insecure deserialization

**Flask Security (FLK001-FLK005)**
- Debug mode detection
- Hardcoded SECRET_KEY
- Insecure session config
- Jinja2 template injection (SSTI)
- Insecure file upload

### ⚙️ Configuration

Support for `.pysecrc` (YAML) or `[tool.pysec]` in `pyproject.toml`:

```yaml
# .pysecrc
rules:
  enabled:
    - SQL001
    - CMD001
  disabled:
    - SEC001
exclude:
  dirs:
    - tests
    - migrations
  files:
    - "*_test.py"
severity:
  minimum: medium
  overrides:
    SEC001: critical  # Upgrade hardcoded secrets to critical
output:
  format: markdown
  color: true
cache:
  enabled: true
  directory: .pysec_cache
```

### 🚫 Ignore Directives

```python
# Ignore specific rule on this line
password = "temp123"  # pysec: ignore SEC001

# Ignore all rules on this line
exec(user_code)  # pysec: ignore

# Ignore multiple rules
query = f"SELECT * FROM users WHERE id={uid}"  # pysec: ignore SQL001,CMD001

# Disable rule for code block
# pysec: disable SEC001
api_key = "sk-1234567890"
secret = "my-secret"
# pysec: enable SEC001
```

### 📊 Report Formats

#### Text (Console)
Colored terminal output with severity highlighting:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 PySecScanner 安全扫描报告
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📈 漏洞统计
  🔴 严重 (Critical): 3
  🟠 高危 (High):     15
  🟡 中危 (Medium):   5
  🟢 低危 (Low):      0
  ━━━━━━━━━━━━━━━━━━━━━━━━
  总计:              23
```

#### Markdown
Professional Markdown report with tables and code snippets

#### JSON
Machine-readable format for CI/CD integration

#### HTML
Styled HTML report with syntax highlighting and charts

### 📁 Project Structure

```
python-security-scanner/
├── main.py                 # Main entry point
├── pysec/                  # Core package
│   ├── __init__.py        # Package initialization
│   ├── models.py          # Data models (Vulnerability, FixResult)
│   ├── scanner.py         # File scanner
│   ├── engine.py          # Rule engine & security scanner
│   ├── reporter.py        # Report generators
│   ├── cli.py             # Command-line interface
│   ├── config.py          # Configuration management
│   ├── cache.py           # AST caching
│   ├── git_utils.py       # Git utilities
│   ├── fixer.py           # Auto-fixer
│   ├── colors.py          # Terminal color support
│   └── rules/             # Detection rules (23+ rules)
│       ├── base.py        # Base rule class
│       ├── sql_injection.py
│       ├── command_injection.py
│       ├── hardcoded_secrets.py
│       ├── dangerous_functions.py
│       ├── path_traversal.py
│       ├── xss.py
│       ├── insecure_random.py
│       ├── insecure_hash.py
│       ├── insecure_ssl.py
│       ├── log_sensitive.py
│       ├── ssrf.py
│       ├── xxe.py
│       ├── redos.py
│       ├── django_security.py
│       └── flask_security.py
├── tests/                  # Test files (121 test cases)
├── docs/                   # Documentation
│   ├── API.md             # API documentation
│   ├── RULE_GUIDE.md      # Rule development guide
│   ├── AST_REFERENCE.md   # AST node types reference
│   ├── BEST_PRACTICES.md  # Best practices
│   └── FAQ.md             # Frequently asked questions
├── README.md              # This file
├── LICENSE                # MIT License
├── CHANGELOG.md           # Version history
├── CONTRIBUTING.md        # Contribution guidelines
├── TODO.md                # Roadmap
├── pyproject.toml         # Project configuration
└── requirements.txt       # Dependencies (for development)
```

### 🧪 Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage report
python -m pytest tests/ --cov=pysec --cov-report=html

# Run specific test file
python -m pytest tests/test_scanner.py -v
```

### 🔧 Extending Rules

Create custom detection rules:

```python
from pysec.rules.base import BaseRule, register_rule
from pysec.models import Vulnerability
import ast

@register_rule
class MyCustomRule(BaseRule):
    rule_id = "CUSTOM001"
    rule_name = "Custom Rule"
    severity = "medium"
    description = "This is a custom detection rule"

    def check(self, ast_tree, file_path, source_code):
        vulnerabilities = []
        
        for node in ast.walk(ast_tree):
            if self._is_vulnerable(node):
                vuln = self._create_vulnerability(
                    file_path=file_path,
                    line_number=node.lineno,
                    code_snippet=self._get_code_snippet(source_code, node.lineno),
                    suggestion="How to fix this vulnerability"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_vulnerable(self, node):
        # Implement detection logic
        pass
```

See [docs/RULE_GUIDE.md](docs/RULE_GUIDE.md) for detailed guide.

### 📚 Documentation

- [API Documentation](docs/API.md) - Complete API reference
- [Rule Development Guide](docs/RULE_GUIDE.md) - How to create custom rules
- [AST Node Reference](docs/AST_REFERENCE.md) - Python AST node types reference
- [Best Practices](docs/BEST_PRACTICES.md) - Security scanning best practices
- [FAQ](docs/FAQ.md) - Frequently asked questions
- [CONTRIBUTING](CONTRIBUTING.md) - Contribution guidelines
- [CHANGELOG](CHANGELOG.md) - Version history

### 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'feat: add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Create Pull Request

### 📝 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

### 🙏 Acknowledgments

- Thanks to all contributors
- Inspired by Bandit, Semgrep, and other security tools

---

## 中文

### 📖 简介

PySecScanner 是一款基于抽象语法树(AST)分析的轻量级 Python 静态代码安全扫描工具。它能帮助开发者发现 Python 代码中的潜在安全漏洞,支持自动修复,并提供多种格式的报告输出。

**主要特性:**

- 🔍 **AST 深度分析** - 基于抽象语法树进行精确的代码分析
- 🛡️ **23+ 漏洞检测规则** - 涵盖 SQL 注入、命令注入、硬编码凭据、框架特定漏洞等
- 🔧 **自动修复功能** - 支持低风险漏洞的自动修复,提供 diff 预览
- 📊 **多格式报告** - 支持 Text、Markdown、JSON、HTML 等多种报告格式
- 🔌 **可扩展架构** - 插件化的规则系统,便于扩展新的检测规则
- ⚡ **零外部依赖** - 仅使用 Python 标准库,开箱即用
- 🖥️ **命令行友好** - 提供直观的命令行接口,支持彩色输出
- 📝 **配置文件支持** - 支持 `.pysecrc` 和 `pyproject.toml` 配置
- 🚀 **增量扫描** - 支持 Git 增量扫描,仅扫描修改的文件
- 💾 **AST 缓存** - 缓存解析结果,加速重复扫描
- 🎨 **彩色终端** - 彩色输出,基于严重级别的高亮显示
- 🔕 **忽略指令** - 支持行内和块级忽略注释

### 🚀 快速开始

#### 安装

```bash
# 克隆仓库
git clone https://github.com/yourusername/python-security-scanner.git
cd python-security-scanner

# 安装(可选,也可直接运行)
pip install -e .

# 或从 PyPI 安装(即将支持)
pip install pysecscanner
```

#### 基本使用

```bash
# 扫描目录
python main.py scan ./your_project

# 扫描单个文件
python main.py scan app.py

# 生成 Markdown 报告
python main.py scan ./src -o report.md -f markdown

# 生成 HTML 报告
python main.py scan ./src -o report.html -f html

# 排除特定目录
python main.py scan ./src --exclude tests,docs,venv

# 按最低严重级别过滤
python main.py scan ./src --severity high

# 禁用彩色输出
python main.py scan ./src --no-color
```

#### 增量扫描(Git)

```bash
# 仅扫描修改的文件(Git 工作目录)
python main.py scan . --changed-only

# 扫描自指定提交以来修改的文件
python main.py scan . --since HEAD~5

# 扫描与分支的差异
python main.py scan . --since main
```

#### 自动修复

```bash
# 预览修复但不实际应用
python main.py scan ./src --fix --dry-run

# 自动应用修复
python main.py scan ./src --fix

# 交互式确认每个修复
python main.py scan ./src --fix --interactive
```

#### 作为模块使用

```python
from pysec import SecurityScanner

# 创建扫描器
scanner = SecurityScanner()

# 扫描目录
result = scanner.scan("./your_project")

# 查看结果
print(f"发现 {len(result.vulnerabilities)} 个漏洞")
for vuln in result.vulnerabilities:
    print(f"[{vuln.severity}] {vuln.rule_name}: {vuln.file_path}:{vuln.line_number}")

# 增量扫描(仅修改的文件)
result = scanner.scan_changed("./your_project")

# 扫描自指定提交以来的修改
result = scanner.scan_since("./your_project", "main")
```

### 🛡️ 检测规则

#### 核心安全规则

| 规则 ID | 名称              | 严重程度 | 描述                                       |
| ------- | ----------------- | -------- | ------------------------------------------ |
| SQL001  | SQL注入检测       | High     | 检测 SQL 字符串拼接、格式化等不安全操作       |
| CMD001  | 命令注入检测       | Critical | 检测 os.system、subprocess 等危险调用       |
| SEC001  | 硬编码凭据检测     | High     | 检测代码中硬编码的密码、密钥等敏感信息       |
| DNG001  | 危险函数检测       | Critical | 检测 eval、exec、pickle 等危险函数           |
| PTH001  | 路径遍历检测       | High     | 检测可能导致目录遍历的文件操作              |
| XSS001  | XSS漏洞检测        | High     | 检测可能导致跨站脚本攻击的代码              |

#### 附加安全规则

| 规则 ID | 名称              | 严重程度 | 描述                                       |
| ------- | ----------------- | -------- | ------------------------------------------ |
| RND001  | 不安全随机数检测   | Medium   | 检测使用 random 模块生成安全相关随机数     |
| HSH001  | 不安全哈希算法检测 | Medium   | 检测 MD5/SHA1 用于密码哈希                   |
| SSL001  | SSL/TLS配置检测    | High     | 检测 verify=False 和不安全SSL上下文 |
| LOG001  | 日志敏感信息检测   | Medium   | 检测日志记录密码、令牌等敏感信息            |
| SSRF001 | SSRF漏洞检测      | High     | 检测服务端请求伪造漏洞                      |
| XXE001  | XXE漏洞检测       | High     | 检测 XML 外部实体注入风险                    |
| REX001  | ReDoS模式检测     | Medium   | 检测易受 ReDoS 攻击的正则表达式模式         |

#### 框架特定规则

**Django 安全 (DJG001-DJG005)**
- 生产环境 Debug 模式检测
- 硬编码 SECRET_KEY 检测
- 不安全的 ALLOWED_HOSTS 配置
- SQL 查询安全检测
- 不安全的反序列化检测

**Flask 安全 (FLK001-FLK005)**
- Debug 模式检测
- 硬编码 SECRET_KEY 检测
- 不安全的会话配置
- Jinja2 模板注入 (SSTI) 检测
- 不安全的文件上传检测

### ⚙️ 配置文件

支持 `.pysecrc` (YAML) 或 `pyproject.toml` 中的 `[tool.pysec]` 配置节:

```yaml
# .pysecrc
rules:
  enabled:
    - SQL001
    - CMD001
  disabled:
    - SEC001
exclude:
  dirs:
    - tests
    - migrations
  files:
    - "*_test.py"
severity:
  minimum: medium
  overrides:
    SEC001: critical  # 将硬编码凭据升级为严重级别
output:
  format: markdown
  color: true
cache:
  enabled: true
  directory: .pysec_cache
```

### 🚫 忽略指令

```python
# 忽略此行的特定规则
password = "temp123"  # pysec: ignore SEC001

# 忽略此行的所有规则
exec(user_code)  # pysec: ignore

# 忽略多个规则
query = f"SELECT * FROM users WHERE id={uid}"  # pysec: ignore SQL001,CMD001

# 禁用代码块的规则
# pysec: disable SEC001
api_key = "sk-1234567890"
secret = "my-secret"
# pysec: enable SEC001
```

### 📊 报告格式

#### 文本格式(控制台)
彩色终端输出,带严重级别高亮:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 PySecScanner 安全扫描报告
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📈 漏洞统计
  🔴 严重 (Critical): 3
  🟠 高危 (High):     15
  🟡 中危 (Medium):   5
  🟢 低危 (Low):      0
  ━━━━━━━━━━━━━━━━━━━━━━━━
  总计:              23
```

#### Markdown 格式
专业的 Markdown 报告,包含表格和代码片段

#### JSON 格式
机器可读格式,便于 CI/CD 集成

#### HTML 格式
带样式的 HTML 报告,包含语法高亮和图表

### 📁 项目结构

```
python-security-scanner/
├── main.py                 # 主入口
├── pysec/                  # 核心包
│   ├── __init__.py        # 包初始化
│   ├── models.py          # 数据模型 (Vulnerability, FixResult)
│   ├── scanner.py         # 文件扫描器
│   ├── engine.py          # 规则引擎和安全扫描器
│   ├── reporter.py        # 报告生成器
│   ├── cli.py             # 命令行接口
│   ├── config.py          # 配置管理
│   ├── cache.py           # AST 缓存
│   ├── git_utils.py       # Git 工具
│   ├── fixer.py           # 自动修复器
│   ├── colors.py          # 终端颜色支持
│   └── rules/             # 检测规则 (23+ 规则)
│       ├── base.py        # 基础规则类
│       ├── sql_injection.py
│       ├── command_injection.py
│       ├── hardcoded_secrets.py
│       ├── dangerous_functions.py
│       ├── path_traversal.py
│       ├── xss.py
│       ├── insecure_random.py
│       ├── insecure_hash.py
│       ├── insecure_ssl.py
│       ├── log_sensitive.py
│       ├── ssrf.py
│       ├── xxe.py
│       ├── redos.py
│       ├── django_security.py
│       └── flask_security.py
├── tests/                  # 测试文件 (121 测试用例)
├── docs/                   # 文档
│   ├── API.md             # API 文档
│   ├── RULE_GUIDE.md      # 规则开发指南
│   ├── AST_REFERENCE.md   # AST 节点类型参考
│   ├── BEST_PRACTICES.md  # 最佳实践
│   └── FAQ.md             # 常见问题
├── README.md              # 本文件
├── LICENSE                # MIT 许可证
├── CHANGELOG.md           # 版本历史
├── CONTRIBUTING.md        # 贡献指南
├── TODO.md                # 路线图
├── pyproject.toml         # 项目配置
└── requirements.txt       # 依赖(用于开发)
```

### 🧪 运行测试

```bash
# 运行所有测试
python -m pytest tests/ -v

# 运行并生成覆盖率报告
python -m pytest tests/ --cov=pysec --cov-report=html

# 运行特定测试文件
python -m pytest tests/test_scanner.py -v
```

### 🔧 扩展规则

创建自定义检测规则:

```python
from pysec.rules.base import BaseRule, register_rule
from pysec.models import Vulnerability
import ast

@register_rule
class MyCustomRule(BaseRule):
    rule_id = "CUSTOM001"
    rule_name = "自定义规则"
    severity = "medium"
    description = "这是一个自定义检测规则"

    def check(self, ast_tree, file_path, source_code):
        vulnerabilities = []
        
        for node in ast.walk(ast_tree):
            if self._is_vulnerable(node):
                vuln = self._create_vulnerability(
                    file_path=file_path,
                    line_number=node.lineno,
                    code_snippet=self._get_code_snippet(source_code, node.lineno),
                    suggestion="如何修复此漏洞"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_vulnerable(self, node):
        # 实现检测逻辑
        pass
```

详细指南请参见 [docs/RULE_GUIDE.md](docs/RULE_GUIDE.md)。

### 📚 文档

- [API 文档](docs/API.md) - 完整的 API 参考
- [规则开发指南](docs/RULE_GUIDE.md) - 如何创建自定义规则
- [AST 节点参考](docs/AST_REFERENCE.md) - Python AST 节点类型参考
- [最佳实践](docs/BEST_PRACTICES.md) - 安全扫描最佳实践
- [常见问题](docs/FAQ.md) - 常见问题解答
- [贡献指南](CONTRIBUTING.md) - 贡献指南
- [更新日志](CHANGELOG.md) - 版本历史

### 🤝 贡献

欢迎贡献!请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交修改 (`git commit -m 'feat: add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

### 📝 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

### 🙏 致谢

- 感谢所有贡献者
- 受 Bandit、Semgrep 等安全工具启发

---

**Star ⭐ this project if you find it helpful!**
