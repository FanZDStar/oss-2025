# PySecScanner

> Python 代码安全漏洞静态分析工具

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📖 简介

PySecScanner 是一个基于 AST（抽象语法树）的 Python 代码安全漏洞静态分析工具。它能够自动扫描 Python 代码中的常见安全漏洞，帮助开发者在早期发现并修复安全问题。

### 主要特性

- 🔍 **AST 深度分析** - 基于抽象语法树进行精确的代码分析
- 🎯 **多种漏洞检测** - 支持 SQL 注入、命令注入、硬编码凭据等多种漏洞类型
- 📊 **多格式报告** - 支持 Text、Markdown、JSON、HTML 等多种报告格式
- 🔌 **可扩展架构** - 插件化的规则系统，便于扩展新的检测规则
- ⚡ **零外部依赖** - 仅使用 Python 标准库，开箱即用
- 🖥️ **命令行友好** - 提供直观的命令行接口
- 📝 **配置文件支持** - 支持 `.pysecrc` 和 `pyproject.toml` 配置
- 🚀 **增量扫描** - 支持 Git 增量扫描，仅扫描修改的文件
- 💾 **AST 缓存** - 缓存解析结果，加速重复扫描

## 🚀 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/username/pysecscanner.git
cd pysecscanner

# 安装（可选，也可直接运行）
pip install -e .
```

### 基本使用

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

# 查看所有规则
python main.py rules --verbose
```

### 增量扫描（Git）

```bash
# 仅扫描自上次提交以来修改的文件
python main.py scan . --changed-only

# 扫描自指定提交/分支以来修改的文件
python main.py scan . --since HEAD~5
python main.py scan . --since main

# 禁用缓存强制重新解析
python main.py scan . --no-cache
```

### 作为模块使用

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

# 增量扫描（仅修改的文件）
result = scanner.scan_changed("./your_project")

# 扫描自指定提交以来的修改
result = scanner.scan_since("./your_project", "main")
```

## 🛡️ 检测规则

| 规则 ID | 名称           | 严重程度 | 描述                                     |
| ------- | -------------- | -------- | ---------------------------------------- |
| SQL001  | SQL注入检测    | High     | 检测 SQL 字符串拼接、格式化等不安全操作  |
| CMD001  | 命令注入检测   | Critical | 检测 os.system、subprocess 等危险调用    |
| SEC001  | 硬编码凭据检测 | Medium   | 检测代码中硬编码的密码、密钥等敏感信息   |
| DNG001  | 危险函数检测   | Critical | 检测 eval、exec、pickle 等危险函数       |
| PTH001  | 路径遍历检测   | High     | 检测可能导致目录遍历的文件操作           |
| XSS001  | XSS漏洞检测    | High     | 检测可能导致跨站脚本攻击的代码           |

## ⚙️ 配置文件

支持 `.pysecrc` (YAML) 或 `pyproject.toml` 中的 `[tool.pysec]` 配置节：

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
output:
  format: markdown
  color: true
```

## 📁 项目结构

```
python-security-scanner/
├── main.py                 # 主入口
├── pysec/                  # 核心包
│   ├── __init__.py        # 包初始化
│   ├── models.py          # 数据模型
│   ├── scanner.py         # 文件扫描器
│   ├── engine.py          # 规则引擎
│   ├── reporter.py        # 报告生成器
│   ├── cli.py             # 命令行接口
│   ├── config.py          # 配置管理
│   ├── cache.py           # AST 缓存
│   ├── git_utils.py       # Git 工具
│   └── rules/             # 检测规则
├── tests/                  # 测试文件
└── docs/                   # 文档
```

## 🧪 运行测试

```bash
# 运行所有测试
python -m pytest tests/ -v

# 运行测试并生成覆盖率报告
python -m pytest tests/ --cov=pysec --cov-report=html
```

##  扩展规则

创建新的检测规则：

```python
from pysec.rules.base import BaseRule, register_rule
from pysec.models import Vulnerability

@register_rule
class MyCustomRule(BaseRule):
    rule_id = "CUSTOM001"
    rule_name = "自定义规则"
    severity = "medium"
    description = "这是一个自定义检测规则"

    def check(self, ast_tree, file_path, source_code):
        vulnerabilities = []
        # 实现检测逻辑
        return vulnerabilities
```

## 📝 License

本项目采用 MIT 协议开源。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

**PySecScanner** - 让 Python 代码更安全 🛡️
