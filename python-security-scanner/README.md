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

# 生成 JSON 报告
python main.py scan ./src -f json

# 生成 HTML 报告
python main.py scan ./src -o report.html -f html

# 排除特定目录
python main.py scan ./src --exclude tests,docs,venv

# 查看所有规则
python main.py rules

# 查看规则详情
python main.py rules --verbose
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

# 扫描代码片段
vulns = scanner.scan_code('''
query = f"SELECT * FROM users WHERE id = {user_id}"
''')
```

## 🛡️ 检测规则

| 规则 ID | 名称           | 严重程度 | 描述                                     |
| ------- | -------------- | -------- | ---------------------------------------- |
| SQL001  | SQL注入检测    | High     | 检测 SQL 字符串拼接、格式化等不安全操作  |
| CMD001  | 命令注入检测   | Critical | 检测 os.system、subprocess 等危险调用    |
| SEC001  | 硬编码凭据检测 | Medium   | 检测代码中硬编码的密码、密钥等敏感信息   |
| DNG001  | 危险函数检测   | High     | 检测 eval、exec、pickle.loads 等危险函数 |
| PTH001  | 路径遍历检测   | High     | 检测可能导致目录遍历的文件操作           |
| XSS001  | XSS漏洞检测    | High     | 检测可能导致跨站脚本攻击的代码           |

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
│   └── rules/             # 检测规则
│       ├── __init__.py
│       ├── base.py        # 规则基类
│       ├── sql_injection.py
│       ├── command_injection.py
│       ├── hardcoded_secrets.py
│       ├── dangerous_functions.py
│       ├── path_traversal.py
│       └── xss.py
├── tests/                  # 测试文件
│   ├── test_scanner.py
│   └── samples/           # 测试样本
├── docs/                   # 文档
│   └── 项目报告.md
├── requirements.txt
├── pyproject.toml
└── README.md
```

## 🧪 运行测试

```bash
# 运行所有测试
python -m pytest tests/ -v

# 运行测试并生成覆盖率报告
python -m pytest tests/ --cov=pysec --cov-report=html

# 运行特定测试
python -m pytest tests/test_scanner.py -v
```

## 📊 示例输出

### 文本格式

```
============================================================
PySecScanner 安全扫描报告
============================================================

扫描目标: ./example
扫描时间: 2025-01-22 10:30:00
扫描耗时: 0.15 秒
扫描文件: 5 个

----------------------------------------
漏洞统计
----------------------------------------
  严重 (Critical): 1
  高危 (High):     3
  中危 (Medium):   2
  低危 (Low):      0
  总计:            6
```

### Markdown 格式

生成美观的 Markdown 报告，可直接在 GitHub 等平台查看。

### HTML 格式

生成带有样式的 HTML 报告，可在浏览器中查看。

## 🔧 扩展规则

创建新的检测规则非常简单：

```python
from pysec.rules.base import BaseRule, register_rule
from pysec.models import Vulnerability

@register_rule
class MyCustomRule(BaseRule):
    rule_id = "CUSTOM001"
    name = "自定义规则"
    severity = "medium"
    description = "这是一个自定义检测规则"

    def check(self, node, file_path, source_lines):
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
