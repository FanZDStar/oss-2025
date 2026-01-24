# 贡献指南

感谢你对 PySecScanner 项目的兴趣！本文档将指导你如何参与项目开发。

## 📋 目录

- [行为准则](#行为准则)
- [如何贡献](#如何贡献)
- [开发环境设置](#开发环境设置)
- [代码规范](#代码规范)
- [提交规范](#提交规范)
- [添加新规则](#添加新规则)
- [测试指南](#测试指南)
- [文档贡献](#文档贡献)

## 行为准则

请尊重所有项目参与者，保持友好和专业的交流环境。

## 如何贡献

### 报告 Bug

1. 在 Issues 中搜索是否已有类似问题
2. 使用 Bug 报告模板创建新 Issue
3. 提供详细的复现步骤和环境信息

### 功能请求

1. 查看 [TODO.md](TODO.md) 了解计划中的功能
2. 在 Issues 中描述你的需求
3. 解释该功能的使用场景

### 提交代码

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交修改 (`git commit -m 'feat: add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 开发环境设置

### 环境要求

- Python 3.8+
- Git

### 安装步骤

```bash
# 克隆仓库
git clone https://github.com/username/pysecscanner.git
cd pysecscanner

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/macOS
# 或
.\venv\Scripts\activate  # Windows

# 安装开发依赖
pip install -e ".[dev]"
```

### 运行测试

```bash
# 运行所有测试
python -m pytest tests/ -v

# 运行测试并生成覆盖率报告
python -m pytest tests/ --cov=pysec --cov-report=html
```

## 代码规范

### Python 代码风格

- 遵循 [PEP 8](https://pep8.org/) 规范
- 使用 Black 格式化代码
- 使用 flake8 进行代码检查
- 行长度限制为 100 字符

```bash
# 格式化代码
black pysec/

# 检查代码风格
flake8 pysec/

# 类型检查
mypy pysec/
```

### 文档字符串

使用 Google 风格的 docstring：

```python
def scan_file(file_path: str, rules: List[BaseRule]) -> List[Vulnerability]:
    """
    扫描单个Python文件。

    Args:
        file_path: 要扫描的文件路径
        rules: 要应用的规则列表

    Returns:
        发现的漏洞列表

    Raises:
        FileNotFoundError: 文件不存在时抛出
    """
    pass
```

## 提交规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### 类型 (type)

- `feat`: 新功能
- `fix`: Bug 修复
- `docs`: 文档更新
- `style`: 代码格式（不影响功能）
- `refactor`: 代码重构
- `test`: 测试相关
- `chore`: 构建/工具相关

### 示例

```
feat(rules): add XXE vulnerability detection

Add new rule XXE001 to detect XML External Entity injection
vulnerabilities in xml.etree and lxml usage.

Closes #123
```

## 添加新规则

### 1. 创建规则文件

在 `pysec/rules/` 目录下创建新文件：

```python
# pysec/rules/my_new_rule.py
"""
新规则的描述
"""

import ast
from typing import List

from .base import BaseRule, register_rule
from ..models import Vulnerability


@register_rule
class MyNewRule(BaseRule):
    """规则类"""

    rule_id = "NEW001"
    rule_name = "规则名称"
    severity = "high"  # critical/high/medium/low
    description = "规则的详细描述"

    def check(self, ast_tree: ast.AST, file_path: str, source_code: str) -> List[Vulnerability]:
        """执行检测"""
        vulnerabilities = []

        for node in ast.walk(ast_tree):
            # 实现检测逻辑
            if self._is_vulnerable(node):
                vuln = self._create_vulnerability(
                    file_path=file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_source_line(source_code, node.lineno),
                    description="检测到的问题描述",
                    suggestion="修复建议"
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_vulnerable(self, node: ast.AST) -> bool:
        """判断节点是否存在漏洞"""
        # 实现判断逻辑
        return False
```

### 2. 注册规则

在 `pysec/rules/__init__.py` 中导入新规则：

```python
from . import my_new_rule
```

### 3. 添加测试

在 `tests/test_scanner.py` 中添加测试用例：

```python
def test_detect_my_new_vulnerability(self):
    """测试新规则检测"""
    code = '''
    # 包含漏洞的代码示例
    '''
    result = self.scanner.scan_code(code)
    rule_ids = [v.rule_id for v in result.vulnerabilities]
    self.assertIn("NEW001", rule_ids)
```

### 4. 添加测试样本

在 `tests/samples/vulnerable_code.py` 中添加漏洞代码示例。

## 测试指南

### 测试结构

```
tests/
├── __init__.py
├── test_scanner.py      # 主测试文件
├── test_rules.py        # 规则测试（可选）
└── samples/             # 测试样本
    ├── vulnerable_code.py
    └── safe_code.py
```

### 编写测试

```python
class TestMyNewRule(unittest.TestCase):
    """测试新规则"""

    def setUp(self):
        self.scanner = SecurityScanner()

    def test_detect_vulnerability(self):
        """应该检测到漏洞"""
        code = "vulnerable code here"
        result = self.scanner.scan_code(code)
        self.assertGreater(len(result.vulnerabilities), 0)

    def test_no_false_positive(self):
        """不应该产生误报"""
        code = "safe code here"
        result = self.scanner.scan_code(code)
        new_vulns = [v for v in result.vulnerabilities if v.rule_id == "NEW001"]
        self.assertEqual(len(new_vulns), 0)
```

### 运行特定测试

```bash
# 运行特定测试类
python -m pytest tests/test_scanner.py::TestMyNewRule -v

# 运行特定测试方法
python -m pytest tests/test_scanner.py::TestMyNewRule::test_detect_vulnerability -v
```

## 文档贡献

### 文档结构

```
docs/
├── 项目报告.md          # 项目文档
├── api/                 # API文档（计划中）
└── guides/              # 使用指南（计划中）
```

### 文档规范

- 使用 Markdown 格式
- 代码示例应可运行
- 保持中英文一致性

---

## ❓ 问题？

如果你有任何问题，请：

1. 查看现有 Issues
2. 阅读项目文档
3. 创建新 Issue 提问

感谢你的贡献！ 🎉
