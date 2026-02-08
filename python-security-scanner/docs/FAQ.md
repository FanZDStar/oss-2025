# Frequently Asked Questions (FAQ)

[English](#english) | [中文](#中文)

---

## English

### General Questions

#### Q: What is PySecScanner?

**A:** PySecScanner is a lightweight Python static code security scanner that analyzes Python code for security vulnerabilities using Abstract Syntax Tree (AST) analysis. It detects issues like SQL injection, command injection, hardcoded secrets, and more.

#### Q: How is PySecScanner different from other security tools?

**A:** PySecScanner differs in several ways:
- **Zero Dependencies**: Uses only Python standard library
- **Lightweight**: Fast scans with AST caching
- **Extensible**: Easy-to-write custom rules
- **Auto-Fix**: Supports automatic vulnerability fixes
- **Framework-Aware**: Includes Django and Flask-specific rules
- **Developer-Friendly**: Colored output, ignore directives, incremental scanning

#### Q: What types of vulnerabilities can PySecScanner detect?

**A:** PySecScanner includes 23+ detection rules covering:
- **Injection**: SQL injection, command injection, XSS, XXE, SSTI
- **Cryptography**: Weak hashing, insecure SSL/TLS, insecure random
- **Secrets**: Hardcoded passwords, API keys, tokens
- **Dangerous Functions**: eval, exec, pickle, compile
- **Framework-Specific**: Django and Flask security issues
- **Other**: Path traversal, SSRF, sensitive logging, ReDoS

See [README.md](../README.md#detection-rules) for complete list.

---

### Installation & Setup

#### Q: How do I install PySecScanner?

**A:** PySecScanner doesn't require installation:

```bash
# Clone repository
git clone https://github.com/yourusername/python-security-scanner.git
cd python-security-scanner

# Run directly
python main.py scan ./your_project
```

Optional: Install as package:
```bash
pip install -e .
```

#### Q: What are the system requirements?

**A:** 
- Python 3.8 or higher
- No external dependencies required
- Works on Windows, macOS, and Linux

#### Q: Can I use PySecScanner without Git?

**A:** Yes! Git is only needed for incremental scanning features (`--changed-only`, `--since`). All other features work without Git.

---

### Usage Questions

#### Q: How do I scan a single file?

**A:**
```bash
python main.py scan path/to/file.py
```

#### Q: How do I scan an entire project?

**A:**
```bash
python main.py scan ./project_directory
```

#### Q: How do I exclude certain directories from scanning?

**A:**
```bash
# Command line
python main.py scan . --exclude tests,venv,docs

# Or use configuration file (.pysecrc)
exclude:
  dirs:
    - tests
    - venv
    - migrations
```

#### Q: Can I filter results by severity?

**A:** Yes:
```bash
# Only show high and critical issues
python main.py scan . --min-severity high

# Only show critical issues
python main.py scan . --min-severity critical
```

####  How do I generate different report formats?

**A:**
```bash
# Markdown report
python main.py scan . -o report.md -f markdown

# JSON report
python main.py scan . -o report.json -f json

# HTML report
python main.py scan . -o report.html -f html

# Console (default)
python main.py scan .
```

#### Q: How do I scan only files I've changed?

**A:**
```bash
# Scan uncommitted changes
python main.py scan . --changed-only

# Scan changes since specific commit
python main.py scan . --since HEAD~5

# Scan differences from branch
python main.py scan . --since main
```

---

### False Positives & Ignoring Issues

#### Q: How do I ignore a specific warning?

**A:** Use inline comments:

```python
# Ignore specific rule
password = "test123"  # pysec: ignore SEC001

# Ignore all rules on this line
exec(code)  # pysec: ignore

# Ignore multiple rules
query = f"SELECT * FROM {table}"  # pysec: ignore SQL001,CMD001
```

#### Q: How do I ignore warnings in a code block?

**A:** Use block-level directives:

```python
# pysec: disable SEC001
API_KEY = "test-key-1234"
SECRET = "test-secret"
PASSWORD = "admin123"
# pysec: enable SEC001
```

#### Q: Can I ignore warnings for an entire file?

**A:** Yes, add comment at top of file:

```python
# pysec: ignore-file

# All warnings in this file will be ignored
```

Or suppress specific rules:
```python
# pysec: ignore-file SEC001,DNG001
```

#### Q: What should I do about false positives?

**A:** 
1. **Verify**: Is it really a false positive?
2. **Contextualize**: Could it be a real issue in some scenarios?
3. **Document**: Add comment explaining why it's safe
4. **Suppress**: Use ignore directive with justification
5. **Report**: If it's a bug in the rule, report it as an issue

Example:
```python
# Safe: This config is for development only, overridden in production
DEBUG = True  # pysec: ignore DJG001
```

---

### Configuration

#### Q: How do I configure PySecScanner?

**A:** Create `.pysecrc` file in project root:

```yaml
rules:
  enabled:
    - SQL001
    - CMD001
  disabled:
    - RND001

exclude:
  dirs:
    - tests
    - venv
  files:
    - "*_test.py"

severity:
  minimum: medium
  overrides:
    SEC001: critical

output:
  format: markdown
  color: true

cache:
  enabled: true
  directory: .pysec_cache
```

Or use `pyproject.toml`:
```toml
[tool.pysec]
min_severity = "high"
exclude_dirs = ["tests", "venv"]
```

#### Q: Can I disable specific rules?

**A:** Yes, in `.pysecrc`:

```yaml
rules:
  disabled:
    - RND001  # Insecure random not relevant for us
    - PRINT001  # Print statements are ok
```

Or command line:
```bash
python main.py scan . --disabled-rules RND001,PRINT001
```

#### Q: Can I change the severity of a rule?

**A:** Yes, use severity overrides:

```yaml
severity:
  overrides:
    SEC001: critical  # Hardcoded secrets are critical for us
    RND001: low       # Insecure random is low risk in our case
```

---

### Advanced Features

#### Q: How does auto-fix work?

**A:** Auto-fix can automatically remediate certain vulnerabilities:

```bash
# Preview fixes without applying
python main.py scan . --fix --dry-run

# Apply fixes automatically
python main.py scan . --fix

# Interactive mode (confirm each fix)
python main.py scan . --fix --interactive
```

Currently supports:
- **SEC001**: Hardcoded secrets → environment variables
- More fix patterns being added

#### Q: What is AST caching and should I enable it?

**A:** AST caching stores parsed Python ASTs to speed up re-scans:

**Enable (recommended):**
```yaml
cache:
  enabled: true
  directory: .pysec_cache
```

**Benefits:**
- 5-10x faster on repeated scans
- Automatically invalidated when files change
- Useful for large codebases

**When to disable:**
- CI/CD (one-time scans)
- Very small projects
- Disk space constraints

#### Q: How do I use PySecScanner in CI/CD?

**A:** Example GitHub Actions:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      
      - name: Security Scan
        run: |
          python main.py scan . --min-severity high --no-color
      
      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: scan-report.json
```

For more examples, see [BEST_PRACTICES.md](BEST_PRACTICES.md#integration-strategies).

#### Q: Can I create custom detection rules?

**A:** Yes! PySecScanner is highly extensible:

```python
from pysec.rules.base import BaseRule, register_rule
from pysec.models import Vulnerability
import ast

@register_rule
class MyCustomRule(BaseRule):
    rule_id = "CUSTOM001"
    rule_name = "My Custom Check"
    severity = "medium"
    description = "Detects custom pattern"
    
    def check(self, ast_tree, file_path, source_code):
        vulnerabilities = []
        # Your detection logic
        return vulnerabilities
```

See [RULE_GUIDE.md](RULE_GUIDE.md) for detailed guide.

---

### Performance

#### Q: How can I make scans faster?

**A:** 
1. **Enable caching**: Speeds up re-scans
   ```yaml
   cache:
     enabled: true
   ```

2. **Use incremental scanning**: Only scan changed files
   ```bash
   python main.py scan . --changed-only
   ```

3. **Exclude unnecessary directories**:
   ```bash
   python main.py scan . --exclude tests,venv,docs
   ```

4. **Disable low-priority rules**:
   ```yaml
   rules:
     disabled:
       - PRINT001
       - RND001
   ```

#### Q: How long does a typical scan take?

**A:** Scan time depends on:
- **Project size**: 1000 files ≈ 5-30 seconds
- **Caching**: 5-10x faster with cache enabled
- **Rule count**: 23 rules by default
- **Hardware**: Faster on SSD, more CPU cores

Benchmarks:
- Small project (100 files): 1-2 seconds
- Medium project (1000 files): 10-15 seconds (first run), 2-3 seconds (cached)
- Large project (10000 files): 2-5 minutes (first run), 20-30 seconds (cached)

#### Q: Can I run scans in parallel?

**A:** PySecScanner itself doesn't parallelize, but you can:

1. **Split by directory**:
   ```bash
   python main.py scan src/api & 
   python main.py scan src/core &
   wait
   ```

2. **Use CI/CD matrix**:
   ```yaml
   strategy:
     matrix:
       dir: [src/api, src/core, src/utils]
   steps:
     - run: python main.py scan ${{ matrix.dir }}
   ```

---

### Troubleshooting

#### Q: I get "No module named 'pysec'" error

**A:** Make sure you're running from the project root:
```bash
cd python-security-scanner
python main.py scan .
```

Or install the package:
```bash
pip install -e .
```

#### Q: Scan finds no Python files

**A:** 
1. Check you're not excluding too much:
   ```bash
   python main.py scan . --exclude ""
   ```

2. Verify Python files exist:
   ```bash
   find . -name "*.py" | head
   ```

3. Check file permissions

#### Q: Colors don't show in terminal

**A:** 
1. **Disable auto-detection**: Use `--no-color` flag
   ```bash
   python main.py scan . --no-color
   ```

2. **Check terminal support**: Some terminals don't support ANSI colors

3. **Windows**: Ensure Windows Terminal or enable ANSI support

#### Q: Scan is very slow

**A:**
1. **Enable caching**:
   ```yaml
   cache:
     enabled: true
   ```

2. **Exclude large directories**:
   ```bash
   python main.py scan . --exclude venv,node_modules,.tox
   ```

3. **Check for very large files**: Scanner may struggle with files >10,000 lines

#### Q: Getting syntax errors when scanning

**A:** PySecScanner parses Python code:
- **Version mismatch**: File uses syntax not supported by your Python version
  - Scanner's Python version must be >= target code version
- **Invalid syntax**: File actually has syntax errors
  ```bash
  python -m py_compile file.py  # Test if file is valid
  ```

---

### Comparison with Other Tools

#### Q: How does PySecScanner compare to Bandit?

**A:**

| Feature | PySecScanner | Bandit |
|---------|--------------|--------|
| Dependencies | None | Multiple |
| Speed | Fast (with cache) | Moderate |
| Auto-fix | Yes | No |
| Custom rules | Easy | Moderate |
| Framework rules | Django, Flask | Generic |
| Ignore directives | Yes | Yes |
| Git integration | Yes | No |

Both are excellent tools. PySecScanner excels at:
- Zero dependencies
- Auto-fixing
- Incremental scanning
- Framework-specific checks

#### Q: Should I use multiple security tools?

**A:** Yes! Layer your security:

```bash
# Static analysis
python main.py scan .          # PySecScanner
bandit -r src/                 # Bandit

# Dependency vulnerabilities
pip-audit                      # pip-audit
safety check                   # Safety

# Type checking (catches some bugs)
mypy src/

# Code quality
flake8 src/
pylint src/
```

Each tool catches different issues.

---

### Getting Help

#### Q: Where can I report bugs or request features?

**A:** 
- **Issues**: https://github.com/yourusername/python-security-scanner/issues
- **Discussions**: https://github.com/yourusername/python-security-scanner/discussions
- **Email**: security@example.com

#### Q: How can I contribute?

**A:** See [CONTRIBUTING.md](../CONTRIBUTING.md):
1. Fork the repository
2. Create a feature branch
3. Add tests for your changes
4. Submit a pull request

Contributions welcome for:
- New detection rules
- Bug fixes
- Documentation improvements
- Performance optimizations

#### Q: Is there a community or chat?

**A:**
- **GitHub Discussions**: Ask questions, share tips
- **Discord**: [Join our server](#) (coming soon)
- **Twitter**: [@pysecscanner](#) (coming soon)

---

## 中文

### 常规问题

#### Q: 什么是 PySecScanner?

**A:** PySecScanner 是一个轻量级的 Python 静态代码安全扫描器,使用抽象语法树(AST)分析来检测 Python 代码中的安全漏洞。它可以检测 SQL 注入、命令注入、硬编码凭据等问题。

#### Q: PySecScanner 与其他安全工具有何不同?

**A:** PySecScanner 在几个方面有所不同:
- **零依赖**: 仅使用 Python 标准库
- **轻量级**: 通过 AST 缓存实现快速扫描
- **可扩展**: 易于编写自定义规则
- **自动修复**: 支持自动修复漏洞
- **框架感知**: 包含 Django 和 Flask 特定规则
- **开发者友好**: 彩色输出、忽略指令、增量扫描

#### Q: PySecScanner 可以检测哪些类型的漏洞?

**A:** PySecScanner 包含 23+ 检测规则,涵盖:
- **注入**: SQL 注入、命令注入、XSS、XXE、SSTI
- **加密**: 弱哈希、不安全 SSL/TLS、不安全随机数
- **凭据**: 硬编码密码、API 密钥、令牌
- **危险函数**: eval、exec、pickle、compile
- **框架特定**: Django 和 Flask 安全问题
- **其他**: 路径遍历、SSRF、敏感日志、ReDoS

完整列表见 [README.md](../README.md#检测规则)。

---

### 安装与设置

#### Q: 如何安装 PySecScanner?

**A:** PySecScanner 不需要安装:

```bash
# 克隆仓库
git clone https://github.com/yourusername/python-security-scanner.git
cd python-security-scanner

# 直接运行
python main.py scan ./your_project
```

可选:安装为包:
```bash
pip install -e .
```

#### Q: 系统要求是什么?

**A:** 
- Python 3.8 或更高版本
- 不需要外部依赖
- 支持 Windows、macOS 和 Linux

#### Q: 可以在没有 Git 的情况下使用 PySecScanner 吗?

**A:** 可以! Git 仅用于增量扫描功能(`--changed-only`、`--since`)。所有其他功能都可以在没有 Git 的情况下工作。

---

### 使用问题

#### Q: 如何扫描单个文件?

**A:**
```bash
python main.py scan path/to/file.py
```

#### Q: 如何扫描整个项目?

**A:**
```bash
python main.py scan ./project_directory
```

#### Q: 如何从扫描中排除某些目录?

**A:**
```bash
# 命令行
python main.py scan . --exclude tests,venv,docs

# 或使用配置文件(.pysecrc)
exclude:
  dirs:
    - tests
    - venv
    - migrations
```

#### Q: 可以按严重性过滤结果吗?

**A:** 可以:
```bash
# 仅显示高危和严重问题
python main.py scan . --min-severity high

# 仅显示严重问题
python main.py scan . --min-severity critical
```

#### Q: 如何生成不同的报告格式?

**A:**
```bash
# Markdown 报告
python main.py scan . -o report.md -f markdown

# JSON 报告
python main.py scan . -o report.json -f json

# HTML 报告
python main.py scan . -o report.html -f html

# 控制台(默认)
python main.py scan .
```

#### Q: 如何仅扫描我更改的文件?

**A:**
```bash
# 扫描未提交的更改
python main.py scan . --changed-only

# 扫描自特定提交以来的更改
python main.py scan . --since HEAD~5

# 扫描与分支的差异
python main.py scan . --since main
```

---

### 误报和忽略问题

#### Q: 如何忽略特定警告?

**A:** 使用行内注释:

```python
# 忽略特定规则
password = "test123"  # pysec: ignore SEC001

# 忽略此行的所有规则
exec(code)  # pysec: ignore

# 忽略多个规则
query = f"SELECT * FROM {table}"  # pysec: ignore SQL001,CMD001
```

#### Q: 如何忽略代码块中的警告?

**A:** 使用块级指令:

```python
# pysec: disable SEC001
API_KEY = "test-key-1234"
SECRET = "test-secret"
PASSWORD = "admin123"
# pysec: enable SEC001
```

#### Q: 可以忽略整个文件的警告吗?

**A:** 可以,在文件顶部添加注释:

```python
# pysec: ignore-file

# 此文件中的所有警告都将被忽略
```

或抑制特定规则:
```python
# pysec: ignore-file SEC001,DNG001
```

#### Q: 对于误报该怎么办?

**A:** 
1. **验证**: 它真的是误报吗?
2. **上下文化**: 在某些场景中可能是真实问题吗?
3. **记录**: 添加注释解释为什么它是安全的
4. **抑制**: 使用带理由的忽略指令
5. **报告**: 如果是规则中的错误,报告为 issue

示例:
```python
# 安全:此配置仅用于开发,在生产中被覆盖
DEBUG = True  # pysec: ignore DJG001
```

---

### 配置

#### Q: 如何配置 PySecScanner?

**A:** 在项目根目录创建 `.pysecrc` 文件:

```yaml
rules:
  enabled:
    - SQL001
    - CMD001
  disabled:
    - RND001

exclude:
  dirs:
    - tests
    - venv
  files:
    - "*_test.py"

severity:
  minimum: medium
  overrides:
    SEC001: critical

output:
  format: markdown
  color: true

cache:
  enabled: true
  directory: .pysec_cache
```

或使用 `pyproject.toml`:
```toml
[tool.pysec]
min_severity = "high"
exclude_dirs = ["tests", "venv"]
```

#### Q: 可以禁用特定规则吗?

**A:** 可以,在 `.pysecrc` 中:

```yaml
rules:
  disabled:
    - RND001  # 不安全随机数对我们不相关
    - PRINT001  # Print 语句可以
```

或命令行:
```bash
python main.py scan . --disabled-rules RND001,PRINT001
```

#### Q: 可以更改规则的严重性吗?

**A:** 可以,使用严重性覆盖:

```yaml
severity:
  overrides:
    SEC001: critical  # 硬编码凭据对我们很严重
    RND001: low       # 不安全随机数在我们的情况下风险低
```

---

### 高级功能

#### Q: 自动修复如何工作?

**A:** 自动修复可以自动修复某些漏洞:

```bash
# 预览修复而不应用
python main.py scan . --fix --dry-run

# 自动应用修复
python main.py scan . --fix

# 交互模式(确认每个修复)
python main.py scan . --fix --interactive
```

当前支持:
- **SEC001**: 硬编码凭据 → 环境变量
- 正在添加更多修复模式

#### Q: 什么是 AST 缓存,我应该启用它吗?

**A:** AST 缓存存储解析的 Python AST 以加速重新扫描:

**启用(推荐):**
```yaml
cache:
  enabled: true
  directory: .pysec_cache
```

**好处:**
- 重复扫描快 5-10 倍
- 文件更改时自动失效
- 对大型代码库有用

**何时禁用:**
- CI/CD(一次性扫描)
- 非常小的项目
- 磁盘空间限制

#### Q: 如何在 CI/CD 中使用 PySecScanner?

**A:** GitHub Actions 示例:

```yaml
name: 安全扫描
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: 设置 Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      
      - name: 安全扫描
        run: |
          python main.py scan . --min-severity high --no-color
      
      - name: 上传报告
        if: always()
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: scan-report.json
```

更多示例见 [BEST_PRACTICES.md](BEST_PRACTICES.md#集成策略)。

#### Q: 可以创建自定义检测规则吗?

**A:** 可以! PySecScanner 高度可扩展:

```python
from pysec.rules.base import BaseRule, register_rule
from pysec.models import Vulnerability
import ast

@register_rule
class MyCustomRule(BaseRule):
    rule_id = "CUSTOM001"
    rule_name = "我的自定义检查"
    severity = "medium"
    description = "检测自定义模式"
    
    def check(self, ast_tree, file_path, source_code):
        vulnerabilities = []
        # 你的检测逻辑
        return vulnerabilities
```

详细指南见 [RULE_GUIDE.md](RULE_GUIDE.md)。

---

### 性能

#### Q: 如何使扫描更快?

**A:** 
1. **启用缓存**: 加速重新扫描
   ```yaml
   cache:
     enabled: true
   ```

2. **使用增量扫描**: 仅扫描更改的文件
   ```bash
   python main.py scan . --changed-only
   ```

3. **排除不必要的目录**:
   ```bash
   python main.py scan . --exclude tests,venv,docs
   ```

4. **禁用低优先级规则**:
   ```yaml
   rules:
     disabled:
       - PRINT001
       - RND001
   ```

#### Q: 典型扫描需要多长时间?

**A:** 扫描时间取决于:
- **项目大小**: 1000 个文件 ≈ 5-30 秒
- **缓存**: 启用缓存快 5-10 倍
- **规则数量**: 默认 23 个规则
- **硬件**: SSD 更快,更多 CPU 核心

基准:
- 小项目(100 个文件): 1-2 秒
- 中型项目(1000 个文件): 10-15 秒(首次运行),2-3 秒(缓存)
- 大型项目(10000 个文件): 2-5 分钟(首次运行),20-30 秒(缓存)

---

### 故障排除

#### Q: 我收到 "No module named 'pysec'" 错误

**A:** 确保你从项目根目录运行:
```bash
cd python-security-scanner
python main.py scan .
```

或安装包:
```bash
pip install -e .
```

#### Q: 扫描找不到 Python 文件

**A:** 
1. 检查你没有排除太多:
   ```bash
   python main.py scan . --exclude ""
   ```

2. 验证 Python 文件存在:
   ```bash
   find . -name "*.py" | head
   ```

3. 检查文件权限

#### Q: 终端中不显示颜色

**A:** 
1. **禁用自动检测**: 使用 `--no-color` 标志
   ```bash
   python main.py scan . --no-color
   ```

2. **检查终端支持**: 某些终端不支持 ANSI 颜色

3. **Windows**: 确保使用 Windows Terminal 或启用 ANSI 支持

#### Q: 扫描非常慢

**A:**
1. **启用缓存**:
   ```yaml
   cache:
     enabled: true
   ```

2. **排除大型目录**:
   ```bash
   python main.py scan . --exclude venv,node_modules,.tox
   ```

3. **检查非常大的文件**: 扫描器可能在 >10,000 行的文件上遇到困难

---

### 与其他工具比较

#### Q: PySecScanner 与 Bandit 相比如何?

**A:**

| 功能 | PySecScanner | Bandit |
|------|--------------|--------|
| 依赖 | 无 | 多个 |
| 速度 | 快(带缓存) | 中等 |
| 自动修复 | 是 | 否 |
| 自定义规则 | 容易 | 中等 |
| 框架规则 | Django, Flask | 通用 |
| 忽略指令 | 是 | 是 |
| Git 集成 | 是 | 否 |

两者都是优秀的工具。PySecScanner 擅长:
- 零依赖
- 自动修复
- 增量扫描
- 框架特定检查

#### Q: 我应该使用多个安全工具吗?

**A:** 是的! 分层你的安全:

```bash
# 静态分析
python main.py scan .          # PySecScanner
bandit -r src/                 # Bandit

# 依赖漏洞
pip-audit                      # pip-audit
safety check                   # Safety

# 类型检查(捕获一些错误)
mypy src/

# 代码质量
flake8 src/
pylint src/
```

每个工具捕获不同的问题。

---

### 获取帮助

#### Q: 在哪里可以报告错误或请求功能?

**A:** 
- **Issues**: https://github.com/yourusername/python-security-scanner/issues
- **Discussions**: https://github.com/yourusername/python-security-scanner/discussions
- **Email**: security@example.com

#### Q: 如何贡献?

**A:** 见 [CONTRIBUTING.md](../CONTRIBUTING.md):
1. Fork 仓库
2. 创建功能分支
3. 为你的更改添加测试
4. 提交拉取请求

欢迎贡献:
- 新检测规则
- Bug 修复
- 文档改进
- 性能优化

---

**Last Updated:** 2026-02-09
