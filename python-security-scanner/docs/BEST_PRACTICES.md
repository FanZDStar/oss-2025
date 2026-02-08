# Security Scanning Best Practices

[English](#english) | [中文](#中文)

---

## English

### Table of Contents

- [Introduction](#introduction)
- [When to Scan](#when-to-scan)
- [Integration Strategies](#integration-strategies)
- [Interpreting Results](#interpreting-results)
- [Reducing False Positives](#reducing-false-positives)
- [Performance Optimization](#performance-optimization)
- [Security Best Practices](#security-best-practices)
- [Team Workflow](#team-workflow)

---

### Introduction

Static security scanning is most effective when integrated into your development workflow. This guide provides best practices for using PySecScanner to improve your application security.

**Key Principles:**
- **Shift Left**: Catch issues early in development
- **Automate**: Integrate scanning into CI/CD pipelines
- **Prioritize**: Focus on high-severity issues first
- **Educate**: Use scan results as learning opportunities
- **Iterate**: Continuously improve your security posture

---

### When to Scan

#### During Development (Pre-Commit)

**Recommendation:** Scan changed files before committing.

```bash
# Scan only modified files
python main.py scan . --changed-only

# Or scan since last commit
python main.py scan . --since HEAD~1
```

**Benefits:**
- Immediate feedback
- Prevents vulnerable code from entering repository
- Minimal performance impact (only scans changes)

**Setup Git Hook:**
```bash
# .git/hooks/pre-commit
#!/bin/bash
python main.py scan . --changed-only --min-severity high --no-color
if [ $? -ne 0 ]; then
    echo "❌ Security issues found! Fix them before committing."
    exit 1
fi
```

#### During Code Review (Pull Request)

**Recommendation:** Scan PR changes automatically.

```bash
# In CI/CD pipeline
python main.py scan . --since origin/main
```

**Benefits:**
- Catches issues before merge
- Provides context for reviewers
- Enforces security standards

**GitHub Actions Example:**
```yaml
name: Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
        with:
          fetch-depth: 0  # Full history for --since
      
      - name: Run Security Scan
        run: |
          python main.py scan . --since origin/${{ github.base_ref }} \
            --format markdown --output report.md
      
      - name: Comment PR
        uses: actions/github-script@v5
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('report.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: report
            });
```

#### Scheduled Scans (Nightly Builds)

**Recommendation:** Full scan of entire codebase regularly.

```bash
# Comprehensive scan
python main.py scan . --format html --output security-report.html
```

**Benefits:**
- Discovers issues in older code
- Tracks security metrics over time
- Detects new vulnerabilities from rule updates

**Cron Example:**
```bash
# Run every night at 2 AM
0 2 * * * cd /path/to/project && python main.py scan . -o /reports/scan-$(date +\%Y\%m\%d).json -f json
```

#### Before Deployment (Release Gate)

**Recommendation:** Scan and enforce severity thresholds.

```bash
# Fail if critical or high severity issues found
python main.py scan . --min-severity high
```

**Benefits:**
- Prevents vulnerable code from reaching production
- Clear go/no-go decision criteria
- Compliance documentation

---

### Integration Strategies

#### CLI Integration

**Local Development:**
```bash
# Quick scan with colored output
python main.py scan src/

# Focused scan on specific directory
python main.py scan src/api/ --min-severity high

# Exclude test files
python main.py scan . --exclude tests,docs,venv
```

#### Python API Integration

**Custom Scripts:**
```python
from pysec import SecurityScanner, ScanConfig

# Configure scanner
config = ScanConfig(
    exclude_dirs=["tests", "venv", ".git"],
    min_severity="high",
    severity_overrides={
        "SEC001": "critical"  # Hardcoded secrets are critical
    }
)

scanner = SecurityScanner(config)
result = scanner.scan("./src")

# Custom handling
critical = [v for v in result.vulnerabilities if v.severity == "critical"]
if len(critical) > 0:
    print(f"❌ Found {len(critical)} critical issues!")
    for vuln in critical:
        print(f"  {vuln.file_path}:{vuln.line_number} - {vuln.rule_name}")
    sys.exit(1)
```

#### CI/CD Integration

**GitLab CI:**
```yaml
security-scan:
  stage: test
  script:
    - python main.py scan . --format json --output scan-results.json
    - python main.py scan . --min-severity high  # Fail on high severity
  artifacts:
    paths:
      - scan-results.json
    reports:
      junit: scan-results.json
```

**Jenkins:**
```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                sh 'python main.py scan . --format json --output scan.json'
                
                script {
                    def result = readJSON file: 'scan.json'
                    def critical = result.summary.critical
                    
                    if (critical > 0) {
                        error("Found ${critical} critical security issues!")
                    }
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'scan.json'
        }
    }
}
```

---

### Interpreting Results

#### Understanding Severity Levels

| Severity | Meaning | Action |
|----------|---------|--------|
| **Critical** | Immediate security risk, easily exploitable | Fix immediately, block deployment |
| **High** | Significant security risk, requires attention | Fix before next release |
| **Medium** | Potential security issue, context-dependent | Review and fix or suppress with justification |
| **Low** | Minor issue or code smell | Fix when convenient, good cleanup target |

#### Analyzing Vulnerabilities

**For Each Vulnerability:**

1. **Verify**: Is this a real issue or false positive?
2. **Contextualize**: What's the actual risk in your application?
3. **Prioritize**: Based on:
   - Exposure (public vs internal API)
   - Data sensitivity
   - User privilege level
   - Exploitability

**Example Analysis:**
```
🔴 [CRITICAL] CMD001: Command Injection
File: api/admin.py:45
Code: os.system("rm " + file_path)

✅ REAL ISSUE - High Risk
- Used in admin endpoint (privileged)
- file_path comes from user input
- No input validation
- Easy to exploit

Priority: P0 - Fix immediately
```

```
🟡 [MEDIUM] RND001: Insecure Random
File: utils/token.py:12
Code: token = ''.join(random.choices(string.ascii_letters, k=16))

⚠️ CONTEXT-DEPENDENT
- Used for password reset tokens (security-sensitive)
- random module is not cryptographically secure
- Should use secrets module

Priority: P1 - Fix in next sprint
```

```
🟢 [LOW] PRINT001: Print Statement
File: tests/test_utils.py:56
Code: print(result)

❌ FALSE POSITIVE (Test File)
- Located in test file
- Not in production code
- Can suppress or ignore

Priority: P3 - Cleanup when convenient
```

---

### Reducing False Positives

#### 1. Use Ignore Directives

**Inline Ignore:**
```python
# Justified use case - admin debugging tool
debug_output = eval(expression)  # pysec: ignore DNG001
```

**Block Ignore:**
```python
# pysec: disable SEC001
# These are example credentials for testing
API_KEY = "test-key-12345"
SECRET = "test-secret"
# pysec: enable SEC001
```

**Best Practice:**
- Always add a comment explaining why you're ignoring
- Review ignored issues periodically
- Prefer fixing over ignoring

#### 2. Configure Exclusions

**`.pysecrc`:**
```yaml
exclude:
  dirs:
    - tests
    - docs
    - migrations
    - venv
  files:
    - "*_test.py"
    - "test_*.py"
    - "conftest.py"
```

#### 3. Adjust Severity Levels

For patterns that are low-risk in your context:

```yaml
severity:
  overrides:
    RND001: low      # Non-security random is ok in our app
    PRINT001: low    # Print statements are for debugging
```

#### 4. Create Custom Rules

If you get too many false positives from a rule, fork it and add context-aware logic:

```python
@register_rule
class CustomSQLInjectionRule(SQLInjectionRule):
    """Extended SQL injection rule with ORM awareness"""
    
    def check(self, ast_tree, file_path, source_code):
        vulns = super().check(ast_tree, file_path, source_code)
        
        # Filter out false positives
        return [v for v in vulns if not self._is_orm_query(v)]
    
    def _is_orm_query(self, vuln):
        # Check if using safe ORM methods
        return "objects.filter" in vuln.code_snippet
```

---

### Performance Optimization

#### 1. Use AST Caching

**Enable in config:**
```yaml
cache:
  enabled: true
  directory: .pysec_cache
```

**Benefits:**
- 5-10x faster on repeated scans
- Especially useful for large codebases
- Automatically invalidated when files change

#### 2. Incremental Scanning

```bash
# Only scan modified files
python main.py scan . --changed-only

# Faster than full scan
python main.py scan . --since HEAD~10
```

**When to Use:**
- Pre-commit hooks (sub-second scans)
- Pull request checks
- Iterative development

#### 3. Parallelize in CI/CD

Split large codebases:

```yaml
# GitHub Actions - matrix strategy
jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        dir: [src/api, src/core, src/utils]
    steps:
      - run: python main.py scan ${{ matrix.dir }}
```

#### 4. Exclude Large Directories

```bash
# Exclude dependencies
python main.py scan . --exclude venv,node_modules,.tox,build,dist
```

---

### Security Best Practices

#### 1. Don't Commit Secrets to Git

Even if you ignore them in scanning:

```bash
# Use environment variables
export DATABASE_URL="postgresql://user:pass@localhost/db"

# Or .env files (add to .gitignore)
echo "DATABASE_URL=..." > .env
```

**If you already committed secrets:**
```bash
# Remove from Git history
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch config/secrets.py" \
  --prune-empty --tag-name-filter cat -- --all

# Rotate the compromised secrets
```

#### 2. Fix Root Causes

Don't just suppress issues:

```python
# ❌ Bad: Suppress without fixing
password = "hardcoded123"  # pysec: ignore SEC001

# ✅ Good: Use proper secrets management
import os
password = os.environ["APP_PASSWORD"]
```

#### 3. Use Auto-Fix Carefully

Review changes before applying:

```bash
# Preview fixes
python main.py scan . --fix --dry-run

# Review each change
python main.py scan . --fix --interactive

# Auto-apply (only for trusted rules)
python main.py scan . --fix
```

#### 4. Combine Multiple Tools

PySecScanner is one layer:

```bash
# Security scanning
python main.py scan .

# Dependency vulnerabilities
pip-audit

# License compliance
pip-licenses

# Code quality
flake8
pylint
```

---

### Team Workflow

#### 1. Establish Severity Policies

**Example Policy:**

| Severity | Policy |
|----------|--------|
| Critical | Must fix before commit |
| High | Must fix before PR merge |
| Medium | Must fix before release |
| Low | Fix or justify/suppress |

#### 2. Security Champions

Designate team members to:
- Review security scan results
- Triage false positives
- Update scanning configuration
- Educate team on security patterns

#### 3. Regular Security Reviews

**Weekly:**
- Review new vulnerabilities
- Update ignore lists
- Check for pattern trends

**Monthly:**
- Full codebase scan
- Update scanning rules
- Review security metrics

**Quarterly:**
- Review and rotate ignored issues
- Security training
- Tool evaluation

#### 4. Documentation

Track decisions:

```markdown
## Suppressed Vulnerabilities

### SEC001 in config/defaults.py:23
- **Date:** 2026-01-15
- **Reason:** Example configuration file, not used in production
- **Reviewer:** @security-champion
- **Next Review:** 2026-04-15
```

#### 5. Metrics and Reporting

Track progress:

```python
# Weekly security metrics
from pysec import SecurityScanner
import json
from datetime import datetime

scanner = SecurityScanner()
result = scanner.scan(".")

metrics = {
    "date": datetime.now().isoformat(),
    "total": len(result.vulnerabilities),
    "by_severity": result.summary(),
    "files_scanned": result.file_count,
    "scan_time": result.scan_time
}

# Append to metrics log
with open("security-metrics.jsonl", "a") as f:
    f.write(json.dumps(metrics) + "\n")
```

**Visualize trends:**
- Vulnerability count over time
- Mean time to fix
- Most common vulnerability types
- Coverage (files scanned / total files)

---

## 中文

### 目录

- [简介](#简介)
- [何时扫描](#何时扫描)
- [集成策略](#集成策略)
- [解读结果](#解读结果)
- [减少误报](#减少误报)
- [性能优化](#性能优化)
- [安全最佳实践](#安全最佳实践)
- [团队工作流](#团队工作流)

---

### 简介

当静态安全扫描集成到开发工作流程中时最为有效。本指南提供了使用 PySecScanner 提高应用程序安全性的最佳实践。

**关键原则:**
- **左移**: 在开发早期发现问题
- **自动化**: 将扫描集成到 CI/CD 管道
- **优先级**: 首先关注高严重性问题
- **教育**: 将扫描结果用作学习机会
- **迭代**: 持续改进安全态势

---

### 何时扫描

#### 开发期间(提交前)

**建议:** 在提交前扫描更改的文件。

```bash
# 仅扫描修改的文件
python main.py scan . --changed-only

# 或扫描自上次提交以来的更改
python main.py scan . --since HEAD~1
```

**好处:**
- 即时反馈
- 防止有漏洞的代码进入仓库
- 性能影响最小(仅扫描更改)

**设置 Git 钩子:**
```bash
# .git/hooks/pre-commit
#!/bin/bash
python main.py scan . --changed-only --min-severity high --no-color
if [ $? -ne 0 ]; then
    echo "❌ 发现安全问题! 请在提交前修复。"
    exit 1
fi
```

#### 代码审查期间(Pull Request)

**建议:** 自动扫描 PR 更改。

```bash
# 在 CI/CD 管道中
python main.py scan . --since origin/main
```

**好处:**
- 在合并前发现问题
- 为审查者提供上下文
- 强制执行安全标准

**GitHub Actions 示例:**
```yaml
name: 安全扫描
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
        with:
          fetch-depth: 0  # 完整历史记录用于 --since
      
      - name: 运行安全扫描
        run: |
          python main.py scan . --since origin/${{ github.base_ref }} \
            --format markdown --output report.md
      
      - name: 评论 PR
        uses: actions/github-script@v5
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('report.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: report
            });
```

#### 定期扫描(夜间构建)

**建议:** 定期对整个代码库进行全面扫描。

```bash
# 全面扫描
python main.py scan . --format html --output security-report.html
```

**好处:**
- 发现旧代码中的问题
- 随时间跟踪安全指标
- 从规则更新中检测新漏洞

**Cron 示例:**
```bash
# 每晚凌晨 2 点运行
0 2 * * * cd /path/to/project && python main.py scan . -o /reports/scan-$(date +\%Y\%m\%d).json -f json
```

#### 部署前(发布门)

**建议:** 扫描并强制执行严重性阈值。

```bash
# 如果发现严重或高危问题则失败
python main.py scan . --min-severity high
```

**好处:**
- 防止有漏洞的代码到达生产环境
- 清晰的通过/不通过决策标准
- 合规性文档

---

### 集成策略

#### CLI 集成

**本地开发:**
```bash
# 带彩色输出的快速扫描
python main.py scan src/

# 针对特定目录的集中扫描
python main.py scan src/api/ --min-severity high

# 排除测试文件
python main.py scan . --exclude tests,docs,venv
```

#### Python API 集成

**自定义脚本:**
```python
from pysec import SecurityScanner, ScanConfig

# 配置扫描器
config = ScanConfig(
    exclude_dirs=["tests", "venv", ".git"],
    min_severity="high",
    severity_overrides={
        "SEC001": "critical"  # 硬编码凭据是严重级别
    }
)

scanner = SecurityScanner(config)
result = scanner.scan("./src")

# 自定义处理
critical = [v for v in result.vulnerabilities if v.severity == "critical"]
if len(critical) > 0:
    print(f"❌ 发现 {len(critical)} 个严重问题!")
    for vuln in critical:
        print(f"  {vuln.file_path}:{vuln.line_number} - {vuln.rule_name}")
    sys.exit(1)
```

---

### 解读结果

#### 理解严重级别

| 严重性 | 含义 | 行动 |
|--------|------|------|
| **Critical** | 立即的安全风险,易于利用 | 立即修复,阻止部署 |
| **High** | 重大安全风险,需要关注 | 在下一个版本前修复 |
| **Medium** | 潜在安全问题,取决于上下文 | 审查并修复或提供理由抑制 |
| **Low** | 次要问题或代码异味 | 方便时修复,良好的清理目标 |

#### 分析漏洞

**对于每个漏洞:**

1. **验证**: 这是真实问题还是误报?
2. **上下文化**: 在你的应用中实际风险是什么?
3. **优先级**: 基于:
   - 暴露程度(公共 vs 内部 API)
   - 数据敏感性
   - 用户权限级别
   - 可利用性

---

### 减少误报

#### 1. 使用忽略指令

**行内忽略:**
```python
# 合理的使用场景 - 管理员调试工具
debug_output = eval(expression)  # pysec: ignore DNG001
```

**块级忽略:**
```python
# pysec: disable SEC001
# 这些是用于测试的示例凭据
API_KEY = "test-key-12345"
SECRET = "test-secret"
# pysec: enable SEC001
```

**最佳实践:**
- 始终添加注释解释为什么忽略
- 定期审查被忽略的问题
- 优先修复而非忽略

---

### 性能优化

#### 1. 使用 AST 缓存

**在配置中启用:**
```yaml
cache:
  enabled: true
  directory: .pysec_cache
```

**好处:**
- 重复扫描快 5-10 倍
- 对大型代码库特别有用
- 文件更改时自动失效

#### 2. 增量扫描

```bash
# 仅扫描修改的文件
python main.py scan . --changed-only

# 比全面扫描更快
python main.py scan . --since HEAD~10
```

---

### 安全最佳实践

#### 1. 不要将凭据提交到 Git

即使在扫描中忽略它们:

```bash
# 使用环境变量
export DATABASE_URL="postgresql://user:pass@localhost/db"

# 或 .env 文件(添加到 .gitignore)
echo "DATABASE_URL=..." > .env
```

#### 2. 修复根本原因

不要只是抑制问题:

```python
# ❌ 不好: 抑制而不修复
password = "hardcoded123"  # pysec: ignore SEC001

# ✅ 好: 使用适当的凭据管理
import os
password = os.environ["APP_PASSWORD"]
```

---

### 团队工作流

#### 1. 建立严重性策略

**示例策略:**

| 严重性 | 策略 |
|--------|------|
| Critical | 提交前必须修复 |
| High | PR 合并前必须修复 |
| Medium | 发布前必须修复 |
| Low | 修复或提供理由/抑制 |

#### 2. 安全冠军

指定团队成员:
- 审查安全扫描结果
- 分类误报
- 更新扫描配置
- 教育团队安全模式

#### 3. 定期安全审查

**每周:**
- 审查新漏洞
- 更新忽略列表
- 检查模式趋势

**每月:**
- 全代码库扫描
- 更新扫描规则
- 审查安全指标

**每季度:**
- 审查和轮换被忽略的问题
- 安全培训
- 工具评估

---

**Last Updated:** 2026-02-09
