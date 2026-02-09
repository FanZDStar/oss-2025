# PySecScanner 功能扩展计划

> 本文档记录 PySecScanner 项目的功能扩展计划和待办事项，用于指导后续开发工作。

## 📋 目录

- [Phase 1: 核心功能增强](#phase-1-核心功能增强)
- [Phase 2: 新增检测规则](#phase-2-新增检测规则)
- [Phase 3: 报告与可视化](#phase-3-报告与可视化)
- [Phase 4: 集成与自动化](#phase-4-集成与自动化)
- [Phase 5: 性能与体验优化](#phase-5-性能与体验优化)
- [Phase 6: 文档与生态](#phase-6-文档与生态)

---

## Phase 1: 核心功能增强

### 1.1 配置文件支持 ✅

**优先级:** 高  
**预计工作量:** 2-3 小时

- [x] 支持 `.pysecrc` YAML/TOML 配置文件
- [x] 支持 `pyproject.toml` 中的 `[tool.pysec]` 配置节
- [x] 配置项包括：
  - 启用/禁用的规则列表
  - 排除的目录和文件模式
  - 自定义严重程度阈值
  - 输出格式偏好
- [x] 配置文件自动发现（从当前目录向上查找）
- [x] 命令行参数优先级高于配置文件

**示例配置:**

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

### 1.2 增量扫描功能 ✅

**优先级:** 高  
**预计工作量:** 3-4 小时

- [x] 基于 Git diff 的增量扫描
- [x] 仅扫描自上次提交以来修改的文件
- [x] 支持指定基准提交/分支进行比较
- [x] 缓存 AST 解析结果，加速重复扫描
- [x] 实现 `--changed-only` 和 `--since <commit>` 参数

```bash
# 使用示例
pysec scan . --changed-only
pysec scan . --since HEAD~5
pysec scan . --since main
```

### 1.3 忽略规则注释 ✅

**优先级:** 高  
**预计工作量:** 2 小时

- [x] 支持行内忽略注释 `# pysec: ignore`
- [x] 支持指定规则忽略 `# pysec: ignore[SQL001]`
- [x] 支持代码块忽略 `# pysec: disable` ... `# pysec: enable`
- [x] 支持文件级别忽略 `# pysec: ignore-file`
- [x] 在报告中标注被忽略的漏洞数量

```python
# 忽略这一行
password = "secret123"  # pysec: ignore[SEC001]

# pysec: disable
# 这个代码块中的所有问题都会被忽略
eval(user_input)
exec(code)
# pysec: enable
```

### 1.4 严重程度自定义 ✅

**优先级:** 中  
**预计工作量:** 1-2 小时

- [x] 允许用户自定义规则严重程度
- [x] 配置文件中指定覆盖级别
- [x] 支持基于上下文的动态严重程度调整
- [x] 实现 `--min-severity` 过滤参数

```yaml
severity_overrides:
  SQL001: critical # 将SQL注入提升为critical
  PTH001: low # 将路径遍历降为low
```

### 1.5 修复建议增强 ✅

**优先级:** 中  
**预计工作量:** 3-4 小时

- [x] 提供具体的代码修复示例
- [x] 实现自动修复功能（--fix 参数）
- [x] 安全的自动修复仅针对低风险场景
- [x] 生成 diff 格式的修复建议
- [x] 交互式修复确认模式

```bash
pysec scan . --fix              # 自动修复所有可修复问题
pysec scan . --fix --dry-run    # 仅显示修复预览
pysec scan . --fix --interactive # 交互式确认每个修复
```

---

## Phase 2: 新增检测规则

### 2.1 不安全的反序列化检测 ✅

**规则ID:** DNG001（已合并到危险函数检测规则中）  
**严重程度:** Critical  
**预计工作量:** 2 小时

- [x] 检测 `marshal.loads()` 不安全反序列化
- [x] 检测 `shelve.open()` 不安全使用
- [x] 检测 `jsonpickle.decode()` 风险
- [x] 检测 `dill.loads()` 风险
- [x] 提供安全的替代方案建议

### 2.2 不安全的随机数生成 ✅

**规则ID:** RND001  
**严重程度:** Medium  
**预计工作量:** 1.5 小时

- [x] 检测 `random.random()` 用于安全场景
- [x] 检测 `random.randint()` 生成密钥/令牌
- [x] 推荐使用 `secrets` 模块
- [x] 区分安全上下文和非安全上下文

```python
# 危险：使用random生成token
token = ''.join(random.choices(string.ascii_letters, k=32))

# 安全：使用secrets模块
token = secrets.token_urlsafe(32)
```

### 2.3 不安全的哈希算法 ✅

**规则ID:** HSH001  
**严重程度:** Medium  
**预计工作量:** 2 小时

- [x] 检测 MD5 用于密码哈希
- [x] 检测 SHA1 用于安全场景
- [x] 检测弱哈希算法的使用
- [x] 推荐 bcrypt/argon2/scrypt
- [x] 检测明文密码比较

```python
# 危险
password_hash = hashlib.md5(password.encode()).hexdigest()

# 安全
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

### 2.4 不安全的SSL/TLS配置 ✅

**规则ID:** SSL001  
**严重程度:** High  
**预计工作量:** 2 小时

- [x] 检测 `verify=False` 禁用证书验证
- [x] 检测 `ssl._create_unverified_context()`
- [x] 检测过时的 SSL/TLS 版本
- [x] 检测不安全的密码套件配置

```python
# 危险
requests.get(url, verify=False)
ssl._create_unverified_context()

# 安全
requests.get(url, verify=True)
ssl.create_default_context()
```

### 2.5 日志敏感信息泄露 ✅

**规则ID:** LOG001  
**严重程度:** Medium  
**预计工作量:** 2 小时

- [x] 检测日志中包含密码变量
- [x] 检测日志中包含令牌/密钥
- [x] 检测日志中包含用户敏感数据
- [x] 检测 f-string 格式化敏感变量到日志

```python
# 危险
logger.info(f"User login: {username}, password: {password}")

# 安全
logger.info(f"User login: {username}")
```

### 2.6 SSRF (服务端请求伪造) ✅

**规则ID:** SSRF001  
**严重程度:** High  
**预计工作量:** 2.5 小时

- [x] 检测用户输入直接作为URL
- [x] 检测 `requests.get(user_url)`
- [x] 检测 `urllib.request.urlopen(user_url)`
- [x] 推荐URL白名单验证

```python
# 危险
url = request.args.get('url')
response = requests.get(url)

# 安全
url = request.args.get('url')
if is_allowed_domain(url):
    response = requests.get(url)
```

### 2.7 XML外部实体注入 (XXE) ✅

**规则ID:** XXE001  
**严重程度:** High  
**预计工作量:** 2 小时

- [x] 检测 `xml.etree.ElementTree` 不安全解析
- [x] 检测 `lxml` 外部实体解析
- [x] 检测 `xml.sax` 不安全配置
- [x] 推荐 `defusedxml` 库

```python
# 危险
tree = ET.parse(user_file)

# 安全
import defusedxml.ElementTree as ET
tree = ET.parse(user_file)
```

### 2.8 正则表达式DoS (ReDoS) ✅

**规则ID:** REX001  
**严重程度:** Medium  
**预计工作量:** 3 小时

- [x] 检测灾难性回溯正则表达式
- [x] 识别嵌套量词 `(a+)+`
- [x] 识别重叠交替 `(a|a)+`
- [x] 推荐设置超时或使用 `re2`

```python
# 危险：可能导致ReDoS
pattern = r'(a+)+$'
re.match(pattern, user_input)

# 安全：使用google-re2
import re2
re2.match(pattern, user_input)
```

### 2.9 Django特定安全检测 ✅

**规则ID:** DJG001-DJG005  
**严重程度:** 各异  
**完成时间:** 4 小时

- [x] 检测 `DEBUG = True` 在生产环境 - DJG001
- [x] 检测 `SECRET_KEY` 硬编码 - DJG002
- [x] 检测 `ALLOWED_HOSTS = ['*']` - DJG003
- [x] 检测 CSRF 保护禁用 - DJG004
- [x] 检测不安全的 `raw()` SQL查询 - DJG005
- [x] 检测 `extra()` 和 `RawSQL()` 使用 - DJG005

### 2.10 Flask特定安全检测 ✅

**规则ID:** FLK001-FLK005  
**严重程度:** 各异  
**完成时间:** 3 小时

- [x] 检测 `app.run(debug=True)` - FLK001
- [x] 检测硬编码 `SECRET_KEY` - FLK002
- [x] 检测不安全的会话配置 - FLK003
- [x] 检测 Jinja2 模板注入 (SSTI) - FLK004
- [x] 检测不安全的文件上传 - FLK005

---

## Phase 3: 报告与可视化

### 3.1 终端彩色输出 ✅

**优先级:** 中  
**完成时间:** 1.5 小时

- [x] 使用 ANSI 颜色代码美化输出
- [x] 根据严重程度着色（CRITICAL=红, HIGH=橙, MEDIUM=黄, LOW=绿）
- [x] 支持 `--no-color` 禁用颜色
- [x] 自动检测终端颜色支持
- [x] Windows 终端 ANSI 兼容处理（ctypes 启用 VT 模式）

### 3.2 进度条显示 ⏳

**优先级:** 低  
**预计工作量:** 1 小时

- [ ] 扫描大型项目时显示进度条
- [ ] 显示当前扫描文件名
- [ ] 显示已扫描文件数/总文件数
- [ ] 显示预计剩余时间

### 3.3 SARIF 格式支持 ⏳

**优先级:** 高  
**预计工作量:** 2-3 小时

- [ ] 实现 SARIF 2.1.0 格式输出
- [ ] 支持 GitHub Code Scanning 集成
- [ ] 支持 VS Code SARIF Viewer 插件
- [ ] 包含规则元数据和帮助URI

```bash
pysec scan . -f sarif -o results.sarif
```

### 3.4 JUnit XML 格式支持 ⏳

**优先级:** 中  
**预计工作量:** 1.5 小时

- [ ] 实现 JUnit XML 格式输出
- [ ] 支持 Jenkins 等 CI 系统集成
- [ ] 每个漏洞作为一个测试用例

```bash
pysec scan . -f junit -o results.xml
```

### 3.5 统计仪表盘 ⏳

**优先级:** 低  
**预计工作量:** 3 小时

- [ ] HTML 报告中添加图表
- [ ] 漏洞类型分布饼图
- [ ] 严重程度分布柱状图
- [ ] 文件漏洞热力图
- [ ] 趋势对比图（多次扫描）

### 3.6 代码上下文显示 ⏳

**优先级:** 中  
**预计工作量:** 2 小时

- [ ] 显示漏洞代码的上下文（前后各3-5行）
- [ ] 代码行号显示
- [ ] 语法高亮（HTML报告）
- [ ] 标记漏洞所在具体位置

---

## Phase 4: 集成与自动化

### 4.1 Git Pre-commit Hook ⏳

**优先级:** 高  
**预计工作量:** 2 小时

- [ ] 提供 pre-commit hook 配置
- [ ] 仅扫描暂存的文件
- [ ] 发现高危漏洞时阻止提交
- [ ] 提供 `.pre-commit-hooks.yaml`

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/username/pysecscanner
    rev: v1.0.0
    hooks:
      - id: pysec
        args: ["--min-severity", "high"]
```

### 4.2 GitHub Actions 集成 ⏳

**优先级:** 高  
**预计工作量:** 2 小时

- [ ] 提供 GitHub Actions 工作流模板
- [ ] 支持 PR 检查和评论
- [ ] 支持 Code Scanning 上传
- [ ] 提供 action.yml 定义

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: username/pysecscanner-action@v1
        with:
          min-severity: medium
          fail-on-findings: true
```

### 4.3 VS Code 扩展 ⏳

**优先级:** 中  
**预计工作量:** 8-10 小时

- [ ] 实时代码检测（保存时扫描）
- [ ] 问题面板集成
- [ ] 代码高亮（波浪线标记）
- [ ] 快速修复建议
- [ ] 鼠标悬停显示漏洞详情
- [ ] 配置界面

### 4.4 GitLab CI 集成 ⏳

**优先级:** 中  
**预计工作量:** 1.5 小时

- [ ] 提供 `.gitlab-ci.yml` 模板
- [ ] 支持 GitLab SAST 报告格式
- [ ] 支持合并请求评论

### 4.5 API 服务模式 ⏳

**优先级:** 低  
**预计工作量:** 4-5 小时

- [ ] 提供 REST API 服务
- [ ] 支持代码片段扫描
- [ ] 支持文件上传扫描
- [ ] 支持异步扫描任务
- [ ] API 认证和限流

```bash
# 启动API服务
pysec serve --port 8080

# API调用
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "eval(user_input)"}'
```

---

## Phase 5: 性能与体验优化

### 5.1 多线程扫描 ⏳

**优先级:** 中  
**预计工作量:** 3 小时

- [x] 使用 `concurrent.futures` 并行扫描
- [x] 支持 `--workers N` 指定线程数
- [x] 自动检测 CPU 核心数
- [x] 线程安全的结果收集

### 5.2 扫描缓存 ⏳

**优先级:** 中  
**预计工作量:** 2-3 小时

- [x] 缓存已扫描文件的结果
- [x] 基于文件哈希判断是否需要重新扫描
- [x] 支持缓存过期时间
- [x] 支持 `--no-cache` 强制重新扫描

### 5.3 内存优化 ⏳

**优先级:** 低  
**预计工作量:** 2 小时

- [x] 大文件分块处理
- [x] 生成器模式减少内存占用
- [x] AST 节点按需遍历
- [x] 及时释放不需要的对象

### 5.4 扫描超时控制 ⏳

**优先级:** 中  
**预计工作量:** 1 小时

- [x] 单文件扫描超时设置
- [x] 总扫描时间限制
- [x] 超时后优雅退出并报告

```bash
pysec scan . --timeout 300  # 5分钟总超时
pysec scan . --file-timeout 30  # 单文件30秒超时
```

### 5.5 友好的错误信息 ⏳

**优先级:** 中  
**预计工作量:** 1.5 小时

- [ ] 更清晰的错误消息
- [ ] 常见问题的解决建议
- [ ] 调试模式 `-vvv` 详细日志
- [ ] 错误追踪信息格式化

---

## Phase 6: 文档与生态

### 6.1 完善文档 ✅

**优先级:** 高  
**预计工作量:** 4 小时  
**完成时间:** 2026-02-09

- [x] 完整的 API 文档 (docs/API.md)
- [x] 规则编写指南 (docs/RULE_GUIDE.md)
- [x] 最佳实践文档 (docs/BEST_PRACTICES.md)
- [x] 常见问题解答 (FAQ) (docs/FAQ.md)
- [x] 中英文双语文档
- [x] 完整的 README.md (中英文双语)
- [x] 清理项目中间测试文档

### 6.2 规则编写教程 ⏳

**优先级:** 中  
**预计工作量:** 2 小时

- [ ] 规则开发入门教程
- [ ] AST 节点类型参考
- [ ] 规则测试指南
- [ ] 贡献规则的流程

### 6.3 示例项目 ⏳

**优先级:** 低  
**预计工作量:** 2 小时

- [ ] 创建包含各类漏洞的示例项目
- [ ] 对应的修复版本
- [ ] 扫描结果演示

### 6.4 PyPI 发布 🔄

**优先级:** 高  
**预计工作量:** 1 小时

- [x] 完善 pyproject.toml
- [x] 添加 classifiers 和 keywords
- [x] 编写 CHANGELOG.md
- [ ] 发布到 PyPI
- [ ] 发布到 conda-forge

```bash
# 安装
pip install pysecscanner

# 使用
pysec scan ./myproject
```

### 6.5 规则仓库 ⏳

**优先级:** 低  
**预计工作量:** 3 小时

- [ ] 支持从外部加载规则
- [ ] 社区规则仓库
- [ ] 规则版本管理
- [ ] 规则自动更新

```bash
pysec rules install community/aws-rules
pysec rules update
```

---

## 📊 进度跟踪

### 当前版本: v1.0.0

| Phase                 | 完成度 | 状态     |
| --------------------- | ------ | -------- |
| Phase 1: 核心功能增强 | 40%    | 🔄 进行中 |
| Phase 2: 新增检测规则 | 10%    | 🔄 进行中 |
| Phase 3: 报告与可视化 | 30%    | 🔄 进行中 |
| Phase 4: 集成与自动化 | 0%     | ⏳ 待开始 |
| Phase 5: 性能优化     | 0%     | ⏳ 待开始 |
| Phase 6: 文档与生态   | 30%    | 🔄 进行中 |

### 里程碑规划

- **v1.1.0** - 配置文件支持 + 忽略注释 + 3个新规则
- **v1.2.0** - SARIF输出 + GitHub Actions + Pre-commit
- **v1.3.0** - 增量扫描 + 彩色输出 + 5个新规则
- **v2.0.0** - VS Code扩展 + API服务 + 完整文档

---

## 🤝 贡献指南

欢迎对以上任何功能进行贡献！请按以下步骤：

1. 选择一个待办事项
2. 在 Issue 中认领任务
3. Fork 仓库并创建分支
4. 完成开发并编写测试
5. 提交 Pull Request

---

_最后更新: 2026-02-01_
