# PySecScanner 安全扫描报告

## 扫描信息

| 项目 | 内容 |
|------|------|
| 扫描目标 | `tests\samples\test_ignore_comments.py` |
| 扫描时间 | 2026-02-05 11:15:14 |
| 扫描耗时 | 0.00 秒 |
| 扫描文件数 | 1 |

## 漏洞统计

| 严重程度 | 数量 |
|----------|------|
| 🔴 严重 (Critical) | 5 |
| 🟠 高危 (High) | 3 |
| 🟡 中危 (Medium) | 0 |
| 🟢 低危 (Low) | 0 |
| **总计** | **8** |

## 漏洞详情

### 1. [CMD001] 命令注入风险

**严重程度:** 🔴 CRITICAL

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\test_ignore_comments.py` 第 80 行

**描述:** 调用危险函数 os.system(): 直接执行shell命令

**问题代码:**

```python
cmd1 = os.system("ls")
```

**修复建议:** 避免执行外部命令；如必须执行，使用参数列表形式并严格校验输入

---

### 2. [CMD001] 命令注入风险

**严重程度:** 🔴 CRITICAL

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\test_ignore_comments.py` 第 89 行

**描述:** 调用危险函数 os.system(): 直接执行shell命令

**问题代码:**

```python
cmd4 = os.system("pwd")
```

**修复建议:** 避免执行外部命令；如必须执行，使用参数列表形式并严格校验输入

---

### 3. [DNG001] 危险函数调用

**严重程度:** 🔴 CRITICAL

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\test_ignore_comments.py` 第 45 行

**描述:** 调用危险函数 eval(): 执行任意Python表达式，可导致远程代码执行

**问题代码:**

```python
eval("1 + 1")
```

**修复建议:** 避免使用eval；如需解析字面量，使用ast.literal_eval

---

### 4. [DNG001] 危险函数调用

**严重程度:** 🔴 CRITICAL

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\test_ignore_comments.py` 第 57 行

**描述:** 调用危险函数 eval(): 执行任意Python表达式，可导致远程代码执行

**问题代码:**

```python
eval("2 + 2")
```

**修复建议:** 避免使用eval；如需解析字面量，使用ast.literal_eval

---

### 5. [DNG001] 危险函数调用

**严重程度:** 🔴 CRITICAL

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\test_ignore_comments.py` 第 73 行

**描述:** 调用危险函数 eval(): 执行任意Python表达式，可导致远程代码执行

**问题代码:**

```python
dangerous_func4 = eval("back_to_normal")
```

**修复建议:** 避免使用eval；如需解析字面量，使用ast.literal_eval

---

### 6. [SQL001] SQL注入风险

**严重程度:** 🟠 HIGH

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\test_ignore_comments.py` 第 27 行

**描述:** 使用 % 格式化拼接SQL语句，存在SQL注入风险

**问题代码:**

```python
query1 = "SELECT * FROM users WHERE id = '%s'" % user_id
```

**修复建议:** 使用参数化查询（如 cursor.execute(sql, params)）代替字符串拼接，或使用ORM框架进行数据库操作

---

### 7. [SEC001] 硬编码敏感信息

**严重程度:** 🟠 HIGH

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\test_ignore_comments.py` 第 15 行

**描述:** 变量 'password1' 包含硬编码的敏感信息，可能导致凭据泄露

**问题代码:**

```python
password1 = "hardcoded_password_123"
```

**修复建议:** 使用环境变量存储敏感信息，如 os.environ.get('SECRET_KEY')；或使用配置文件（不提交到版本控制）；或使用密钥管理服务

---

### 8. [SEC001] 硬编码敏感信息

**严重程度:** 🟠 HIGH

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\test_ignore_comments.py` 第 39 行

**描述:** 变量 'another_secret' 包含硬编码的敏感信息，可能导致凭据泄露

**问题代码:**

```python
another_secret = "yet_another_secret"
```

**修复建议:** 使用环境变量存储敏感信息，如 os.environ.get('SECRET_KEY')；或使用配置文件（不提交到版本控制）；或使用密钥管理服务

---

---

*报告由 PySecScanner v1.0.0 生成 | 2026-02-05 11:15:14*