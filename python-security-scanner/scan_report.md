# PySecScanner 安全扫描报告

## 扫描信息

| 项目 | 内容 |
|------|------|
| 扫描目标 | `tests\samples\vulnerable_code.py` |
| 扫描时间 | 2026-01-24 12:51:08 |
| 扫描耗时 | 0.00 秒 |
| 扫描文件数 | 1 |

## 漏洞统计

| 严重程度 | 数量 |
|----------|------|
| 🔴 严重 (Critical) | 6 |
| 🟠 高危 (High) | 12 |
| 🟡 中危 (Medium) | 4 |
| 🟢 低危 (Low) | 0 |
| **总计** | **22** |

## 漏洞详情

### 1. [CMD001] 命令注入风险

**严重程度:** 🔴 CRITICAL

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 50 行

**描述:** 调用危险函数 os.system(): 直接执行shell命令

**问题代码:**

```python
os.system("ping " + user_input)
```

**修复建议:** 避免执行外部命令；如必须执行，使用参数列表形式并严格校验输入

---

### 2. [CMD001] 命令注入风险

**严重程度:** 🔴 CRITICAL

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 56 行

**描述:** 调用 subprocess.run() 时使用 shell=True，存在命令注入风险

**问题代码:**

```python
result = subprocess.run(cmd, shell=True, capture_output=True)
```

**修复建议:** 避免使用 shell=True；使用参数列表传递命令；对用户输入进行严格校验

---

### 3. [CMD001] 命令注入风险

**严重程度:** 🔴 CRITICAL

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 63 行

**描述:** 调用危险函数 os.popen(): 执行命令并返回文件对象

**问题代码:**

```python
output = os.popen(f"cat {filename}").read()
```

**修复建议:** 避免执行外部命令；如必须执行，使用参数列表形式并严格校验输入

---

### 4. [DNG001] 危险函数调用

**严重程度:** 🔴 CRITICAL

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 91 行

**描述:** 调用危险函数 eval(): 执行任意Python表达式，可导致远程代码执行

**问题代码:**

```python
result = eval(user_expr)
```

**修复建议:** 避免使用eval；如需解析字面量，使用ast.literal_eval

---

### 5. [DNG001] 危险函数调用

**严重程度:** 🔴 CRITICAL

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 98 行

**描述:** 调用危险函数 exec(): 执行任意Python代码，可导致远程代码执行

**问题代码:**

```python
exec(user_code)
```

**修复建议:** 避免使用exec；重新设计程序逻辑避免动态代码执行

---

### 6. [DNG001] 危险函数调用

**严重程度:** 🔴 CRITICAL

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 104 行

**描述:** 调用危险方法 pickle.loads(): 反序列化不可信数据可导致远程代码执行

**问题代码:**

```python
obj = pickle.loads(data)
```

**修复建议:** 避免反序列化不可信数据；使用json等安全格式

---

### 7. [SQL001] SQL注入风险

**严重程度:** 🟠 HIGH

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 20 行

**描述:** 使用 % 格式化拼接SQL语句，存在SQL注入风险

**问题代码:**

```python
query = "SELECT * FROM users WHERE id = '%s'" % user_id
```

**修复建议:** 使用参数化查询（如 cursor.execute(sql, params)）代替字符串拼接，或使用ORM框架进行数据库操作

---

### 8. [SQL001] SQL注入风险

**严重程度:** 🟠 HIGH

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 30 行

**描述:** 使用 f-string 拼接SQL语句，存在SQL注入风险

**问题代码:**

```python
query = f"SELECT * FROM users WHERE username = '{username}'"
```

**修复建议:** 使用参数化查询（如 cursor.execute(sql, params)）代替字符串拼接，或使用ORM框架进行数据库操作

---

### 9. [SQL001] SQL注入风险

**严重程度:** 🟠 HIGH

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 40 行

**描述:** 使用 + 连接拼接SQL语句，存在SQL注入风险

**问题代码:**

```python
query = "SELECT * FROM " + table_name + " WHERE active = 1"
```

**修复建议:** 使用参数化查询（如 cursor.execute(sql, params)）代替字符串拼接，或使用ORM框架进行数据库操作

---

### 10. [SQL001] SQL注入风险

**严重程度:** 🟠 HIGH

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 40 行

**描述:** 使用 + 连接拼接SQL语句，存在SQL注入风险

**问题代码:**

```python
query = "SELECT * FROM " + table_name + " WHERE active = 1"
```

**修复建议:** 使用参数化查询（如 cursor.execute(sql, params)）代替字符串拼接，或使用ORM框架进行数据库操作

---

### 11. [SEC001] 硬编码敏感信息

**严重程度:** 🟠 HIGH

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 70 行

**描述:** 变量 'DATABASE_PASSWORD' 包含硬编码的敏感信息，可能导致凭据泄露

**问题代码:**

```python
DATABASE_PASSWORD = "super_secret_password_123"
```

**修复建议:** 使用环境变量存储敏感信息，如 os.environ.get('SECRET_KEY')；或使用配置文件（不提交到版本控制）；或使用密钥管理服务

---

### 12. [SEC001] 硬编码敏感信息

**严重程度:** 🟠 HIGH

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 71 行

**描述:** 变量 'API_KEY' 包含硬编码的敏感信息，可能导致凭据泄露

**问题代码:**

```python
API_KEY = "sk-1234567890abcdef"
```

**修复建议:** 使用环境变量存储敏感信息，如 os.environ.get('SECRET_KEY')；或使用配置文件（不提交到版本控制）；或使用密钥管理服务

---

### 13. [SEC001] 硬编码敏感信息

**严重程度:** 🟠 HIGH

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 72 行

**描述:** 变量 'SECRET_TOKEN' 包含硬编码的敏感信息，可能导致凭据泄露

**问题代码:**

```python
SECRET_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxx"
```

**修复建议:** 使用环境变量存储敏感信息，如 os.environ.get('SECRET_KEY')；或使用配置文件（不提交到版本控制）；或使用密钥管理服务

---

### 14. [SEC001] 硬编码敏感信息

**严重程度:** 🟠 HIGH

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 76 行

**描述:** 变量 'password' 包含硬编码的敏感信息，可能导致凭据泄露

**问题代码:**

```python
password = "mysql_password_2024"  # 危险：硬编码密码
```

**修复建议:** 使用环境变量存储敏感信息，如 os.environ.get('SECRET_KEY')；或使用配置文件（不提交到版本控制）；或使用密钥管理服务

---

### 15. [SEC001] 硬编码敏感信息

**严重程度:** 🟠 HIGH

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 82 行

**描述:** 变量 'secret' 包含硬编码的敏感信息，可能导致凭据泄露

**问题代码:**

```python
secret = "aws_secret_access_key_xxxxx"  # 危险
```

**修复建议:** 使用环境变量存储敏感信息，如 os.environ.get('SECRET_KEY')；或使用配置文件（不提交到版本控制）；或使用密钥管理服务

---

### 16. [DNG001] 危险函数调用

**严重程度:** 🟠 HIGH

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 111 行

**描述:** 调用危险方法 yaml.load(): 不安全的YAML解析，可执行任意Python代码

**问题代码:**

```python
data = yaml.load(yaml_content)
```

**修复建议:** 使用yaml.safe_load代替yaml.load

---

### 17. [XSS001] XSS风险

**严重程度:** 🟠 HIGH

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 145 行

**描述:** 调用 render_template_string() 渲染包含用户输入的模板，存在XSS风险

**问题代码:**

```python
return render_template_string(template)
```

**修复建议:** 使用 render_template() 渲染模板文件而非字符串；确保对用户输入进行HTML转义；使用模板引擎的自动转义功能

---

### 18. [XSS001] XSS风险

**严重程度:** 🟠 HIGH

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 151 行

**描述:** 调用 mark_safe() 将包含用户输入的内容标记为安全，存在XSS风险

**问题代码:**

```python
return mark_safe(f"<div>{user_content}</div>")
```

**修复建议:** 永远不要将用户输入直接标记为安全；使用 format_html() 或手动转义后再标记

---

### 19. [PTH001] 路径遍历风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 127 行

**描述:** os.path.join() 的参数可能来自用户输入，如果包含 '../' 可导致路径遍历

**问题代码:**

```python
file_path = os.path.join(base_dir, user_path)
```

**修复建议:** 在拼接前使用os.path.basename()清理用户输入；拼接后使用os.path.realpath()验证最终路径是否在允许的目录内

---

### 20. [PTH001] 路径遍历风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 120 行

**描述:** 调用 open() 的路径参数可能来自用户输入，存在路径遍历风险

**问题代码:**

```python
with open(filename, 'r') as f:
```

**修复建议:** 对文件路径进行严格校验；使用os.path.basename()提取文件名；使用os.path.realpath()解析真实路径后验证是否在允许的目录内

---

### 21. [PTH001] 路径遍历风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 135 行

**描述:** 调用 open() 的路径参数可能来自用户输入，存在路径遍历风险

**问题代码:**

```python
with open(f"/uploads/{filename}", 'rb') as f:
```

**修复建议:** 对文件路径进行严格校验；使用os.path.basename()提取文件名；使用os.path.realpath()解析真实路径后验证是否在允许的目录内

---

### 22. [PTH001] 路径遍历风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\project\oss-2025\python-security-scanner\tests\samples\vulnerable_code.py` 第 128 行

**描述:** 调用 open() 的路径参数可能来自用户输入，存在路径遍历风险

**问题代码:**

```python
return open(file_path, 'r').read()
```

**修复建议:** 对文件路径进行严格校验；使用os.path.basename()提取文件名；使用os.path.realpath()解析真实路径后验证是否在允许的目录内

---

---

*报告由 PySecScanner v1.0.0 生成 | 2026-01-24 12:51:08*