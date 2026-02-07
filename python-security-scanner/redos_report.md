# PySecScanner 安全扫描报告

## 扫描信息

| 项目 | 内容 |
|------|------|
| 扫描目标 | `tests\samples\redos_vulnerable.py` |
| 扫描时间 | 2026-02-07 23:53:57 |
| 扫描耗时 | 0.03 秒 |
| 扫描文件数 | 1 |

## 漏洞统计

| 严重程度 | 数量 |
|----------|------|
| 🔴 严重 (Critical) | 0 |
| 🟠 高危 (High) | 1 |
| 🟡 中危 (Medium) | 28 |
| 🟢 低危 (Low) | 0 |
| **总计** | **29** |

## 漏洞详情

### 1. [DNG001] 危险函数调用

**严重程度:** 🟠 HIGH

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 176 行

**描述:** 调用危险函数 compile(): 编译代码对象，配合eval/exec可执行任意代码

**问题代码:**

```python
pattern1 = compile(r"(a+)+")
```

**修复建议:** 确保compile的输入来自可信源；避免编译用户输入

---

### 2. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 16 行

**描述:** 检测到嵌套量词 '(a+)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern1 = re.compile(r"(a+)+")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 3. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 19 行

**描述:** 检测到嵌套量词 '(a*)*'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern2 = re.compile(r"(a*)*")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 4. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 22 行

**描述:** 检测到嵌套量词 '(a+)*'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern3 = re.compile(r"(a+)*")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 5. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 25 行

**描述:** 检测到嵌套量词 '(a?)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern4 = re.compile(r"(a?)+")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 6. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 28 行

**描述:** 检测到嵌套量词 '(\d+)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern5 = re.compile(r"(\d+)+")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 7. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 39 行

**描述:** 检测到重叠交替模式 '(a|a)+'，可能导致指数级回溯（ReDoS攻击）

**问题代码:**

```python
pattern1 = re.compile(r"(a|a)+")
```

**修复建议:** 避免交替分支重叠；使用更精确的模式；或使用 regex 库（re2）限制回溯

---

### 8. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 42 行

**描述:** 检测到重叠交替模式 '(a|ab)+'，可能导致指数级回溯（ReDoS攻击）

**问题代码:**

```python
pattern2 = re.compile(r"(a|ab)+")
```

**修复建议:** 避免交替分支重叠；使用更精确的模式；或使用 regex 库（re2）限制回溯

---

### 9. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 45 行

**描述:** 检测到重叠交替模式 '(abc|ab)+'，可能导致指数级回溯（ReDoS攻击）

**问题代码:**

```python
pattern3 = re.compile(r"(abc|ab)+")
```

**修复建议:** 避免交替分支重叠；使用更精确的模式；或使用 regex 库（re2）限制回溯

---

### 10. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 48 行

**描述:** 检测到重叠交替模式 '(test|tests)+'，可能导致指数级回溯（ReDoS攻击）

**问题代码:**

```python
pattern4 = re.compile(r"(test|tests)+")
```

**修复建议:** 避免交替分支重叠；使用更精确的模式；或使用 regex 库（re2）限制回溯

---

### 11. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 59 行

**描述:** 检测到嵌套量词 '(\w+)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern1 = re.compile(r"(\w+)+")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 12. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 62 行

**描述:** 检测到嵌套量词 '([a-z]+)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern2 = re.compile(r"([a-z]+)+")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 13. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 65 行

**描述:** 检测到嵌套量词 '(.*)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern3 = re.compile(r"(.*)+end")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 14. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 68 行

**描述:** 检测到嵌套量词 '(.+)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern4 = re.compile(r"(.+)+$")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 15. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 79 行

**描述:** 检测到嵌套量词 '(a{1,5})+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern1 = re.compile(r"(a{1,5})+")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 16. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 82 行

**描述:** 检测到嵌套量词 '(a+){1,10}'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern2 = re.compile(r"(a+){1,10}")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 17. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 85 行

**描述:** 检测到嵌套量词 '(\d{2,4})*'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern3 = re.compile(r"(\d{2,4})*")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 18. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 95 行

**描述:** 检测到嵌套量词 '([a-zA-Z0-9])+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern = re.compile(r"^([a-zA-Z0-9])+@([a-zA-Z0-9])+\.([a-zA-Z])+$")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 19. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 102 行

**描述:** 检测到嵌套量词 '(\w+)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern = re.compile(r"(http|https)://(\w+)+\.(\w+)+")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 20. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 109 行

**描述:** 检测到嵌套量词 '(\s*"[^"]*"\s*:\s*"[^"]*"\s*,?\s*)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern = re.compile(r'(\s*"[^"]*"\s*:\s*"[^"]*"\s*,?\s*)+')
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 21. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 116 行

**描述:** 检测到嵌套量词 '(.*)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern = re.compile(r"<(\w+)>(.*)+</\1>")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 22. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 126 行

**描述:** 检测到嵌套量词 '(a+)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
result1 = re.match(r"(a+)+b", "aaaaab")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 23. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 129 行

**描述:** 检测到嵌套量词 '(\d+)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
result2 = re.search(r"(\d+)+", "12345")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 24. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 132 行

**描述:** 检测到嵌套量词 '(\w+)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
result3 = re.findall(r"(\w+)+", "hello world")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 25. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 135 行

**描述:** 检测到嵌套量词 '(a*)*'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
result4 = re.sub(r"(a*)*", "x", "aaaa")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 26. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 138 行

**描述:** 检测到嵌套量词 '(,\s*)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
result5 = re.split(r"(,\s*)+", "a, b, c")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 27. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 176 行

**描述:** 检测到嵌套量词 '(a+)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
pattern1 = compile(r"(a+)+")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 28. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 179 行

**描述:** 检测到嵌套量词 '(\d+)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
result1 = match(r"(\d+)+", "12345")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

### 29. [REX001] 正则表达式DoS风险

**严重程度:** 🟡 MEDIUM

**位置:** `D:\EduLibrary\OurEDA\oss-2025\python-security-scanner\tests\samples\redos_vulnerable.py` 第 182 行

**描述:** 检测到嵌套量词 '(\w+)+'，可能导致灾难性回溯（ReDoS攻击）

**问题代码:**

```python
result2 = search(r"(\w+)+", "hello")
```

**修复建议:** 避免使用嵌套量词；重新设计正则表达式；使用量词的非贪婪模式；或使用 regex 库（re2）代替 re 模块

---

---

*报告由 PySecScanner v1.0.0 生成 | 2026-02-07 23:53:57*