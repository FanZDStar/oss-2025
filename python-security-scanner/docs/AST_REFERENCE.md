# Python AST Node Reference

[English](#english) | [中文](#中文)

---

## English

### Table of Contents

- [Overview](#overview)
- [Basic Node Types](#basic-node-types)
- [Expression Nodes](#expression-nodes)
- [Statement Nodes](#statement-nodes)
- [Function & Class Nodes](#function--class-nodes)
- [Control Flow Nodes](#control-flow-nodes)
- [Import Nodes](#import-nodes)
- [Operator Nodes](#operator-nodes)
- [Common Patterns](#common-patterns)
- [Practical Examples](#practical-examples)

---

### Overview

Python's Abstract Syntax Tree (AST) module provides a way to analyze Python source code programmatically. This reference covers the most important node types used in security rule development.

**Quick Start:**

```python
import ast

code = """
def hello(name):
    print(f"Hello, {name}")
"""

tree = ast.parse(code)
print(ast.dump(tree, indent=2))
```

**Key Concepts:**

- **Node**: Base class for all AST nodes
- **expr**: Expression nodes (values)
- **stmt**: Statement nodes (actions)
- **lineno**: Line number in source code
- **col_offset**: Column offset in source code

---

### Basic Node Types

#### Module

Top-level node representing a Python file.

```python
class ast.Module(body, type_ignores)
```

**Attributes:**
- `body`: List of statements

**Example:**
```python
# Python code
x = 1
print(x)

# AST
Module(body=[
    Assign(...),
    Expr(value=Call(...))
])
```

#### Constant

Literal values (strings, numbers, booleans, None).

```python
class ast.Constant(value, kind)
```

**Attributes:**
- `value`: The actual constant value
- `kind`: Optional string type hint

**Example:**
```python
# Python: "hello", 123, True, None
Constant(value='hello')
Constant(value=123)
Constant(value=True)
Constant(value=None)
```

**Security Note:** Check for hardcoded secrets in string constants.

#### Name

Variable references.

```python
class ast.Name(id, ctx)
```

**Attributes:**
- `id`: Variable name as string
- `ctx`: Load (reading) or Store (writing)

**Example:**
```python
# Python: x = y
Assign(
    targets=[Name(id='x', ctx=Store())],
    value=Name(id='y', ctx=Load())
)
```

---

### Expression Nodes

#### Call

Function/method calls.

```python
class ast.Call(func, args, keywords)
```

**Attributes:**
- `func`: The called function (Name or Attribute)
- `args`: Positional arguments
- `keywords`: Keyword arguments

**Example:**
```python
# Python: print("hello", end="\n")
Call(
    func=Name(id='print'),
    args=[Constant(value='hello')],
    keywords=[keyword(arg='end', value=Constant(value='\n'))]
)

# Python: obj.method(arg)
Call(
    func=Attribute(value=Name(id='obj'), attr='method'),
    args=[Name(id='arg')],
    keywords=[]
)
```

**Common Patterns:**

```python
def get_function_name(node: ast.Call) -> str:
    """Extract function name from Call node"""
    if isinstance(node.func, ast.Name):
        return node.func.id  # Simple call: func()
    elif isinstance(node.func, ast.Attribute):
        return node.func.attr  # Method call: obj.method()
    return ""

def get_full_call_path(node: ast.Call) -> str:
    """Get full call path like 'os.system'"""
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
    elif isinstance(node.func, ast.Name):
        return node.func.id
    return ""
```

**Security Patterns:**

```python
# Check for dangerous function calls
DANGEROUS_FUNCTIONS = {'eval', 'exec', 'compile', '__import__'}

for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        func_name = get_function_name(node)
        if func_name in DANGEROUS_FUNCTIONS:
            # Found dangerous call
            pass
```

#### Attribute

Attribute access (obj.attr).

```python
class ast.Attribute(value, attr, ctx)
```

**Attributes:**
- `value`: Object being accessed
- `attr`: Attribute name as string
- `ctx`: Load or Store

**Example:**
```python
# Python: obj.attr
Attribute(
    value=Name(id='obj'),
    attr='attr',
    ctx=Load()
)

# Python: user.password
Attribute(
    value=Name(id='user'),
    attr='password'
)
```

#### BinOp

Binary operations (+, -, *, /, %, etc.).

```python
class ast.BinOp(left, op, right)
```

**Attributes:**
- `left`: Left operand
- `op`: Operator (Add, Sub, Mult, Div, Mod, etc.)
- `right`: Right operand

**Example:**
```python
# Python: "SELECT * FROM " + table_name
BinOp(
    left=Constant(value="SELECT * FROM "),
    op=Add(),
    right=Name(id='table_name')
)
```

**Security Pattern (SQL Injection):**

```python
def has_sql_concatenation(node: ast.BinOp) -> bool:
    """Detect SQL query string concatenation"""
    if not isinstance(node.op, ast.Add):
        return False
    
    # Check if left side contains SQL keywords
    if isinstance(node.left, ast.Constant):
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE']
        if any(kw in str(node.left.value).upper() for kw in sql_keywords):
            return True
    return False
```

#### Compare

Comparison operations (==, !=, <, >, <=, >=, in, is).

```python
class ast.Compare(left, ops, comparators)
```

**Attributes:**
- `left`: Left value
- `ops`: List of operators (Eq, NotEq, Lt, Gt, In, Is, etc.)
- `comparators`: List of right values

**Example:**
```python
# Python: x < 10
Compare(
    left=Name(id='x'),
    ops=[Lt()],
    comparators=[Constant(value=10)]
)

# Python: 1 < x < 10
Compare(
    left=Constant(value=1),
    ops=[Lt(), Lt()],
    comparators=[Name(id='x'), Constant(value=10)]
)
```

#### JoinedStr (f-strings)

Formatted string literals (f"...").

```python
class ast.JoinedStr(values)
```

**Attributes:**
- `values`: List of Constant and FormattedValue nodes

**Example:**
```python
# Python: f"Hello {name}"
JoinedStr(values=[
    Constant(value='Hello '),
    FormattedValue(
        value=Name(id='name'),
        conversion=-1,
        format_spec=None
    )
])
```

**Security Pattern (XSS/Injection):**

```python
def has_user_input_in_fstring(node: ast.JoinedStr) -> bool:
    """Check if f-string contains user input"""
    for value in node.values:
        if isinstance(value, ast.FormattedValue):
            if isinstance(value.value, ast.Name):
                # Check if variable name suggests user input
                var_name = value.value.id.lower()
                if any(x in var_name for x in ['user', 'input', 'request', 'param']):
                    return True
    return False
```

---

### Statement Nodes

#### Assign

Variable assignment.

```python
class ast.Assign(targets, value, type_comment)
```

**Attributes:**
- `targets`: List of assignment targets (Name, Attribute, etc.)
- `value`: Assigned value

**Example:**
```python
# Python: x = 10
Assign(
    targets=[Name(id='x', ctx=Store())],
    value=Constant(value=10)
)

# Python: a = b = 0
Assign(
    targets=[Name(id='a'), Name(id='b')],
    value=Constant(value=0)
)
```

**Security Pattern (Hardcoded Secrets):**

```python
SECRET_PATTERNS = ['password', 'secret', 'api_key', 'token', 'api_secret']

for node in ast.walk(tree):
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(pattern in var_name for pattern in SECRET_PATTERNS):
                    if isinstance(node.value, ast.Constant):
                        # Hardcoded secret detected!
                        pass
```

#### AugAssign

Augmented assignment (+=, -=, etc.).

```python
class ast.AugAssign(target, op, value)
```

**Example:**
```python
# Python: x += 1
AugAssign(
    target=Name(id='x'),
    op=Add(),
    value=Constant(value=1)
)
```

#### Return

Return statement.

```python
class ast.Return(value)
```

**Example:**
```python
# Python: return result
Return(value=Name(id='result'))
```

#### Expr

Expression statement (expression used as statement).

```python
class ast.Expr(value)
```

**Example:**
```python
# Python: print("hello")
Expr(value=Call(func=Name(id='print'), args=[...]))
```

---

### Function & Class Nodes

#### FunctionDef

Function definition.

```python
class ast.FunctionDef(name, args, body, decorator_list, returns)
```

**Attributes:**
- `name`: Function name
- `args`: arguments object
- `body`: List of statements in function body
- `decorator_list`: List of decorators
- `returns`: Return type annotation

**Example:**
```python
# Python:
# @decorator
# def greet(name: str) -> str:
#     return f"Hello {name}"

FunctionDef(
    name='greet',
    args=arguments(
        args=[arg(arg='name', annotation=Name(id='str'))],
        defaults=[]
    ),
    body=[Return(...)],
    decorator_list=[Name(id='decorator')],
    returns=Name(id='str')
)
```

**Security Pattern:**

```python
def find_functions_with_user_input(tree):
    """Find functions that accept user input"""
    user_input_params = ['request', 'user_input', 'data', 'params']
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for arg in node.args.args:
                if any(pattern in arg.arg.lower() for pattern in user_input_params):
                    # This function handles user input
                    yield node
```

#### ClassDef

Class definition.

```python
class ast.ClassDef(name, bases, keywords, body, decorator_list)
```

**Attributes:**
- `name`: Class name
- `bases`: Base classes
- `body`: Class body statements
- `decorator_list`: Decorators

**Example:**
```python
# Python:
# class MyClass(BaseClass):
#     pass

ClassDef(
    name='MyClass',
    bases=[Name(id='BaseClass')],
    body=[Pass()]
)
```

#### arguments

Function arguments specification.

```python
class ast.arguments(posonlyargs, args, vararg, kwonlyargs, kw_defaults, kwarg, defaults)
```

**Attributes:**
- `args`: Regular arguments
- `vararg`: *args
- `kwarg`: **kwargs
- `defaults`: Default values

**Example:**
```python
# Python: def func(a, b=1, *args, c=2, **kwargs)
arguments(
    args=[arg(arg='a'), arg(arg='b')],
    defaults=[Constant(value=1)],
    vararg=arg(arg='args'),
    kwonlyargs=[arg(arg='c')],
    kw_defaults=[Constant(value=2)],
    kwarg=arg(arg='kwargs')
)
```

---

### Control Flow Nodes

#### If

Conditional statement.

```python
class ast.If(test, body, orelse)
```

**Attributes:**
- `test`: Condition expression
- `body`: Statements if True
- `orelse`: Statements if False (can contain another If for elif)

**Example:**
```python
# Python:
# if x > 0:
#     print("positive")
# else:
#     print("non-positive")

If(
    test=Compare(left=Name(id='x'), ops=[Gt()], comparators=[Constant(value=0)]),
    body=[Expr(value=Call(...))],
    orelse=[Expr(value=Call(...))]
)
```

#### For

For loop.

```python
class ast.For(target, iter, body, orelse)
```

**Attributes:**
- `target`: Loop variable
- `iter`: Iterable expression
- `body`: Loop body
- `orelse`: Else clause (executed if no break)

**Example:**
```python
# Python: for item in items:
For(
    target=Name(id='item'),
    iter=Name(id='items'),
    body=[...]
)
```

#### While

While loop.

```python
class ast.While(test, body, orelse)
```

#### Try

Try-except block.

```python
class ast.Try(body, handlers, orelse, finalbody)
```

**Attributes:**
- `body`: Try block statements
- `handlers`: List of ExceptHandler nodes
- `orelse`: Else block (executed if no exception)
- `finalbody`: Finally block

**Example:**
```python
# Python:
# try:
#     risky_operation()
# except ValueError as e:
#     handle_error(e)
# finally:
#     cleanup()

Try(
    body=[Expr(value=Call(...))],
    handlers=[
        ExceptHandler(
            type=Name(id='ValueError'),
            name='e',
            body=[Expr(value=Call(...))]
        )
    ],
    finalbody=[Expr(value=Call(...))]
)
```

**Security Pattern (Bare Except):**

```python
def has_bare_except(node: ast.Try) -> bool:
    """Detect dangerous bare except clauses"""
    for handler in node.handlers:
        if handler.type is None:
            return True  # except: without exception type
    return False
```

#### With

Context manager (with statement).

```python
class ast.With(items, body)
```

**Attributes:**
- `items`: List of withitem objects
- `body`: With block statements

**Example:**
```python
# Python: with open(file) as f:
With(
    items=[
        withitem(
            context_expr=Call(func=Name(id='open'), args=[Name(id='file')]),
            optional_vars=Name(id='f')
        )
    ],
    body=[...]
)
```

---

### Import Nodes

#### Import

Import statement.

```python
class ast.Import(names)
```

**Attributes:**
- `names`: List of alias objects

**Example:**
```python
# Python: import os, sys
Import(names=[
    alias(name='os', asname=None),
    alias(name='sys', asname=None)
])

# Python: import numpy as np
Import(names=[
    alias(name='numpy', asname='np')
])
```

#### ImportFrom

From-import statement.

```python
class ast.ImportFrom(module, names, level)
```

**Attributes:**
- `module`: Module name
- `names`: List of imported names
- `level`: Relative import level (0 for absolute)

**Example:**
```python
# Python: from os import path, system
ImportFrom(
    module='os',
    names=[alias(name='path'), alias(name='system')],
    level=0
)

# Python: from ..module import func
ImportFrom(
    module='module',
    names=[alias(name='func')],
    level=2  # Two levels up
)
```

**Security Pattern:**

```python
DANGEROUS_IMPORTS = {
    'pickle': ['loads', 'load'],
    'subprocess': ['Popen'],
    'os': ['system', 'popen']
}

for node in ast.walk(tree):
    if isinstance(node, ast.ImportFrom):
        if node.module in DANGEROUS_IMPORTS:
            for name in node.names:
                if name.name in DANGEROUS_IMPORTS[node.module]:
                    # Dangerous import detected
                    pass
```

---

### Operator Nodes

#### Comparison Operators

- `ast.Eq()`: ==
- `ast.NotEq()`: !=
- `ast.Lt()`: <
- `ast.LtE()`: <=
- `ast.Gt()`: >
- `ast.GtE()`: >=
- `ast.Is()`: is
- `ast.IsNot()`: is not
- `ast.In()`: in
- `ast.NotIn()`: not in

#### Binary Operators

- `ast.Add()`: +
- `ast.Sub()`: -
- `ast.Mult()`: *
- `ast.Div()`: /
- `ast.FloorDiv()`: //
- `ast.Mod()`: %
- `ast.Pow()`: **
- `ast.BitOr()`: |
- `ast.BitXor()`: ^
- `ast.BitAnd()`: &
- `ast.LShift()`: <<
- `ast.RShift()`: >>

#### Unary Operators

- `ast.UAdd()`: +x
- `ast.USub()`: -x
- `ast.Not()`: not x
- `ast.Invert()`: ~x

#### Boolean Operators

- `ast.And()`: and
- `ast.Or()`: or

---

### Common Patterns

#### Walking the AST

```python
import ast

# Walk all nodes (depth-first)
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        print(f"Found function call at line {node.lineno}")

# Walk with parent tracking
class Visitor(ast.NodeVisitor):
    def __init__(self):
        self.parent_map = {}
    
    def visit(self, node):
        for child in ast.iter_child_nodes(node):
            self.parent_map[child] = node
        self.generic_visit(node)
    
    def visit_Call(self, node):
        parent = self.parent_map.get(node)
        print(f"Call inside {type(parent).__name__}")
        self.generic_visit(node)
```

#### Finding Specific Patterns

```python
def find_nodes_of_type(tree, node_type):
    """Find all nodes of specific type"""
    return [node for node in ast.walk(tree) if isinstance(node, node_type)]

def find_calls_to_function(tree, func_name):
    """Find all calls to a specific function"""
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == func_name:
                calls.append(node)
    return calls

def find_assignments_to_variable(tree, var_name):
    """Find all assignments to a variable"""
    assignments = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var_name:
                    assignments.append(node)
    return assignments
```

#### Getting Source Code

```python
def get_source_segment(source_code: str, node: ast.AST) -> str:
    """Get source code for an AST node"""
    lines = source_code.split('\n')
    if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
        start = node.lineno - 1
        end = node.end_lineno
        return '\n'.join(lines[start:end])
    return ""

def get_line(source_code: str, line_number: int) -> str:
    """Get a single line from source code"""
    lines = source_code.split('\n')
    if 0 <= line_number - 1 < len(lines):
        return lines[line_number - 1]
    return ""
```

#### Checking for String Patterns

```python
def contains_sql_keyword(node: ast.AST) -> bool:
    """Check if node contains SQL keywords"""
    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE']
    
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return any(kw in node.value.upper() for kw in sql_keywords)
    
    return False

def is_sensitive_variable_name(name: str) -> bool:
    """Check if variable name suggests sensitive data"""
    sensitive_patterns = ['password', 'secret', 'key', 'token', 'credential']
    name_lower = name.lower()
    return any(pattern in name_lower for pattern in sensitive_patterns)
```

---

### Practical Examples

#### Example 1: Detect eval() Calls

```python
def detect_eval_usage(tree):
    """Find all eval() calls"""
    vulnerabilities = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == 'eval':
                vulnerabilities.append({
                    'line': node.lineno,
                    'issue': 'Use of eval() is dangerous',
                    'suggestion': 'Use ast.literal_eval() or safer alternatives'
                })
    
    return vulnerabilities
```

#### Example 2: Detect SQL Injection

```python
def detect_sql_injection(tree):
    """Find potential SQL injection vulnerabilities"""
    vulnerabilities = []
    
    for node in ast.walk(tree):
        # Check for string concatenation with SQL keywords
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if contains_sql_keyword(node.left):
                if not isinstance(node.right, ast.Constant):
                    vulnerabilities.append({
                        'line': node.lineno,
                        'issue': 'Potential SQL injection via string concatenation',
                        'suggestion': 'Use parameterized queries'
                    })
        
        # Check for % operator with SQL strings
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            if contains_sql_keyword(node.left):
                vulnerabilities.append({
                    'line': node.lineno,
                    'issue': 'SQL query with % formatting',
                    'suggestion': 'Use parameterized queries instead'
                })
    
    return vulnerabilities
```

#### Example 3: Detect Hardcoded Secrets

```python
def detect_hardcoded_secrets(tree):
    """Find hardcoded passwords/keys"""
    vulnerabilities = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    
                    # Check if variable name suggests a secret
                    if is_sensitive_variable_name(var_name):
                        # Check if assigned a literal value
                        if isinstance(node.value, ast.Constant):
                            value = node.value.value
                            if isinstance(value, str) and len(value) > 0:
                                vulnerabilities.append({
                                    'line': node.lineno,
                                    'variable': var_name,
                                    'issue': f'Hardcoded secret in variable "{var_name}"',
                                    'suggestion': 'Use environment variables or secret management'
                                })
    
    return vulnerabilities
```

#### Example 4: Detect Path Traversal

```python
def detect_path_traversal(tree):
    """Find potential path traversal vulnerabilities"""
    vulnerabilities = []
    file_operations = ['open', 'read', 'write']
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = None
            
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            
            if func_name in file_operations and node.args:
                # Check if path comes from variable
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Name):
                    var_name = first_arg.id.lower()
                    if any(x in var_name for x in ['user', 'input', 'request']):
                        vulnerabilities.append({
                            'line': node.lineno,
                            'issue': f'Potential path traversal in {func_name}()',
                            'suggestion': 'Validate and sanitize file paths'
                        })
    
    return vulnerabilities
```

#### Example 5: Track Data Flow

```python
class DataFlowAnalyzer(ast.NodeVisitor):
    """Track tainted variables (user input)"""
    
    def __init__(self):
        self.tainted = set()  # Variables containing user input
        self.vulnerabilities = []
    
    def visit_Assign(self, node):
        # Check if value comes from user input
        if self._is_user_input(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.add(target.id)
        
        # Check if value uses tainted variable
        elif self._uses_tainted_var(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.add(target.id)
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        # Check if tainted variable used in dangerous function
        if self._is_dangerous_call(node):
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.tainted:
                    self.vulnerabilities.append({
                        'line': node.lineno,
                        'issue': f'Tainted variable "{arg.id}" used in dangerous call',
                        'suggestion': 'Sanitize user input before use'
                    })
        
        self.generic_visit(node)
    
    def _is_user_input(self, node):
        """Check if node represents user input"""
        if isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            return func_name in ['input', 'get', 'POST']
        return False
    
    def _uses_tainted_var(self, node):
        """Check if expression uses tainted variable"""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.tainted:
                return True
        return False
    
    def _is_dangerous_call(self, node):
        """Check if call is potentially dangerous"""
        if isinstance(node.func, ast.Name):
            return node.func.id in ['eval', 'exec', 'system']
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr in ['execute', 'system']
        return False
```

**Usage:**

```python
code = """
user_input = input("Enter command: ")
command = "ls " + user_input
os.system(command)
"""

tree = ast.parse(code)
analyzer = DataFlowAnalyzer()
analyzer.visit(tree)
print(analyzer.vulnerabilities)
```

---

## 中文

### 目录

- [概述](#概述-1)
- [基本节点类型](#基本节点类型-1)
- [表达式节点](#表达式节点-1)
- [语句节点](#语句节点-1)
- [函数和类节点](#函数和类节点-1)
- [控制流节点](#控制流节点-1)
- [导入节点](#导入节点-1)
- [操作符节点](#操作符节点-1)
- [常用模式](#常用模式-1)
- [实战示例](#实战示例-1)

---

### 概述

Python 的抽象语法树(AST)模块提供了一种以编程方式分析 Python 源代码的方法。本参考文档涵盖了安全规则开发中最重要的节点类型。

**快速开始：**

```python
import ast

code = """
def hello(name):
    print(f"Hello, {name}")
"""

tree = ast.parse(code)
print(ast.dump(tree, indent=2))
```

**核心概念：**

- **Node**: 所有 AST 节点的基类
- **expr**: 表达式节点（值）
- **stmt**: 语句节点（动作）
- **lineno**: 源代码中的行号
- **col_offset**: 源代码中的列偏移量

---

### 基本节点类型

#### Module (模块)

表示 Python 文件的顶层节点。

```python
class ast.Module(body, type_ignores)
```

**属性：**
- `body`: 语句列表

**示例：**
```python
# Python 代码
x = 1
print(x)

# AST
Module(body=[
    Assign(...),
    Expr(value=Call(...))
])
```

#### Constant (常量)

字面值（字符串、数字、布尔值、None）。

```python
class ast.Constant(value, kind)
```

**属性：**
- `value`: 实际的常量值
- `kind`: 可选的字符串类型提示

**示例：**
```python
# Python: "hello", 123, True, None
Constant(value='hello')
Constant(value=123)
Constant(value=True)
Constant(value=None)
```

**安全提示：** 检查字符串常量中的硬编码密钥。

#### Name (名称)

变量引用。

```python
class ast.Name(id, ctx)
```

**属性：**
- `id`: 变量名（字符串）
- `ctx`: Load（读取）或 Store（写入）

**示例：**
```python
# Python: x = y
Assign(
    targets=[Name(id='x', ctx=Store())],
    value=Name(id='y', ctx=Load())
)
```

---

### 表达式节点

#### Call (调用)

函数/方法调用。

```python
class ast.Call(func, args, keywords)
```

**属性：**
- `func`: 被调用的函数（Name 或 Attribute）
- `args`: 位置参数
- `keywords`: 关键字参数

**示例：**
```python
# Python: print("hello", end="\n")
Call(
    func=Name(id='print'),
    args=[Constant(value='hello')],
    keywords=[keyword(arg='end', value=Constant(value='\n'))]
)

# Python: obj.method(arg)
Call(
    func=Attribute(value=Name(id='obj'), attr='method'),
    args=[Name(id='arg')],
    keywords=[]
)
```

**常用模式：**

```python
def get_function_name(node: ast.Call) -> str:
    """从 Call 节点提取函数名"""
    if isinstance(node.func, ast.Name):
        return node.func.id  # 简单调用: func()
    elif isinstance(node.func, ast.Attribute):
        return node.func.attr  # 方法调用: obj.method()
    return ""

def get_full_call_path(node: ast.Call) -> str:
    """获取完整调用路径，如 'os.system'"""
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
    elif isinstance(node.func, ast.Name):
        return node.func.id
    return ""
```

**安全模式：**

```python
# 检查危险函数调用
DANGEROUS_FUNCTIONS = {'eval', 'exec', 'compile', '__import__'}

for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        func_name = get_function_name(node)
        if func_name in DANGEROUS_FUNCTIONS:
            # 发现危险调用
            pass
```

#### Attribute (属性)

属性访问 (obj.attr)。

```python
class ast.Attribute(value, attr, ctx)
```

**属性：**
- `value`: 被访问的对象
- `attr`: 属性名（字符串）
- `ctx`: Load 或 Store

**示例：**
```python
# Python: user.password
Attribute(
    value=Name(id='user'),
    attr='password'
)
```

#### BinOp (二元操作)

二元运算 (+, -, *, /, %, 等)。

```python
class ast.BinOp(left, op, right)
```

**属性：**
- `left`: 左操作数
- `op`: 操作符（Add, Sub, Mult, Div, Mod, 等）
- `right`: 右操作数

**示例：**
```python
# Python: "SELECT * FROM " + table_name
BinOp(
    left=Constant(value="SELECT * FROM "),
    op=Add(),
    right=Name(id='table_name')
)
```

**安全模式（SQL 注入）：**

```python
def has_sql_concatenation(node: ast.BinOp) -> bool:
    """检测 SQL 查询字符串拼接"""
    if not isinstance(node.op, ast.Add):
        return False
    
    # 检查左侧是否包含 SQL 关键字
    if isinstance(node.left, ast.Constant):
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE']
        if any(kw in str(node.left.value).upper() for kw in sql_keywords):
            return True
    return False
```

#### JoinedStr (f-字符串)

格式化字符串字面量 (f"...")。

```python
class ast.JoinedStr(values)
```

**属性：**
- `values`: Constant 和 FormattedValue 节点列表

**示例：**
```python
# Python: f"Hello {name}"
JoinedStr(values=[
    Constant(value='Hello '),
    FormattedValue(
        value=Name(id='name'),
        conversion=-1,
        format_spec=None
    )
])
```

**安全模式（XSS/注入）：**

```python
def has_user_input_in_fstring(node: ast.JoinedStr) -> bool:
    """检查 f-字符串是否包含用户输入"""
    for value in node.values:
        if isinstance(value, ast.FormattedValue):
            if isinstance(value.value, ast.Name):
                # 检查变量名是否暗示用户输入
                var_name = value.value.id.lower()
                if any(x in var_name for x in ['user', 'input', 'request', 'param']):
                    return True
    return False
```

---

### 语句节点

#### Assign (赋值)

变量赋值。

```python
class ast.Assign(targets, value, type_comment)
```

**属性：**
- `targets`: 赋值目标列表（Name, Attribute, 等）
- `value`: 赋值的值

**示例：**
```python
# Python: x = 10
Assign(
    targets=[Name(id='x', ctx=Store())],
    value=Constant(value=10)
)

# Python: a = b = 0
Assign(
    targets=[Name(id='a'), Name(id='b')],
    value=Constant(value=0)
)
```

**安全模式（硬编码密钥）：**

```python
SECRET_PATTERNS = ['password', 'secret', 'api_key', 'token', 'api_secret']

for node in ast.walk(tree):
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(pattern in var_name for pattern in SECRET_PATTERNS):
                    if isinstance(node.value, ast.Constant):
                        # 检测到硬编码密钥!
                        pass
```

#### Return (返回)

返回语句。

```python
class ast.Return(value)
```

**示例：**
```python
# Python: return result
Return(value=Name(id='result'))
```

---

### 函数和类节点

#### FunctionDef (函数定义)

函数定义。

```python
class ast.FunctionDef(name, args, body, decorator_list, returns)
```

**属性：**
- `name`: 函数名
- `args`: arguments 对象
- `body`: 函数体中的语句列表
- `decorator_list`: 装饰器列表
- `returns`: 返回类型注解

**示例：**
```python
# Python:
# @decorator
# def greet(name: str) -> str:
#     return f"Hello {name}"

FunctionDef(
    name='greet',
    args=arguments(
        args=[arg(arg='name', annotation=Name(id='str'))],
        defaults=[]
    ),
    body=[Return(...)],
    decorator_list=[Name(id='decorator')],
    returns=Name(id='str')
)
```

**安全模式：**

```python
def find_functions_with_user_input(tree):
    """查找接受用户输入的函数"""
    user_input_params = ['request', 'user_input', 'data', 'params']
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for arg in node.args.args:
                if any(pattern in arg.arg.lower() for pattern in user_input_params):
                    # 该函数处理用户输入
                    yield node
```

#### ClassDef (类定义)

类定义。

```python
class ast.ClassDef(name, bases, keywords, body, decorator_list)
```

**属性：**
- `name`: 类名
- `bases`: 基类
- `body`: 类体语句
- `decorator_list`: 装饰器

---

### 控制流节点

#### If (条件语句)

条件语句。

```python
class ast.If(test, body, orelse)
```

**属性：**
- `test`: 条件表达式
- `body`: True 时的语句
- `orelse`: False 时的语句（可包含另一个 If 实现 elif）

#### Try (异常处理)

Try-except 块。

```python
class ast.Try(body, handlers, orelse, finalbody)
```

**属性：**
- `body`: Try 块语句
- `handlers`: ExceptHandler 节点列表
- `orelse`: Else 块（无异常时执行）
- `finalbody`: Finally 块

**安全模式（裸 Except）：**

```python
def has_bare_except(node: ast.Try) -> bool:
    """检测危险的裸 except 子句"""
    for handler in node.handlers:
        if handler.type is None:
            return True  # except: 没有指定异常类型
    return False
```

---

### 导入节点

#### Import (导入)

Import 语句。

```python
class ast.Import(names)
```

**示例：**
```python
# Python: import os, sys
Import(names=[
    alias(name='os', asname=None),
    alias(name='sys', asname=None)
])
```

#### ImportFrom (从导入)

From-import 语句。

```python
class ast.ImportFrom(module, names, level)
```

**属性：**
- `module`: 模块名
- `names`: 导入的名称列表
- `level`: 相对导入级别（0 表示绝对导入）

**安全模式：**

```python
DANGEROUS_IMPORTS = {
    'pickle': ['loads', 'load'],
    'subprocess': ['Popen'],
    'os': ['system', 'popen']
}

for node in ast.walk(tree):
    if isinstance(node, ast.ImportFrom):
        if node.module in DANGEROUS_IMPORTS:
            for name in node.names:
                if name.name in DANGEROUS_IMPORTS[node.module]:
                    # 检测到危险导入
                    pass
```

---

### 操作符节点

#### 比较操作符

- `ast.Eq()`: ==
- `ast.NotEq()`: !=
- `ast.Lt()`: <
- `ast.LtE()`: <=
- `ast.Gt()`: >
- `ast.GtE()`: >=
- `ast.Is()`: is
- `ast.IsNot()`: is not
- `ast.In()`: in
- `ast.NotIn()`: not in

#### 二元操作符

- `ast.Add()`: +
- `ast.Sub()`: -
- `ast.Mult()`: *
- `ast.Div()`: /
- `ast.Mod()`: %
- `ast.Pow()`: **

#### 布尔操作符

- `ast.And()`: and
- `ast.Or()`: or

---

### 常用模式

#### 遍历 AST

```python
import ast

# 遍历所有节点（深度优先）
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        print(f"在第 {node.lineno} 行发现函数调用")

# 带父节点跟踪的遍历
class Visitor(ast.NodeVisitor):
    def __init__(self):
        self.parent_map = {}
    
    def visit(self, node):
        for child in ast.iter_child_nodes(node):
            self.parent_map[child] = node
        self.generic_visit(node)
    
    def visit_Call(self, node):
        parent = self.parent_map.get(node)
        print(f"调用位于 {type(parent).__name__} 内部")
        self.generic_visit(node)
```

#### 查找特定模式

```python
def find_nodes_of_type(tree, node_type):
    """查找特定类型的所有节点"""
    return [node for node in ast.walk(tree) if isinstance(node, node_type)]

def find_calls_to_function(tree, func_name):
    """查找对特定函数的所有调用"""
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == func_name:
                calls.append(node)
    return calls

def find_assignments_to_variable(tree, var_name):
    """查找对变量的所有赋值"""
    assignments = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var_name:
                    assignments.append(node)
    return assignments
```

#### 获取源代码

```python
def get_source_segment(source_code: str, node: ast.AST) -> str:
    """获取 AST 节点的源代码"""
    lines = source_code.split('\n')
    if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
        start = node.lineno - 1
        end = node.end_lineno
        return '\n'.join(lines[start:end])
    return ""

def get_line(source_code: str, line_number: int) -> str:
    """从源代码获取单行"""
    lines = source_code.split('\n')
    if 0 <= line_number - 1 < len(lines):
        return lines[line_number - 1]
    return ""
```

---

### 实战示例

#### 示例 1：检测 eval() 调用

```python
def detect_eval_usage(tree):
    """查找所有 eval() 调用"""
    vulnerabilities = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == 'eval':
                vulnerabilities.append({
                    'line': node.lineno,
                    'issue': '使用 eval() 是危险的',
                    'suggestion': '使用 ast.literal_eval() 或更安全的替代方案'
                })
    
    return vulnerabilities
```

#### 示例 2：检测 SQL 注入

```python
def detect_sql_injection(tree):
    """查找潜在的 SQL 注入漏洞"""
    vulnerabilities = []
    
    for node in ast.walk(tree):
        # 检查包含 SQL 关键字的字符串拼接
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if contains_sql_keyword(node.left):
                if not isinstance(node.right, ast.Constant):
                    vulnerabilities.append({
                        'line': node.lineno,
                        'issue': '通过字符串拼接可能导致 SQL 注入',
                        'suggestion': '使用参数化查询'
                    })
    
    return vulnerabilities
```

#### 示例 3：检测硬编码密钥

```python
def detect_hardcoded_secrets(tree):
    """查找硬编码的密码/密钥"""
    vulnerabilities = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    
                    # 检查变量名是否暗示这是密钥
                    if is_sensitive_variable_name(var_name):
                        # 检查是否赋值为字面量
                        if isinstance(node.value, ast.Constant):
                            value = node.value.value
                            if isinstance(value, str) and len(value) > 0:
                                vulnerabilities.append({
                                    'line': node.lineno,
                                    'variable': var_name,
                                    'issue': f'变量 "{var_name}" 中硬编码了密钥',
                                    'suggestion': '使用环境变量或密钥管理系统'
                                })
    
    return vulnerabilities
```

#### 示例 4：检测路径遍历

```python
def detect_path_traversal(tree):
    """查找潜在的路径遍历漏洞"""
    vulnerabilities = []
    file_operations = ['open', 'read', 'write']
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = None
            
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            
            if func_name in file_operations and node.args:
                # 检查路径是否来自变量
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Name):
                    var_name = first_arg.id.lower()
                    if any(x in var_name for x in ['user', 'input', 'request']):
                        vulnerabilities.append({
                            'line': node.lineno,
                            'issue': f'{func_name}() 中可能存在路径遍历',
                            'suggestion': '验证和清理文件路径'
                        })
    
    return vulnerabilities
```

#### 示例 5：数据流追踪

```python
class DataFlowAnalyzer(ast.NodeVisitor):
    """追踪污点变量（用户输入）"""
    
    def __init__(self):
        self.tainted = set()  # 包含用户输入的变量
        self.vulnerabilities = []
    
    def visit_Assign(self, node):
        # 检查值是否来自用户输入
        if self._is_user_input(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.add(target.id)
        
        # 检查值是否使用了污点变量
        elif self._uses_tainted_var(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.add(target.id)
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        # 检查污点变量是否用于危险函数
        if self._is_dangerous_call(node):
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.tainted:
                    self.vulnerabilities.append({
                        'line': node.lineno,
                        'issue': f'污点变量 "{arg.id}" 用于危险调用',
                        'suggestion': '在使用前清理用户输入'
                    })
        
        self.generic_visit(node)
    
    def _is_user_input(self, node):
        """检查节点是否表示用户输入"""
        if isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            return func_name in ['input', 'get', 'POST']
        return False
    
    def _uses_tainted_var(self, node):
        """检查表达式是否使用了污点变量"""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.tainted:
                return True
        return False
    
    def _is_dangerous_call(self, node):
        """检查调用是否可能危险"""
        if isinstance(node.func, ast.Name):
            return node.func.id in ['eval', 'exec', 'system']
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr in ['execute', 'system']
        return False
```

**使用方式：**

```python
code = """
user_input = input("输入命令: ")
command = "ls " + user_input
os.system(command)
"""

tree = ast.parse(code)
analyzer = DataFlowAnalyzer()
analyzer.visit(tree)
print(analyzer.vulnerabilities)
```

---

## Additional Resources

### Official Documentation
- [Python AST Module](https://docs.python.org/3/library/ast.html)
- [Green Tree Snakes - AST Tutorial](https://greentreesnakes.readthedocs.io/)

### Tools
- `ast.dump()` - Visualize AST structure
- `ast.unparse()` - Convert AST back to code (Python 3.9+)
- `astpretty` - Pretty-print AST (third-party)

### Best Practices
1. **Always check node types** - Use `isinstance()` before accessing attributes
2. **Handle edge cases** - Not all nodes have `lineno` or `col_offset`
3. **Use helper methods** - Extract common patterns into reusable functions
4. **Test thoroughly** - AST patterns can be complex
5. **Consider performance** - `ast.walk()` is recursive, optimize for large files

---

**Note:** This reference covers Python 3.8+ AST. Some node types (like `Constant`) were unified in Python 3.8. For older versions, check `Str`, `Num`, `Bytes`, etc.
