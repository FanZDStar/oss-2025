# PySecScanner 测试样本 - 安全的代码
# 这些代码应该不会触发任何安全警告

import os
import subprocess
import sqlite3
import json
import yaml
from pathlib import Path


# ============== 安全的SQL操作 ==============


def safe_sql_parameterized(user_id):
    """使用参数化查询 - 安全"""
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()


def safe_sql_named_params(username, email):
    """使用命名参数 - 安全"""
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username = :name AND email = :email",
        {"name": username, "email": email},
    )
    return cursor.fetchall()


# ============== 安全的命令执行 ==============


def safe_subprocess_list(filename):
    """使用列表参数 - 安全"""
    result = subprocess.run(["cat", filename], capture_output=True, text=True)
    return result.stdout


def safe_subprocess_no_shell(command_list):
    """shell=False - 安全"""
    result = subprocess.run(command_list, shell=False, capture_output=True)
    return result.stdout


# ============== 安全的配置管理 ==============


def load_config_from_env():
    """从环境变量加载配置 - 安全"""
    return {
        "database_url": os.environ.get("DATABASE_URL"),
        "api_key": os.environ.get("API_KEY"),
        "secret": os.environ.get("SECRET_KEY"),
    }


def load_config_from_file(config_path):
    """从配置文件加载 - 安全"""
    with open(config_path, "r") as f:
        return json.load(f)


# ============== 安全的YAML处理 ==============


def safe_yaml_load(yaml_content):
    """使用 safe_load - 安全"""
    return yaml.safe_load(yaml_content)


def safe_yaml_load_explicit(yaml_content):
    """使用 SafeLoader - 安全"""
    return yaml.load(yaml_content, Loader=yaml.SafeLoader)


# ============== 安全的文件操作 ==============


def safe_file_read(base_dir, filename):
    """验证路径 - 安全"""
    base = Path(base_dir).resolve()
    target = (base / filename).resolve()

    # 验证目标路径在基础目录内
    if not str(target).startswith(str(base)):
        raise ValueError("非法路径访问")

    with open(target, "r") as f:
        return f.read()


def safe_file_with_whitelist(filename):
    """使用白名单 - 安全"""
    ALLOWED_FILES = {"readme.txt", "config.json", "data.csv"}

    if filename not in ALLOWED_FILES:
        raise ValueError("不允许访问该文件")

    with open(f"./data/{filename}", "r") as f:
        return f.read()


# ============== 安全的模板渲染 ==============


def safe_template_render(username):
    """使用自动转义的模板引擎 - 安全"""
    # 在实际应用中使用 Jinja2 的自动转义功能
    from markupsafe import escape

    safe_username = escape(username)
    return f"<h1>Hello, {safe_username}!</h1>"


# ============== 普通代码（无安全相关） ==============


def calculate_sum(numbers):
    """计算数字和 - 普通代码"""
    return sum(numbers)


def format_message(template, **kwargs):
    """格式化消息 - 普通代码"""
    # 这是普通的字符串格式化，不是SQL
    return template.format(**kwargs)


class DataProcessor:
    """数据处理器 - 普通类"""

    def __init__(self, data):
        self.data = data

    def process(self):
        """处理数据"""
        return [item.strip() for item in self.data if item]

    def to_json(self):
        """转换为JSON"""
        return json.dumps(self.data)
