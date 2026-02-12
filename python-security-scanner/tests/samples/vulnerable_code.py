# PySecScanner 测试样本 - 包含漏洞的代码
# 用于测试安全扫描器的检测能力

import os
import subprocess
import sqlite3
import pickle
import yaml
from flask import request, render_template_string
from django.utils.safestring import mark_safe


# ============== SQL注入漏洞 ==============


def vulnerable_sql_query_format(user_id):
    """SQL注入 - 使用 % 格式化"""
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # 危险：直接将用户输入拼接到SQL语句
    query = "SELECT * FROM users WHERE id = '%s'" % user_id
    cursor.execute(query)
    return cursor.fetchall()


def vulnerable_sql_query_fstring(username):
    """SQL注入 - 使用 f-string"""
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # 危险：f-string 拼接SQL
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()


def vulnerable_sql_query_concat(table_name):
    """SQL注入 - 使用字符串拼接"""
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # 危险：字符串连接拼接SQL
    query = "SELECT * FROM " + table_name + " WHERE active = 1"
    cursor.execute(query)
    return cursor.fetchall()


# ============== 命令注入漏洞 ==============


def vulnerable_os_system(user_input):
    """命令注入 - os.system"""
    # 危险：用户输入直接传递给系统命令
    os.system("ping " + user_input)


def vulnerable_subprocess_shell(cmd):
    """命令注入 - subprocess with shell=True"""
    # 危险：shell=True 且使用用户输入
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout


def vulnerable_os_popen(filename):
    """命令注入 - os.popen"""
    # 危险：os.popen 执行用户可控命令
    output = os.popen(f"cat {filename}").read()
    return output


# ============== 硬编码凭据 ==============

# 危险：硬编码密码
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD", "")
API_KEY = os.environ.get("API_KEY", "")
SECRET_TOKEN = os.environ.get("SECRET_TOKEN", "")


def connect_database():
    """使用硬编码密码连接数据库"""
    password = os.environ.get("PASSWORD", "")  # 危险：硬编码密码
    return f"mysql://admin:{password}@localhost/mydb"


def get_api_credentials():
    """返回硬编码的API密钥"""
    secret = os.environ.get("SECRET", "")  # 危险
    return {"key": API_KEY, "secret": secret}


# ============== 危险函数调用 ==============


def vulnerable_eval(user_expr):
    """危险函数 - eval"""
    # 危险：执行用户输入的代码
    result = eval(user_expr)
    return result


def vulnerable_exec(user_code):
    """危险函数 - exec"""
    # 危险：执行用户提供的代码
    exec(user_code)


def vulnerable_pickle_loads(data):
    """危险函数 - pickle.loads"""
    # 危险：反序列化不可信数据
    obj = pickle.loads(data)
    return obj


def vulnerable_yaml_load(yaml_content):
    """危险函数 - yaml.load without Loader"""
    # 危险：使用不安全的 yaml.load
    data = yaml.load(yaml_content)
    return data


# ============== 路径遍历漏洞 ==============


def vulnerable_file_read(filename):
    """路径遍历 - 直接打开用户指定文件"""
    # 危险：没有验证文件路径
    with open(filename, "r") as f:
        return f.read()


def vulnerable_path_join(base_dir, user_path):
    """路径遍历 - os.path.join 可被绕过"""
    # 危险：os.path.join 无法阻止绝对路径
    file_path = os.path.join(base_dir, user_path)
    return open(file_path, "r").read()


def vulnerable_file_download(request):
    """路径遍历 - 下载用户指定文件"""
    filename = request.args.get("file")
    # 危险：直接使用用户输入作为文件路径
    with open(f"/uploads/{filename}", "rb") as f:
        return f.read()


# ============== XSS 漏洞 ==============


def vulnerable_render_template_string(user_input):
    """XSS - render_template_string"""
    # 危险：用户输入直接渲染到模板
    template = f"<h1>Hello, {user_input}!</h1>"
    return render_template_string(template)


def vulnerable_mark_safe(user_content):
    """XSS - mark_safe"""
    # 危险：将用户内容标记为安全
    return mark_safe(f"<div>{user_content}</div>")


# ============== 安全的代码示例（不应被检测） ==============


def safe_sql_query(user_id):
    """安全的SQL查询 - 使用参数化查询"""
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # 安全：使用参数化查询
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()


def safe_subprocess(args_list):
    """安全的子进程调用 - 使用列表参数"""
    # 安全：shell=False 且使用列表参数
    result = subprocess.run(args_list, capture_output=True)
    return result.stdout


def safe_yaml_load(yaml_content):
    """安全的YAML加载 - 使用SafeLoader"""
    # 安全：使用 safe_load
    data = yaml.safe_load(yaml_content)
    return data


# ============== SSRF 漏洞 ==============


def vulnerable_ssrf_requests(url):
    """SSRF - requests.get 用户输入URL"""
    import requests

    # 危险：用户输入直接作为URL
    response = requests.get(url)
    return response.text


def vulnerable_ssrf_requests_post(user_url):
    """SSRF - requests.post 用户输入URL"""
    import requests

    # 危险：用户可控制请求目标
    response = requests.post(user_url, data={"key": "value"})
    return response.json()


def vulnerable_ssrf_urllib(target_url):
    """SSRF - urllib.request.urlopen 用户输入URL"""
    import urllib.request

    # 危险：用户输入直接传递给urlopen
    response = urllib.request.urlopen(target_url)
    return response.read()


def vulnerable_ssrf_urlopen_direct(url):
    """SSRF - urlopen 直接调用"""
    from urllib.request import urlopen

    # 危险：直接使用用户URL
    response = urlopen(url)
    return response.read()


# ============== XXE 漏洞 ==============


def vulnerable_xxe_elementtree(xml_file):
    """XXE - xml.etree.ElementTree 不安全解析"""
    import xml.etree.ElementTree as ET

    # 危险：默认配置存在XXE风险
    tree = ET.parse(xml_file)
    return tree.getroot()


def vulnerable_xxe_lxml(xml_content):
    """XXE - lxml 不安全解析"""
    from lxml import etree

    # 危险：默认配置允许外部实体
    doc = etree.fromstring(xml_content)
    return doc


def vulnerable_xxe_sax(xml_file):
    """XXE - xml.sax 不安全解析"""
    import xml.sax

    # 危险：xml.sax 默认配置存在XXE风险
    xml.sax.parse(xml_file, xml.sax.ContentHandler())
