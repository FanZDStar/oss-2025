"""
Django 安全漏洞测试样例

包含 Django 框架常见的安全配置问题
"""

import os
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.db import models
from django.db.models import Q
from django.db.models.expressions import RawSQL


# ========== settings.py 模拟配置 ==========

# DJG001: DEBUG 模式开启 - 高危
DEBUG = True  # 危险：生产环境不应启用 DEBUG

# DJG002: SECRET_KEY 硬编码 - 严重
SECRET_KEY = 'django-insecure-#p3l@k$m9n@b8v7c6x4z2a1s'  # 危险：密钥硬编码

# DJG003: ALLOWED_HOSTS 配置不当 - 高危
ALLOWED_HOSTS = ['*']  # 危险：允许所有主机

# DJG004: CSRF 中间件未配置
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware',  # 危险：CSRF 保护被注释掉
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# 其他配置
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'db.sqlite3',
    }
}


# ========== 安全的配置示例（不应该被检测到）==========

class SafeSettings:
    """安全的配置示例"""
    
    # 安全：使用环境变量
    DEBUG = os.getenv('DEBUG', 'False') == 'True'
    SECRET_KEY = os.environ.get('SECRET_KEY')
    ALLOWED_HOSTS = ['example.com', 'www.example.com']
    
    # 安全：包含 CSRF 中间件
    MIDDLEWARE = [
        'django.middleware.security.SecurityMiddleware',
        'django.middleware.csrf.CsrfViewMiddleware',  # 正确配置
        'django.contrib.auth.middleware.AuthenticationMiddleware',
    ]


# ========== DJG004: CSRF 保护禁用 ==========

# 危险：使用 @csrf_exempt 装饰器
@csrf_exempt
def vulnerable_api_view(request):
    """这个视图禁用了 CSRF 保护"""
    user_data = request.POST.get('data')
    # 处理数据...
    return render(request, 'template.html')


@csrf_exempt
def payment_endpoint(request):
    """危险：支付接口禁用 CSRF 保护"""
    amount = request.POST.get('amount')
    # 处理支付...
    return render(request, 'payment.html')


# 安全示例：正常的视图（有 CSRF 保护）
def safe_view(request):
    """安全的视图，使用 CSRF 保护"""
    return render(request, 'template.html')


# ========== DJG005: 原始 SQL 查询 ==========

class User(models.Model):
    username = models.CharField(max_length=100)
    email = models.EmailField()


def get_users_vulnerable_1(user_id):
    """危险：使用 raw() 和字符串拼接"""
    # 字符串格式化
    sql = "SELECT * FROM users WHERE id = %s" % user_id
    users = User.objects.raw(sql)
    return users


def get_users_vulnerable_2(username):
    """危险：使用 raw() 和 f-string"""
    # f-string 拼接
    users = User.objects.raw(f"SELECT * FROM users WHERE username = '{username}'")
    return users


def get_users_vulnerable_3(email):
    """危险：使用 raw() 和 .format()"""
    # .format() 拼接
    sql = "SELECT * FROM users WHERE email = '{}'".format(email)
    users = User.objects.raw(sql)
    return users


def get_users_vulnerable_4(query):
    """危险：使用 extra() 方法"""
    # extra() 允许添加原始 SQL
    users = User.objects.extra(
        where=["username = '%s'" % query]
    )
    return users


def get_users_vulnerable_5():
    """危险：使用 RawSQL 表达式"""
    # RawSQL 允许原始 SQL
    users = User.objects.annotate(
        custom_field=RawSQL("SELECT COUNT(*) FROM other_table", [])
    )
    return users


def complex_vulnerable_query(user_input):
    """危险：复杂的原始 SQL 查询"""
    # 使用 extra() 和字符串拼接
    users = User.objects.extra(
        select={'full_name': "username || ' ' || email"},
        where=[f"id > {user_input}"]  # SQL 注入风险
    )
    return users


# 安全示例：使用参数化查询
def get_users_safe_1(user_id):
    """安全：使用参数化查询"""
    users = User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])
    return users


def get_users_safe_2(username):
    """安全：使用 Django ORM"""
    users = User.objects.filter(username=username)
    return users


def get_users_safe_3(email):
    """安全：使用 Q 对象"""
    users = User.objects.filter(Q(email=email))
    return users


# ========== 实际应用场景 ==========

def search_users_vulnerable(search_term, order_by):
    """危险：搜索功能使用原始 SQL"""
    # 排序字段直接拼接，可能导致 SQL 注入
    users = User.objects.extra(
        where=["username LIKE '%%' || %s || '%%'" % search_term],
        order_by=[order_by]  # 直接使用用户输入作为排序字段
    )
    return users


def get_report_vulnerable(start_date, end_date):
    """危险：报表查询使用 raw()"""
    sql = f"""
        SELECT * FROM users 
        WHERE created_at BETWEEN '{start_date}' AND '{end_date}'
        ORDER BY created_at DESC
    """
    return User.objects.raw(sql)


@csrf_exempt
def api_upload_file(request):
    """危险：文件上传 API 禁用 CSRF 保护"""
    if request.method == 'POST':
        uploaded_file = request.FILES.get('file')
        # 处理文件...
    return render(request, 'upload.html')


# ========== 多个问题组合 ==========

class VulnerableView:
    """包含多个安全问题的视图类"""
    
    @csrf_exempt  # 问题1：禁用 CSRF
    def dangerous_action(self, request):
        """危险的操作"""
        user_id = request.POST.get('id')
        
        # 问题2：使用原始 SQL
        sql = f"DELETE FROM users WHERE id = {user_id}"
        User.objects.raw(sql)
        
        return render(request, 'template.html')


# ========== 配置变体测试 ==========

# 测试不同的 DEBUG 配置
DEBUG_PROD = True  # 也应该被检测

# 测试其他变量名（不应该被检测）
MY_DEBUG = True
IS_DEBUG = True

# 测试 ALLOWED_HOSTS 的其他形式
ALLOWED_HOSTS_2 = ['*', 'example.com']  # 包含 * 也是危险的

# 测试 ALLOWED_HOSTS 安全配置
ALLOWED_HOSTS_SAFE = ['localhost', '127.0.0.1', 'example.com']
