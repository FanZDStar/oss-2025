"""Flask 安全漏洞测试样本

包含各种 Flask 框架的安全问题示例
"""

from flask import Flask, request, render_template_string, session
from flask import render_template, redirect, url_for, send_from_directory
from markupsafe import Markup
import os

# ============================================
# FLK001: Debug 模式启用
# ============================================

app = Flask(__name__)

# 问题1：app.run(debug=True)
def create_app_with_debug():
    """危险：启用 debug 模式"""
    app.run(debug=True)  # FLK001


# 问题2：app.debug = True
def configure_debug_property():
    """危险：直接设置 debug 属性"""
    app.debug = True  # FLK001


# 问题3：通过配置启用 DEBUG
def configure_debug_config():
    """危险：通过配置启用 DEBUG"""
    app.config['DEBUG'] = True  # FLK001


# 安全示例：使用环境变量
def safe_debug_config():
    """安全：从环境变量读取 debug 配置"""
    app.config['DEBUG'] = os.getenv('FLASK_DEBUG', 'False') == 'True'


# ============================================
# FLK002: SECRET_KEY 硬编码
# ============================================

# 问题1：硬编码 SECRET_KEY
app.config['SECRET_KEY'] = 'my-super-secret-key-12345'  # FLK002

# 问题2：使用 secret_key 属性
def configure_secret_key_property():
    """危险：硬编码 secret_key"""
    app.secret_key = 'hardcoded-secret-value'  # FLK002


# 安全示例：从环境变量读取
def safe_secret_key_config():
    """安全：从环境变量读取 SECRET_KEY"""
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')


# ============================================
# FLK003: Session 配置不安全
# ============================================

# 问题1：SESSION_COOKIE_SECURE = False
app.config['SESSION_COOKIE_SECURE'] = False  # FLK003

# 问题2：SESSION_COOKIE_HTTPONLY = False
app.config['SESSION_COOKIE_HTTPONLY'] = False  # FLK003

# 问题3：SESSION_COOKIE_SAMESITE = None
app.config['SESSION_COOKIE_SAMESITE'] = None  # FLK003


# 安全示例：正确的 session 配置
def safe_session_config():
    """安全：设置安全的 session 配置"""
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


# ============================================
# FLK004: Jinja2 模板注入
# ============================================

@app.route('/greet/<name>')
def vulnerable_template_injection_1(name):
    """危险：使用 f-string 拼接模板"""
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)  # FLK004


@app.route('/welcome')
def vulnerable_template_injection_2():
    """危险：使用字符串拼接"""
    user_input = request.args.get('name', 'Guest')
    template = "<h1>Welcome " + user_input + "!</h1>"
    return render_template_string(template)  # FLK004


@app.route('/message')
def vulnerable_template_injection_3():
    """危险：使用 .format() 拼接模板"""
    message = request.args.get('msg', '')
    template = "<p>{}</p>".format(message)
    return render_template_string(template)  # FLK004


@app.route('/custom')
def vulnerable_template_injection_4():
    """危险：使用变量作为模板"""
    user_template = request.args.get('template', '<h1>Default</h1>')
    return render_template_string(user_template)  # FLK004


@app.route('/safe_html')
def vulnerable_markup():
    """问题：使用 Markup 可能导致 XSS"""
    user_html = request.args.get('html', '')
    safe_html = Markup(user_html)  # FLK004 (MEDIUM)
    return safe_html


# 安全示例：使用模板文件
@app.route('/safe/greet/<name>')
def safe_template_usage(name):
    """安全：使用模板文件和自动转义"""
    return render_template('greet.html', name=name)


# ============================================
# FLK005: 不安全的文件上传
# ============================================

@app.route('/upload1', methods=['POST'])
def vulnerable_file_upload_1():
    """危险：未使用 secure_filename，未验证扩展名"""
    file = request.files['file']
    filename = file.filename  # 直接使用用户提供的文件名
    file.save(f'uploads/{filename}')  # FLK005 x2
    return 'File uploaded'


@app.route('/upload2', methods=['POST'])
def vulnerable_file_upload_2():
    """危险：未验证文件扩展名"""
    from werkzeug.utils import secure_filename
    
    file = request.files['file']
    filename = secure_filename(file.filename)  # 有 secure_filename
    file.save(f'uploads/{filename}')  # 但缺少扩展名验证 - FLK005
    return 'File uploaded'


@app.route('/upload3', methods=['POST'])
def vulnerable_file_upload_3():
    """危险：未使用 secure_filename"""
    file = request.files.get('document')
    
    # 检查扩展名但未使用 secure_filename
    if file and file.filename.endswith('.pdf'):  # 有扩展名检查
        file.save(f'documents/{file.filename}')  # 缺少 secure_filename - FLK005
    return 'Document uploaded'


# 安全示例：完整的文件上传验证
@app.route('/safe/upload', methods=['POST'])
def safe_file_upload():
    """安全：完整的文件上传验证"""
    from werkzeug.utils import secure_filename
    
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
    
    file = request.files['file']
    if file and file.filename:
        # 验证扩展名
        ext = file.filename.rsplit('.', 1)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            return 'Invalid file type', 400
        
        # 使用 secure_filename
        filename = secure_filename(file.filename)
        
        # 保存到安全位置
        file.save(os.path.join('uploads', filename))
        return 'File uploaded successfully'
    
    return 'No file provided', 400


# ============================================
# 综合示例：多个问题
# ============================================

@app.route('/admin/users')
def dangerous_admin_view():
    """危险：综合多个安全问题"""
    # 问题1：未验证身份
    user_id = request.args.get('id')
    
    # 问题2：模板注入
    template = f"<h1>User ID: {user_id}</h1>"
    return render_template_string(template)  # FLK004


# 启动应用（多个问题）
if __name__ == '__main__':
    # 问题：硬编码密钥 + 启用 debug
    app.secret_key = 'weak-secret-123'  # FLK002
    app.config['SESSION_COOKIE_SECURE'] = False  # FLK003
    app.run(debug=True, host='0.0.0.0')  # FLK001
