"""
测试忽略注释功能的示例代码

此文件包含各种安全漏洞，并使用不同的忽略注释进行测试
"""

import os
import subprocess
import pickle


# ========== 测试1: 行级忽略所有规则 ==========

# 这行会被检测到
password1 = "hardcoded_password_123"

# 这行不会被检测到（忽略所有规则）
password2 = "another_secret_456"  # pysec: ignore


# ========== 测试2: 指定规则忽略 ==========

# 只忽略 SEC001（硬编码密钥检测），但其他规则仍然生效
API_KEY = "sk-test-key-12345"  # pysec: ignore[SEC001]

# 这行会被 SQL001 检测到，因为没有忽略
query1 = "SELECT * FROM users WHERE id = '%s'" % user_id

# 这行不会被 SQL001 检测到（忽略 SQL001）
query2 = "SELECT * FROM users WHERE id = '%s'" % user_id  # pysec: ignore[SQL001]


# ========== 测试3: 忽略多个规则 ==========

# 同时忽略 SEC001 和 DNG001
secret = "my_secret_token"  # pysec: ignore[SEC001,DNG001]

# 这行会被检测到（没有忽略）
another_secret = "yet_another_secret"


# ========== 测试4: 代码块忽略 ==========

# 正常检测：这个会被检测到
eval("1 + 1")

# pysec: disable
# 这个代码块中的所有问题都会被忽略
eval(user_input)
exec(malicious_code)
os.system("rm -rf " + user_path)
pickle.loads(untrusted_data)
password_in_block = "block_password_123"
# pysec: enable

# 恢复检测：这个会被检测到
eval("2 + 2")


# ========== 测试5: 混合使用 ==========

# pysec: disable
# 代码块忽略中
dangerous_func1 = eval("dangerous")

# 即使在代码块中，行级忽略仍然有效（冗余但不冲突）
dangerous_func2 = eval("more_dangerous")  # pysec: ignore

dangerous_func3 = exec("code")
# pysec: enable

# 代码块外，恢复检测
dangerous_func4 = eval("back_to_normal")


# ========== 测试6: 嵌套和边界情况 ==========

def test_function():
    # 这个会被检测到
    cmd1 = os.system("ls")
    
    # pysec: disable
    # 函数内部的代码块忽略
    cmd2 = os.system("rm -rf /")
    cmd3 = subprocess.run("dangerous", shell=True)
    # pysec: enable
    
    # 恢复检测
    cmd4 = os.system("pwd")
    
    return cmd1, cmd4


# ========== 测试7: 大小写和空格容错 ==========

# 测试不同的注释格式（应该都能识别）
secret1 = "test1"  # pysec:ignore
secret2 = "test2"  # PYSEC: IGNORE
secret3 = "test3"  #pysec:ignore[SEC001]
secret4 = "test4"  # pysec: ignore[SEC001, DNG001]
