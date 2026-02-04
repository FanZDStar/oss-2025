# 1. 行内忽略（单行忽略）
password = "secret123"  # pysec: ignore

# 2. 指定规则忽略
# 只忽略 SQL 注入检查，其他规则仍会检查
query = f"SELECT * FROM users WHERE id = {user_input}"  # pysec: ignore[SQL001]

# 3. 代码块忽略
# pysec: disable
# 以下代码块中的所有安全检查都会被忽略
eval(user_input)  # 通常会被标记为危险，但这里被忽略
exec("print('危险操作')")  # 同样被忽略
# pysec: enable

# 4. 文件级别忽略（通常在文件开头）
# pysec: ignore-file
# 如果添加这行注释，整个文件都会被忽略

# 忽略后恢复正常检查的代码
another_password = "test456"  # 这行会被检查（如果没有文件级别忽略）

print("示例结束")
