import sys
sys.path.insert(0, '.')

from pysec.scanner import Scanner

# 准备文件列表
file_paths = [f"test_threads/test_{i}.py" for i in range(1, 11)]

scanner = Scanner(use_cache=False)

print("=== 测试单线程 ===")
results_single = scanner.scan_files(file_paths)
for result in results_single:
    file_path, tree, source, error = result
    if error:
        print(f"✗ {file_path}: {error}")
    else:
        print(f"✓ {file_path}: 解析成功")

print("\n=== 测试多线程 (2个线程) ===")
results_parallel = scanner.scan_files_parallel(file_paths, max_workers=2)
for result in results_parallel:
    file_path, tree, source, error = result
    if error:
        print(f"✗ {file_path}: {error}")
    else:
        print(f"✓ {file_path}: 解析成功")

print("\n=== 测试多线程 (自动检测核心数) ===")
results_auto = scanner.scan_files_parallel(file_paths, max_workers=None)
for result in results_auto:
    file_path, tree, source, error = result
    if error:
        print(f"✗ {file_path}: {error}")
    else:
        print(f"✓ {file_path}: 解析成功")
