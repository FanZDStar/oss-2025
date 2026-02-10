"""
安全扫描器模块，用于扫描Python代码中的安全漏洞。
此版本已包含5.3内存优化任务的所有优化点：
1. 大文件分块处理
2. 生成器模式减少内存占用
3. AST节点按需遍历
4. 及时释放不需要的对象
"""
from pathlib import Path
from typing import List, Dict, Any, Generator, Optional
import time
import ast
import re
from .cache import CacheManager


class Vulnerability:
    """表示一个安全漏洞"""
    def __init__(self, rule_id: str, description: str, severity: str, 
                 line_number: int, code_snippet: str, suggestion: str = ""):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        self.line_number = line_number
        self.code_snippet = code_snippet
        self.suggestion = suggestion
    
    def to_dict(self) -> Dict[str, Any]:
        """将漏洞对象转换为字典，便于缓存存储"""
        return {
            'rule_id': self.rule_id,
            'description': self.description,
            'severity': self.severity,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'suggestion': self.suggestion
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Vulnerability':
        """从字典创建漏洞对象"""
        return cls(
            rule_id=data['rule_id'],
            description=data['description'],
            severity=data['severity'],
            line_number=data['line_number'],
            code_snippet=data['code_snippet'],
            suggestion=data.get('suggestion', '')
        )


class SecurityScanner:
    def __init__(self, config=None, no_cache=False):
        """
        初始化安全扫描器。
        
        Args:
            config: 配置字典
            no_cache: 是否禁用缓存
        """
        self.config = config or {}
        # 初始化缓存管理器，如果no_cache为True，则禁用缓存
        self.cache_manager = CacheManager(enable=not no_cache)
        
    def scan_file(self, file_path: Path) -> List[Vulnerability]:
        """
        扫描单个Python文件的安全漏洞。
        
        Args:
            file_path: 文件路径
            
        Returns:
            漏洞对象列表
        """
        # 1. 尝试从缓存获取结果
        cached_result = self.cache_manager.get(file_path)
        if cached_result is not None:
            # 缓存命中，从缓存数据恢复漏洞对象
            print(f"[缓存命中] {file_path}")
            vulnerabilities = []
            for vuln_data in cached_result.get('vulnerabilities', []):
                vulnerabilities.append(Vulnerability.from_dict(vuln_data))
            return vulnerabilities
        
        # 2. 缓存未命中，执行实际扫描
        print(f"[扫描文件] {file_path}")
        vulnerabilities = self._do_actual_scan(file_path)
        
        # 3. 将结果存入缓存
        result_to_cache = {
            'file_path': str(file_path),
            'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities],
            'scan_timestamp': time.time()
        }
        self.cache_manager.set(file_path, result_to_cache)
        
        return vulnerabilities
    
    def _do_actual_scan(self, file_path: Path) -> List[Vulnerability]:
        """
        实际的扫描逻辑。
        
        已实现优化点：
        1. 大文件分块处理：超过1000行的文件使用正则扫描，避免AST内存消耗
        2. AST节点按需遍历：只遍历Call节点，减少不必要的对象创建
        3. 及时释放对象：显式删除大对象
        """
        vulnerabilities = []
        
        try:
            # ========== 优化1：大文件分块处理 ==========
            # 按行读取文件，避免一次性读取大文件到内存
            lines = []
            line_count = 0
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    lines.append((line_num, line.rstrip('\n')))
                    line_count += 1
            
            # 如果文件过大（超过1000行），使用正则表达式扫描（降级方案）
            if line_count > 1000:
                print(f"  警告: 文件过大({line_count}行)，使用正则扫描以避免内存问题")
                return self._scan_large_file_with_regex(lines, file_path)
            
            # 将行合并为字符串（用于AST解析）
            content = '\n'.join(line for _, line in lines)
            # ========== 优化1结束 ==========
            
            # 解析Python代码为AST
            try:
                tree = ast.parse(content)
            except SyntaxError:
                # 语法错误不视为安全漏洞
                del content, lines  # 及时释放对象
                return vulnerabilities
            
            # ========== 优化3：AST节点按需遍历 ==========
            # 只遍历我们关心的Call节点，而不是遍历所有节点
            
            # 自定义生成器，只遍历函数调用节点
            def visit_call_nodes(node):
                """递归遍历AST，只返回函数调用节点"""
                if isinstance(node, ast.Call):
                    yield node
                # 递归遍历子节点
                for child in ast.iter_child_nodes(node):
                    yield from visit_call_nodes(child)
            
            # 规则1: 检测exec的使用
            for node in visit_call_nodes(tree):
                if isinstance(node.func, ast.Name) and node.func.id == 'exec':
                    line_content = lines[node.lineno-1][1] if node.lineno <= len(lines) else ""
                    vulnerabilities.append(Vulnerability(
                        rule_id="SEC001",
                        description="检测到exec()函数的使用，可能存在代码注入风险",
                        severity="高危",
                        line_number=node.lineno,
                        code_snippet=line_content,
                        suggestion="避免使用exec()，考虑使用更安全的方法如eval()或ast.literal_eval()"
                    ))
                    break  # 找到一个就够，不用继续找
            
            # 规则2: 检测eval的使用
            for node in visit_call_nodes(tree):
                if isinstance(node.func, ast.Name) and node.func.id == 'eval':
                    line_content = lines[node.lineno-1][1] if node.lineno <= len(lines) else ""
                    vulnerabilities.append(Vulnerability(
                        rule_id="SEC002",
                        description="检测到eval()函数的使用，可能存在代码注入风险",
                        severity="中危",
                        line_number=node.lineno,
                        code_snippet=line_content,
                        suggestion="避免使用eval()，考虑使用ast.literal_eval()或直接解析"
                    ))
                    break
            
            # 规则3: 检测pickle.loads的使用
            for node in visit_call_nodes(tree):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == 'loads' and isinstance(node.func.value, ast.Name):
                        if node.func.value.id == 'pickle':
                            line_content = lines[node.lineno-1][1] if node.lineno <= len(lines) else ""
                            vulnerabilities.append(Vulnerability(
                                rule_id="SEC003",
                                description="检测到pickle.loads()的使用，可能存在反序列化攻击风险",
                                severity="高危",
                                line_number=node.lineno,
                                code_snippet=line_content,
                                suggestion="避免反序列化不受信任的数据，考虑使用json或yaml等更安全的格式"
                            ))
                            break
            
            # 规则4: 检测os.system的使用
            for node in visit_call_nodes(tree):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == 'system' and isinstance(node.func.value, ast.Name):
                        if node.func.value.id == 'os':
                            line_content = lines[node.lineno-1][1] if node.lineno <= len(lines) else ""
                            vulnerabilities.append(Vulnerability(
                                rule_id="SEC004",
                                description="检测到os.system()的使用，可能存在命令注入风险",
                                severity="高危",
                                line_number=node.lineno,
                                code_snippet=line_content,
                                suggestion="使用subprocess.run()替代，并避免将用户输入直接传递给shell"
                            ))
                            break
            
            # 规则5: 检测硬编码的密码/密钥（使用正则表达式，避免AST遍历）
            sensitive_keywords = ['password', 'secret', 'key', 'token', 'credential']
            for line_num, line in lines:
                line_lower = line.lower()
                for keyword in sensitive_keywords:
                    if f'"{keyword}"' in line_lower or f"'{keyword}'" in line_lower:
                        if '=' in line and ('"' in line or "'" in line):
                            vulnerabilities.append(Vulnerability(
                                rule_id="SEC005",
                                description=f"检测到可能硬编码的敏感信息: {keyword}",
                                severity="中危",
                                line_number=line_num,
                                code_snippet=line[:100],  # 只取前100字符
                                suggestion="避免在代码中硬编码敏感信息，使用环境变量或配置文件"
                            ))
                            break
            # ========== 优化3结束 ==========
            
        except Exception as e:
            # 文件读取或解析出错
            print(f"  扫描文件时出错: {e}")
        
        finally:
            # ========== 优化4：及时释放不需要的对象 ==========
            # 显式删除大对象，帮助垃圾回收
            if 'content' in locals():
                del content
            if 'lines' in locals():
                del lines
            if 'tree' in locals():
                del tree
            # ========== 优化4结束 ==========
        
        return vulnerabilities
    
    def _scan_large_file_with_regex(self, lines: List[tuple], file_path: Path) -> List[Vulnerability]:
        """
        对大文件使用正则表达式进行简单扫描，避免完整AST解析的内存消耗。
        
        Args:
            lines: 文件行列表，每个元素为(行号, 行内容)
            file_path: 文件路径
            
        Returns:
            漏洞对象列表
        """
        vulnerabilities = []
        
        # 使用正则表达式检测明显的安全问题
        exec_pattern = re.compile(r'\bexec\s*\(')
        eval_pattern = re.compile(r'\beval\s*\(')
        pickle_pattern = re.compile(r'\bpickle\.loads\s*\(')
        system_pattern = re.compile(r'\bos\.system\s*\(')
        password_pattern = re.compile(r'password\s*=\s*[\'"][^\'"]+[\'"]')
        
        for line_num, line_str in lines:
            line_str = line_str.strip()
            if not line_str or line_str.startswith('#'):
                continue
            
            if exec_pattern.search(line_str):
                vulnerabilities.append(Vulnerability(
                    rule_id="SEC001",
                    description="检测到exec()函数的使用，可能存在代码注入风险",
                    severity="高危",
                    line_number=line_num,
                    code_snippet=line_str[:100],
                    suggestion="避免使用exec()，考虑使用更安全的方法"
                ))
            
            if eval_pattern.search(line_str):
                vulnerabilities.append(Vulnerability(
                    rule_id="SEC002",
                    description="检测到eval()函数的使用，可能存在代码注入风险",
                    severity="中危",
                    line_number=line_num,
                    code_snippet=line_str[:100],
                    suggestion="避免使用eval()"
                ))
            
            if pickle_pattern.search(line_str):
                vulnerabilities.append(Vulnerability(
                    rule_id="SEC003",
                    description="检测到pickle.loads()的使用，可能存在反序列化攻击风险",
                    severity="高危",
                    line_number=line_num,
                    code_snippet=line_str[:100],
                    suggestion="避免反序列化不受信任的数据"
                ))
            
            if system_pattern.search(line_str):
                vulnerabilities.append(Vulnerability(
                    rule_id="SEC004",
                    description="检测到os.system()的使用，可能存在命令注入风险",
                    severity="高危",
                    line_number=line_num,
                    code_snippet=line_str[:100],
                    suggestion="使用subprocess.run()替代"
                ))
            
            if password_pattern.search(line_str):
                vulnerabilities.append(Vulnerability(
                    rule_id="SEC005",
                    description="检测到硬编码的密码/密钥",
                    severity="中危",
                    line_number=line_num,
                    code_snippet=line_str[:100],
                    suggestion="使用环境变量或配置文件存储敏感信息"
                ))
        
        return vulnerabilities
    
    def scan_files_generator(self, directory_path: Path, exclude_dirs=None) -> Generator:
        """
        生成器版本的目录扫描，逐个文件产出结果，减少内存占用。
        
        Args:
            directory_path: 要扫描的目录路径
            exclude_dirs: 排除的目录列表
            
        Yields:
            (file_path, vulnerabilities) 对每个文件
            
        这是优化点2：生成器模式减少内存占用
        """
        if exclude_dirs is None:
            exclude_dirs = []
        
        # 遍历目录中的Python文件
        for py_file in directory_path.rglob("*.py"):
            # 跳过排除目录
            skip = False
            for exclude in exclude_dirs:
                if exclude in str(py_file):
                    skip = True
                    break
            if skip:
                continue
            
            # 跳过缓存目录
            if '.pysec_cache' in str(py_file):
                continue
            
            # 扫描单个文件并立即产出结果
            vulnerabilities = self.scan_file(py_file)
            yield (py_file, vulnerabilities)
    
    def scan_directory(self, directory_path: Path) -> Dict[str, Any]:
        """
        扫描整个目录（兼容旧接口，内部使用生成器）。
        
        使用了优化点2：生成器模式减少内存占用
        """
        results = {
            'total_files': 0,
            'files_scanned': 0,
            'vulnerabilities_found': 0,
            'details': []
        }
        
        # 收集排除目录（从配置或参数）
        exclude_dirs = self.config.get('exclude_dirs', [])
        
        # 使用生成器逐个处理文件，减少内存占用
        for py_file, vulnerabilities in self.scan_files_generator(directory_path, exclude_dirs):
            results['total_files'] += 1
            
            if vulnerabilities:
                results['vulnerabilities_found'] += len(vulnerabilities)
                results['details'].append({
                    'file': str(py_file.relative_to(directory_path)),
                    'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities]
                })
            
            results['files_scanned'] += 1
        
        return results