"""
高级扫描引擎模块 - AdvancedScanner
整合多线程扫描、进度条、JUnit报告、缓存、日志等全功能
支持大规模项目的高效安全扫描

作者：wowowow666
版本：1.0.0
"""

import os
import sys
import time
import json
import logging
import threading
import multiprocessing
from typing import List, Dict, Set, Optional, Callable, Iterable, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from xml.etree import ElementTree as ET
from xml.dom import minidom

# 第三方依赖（兼容标准库）
try:
    from tqdm import tqdm
except ImportError:
    # 降级到原生进度条（无tqdm时）
    class tqdm:
        def __init__(self, total, desc="", unit="", dynamic_ncols=True, bar_format=None):
            self.total = total
            self.desc = desc
            self.unit = unit
            self.n = 0
            self.start_time = time.time()

        def update(self, n=1):
            self.n += n
            self._print_progress()

        def set_postfix(self, **kwargs):
            self.postfix = kwargs

        def close(self):
            print(f"\n{self.desc} 完成：{self.n}/{self.total} {self.unit}")

        def _print_progress(self):
            elapsed = time.time() - self.start_time
            rate = self.n / elapsed if elapsed > 0 else 0
            print(f"\r{self.desc}: {self.n}/{self.total} {self.unit} | {rate:.2f} {self.unit}/s", end="")

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("pysec_scan.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("AdvancedScanner")

# 漏洞等级枚举
class VulnerabilitySeverity(Enum):
    CRITICAL = "critical"  # 致命
    HIGH = "high"          # 高风险
    MEDIUM = "medium"      # 中风险
    LOW = "low"            # 低风险
    INFO = "info"          # 信息提示

# 漏洞类型枚举
class VulnerabilityType(Enum):
    SQL_INJECTION = "SQL注入"
    COMMAND_INJECTION = "命令注入"
    HARDCODED_CREDENTIALS = "硬编码凭据"
    DANGEROUS_FUNCTIONS = "危险函数"
    PATH_TRAVERSAL = "路径遍历"
    XSS = "跨站脚本攻击"
    INSECURE_RANDOM = "不安全随机数"
    INSECURE_HASH = "不安全哈希算法"
    SSL_CONFIG = "SSL/TLS配置不当"
    LOG_LEAKAGE = "日志敏感信息泄露"
    UNVALIDATED_INPUT = "未验证输入"
    INSECURE_DESERIALIZATION = "不安全反序列化"
    PERMISSION_ISSUE = "权限配置问题"

# 漏洞数据模型
@dataclass
class Vulnerability:
    """漏洞数据模型"""
    file_path: str
    line_number: int
    column: int = 0
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    vuln_type: VulnerabilityType = VulnerabilityType.UNVALIDATED_INPUT
    message: str = ""
    code_snippet: str = ""
    fix_suggestion: str = ""
    rule_id: str = ""
    confidence: float = 1.0  # 置信度 0-1

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        data = asdict(self)
        data["severity"] = self.severity.value
        data["vuln_type"] = self.vuln_type.value
        return data

# 扫描结果模型
@dataclass
class ScanResult:
    """扫描结果汇总"""
    scan_id: str = field(default_factory=lambda: datetime.now().strftime("%Y%m%d%H%M%S%f"))
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    total_files: int = 0
    scanned_files: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    excluded_files: List[str] = field(default_factory=list)
    scan_duration: float = 0.0
    error_files: List[Tuple[str, str]] = field(default_factory=list)  # (文件路径, 错误信息)

    @property
    def vuln_stats(self) -> Dict[str, int]:
        """漏洞统计（按等级）"""
        stats = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": len(self.vulnerabilities)
        }
        for vuln in self.vulnerabilities:
            stats[vuln.severity.value] += 1
        return stats

    @property
    def type_stats(self) -> Dict[str, int]:
        """漏洞统计（按类型）"""
        stats = {}
        for vuln in self.vulnerabilities:
            type_name = vuln.vuln_type.value
            stats[type_name] = stats.get(type_name, 0) + 1
        return stats

# 进度条管理器（增强版）
class AdvancedProgressBar:
    """高级进度条管理器 - 支持多线程/多进程扫描"""
    
    def __init__(self, total_files: int, disable: bool = False, use_color: bool = True):
        self.total = total_files
        self.disable = disable or not self._is_interactive()
        self.use_color = use_color
        self.pbar = None
        self.lock = threading.Lock()
        self.current_file = ""
        self.errors = 0
        self.skipped = 0
        
    def _is_interactive(self) -> bool:
        """判断是否为交互式终端"""
        try:
            return os.isatty(1)
        except Exception:
            return False
    
    def start(self) -> None:
        """启动进度条"""
        if self.disable:
            return
        
        bar_format = "{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        if self.use_color:
            bar_format = "\033[96m{l_bar}{bar}\033[0m| \033[92m{n_fmt}/{total_fmt}\033[0m [\033[93m{elapsed}\033[0m<\033[93m{remaining}\033[0m, \033[94m{rate_fmt}\033[0m]"
        
        self.pbar = tqdm(
            total=self.total,
            desc="🔍 安全扫描",
            unit="文件",
            dynamic_ncols=True,
            bar_format=bar_format,
            leave=True
        )
    
    def update(self, file_path: str, step: int = 1, is_error: bool = False, is_skipped: bool = False) -> None:
        """更新进度条（线程安全）"""
        with self.lock:
            if self.disable or not self.pbar:
                return
            
            self.current_file = file_path
            if is_error:
                self.errors += 1
            if is_skipped:
                self.skipped += 1
            
            # 构建后缀信息
            postfix = {
                "文件": self._truncate_path(file_path),
                "错误": self.errors,
                "跳过": self.skipped
            }
            
            # 彩色后缀
            if self.use_color:
                postfix = {
                    "文件": f"\033[95m{self._truncate_path(file_path)}\033[0m",
                    "错误": f"\033[91m{self.errors}\033[0m",
                    "跳过": f"\033[90m{self.skipped}\033[0m"
                }
            
            self.pbar.set_postfix(**postfix)
            self.pbar.update(step)
    
    def finish(self) -> None:
        """结束进度条"""
        with self.lock:
            if self.disable or not self.pbar:
                return
            self.pbar.close()
            logger.info(f"扫描完成：处理 {self.pbar.n} 个文件，错误 {self.errors} 个，跳过 {self.skipped} 个")
    
    def _truncate_path(self, path: str, max_len: int = 40) -> str:
        """截断过长路径"""
        if len(path) <= max_len:
            return path
        return "..." + path[-(max_len - 3):]

# JUnit报告生成器（增强版）
class AdvancedJUnitReporter:
    """高级JUnit报告生成器 - 支持完整的CI/CD集成"""
    
    def __init__(self, scan_result: ScanResult):
        self.result = scan_result
        self.root = ET.Element("testsuites")
        self.testsuite = ET.SubElement(self.root, "testsuite")
        self._init_testsuite()
    
    def _init_testsuite(self) -> None:
        """初始化testsuite属性"""
        # 基础信息
        self.testsuite.set("name", "PySecScanner-SecurityScan")
        self.testsuite.set("id", self.result.scan_id)
        self.testsuite.set("timestamp", self.result.start_time.isoformat())
        self.testsuite.set("tests", str(self.result.total_files))
        self.testsuite.set("failures", str(len(self.result.vulnerabilities)))
        self.testsuite.set("errors", str(len(self.result.error_files)))
        self.testsuite.set("skipped", str(len(self.result.excluded_files)))
        self.testsuite.set("time", f"{self.result.scan_duration:.2f}")
        
        # 添加属性
        props = ET.SubElement(self.testsuite, "properties")
        for severity, count in self.result.vuln_stats.items():
            prop = ET.SubElement(props, "property")
            prop.set("name", f"vuln_{severity}")
            prop.set("value", str(count))
    
    def _create_testcase(self, file_path: str, vulnerabilities: List[Vulnerability]) -> ET.Element:
        """为单个文件创建testcase"""
        testcase = ET.SubElement(self.testsuite, "testcase")
        testcase.set("name", f"SecurityScan-{os.path.basename(file_path)}")
        testcase.set("classname", file_path)
        testcase.set("file", file_path)
        
        # 添加漏洞作为failure
        for vuln in vulnerabilities:
            failure = ET.SubElement(testcase, "failure")
            failure.set("type", vuln.vuln_type.value)
            failure.set("severity", vuln.severity.value)
            failure.set("ruleId", vuln.rule_id)
            failure.set("line", str(vuln.line_number))
            
            # 失败详情
            failure_text = f"""
漏洞类型: {vuln.vuln_type.value}
严重程度: {vuln.severity.value.upper()}
位置: {file_path}:{vuln.line_number}:{vuln.column}
描述: {vuln.message}
代码片段:
{vuln.code_snippet}
修复建议:
{vuln.fix_suggestion}
置信度: {vuln.confidence:.2f}
            """.strip()
            failure.text = failure_text
        
        # 添加错误（如果有）
        for err_file, err_msg in self.result.error_files:
            if err_file == file_path:
                error = ET.SubElement(testcase, "error")
                error.set("type", "ScanError")
                error.text = err_msg
        
        return testcase
    
    def generate(self, output_path: str, pretty_print: bool = True) -> None:
        """生成JUnit XML报告"""
        # 按文件分组漏洞
        vulns_by_file: Dict[str, List[Vulnerability]] = {}
        for vuln in self.result.vulnerabilities:
            if vuln.file_path not in vulns_by_file:
                vulns_by_file[vuln.file_path] = []
            vulns_by_file[vuln.file_path].append(vuln)
        
        # 为每个文件创建testcase
        all_files = set(self.result.scanned_files) | set(vulns_by_file.keys())
        for file_path in all_files:
            self._create_testcase(file_path, vulns_by_file.get(file_path, []))
        
        # 为排除的文件创建skipped testcase
        for excluded_file in self.result.excluded_files:
            testcase = ET.SubElement(self.testsuite, "testcase")
            testcase.set("name", f"Excluded-{os.path.basename(excluded_file)}")
            testcase.set("classname", excluded_file)
            skip = ET.SubElement(testcase, "skipped")
            skip.text = "File excluded from scan"
        
        # 生成XML
        xml_str = ET.tostring(self.root, encoding="utf-8")
        if pretty_print:
            xml_str = minidom.parseString(xml_str).toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")
            # 移除多余的空行
            xml_str = "\n".join([line for line in xml_str.split("\n") if line.strip()])
        
        # 保存文件
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(xml_str)
        
        logger.info(f"JUnit报告已生成：{output_path}")

# 扫描缓存管理器
class ScanCache:
    """扫描结果缓存管理器 - 加速增量扫描"""
    
    def __init__(self, cache_dir: str = ".pysec_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_file = self.cache_dir / "scan_cache.json"
        self.cache: Dict[str, Dict[str, Any]] = self._load_cache()
    
    def _load_cache(self) -> Dict[str, Any]:
        """加载缓存"""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"加载缓存失败：{e}")
        return {}
    
    def _save_cache(self) -> None:
        """保存缓存"""
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存缓存失败：{e}")
    
    def get_file_hash(self, file_path: str) -> str:
        """获取文件哈希（简化版）"""
        try:
            import hashlib
            with open(file_path, "rb") as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return ""
    
    def is_file_changed(self, file_path: str) -> bool:
        """检查文件是否变更"""
        file_path = os.path.abspath(file_path)
        current_hash = self.get_file_hash(file_path)
        cached_hash = self.cache.get(file_path, {}).get("hash", "")
        return current_hash != cached_hash
    
    def update_file_cache(self, file_path: str, vulnerabilities: List[Vulnerability]) -> None:
        """更新文件缓存"""
        file_path = os.path.abspath(file_path)
        self.cache[file_path] = {
            "hash": self.get_file_hash(file_path),
            "scan_time": datetime.now().isoformat(),
            "vulnerabilities": [v.to_dict() for v in vulnerabilities]
        }
        self._save_cache()
    
    def get_cached_vulns(self, file_path: str) -> List[Vulnerability]:
        """获取缓存的漏洞"""
        file_path = os.path.abspath(file_path)
        cached_data = self.cache.get(file_path, {})
        vulns = []
        for v_data in cached_data.get("vulnerabilities", []):
            try:
                vuln = Vulnerability(
                    file_path=file_path,
                    line_number=v_data["line_number"],
                    column=v_data.get("column", 0),
                    severity=VulnerabilitySeverity(v_data["severity"]),
                    vuln_type=VulnerabilityType(v_data["vuln_type"]),
                    message=v_data["message"],
                    code_snippet=v_data.get("code_snippet", ""),
                    fix_suggestion=v_data.get("fix_suggestion", ""),
                    rule_id=v_data.get("rule_id", ""),
                    confidence=v_data.get("confidence", 1.0)
                )
                vulns.append(vuln)
            except Exception as e:
                logger.warning(f"解析缓存漏洞失败：{e}")
        return vulns
    
    def clear_cache(self) -> None:
        """清空缓存"""
        self.cache = {}
        if self.cache_file.exists():
            self.cache_file.unlink()
        logger.info("缓存已清空")

# 核心扫描引擎
class AdvancedSecurityScanner:
    """高级安全扫描引擎"""
    
    def __init__(
        self,
        exclude_patterns: List[str] = None,
        include_patterns: List[str] = None,
        min_severity: VulnerabilitySeverity = VulnerabilitySeverity.LOW,
        use_cache: bool = True,
        use_multithreading: bool = True,
        max_workers: int = None,
        show_progress: bool = True
    ):
        self.exclude_patterns = exclude_patterns or ["__pycache__", "venv", "env", ".git", "tests"]
        self.include_patterns = include_patterns or ["*.py"]
        self.min_severity = min_severity
        self.use_cache = use_cache
        self.use_multithreading = use_multithreading
        self.max_workers = max_workers or (multiprocessing.cpu_count() * 2)
        self.show_progress = show_progress
        
        # 初始化组件
        self.cache = ScanCache() if use_cache else None
        self.progress = None
        self.result = ScanResult()
        
        # 严重性等级优先级（用于过滤）
        self.severity_priority = {
            VulnerabilitySeverity.CRITICAL: 5,
            VulnerabilitySeverity.HIGH: 4,
            VulnerabilitySeverity.MEDIUM: 3,
            VulnerabilitySeverity.LOW: 2,
            VulnerabilitySeverity.INFO: 1
        }
    
    def _is_file_included(self, file_path: str) -> bool:
        """检查文件是否应被包含"""
        # 检查排除规则
        for pattern in self.exclude_patterns:
            if pattern in file_path:
                return False
        
        # 检查包含规则
        file_ext = os.path.splitext(file_path)[1]
        for pattern in self.include_patterns:
            if pattern.startswith("*.") and file_ext == pattern[1:]:
                return True
            if pattern in file_path:
                return True
        
        return file_ext == ".py"  # 默认包含py文件
    
    def _find_python_files(self, scan_path: str) -> List[str]:
        """查找所有需要扫描的Python文件"""
        python_files = []
        scan_path = os.path.abspath(scan_path)
        
        if os.path.isfile(scan_path) and self._is_file_included(scan_path):
            python_files.append(scan_path)
        elif os.path.isdir(scan_path):
            for root, dirs, files in os.walk(scan_path):
                # 排除目录
                dirs[:] = [d for d in dirs if d not in self.exclude_patterns]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    if self._is_file_included(file_path):
                        python_files.append(file_path)
        
        self.result.total_files = len(python_files)
        logger.info(f"找到 {len(python_files)} 个待扫描文件")
        return python_files
    
    def _scan_single_file(self, file_path: str) -> List[Vulnerability]:
        """扫描单个文件（核心扫描逻辑）"""
        vulnerabilities = []
        
        try:
            # 检查缓存
            if self.use_cache and self.cache and not self.cache.is_file_changed(file_path):
                logger.debug(f"使用缓存扫描：{file_path}")
                vulnerabilities = self.cache.get_cached_vulns(file_path)
                self.progress.update(file_path, is_skipped=True)
                return vulnerabilities
            
            logger.debug(f"开始扫描：{file_path}")
            
            # 读取文件内容
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            lines = content.split("\n")
            
            # ========== 模拟漏洞检测逻辑（可替换为真实AST分析） ==========
            # 1. 检测硬编码凭据
            credential_patterns = ["password=", "secret=", "key=", "token=", "api_key="]
            for idx, line in enumerate(lines, 1):
                line_lower = line.lower()
                for pattern in credential_patterns:
                    if pattern in line_lower and "=" in line and not line.strip().startswith("#"):
                        # 检查是否是硬编码值
                        parts = line.split("=", 1)
                        if len(parts) > 1 and parts[1].strip() not in ["", "''", '""', "None"]:
                            vuln = Vulnerability(
                                file_path=file_path,
                                line_number=idx,
                                severity=VulnerabilitySeverity.HIGH,
                                vuln_type=VulnerabilityType.HARDCODED_CREDENTIALS,
                                message=f"检测到硬编码凭据：{pattern[:-1]}",
                                code_snippet=line.strip(),
                                fix_suggestion="将硬编码凭据替换为环境变量或配置文件读取",
                                rule_id="SEC001",
                                confidence=0.9
                            )
                            vulnerabilities.append(vuln)
            
            # 2. 检测危险函数
            dangerous_functions = ["eval(", "exec(", "pickle.load(", "os.system(", "subprocess.call("]
            for idx, line in enumerate(lines, 1):
                for func in dangerous_functions:
                    if func in line and not line.strip().startswith("#"):
                        vuln = Vulnerability(
                            file_path=file_path,
                            line_number=idx,
                            severity=VulnerabilitySeverity.CRITICAL,
                            vuln_type=VulnerabilityType.DANGEROUS_FUNCTIONS,
                            message=f"检测到危险函数调用：{func[:-1]}",
                            code_snippet=line.strip(),
                            fix_suggestion=f"避免使用 {func[:-1]} 函数，使用更安全的替代方案",
                            rule_id="DNG001",
                            confidence=0.95
                        )
                        vulnerabilities.append(vuln)
            
            # 3. 检测SQL注入风险
            sql_patterns = ["cursor.execute(", "mysql.connector.connect(", "sqlite3.connect("]
            for idx, line in enumerate(lines, 1):
                for pattern in sql_patterns:
                    if pattern in line and ("%" in line or "+" in line) and not line.strip().startswith("#"):
                        vuln = Vulnerability(
                            file_path=file_path,
                            line_number=idx,
                            severity=VulnerabilitySeverity.HIGH,
                            vuln_type=VulnerabilityType.SQL_INJECTION,
                            message="检测到SQL语句拼接，存在注入风险",
                            code_snippet=line.strip(),
                            fix_suggestion="使用参数化查询替代字符串拼接",
                            rule_id="SQL001",
                            confidence=0.85
                        )
                        vulnerabilities.append(vuln)
            
            # 4. 检测不安全随机数
            if "import random" in content and "random." in content:
                for idx, line in enumerate(lines, 1):
                    if "random." in line and not line.strip().startswith("#"):
                        vuln = Vulnerability(
                            file_path=file_path,
                            line_number=idx,
                            severity=VulnerabilitySeverity.MEDIUM,
                            vuln_type=VulnerabilityType.INSECURE_RANDOM,
                            message="使用不安全的random模块生成随机数",
                            code_snippet=line.strip(),
                            fix_suggestion="使用secrets模块替代random模块生成安全随机数",
                            rule_id="RND001",
                            confidence=0.9
                        )
                        vulnerabilities.append(vuln)
            
            # ========== 结束模拟检测 ==========
            
            # 过滤低严重性漏洞
            vulnerabilities = [
                v for v in vulnerabilities
                if self.severity_priority[v.severity] >= self.severity_priority[self.min_severity]
            ]
            
            # 更新缓存
            if self.use_cache and self.cache:
                self.cache.update_file_cache(file_path, vulnerabilities)
            
            logger.info(f"扫描完成：{file_path} - 发现 {len(vulnerabilities)} 个漏洞")
            self.progress.update(file_path)
            
        except Exception as e:
            error_msg = f"扫描文件失败：{str(e)}"
            logger.error(error_msg)
            self.result.error_files.append((file_path, error_msg))
            self.progress.update(file_path, is_error=True)
        
        return vulnerabilities
    
    def scan(self, scan_path: str) -> ScanResult:
        """执行扫描"""
        self.result.start_time = datetime.now()
        logger.info(f"开始扫描：{scan_path}")
        
        # 查找待扫描文件
        python_files = self._find_python_files(scan_path)
        
        # 初始化进度条
        if self.show_progress:
            self.progress = AdvancedProgressBar(len(python_files))
            self.progress.start()
        
        # 执行扫描
        all_vulnerabilities = []
        
        if self.use_multithreading and len(python_files) > 1:
            # 多线程扫描
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {executor.submit(self._scan_single_file, file): file for file in python_files}
                for future in as_completed(futures):
                    try:
                        vulns = future.result()
                        all_vulnerabilities.extend(vulns)
                        self.result.scanned_files += 1
                    except Exception as e:
                        logger.error(f"线程扫描失败：{e}")
        else:
            # 单线程扫描
            for file_path in python_files:
                vulns = self._scan_single_file(file_path)
                all_vulnerabilities.extend(vulns)
                self.result.scanned_files += 1
        
        # 完成扫描
        if self.show_progress:
            self.progress.finish()
        
        # 整理结果
        self.result.vulnerabilities = all_vulnerabilities
        self.result.end_time = datetime.now()
        self.result.scan_duration = (self.result.end_time - self.result.start_time).total_seconds()
        
        # 打印汇总
        stats = self.result.vuln_stats
        logger.info(f"""
扫描完成！
├── 总文件数：{self.result.total_files}
├── 已扫描：{self.result.scanned_files}
├── 排除文件：{len(self.result.excluded_files)}
├── 错误文件：{len(self.result.error_files)}
├── 扫描耗时：{self.result.scan_duration:.2f} 秒
├── 漏洞统计：
│   ├── 致命：{stats['critical']}
│   ├── 高风险：{stats['high']}
│   ├── 中风险：{stats['medium']}
│   ├── 低风险：{stats['low']}
│   ├── 信息：{stats['info']}
│   └── 总计：{stats['total']}
└── 扫描ID：{self.result.scan_id}
        """.strip())
        
        return self.result
    
    def generate_junit_report(self, output_path: str) -> None:
        """生成JUnit报告"""
        if not self.result.end_time:
            raise RuntimeError("请先执行扫描")
        
        reporter = AdvancedJUnitReporter(self.result)
        reporter.generate(output_path)
    
    def generate_json_report(self, output_path: str) -> None:
        """生成JSON报告"""
        if not self.result.end_time:
            raise RuntimeError("请先执行扫描")
        
        report = {
            "scan_info": {
                "scan_id": self.result.scan_id,
                "start_time": self.result.start_time.isoformat(),
                "end_time": self.result.end_time.isoformat(),
                "duration_seconds": self.result.scan_duration,
                "total_files": self.result.total_files,
                "scanned_files": self.result.scanned_files,
                "excluded_files": self.result.excluded_files,
                "error_files": [{"file": f, "error": e} for f, e in self.result.error_files]
            },
            "vulnerability_stats": self.result.vuln_stats,
            "type_stats": self.result.type_stats,
            "vulnerabilities": [v.to_dict() for v in self.result.vulnerabilities]
        }
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        logger.info(f"JSON报告已生成：{output_path}")

# 便捷函数
def scan_directory(
    path: str,
    output_junit: str = "junit-report.xml",
    output_json: str = "scan-results.json",
    min_severity: str = "low",
    use_multithreading: bool = True
) -> ScanResult:
    """便捷扫描函数"""
    # 解析严重性等级
    severity_map = {
        "critical": VulnerabilitySeverity.CRITICAL,
        "high": VulnerabilitySeverity.HIGH,
        "medium": VulnerabilitySeverity.MEDIUM,
        "low": VulnerabilitySeverity.LOW,
        "info": VulnerabilitySeverity.INFO
    }
    min_sev = severity_map.get(min_severity.lower(), VulnerabilitySeverity.LOW)
    
    # 创建扫描器
    scanner = AdvancedSecurityScanner(
        min_severity=min_sev,
        use_multithreading=use_multithreading,
        show_progress=True
    )
    
    # 执行扫描
    result = scanner.scan(path)
    
    # 生成报告
    scanner.generate_junit_report(output_junit)
    scanner.generate_json_report(output_json)
    
    return result

# 命令行入口
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="PySecScanner - 高级Python安全扫描工具")
    parser.add_argument("scan_path", help="要扫描的文件/目录路径")
    parser.add_argument("-o", "--output", help="JUnit报告输出路径", default="junit-report.xml")
    parser.add_argument("-j", "--json", help="JSON报告输出路径", default="scan-results.json")
    parser.add_argument("-s", "--severity", help="最小严重性等级 (critical/high/medium/low/info)", default="low")
    parser.add_argument("--no-threads", help="禁用多线程", action="store_false", dest="use_threads")
    parser.add_argument("--no-cache", help="禁用缓存", action="store_false", dest="use_cache")
    
    args = parser.parse_args()
    
    # 执行扫描
    scanner = AdvancedSecurityScanner(
        min_severity=VulnerabilitySeverity(args.severity.lower()),
        use_multithreading=args.use_threads,
        use_cache=args.use_cache
    )
    result = scanner.scan(args.scan_path)
    
    # 生成报告
    scanner.generate_junit_report(args.output)
    scanner.generate_json_report(args.json)
    
    print(f"\n✅ 扫描完成！")
    print(f"📊 JUnit报告：{args.output}")
    print(f"📄 JSON报告：{args.json}")
    print(f"🔍 发现漏洞：{len(result.vulnerabilities)} 个")