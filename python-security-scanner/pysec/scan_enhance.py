"""
扫描增强模块 - 整合进度条和JUnit报告核心功能
轻量版，专注核心能力，易于维护和使用
"""

import os
import sys
import time
import json
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
from xml.etree import ElementTree as ET
from xml.dom import minidom

# 兼容tqdm（无则降级）
try:
    from tqdm import tqdm
except ImportError:
    class tqdm:
        def __init__(self, total, desc="", unit=""):
            self.total = total
            self.desc = desc
            self.unit = unit
            self.n = 0
            self.start_time = time.time()

        def update(self, n=1):
            self.n += n
            elapsed = time.time() - self.start_time
            rate = self.n / elapsed if elapsed > 0 else 0
            print(f"\r{self.desc}: {self.n}/{self.total} {self.unit} | {rate:.1f} {self.unit}/s", end="")

        def set_postfix(self, **kwargs):
            pass

        def close(self):
            print(f"\n{self.desc} 完成！共处理 {self.n} 个文件")

# 漏洞等级枚举
class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

# 漏洞数据模型
@dataclass
class Vulnerability:
    file_path: str
    line: int
    severity: Severity
    title: str
    description: str
    fix: str = ""

# 扫描结果模型
@dataclass
class ScanResult:
    scan_id: str = datetime.now().strftime("%Y%m%d%H%M%S")
    start_time: datetime = datetime.now()
    end_time: Optional[datetime] = None
    total_files: int = 0
    scanned_files: int = 0
    vulnerabilities: List[Vulnerability] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
    
    @property
    def duration(self) -> float:
        """扫描耗时（秒）"""
        if not self.end_time:
            return 0.0
        return (self.end_time - self.start_time).total_seconds()
    
    @property
    def stats(self) -> Dict[str, int]:
        """漏洞统计"""
        stats = {s.value: 0 for s in Severity}
        stats["total"] = 0
        for vuln in self.vulnerabilities:
            stats[vuln.severity.value] += 1
            stats["total"] += 1
        return stats

# 进度条管理器（轻量版）
class ScanProgress:
    """轻量级扫描进度条"""
    
    def __init__(self, total_files: int):
        self.total = total_files
        self.pbar = tqdm(total=total_files, desc="扫描进度", unit="文件")
        self.current_file = ""
    
    def update(self, file_path: str, step: int = 1):
        """更新进度"""
        self.current_file = os.path.basename(file_path)
        self.pbar.set_postfix(file=self.current_file[:20])
        self.pbar.update(step)
    
    def error(self, file_path: str):
        """标记错误文件"""
        self.current_file = os.path.basename(file_path)
        self.pbar.set_postfix(file=f"❌ {self.current_file[:18]}")
        self.pbar.update(1)
    
    def finish(self):
        """结束进度条"""
        self.pbar.close()

# JUnit报告生成器（轻量版）
class JUnitReport:
    """轻量级JUnit报告生成器"""
    
    def __init__(self, result: ScanResult):
        self.result = result
        self.root = ET.Element("testsuites")
        self._build_report()
    
    def _build_report(self):
        """构建报告结构"""
        # 创建testsuite
        testsuite = ET.SubElement(self.root, "testsuite")
        testsuite.set("name", "PySecScanner")
        testsuite.set("id", self.result.scan_id)
        testsuite.set("timestamp", self.result.start_time.isoformat())
        testsuite.set("tests", str(self.result.total_files))
        testsuite.set("failures", str(len(self.result.vulnerabilities)))
        testsuite.set("time", f"{self.result.duration:.2f}")
        
        # 添加统计信息
        props = ET.SubElement(testsuite, "properties")
        for key, value in self.result.stats.items():
            prop = ET.SubElement(props, "property")
            prop.set("name", f"vuln_{key}")
            prop.set("value", str(value))
        
        # 按文件分组漏洞
        vuln_by_file: Dict[str, List[Vulnerability]] = {}
        for vuln in self.result.vulnerabilities:
            if vuln.file_path not in vuln_by_file:
                vuln_by_file[vuln.file_path] = []
            vuln_by_file[vuln.file_path].append(vuln)
        
        # 创建testcase
        for file_path, vulns in vuln_by_file.items():
            testcase = ET.SubElement(testsuite, "testcase")
            testcase.set("name", os.path.basename(file_path))
            testcase.set("classname", file_path)
            
            # 添加漏洞信息
            for vuln in vulns:
                failure = ET.SubElement(testcase, "failure")
                failure.set("severity", vuln.severity.value)
                failure.set("line", str(vuln.line))
                failure.text = f"""
{vuln.title}
严重程度: {vuln.severity.value.upper()}
位置: {file_path}:{vuln.line}
描述: {vuln.description}
修复建议: {vuln.fix}
                """.strip()
    
    def save(self, output_path: str = "junit-report.xml"):
        """保存报告文件"""
        # 美化XML格式
        xml_str = ET.tostring(self.root, encoding="utf-8")
        pretty_xml = minidom.parseString(xml_str).toprettyxml(indent="  ", encoding="utf-8")
        
        # 保存文件
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(pretty_xml.decode("utf-8"))
        
        print(f"✅ JUnit报告已保存到: {output_path}")

# 核心扫描类
class EnhancedScanner:
    """增强版扫描器（带进度条+报告）"""
    
    def __init__(self):
        self.result = ScanResult()
        self.progress: Optional[ScanProgress] = None
    
    def _find_python_files(self, scan_path: str) -> List[str]:
        """查找所有Python文件"""
        files = []
        if os.path.isfile(scan_path) and scan_path.endswith(".py"):
            files.append(scan_path)
        elif os.path.isdir(scan_path):
            for root, _, filenames in os.walk(scan_path):
                # 排除无关目录
                if any(excl in root for excl in ["__pycache__", "venv", ".git"]):
                    continue
                for filename in filenames:
                    if filename.endswith(".py"):
                        files.append(os.path.join(root, filename))
        
        self.result.total_files = len(files)
        self.progress = ScanProgress(len(files))
        return files
    
    def _scan_file(self, file_path: str) -> List[Vulnerability]:
        """扫描单个文件（模拟检测逻辑）"""
        vulnerabilities = []
        
        try:
            # 读取文件内容
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            
            # 模拟漏洞检测
            for idx, line in enumerate(lines, 1):
                line = line.strip()
                
                # 检测硬编码密码
                if any(key in line.lower() for key in ["password=", "secret=", "key="]):
                    if "=" in line and not line.startswith("#"):
                        vuln = Vulnerability(
                            file_path=file_path,
                            line=idx,
                            severity=Severity.HIGH,
                            title="硬编码凭据检测",
                            description="代码中发现硬编码的密码/密钥，存在泄露风险",
                            fix="将敏感信息移至环境变量或加密配置文件"
                        )
                        vulnerabilities.append(vuln)
                
                # 检测危险函数
                elif any(func in line for func in ["eval(", "exec(", "os.system("]):
                    vuln = Vulnerability(
                        file_path=file_path,
                        line=idx,
                        severity=Severity.CRITICAL,
                        title="危险函数调用",
                        description="使用了高风险函数，可能导致代码执行漏洞",
                        fix="避免使用eval/exec/os.system等危险函数"
                    )
                    vulnerabilities.append(vuln)
            
            self.progress.update(file_path)
            self.result.scanned_files += 1
            return vulnerabilities
            
        except Exception as e:
            self.progress.error(file_path)
            print(f"\n❌ 扫描文件失败 {file_path}: {str(e)}")
            return []
    
    def scan(self, scan_path: str) -> ScanResult:
        """执行扫描"""
        print(f"🔍 开始扫描: {scan_path}")
        self.result.start_time = datetime.now()
        
        # 查找文件
        files = self._find_python_files(scan_path)
        if not files:
            print("⚠️ 未找到需要扫描的Python文件")
            return self.result
        
        # 扫描所有文件
        for file in files:
            vulns = self._scan_file(file)
            self.result.vulnerabilities.extend(vulns)
        
        # 完成扫描
        self.progress.finish()
        self.result.end_time = datetime.now()
        
        # 打印汇总
        stats = self.result.stats
        print(f"\n📊 扫描汇总:")
        print(f"   总文件数: {self.result.total_files}")
        print(f"   已扫描: {self.result.scanned_files}")
        print(f"   漏洞总数: {stats['total']}")
        print(f"   致命漏洞: {stats['critical']} | 高风险: {stats['high']} | 中风险: {stats['medium']} | 低风险: {stats['low']}")
        print(f"   耗时: {self.result.duration:.2f} 秒")
        
        return self.result

# 便捷使用函数
def scan_with_report(scan_path: str, report_path: str = "junit-report.xml"):
    """一键扫描并生成报告"""
    scanner = EnhancedScanner()
    result = scanner.scan(scan_path)
    
    # 生成JUnit报告
    reporter = JUnitReport(result)
    reporter.save(report_path)
    
    # 生成JSON报告（额外）
    with open("scan-results.json", "w", encoding="utf-8") as f:
        json.dump({
            "scan_info": asdict(result),
            "vulnerabilities": [asdict(v) for v in result.vulnerabilities]
        }, f, ensure_ascii=False, indent=2)
    print("✅ JSON报告已保存到: scan-results.json")

# 命令行入口
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("使用方法: python scan_enhance.py <扫描路径> [报告路径]")
        print("示例: python scan_enhance.py ./my_project ./report.xml")
        sys.exit(1)
    
    scan_path = sys.argv[1]
    report_path = sys.argv[2] if len(sys.argv) > 2 else "junit-report.xml"
    
    scan_with_report(scan_path, report_path)