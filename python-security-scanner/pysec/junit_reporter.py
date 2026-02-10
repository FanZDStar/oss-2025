# junit_reporter.py
# 仅使用Python内置库，无需额外安装
import xml.etree.ElementTree as ET
from xml.dom import minidom
from typing import List, Dict
import os

def generate_junit_report(vulnerabilities: List[Dict], output_path: str) -> None:
    """
    生成JUnit XML格式的扫描报告
    :param vulnerabilities: 漏洞列表（每个元素是包含file/line/severity/description的字典）
    :param output_path: 输出XML文件路径
    """
    # 1. 创建XML根节点（testsuites）
    testsuites = ET.Element("testsuites")
    # 2. 创建单个testsuite节点（对应本次扫描）
    testsuite = ET.SubElement(testsuites, "testsuite")
    # 3. 统计数据：总用例数=漏洞数，失败数=漏洞数，跳过数=0
    total_tests = len(vulnerabilities)
    testsuite.set("name", "PySecScanner Security Scan")
    testsuite.set("tests", str(total_tests))
    testsuite.set("failures", str(total_tests))  # 漏洞视为失败的测试用例
    testsuite.set("skipped", "0")
    testsuite.set("errors", "0")

    # 4. 为每个漏洞创建testcase节点
    for idx, vuln in enumerate(vulnerabilities):
        # 基础信息提取（兼容空值，避免报错）
        file_path = vuln.get("file", "unknown.py")
        line = vuln.get("line", 0)
        severity = vuln.get("severity", "UNKNOWN")
        description = vuln.get("description", "No description")
        rule_id = vuln.get("rule_id", f"RULE{idx+1}")

        # 创建testcase节点：用例名称=规则ID+文件+行号
        testcase = ET.SubElement(testsuite, "testcase")
        testcase.set("name", f"{rule_id} - {os.path.basename(file_path)}:{line}")
        testcase.set("classname", f"pysec.{severity.lower()}")  # 按严重程度分类
        testcase.set("file", file_path)
        testcase.set("line", str(line))

        # 创建failure节点：描述漏洞详情
        failure = ET.SubElement(testcase, "failure")
        failure.set("type", severity)
        failure.set("message", description)
        # 详细信息（CDATA格式，避免XML转义问题）
        failure.text = ET.CDATA(f"""
File: {file_path}
Line: {line}
Severity: {severity}
Description: {description}
        """.strip())

    # 5. 美化XML格式（缩进2个空格，可读性更好）
    rough_xml = ET.tostring(testsuites, encoding="utf-8")
    parsed_xml = minidom.parseString(rough_xml)
    pretty_xml = parsed_xml.toprettyxml(indent="  ")
    # 移除自动生成的xml声明重复行
    pretty_xml = "\n".join([line for line in pretty_xml.splitlines() if line.strip()])

    # 6. 写入文件
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(pretty_xml)

    print(f"✅ JUnit报告已生成：{os.path.abspath(output_path)}")

# 测试示例（直接运行该文件即可验证）
if __name__ == "__main__":
    # 模拟扫描结果
    test_vulnerabilities = [
        {
            "file": "test.py",
            "line": 10,
            "severity": "CRITICAL",
            "description": "硬编码的SECRET_KEY存在泄露风险",
            "rule_id": "SEC001"
        },
        {
            "file": "test.py",
            "line": 20,
            "severity": "HIGH",
            "description": "禁用SSL证书验证存在中间人攻击风险",
            "rule_id": "SSL001"
        }
    ]
    # 生成报告
    generate_junit_report(test_vulnerabilities, "test-results.xml")