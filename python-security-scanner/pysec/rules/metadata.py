"""
规则元数据

为安全规则提供详细的描述、帮助URI、CWE分类等信息。
用于生成 SARIF 报告和其他工具集成。
"""

# 规则帮助URI映射（链接到详细解释）
RULE_HELP_URIS = {
    "SEC001": "https://cwe.mitre.org/data/definitions/95.html",  # CWE-95: Eval Injection
    "SEC002": "https://cwe.mitre.org/data/definitions/95.html",  # CWE-95: Eval Injection
    "SEC003": "https://cwe.mitre.org/data/definitions/502.html", # CWE-502: Deserialization
    "SEC004": "https://cwe.mitre.org/data/definitions/78.html",  # CWE-78: OS Command Injection
    "SEC005": "https://cwe.mitre.org/data/definitions/798.html", # CWE-798: Hardcoded Credentials
}

# 规则CWE分类映射
RULE_CWE_IDS = {
    "SEC001": "CWE-95",
    "SEC002": "CWE-95",
    "SEC003": "CWE-502",
    "SEC004": "CWE-78",
    "SEC005": "CWE-798",
}

# 规则OWASP分类映射
RULE_OWASP_CATEGORIES = {
    "SEC001": "A03:2021-Injection",
    "SEC002": "A03:2021-Injection",
    "SEC003": "A08:2021-Software and Data Integrity Failures",
    "SEC004": "A03:2021-Injection",
    "SEC005": "A07:2021-Identification and Authentication Failures",
}

# 规则详细描述
RULE_DESCRIPTIONS = {
    "SEC001": "检测到 exec() 函数的使用，这可能允许攻击者执行任意代码。",
    "SEC002": "检测到 eval() 函数的使用，这可能允许攻击者执行任意代码。",
    "SEC003": "检测到 pickle.loads() 的使用，这可能允许攻击者通过反序列化执行任意代码。",
    "SEC004": "检测到 os.system() 的使用，这可能允许攻击者执行任意系统命令。",
    "SEC005": "检测到硬编码的密码或密钥，这可能导致敏感信息泄露。",
}

# 规则修复建议
RULE_SUGGESTIONS = {
    "SEC001": "避免使用 exec()，考虑使用 ast.literal_eval() 或更安全的替代方案。",
    "SEC002": "避免使用 eval()，考虑使用 ast.literal_eval() 或直接解析表达式。",
    "SEC003": "避免反序列化不受信任的数据，考虑使用 JSON、YAML 或 MessagePack 等更安全的格式。",
    "SEC004": "使用 subprocess.run() 替代 os.system()，并避免将用户输入直接传递给 shell。",
    "SEC005": "使用环境变量、配置文件或密钥管理服务存储敏感信息。",
}

def get_rule_metadata(rule_id: str) -> dict:
    """
    获取规则的元数据
    
    Args:
        rule_id: 规则ID
        
    Returns:
        包含规则元数据的字典
    """
    return {
        "help_uri": RULE_HELP_URIS.get(rule_id),
        "cwe_id": RULE_CWE_IDS.get(rule_id, "").replace("CWE-", ""),
        "owasp_category": RULE_OWASP_CATEGORIES.get(rule_id),
        "description": RULE_DESCRIPTIONS.get(rule_id, f"安全规则: {rule_id}"),
        "suggestion": RULE_SUGGESTIONS.get(rule_id, "请参考安全最佳实践。"),
        "tags": ["security", "python"]
    }