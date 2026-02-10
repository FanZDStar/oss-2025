"""
AST自动修复模块 - 基于抽象语法树的漏洞自动修复
对应报告4.3章节：自动修复与AST重构技术
"""

import ast
from typing import List, Optional, Tuple
from dataclasses import dataclass

# 修复结果模型
@dataclass
class FixResult:
    file_path: str
    line: int
    original_code: str
    fixed_code: str
    fix_type: str
    success: bool = True
    message: str = ""

# AST自动修复器
class ASTVulnerabilityFixer:
    """基于AST的漏洞自动修复器"""
    
    def __init__(self):
        self.fix_results: List[FixResult] = []

    def fix_file(self, file_path: str, dry_run: bool = True) -> List[FixResult]:
        """修复单个文件的漏洞"""
        try:
            # 读取文件内容并解析为AST
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content)
            lines = content.split("\n")
            
            # 遍历AST并修复漏洞
            self._traverse_ast(tree, lines)
            
            # 生成修复后的代码
            if not dry_run:
                fixed_code = ast.unparse(tree)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(fixed_code)
            
            return self.fix_results
        
        except Exception as e:
            self.fix_results.append(FixResult(
                file_path=file_path,
                line=0,
                original_code="",
                fixed_code="",
                fix_type="FileError",
                success=False,
                message=str(e)
            ))
            return self.fix_results

    def _traverse_ast(self, node: ast.AST, lines: List[str]):
        """遍历AST节点，修复已知漏洞"""
        # 修复1：硬编码密码 → 替换为环境变量
        if isinstance(node, ast.Assign):
            self._fix_hardcoded_credential(node, lines)
        
        # 修复2：不安全随机数 → 替换为secrets模块
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            self._fix_insecure_random(node, lines)
        
        # 修复3：eval函数 → 替换为安全替代方案
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "eval":
            self._fix_eval_call(node, lines)
        
        # 递归遍历子节点
        for child in ast.iter_child_nodes(node):
            self._traverse_ast(child, lines)

    def _fix_hardcoded_credential(self, node: ast.Assign, lines: List[str]):
        """修复硬编码凭据（如 password="123456"）"""
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.lower() in ["password", "secret", "api_key"]:
                # 获取原始代码
                line_num = node.lineno
                original_code = lines[line_num-1].strip()
                
                # 生成修复后的代码（替换为环境变量）
                fixed_code = f"{target.id} = os.getenv('{target.id.upper()}')"
                node.value = ast.parse(fixed_code.split("=")[1].strip()).body[0].value  # 替换AST节点
                
                # 记录修复结果
                self.fix_results.append(FixResult(
                    file_path="",  # 实际使用时补充
                    line=line_num,
                    original_code=original_code,
                    fixed_code=fixed_code,
                    fix_type="HardcodedCredential"
                ))

    def _fix_insecure_random(self, node: ast.Call, lines: List[str]):
        """修复不安全随机数（random → secrets）"""
        if node.func.value.id == "random" and node.func.attr in ["randint", "random"]:
            # 获取原始代码
            line_num = node.lineno
            original_code = lines[line_num-1].strip()
            
            # 生成修复后的代码（替换为secrets模块）
            if node.func.attr == "randint":
                fixed_code = original_code.replace("random.randint", "secrets.randbelow")
                node.func.value.id = "secrets"
                node.func.attr = "randbelow"
            else:
                fixed_code = original_code.replace("random.random", "secrets.SystemRandom().random")
                node.func.value = ast.parse("secrets.SystemRandom()").body[0].value
            
            # 记录修复结果
            self.fix_results.append(FixResult(
                file_path="",
                line=line_num,
                original_code=original_code,
                fixed_code=fixed_code,
                fix_type="InsecureRandom"
            ))

    def _fix_eval_call(self, node: ast.Call, lines: List[str]):
        """修复eval函数调用（替换为安全替代方案）"""
        line_num = node.lineno
        original_code = lines[line_num-1].strip()
        
        # 生成修复后的代码（提示使用安全解析方式）
        fixed_code = f"# 安全提示：避免使用eval，建议使用ast.literal_eval\n# {original_code}"
        node.func.id = "# eval"  # 注释掉危险代码
        
        # 记录修复结果
        self.fix_results.append(FixResult(
            file_path="",
            line=line_num,
            original_code=original_code,
            fixed_code=fixed_code,
            fix_type="DangerousEval"
        ))

# 便捷使用示例
def demo_fix():
    """自动修复演示"""
    fixer = ASTVulnerabilityFixer()
    # 模拟修复（实际使用时传入文件路径）
    fixer._fix_hardcoded_credential(
        ast.parse("password = '123456'").body[0],
        ["password = '123456'"]
    )
    fixer._fix_insecure_random(
        ast.parse("random.randint(1, 100)").body[0].value,
        ["random.randint(1, 100)"]
    )
    
    # 打印修复结果
    print("🛠️ AST自动修复结果：")
    for res in fixer.fix_results:
        print(f"\n行{res.line} | {res.fix_type}")
        print(f"原始代码：{res.original_code}")
        print(f"修复后：{res.fixed_code}")

if __name__ == "__main__":
    demo_fix()