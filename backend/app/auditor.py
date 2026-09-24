"""确定性合约审计引擎：漏洞模式扫描 + Gas 分析 + 安全评分。

同一输入合约永远产生同一输出：不依赖随机数、不依赖系统时间，
保证同一份合约任意时刻重跑、服务重启后重放，结论都完全一致。
"""

import re
from typing import List

# ---------------------------------------------------------------------------
# 漏洞模式库（正则类）
# ---------------------------------------------------------------------------

REGEX_PATTERNS = [
    {
        "type": "重入攻击 (Reentrancy)",
        "severity": "critical",
        "pattern": r"\.call\{[^}]*value:\s*[^}]*\}\([^)]*\)",
        "description": "使用低级call()转移ETH存在重入攻击风险。攻击者可部署恶意合约在fallback中反复调用提款。",
        "suggestion": "使用Checks-Effects-Interactions模式，或引入ReentrancyGuard。",
    },
    {
        "type": "整数溢出 (Integer Overflow/Underflow)",
        "severity": "high",
        "pattern": r"[+\-*/]\s*=",
        "description": "未使用SafeMath且编译器版本低于0.8时，复合赋值运算可能发生整数溢出。",
        "suggestion": "使用SafeMath库或升级到Solidity 0.8+（内置溢出检查）。",
        # Solidity 0.8+ 内置溢出检查，不再误报
        "skip_if_safe_pragma": True,
    },
    {
        "type": "selfdestruct使用",
        "severity": "medium",
        "pattern": r"selfdestruct|suicide",
        "description": "selfdestruct可强制将合约所有ETH发送到任意地址，可能被滥用。",
        "suggestion": "谨慎使用selfdestruct，确保有正当的业务需求。",
    },
    {
        "type": "tx.origin钓鱼",
        "severity": "high",
        "pattern": r"tx\.origin",
        "description": "使用tx.origin进行身份验证可能被钓鱼攻击，攻击者诱导用户触发交易。",
        "suggestion": "使用msg.sender代替tx.origin进行身份验证。",
    },
    {
        "type": "精确度损失",
        "severity": "medium",
        "pattern": r"/\s*\d+",
        "description": "除法运算可能导致精度损失，特别是在代币金额计算中。",
        "suggestion": "先乘后除，使用高精度计算或使用Babylonian方法。",
    },
]

# “未授权访问控制”采用结构化函数分析（见 detect_unauthorized_access），
# 此处仅保留模式库展示信息。
UNAUTHORIZED_ACCESS_INFO = {
    "type": "未授权访问控制",
    "severity": "high",
    "pattern": "结构化分析：public/external 敏感函数缺少 onlyOwner 等访问控制",
    "description": "关键函数缺少访问控制检查，任何人都可以调用。",
    "suggestion": "添加onlyOwner或自定义访问控制修饰符。",
}

PATTERNS_FOR_DISPLAY = [
    {k: v for k, v in p.items() if k != "skip_if_safe_pragma"}
    for p in REGEX_PATTERNS
] + [UNAUTHORIZED_ACCESS_INFO]

# ---------------------------------------------------------------------------
# 函数级结构化分析
# ---------------------------------------------------------------------------

_FUNC_HEADER_RE = re.compile(r"function\s+(\w+)\s*\(([^)]*)\)\s*([^{]*)\{")

# 修饰符中出现的 Solidity 关键字（非自定义修饰符）
_MODIFIER_KEYWORDS = {
    "public", "external", "internal", "private",
    "view", "pure", "payable", "virtual", "override",
    "returns", "memory", "calldata", "storage", "immutable",
}

# 常见访问控制修饰符名称（小写）；此外任何 onlyXxx 形式的修饰符也视为访问控制
_ACCESS_CONTROL_MODIFIERS = {
    "onlyowner", "onlyadmin", "onlyrole", "onlygovernance", "onlyoperator",
    "onlyauthorized", "authorized", "auth", "restricted", "requiresauth",
}

# 敏感函数名：涉及资金、所有权、铸币、暂停等关键操作
_SENSITIVE_NAME_RE = re.compile(
    r"withdraw|mint|burn|pause|unpause|owner|admin|upgrade|kill|destroy"
    r"|setfee|setrate|setprice|sweep|drain",
    re.IGNORECASE,
)


def strip_comments(code: str) -> str:
    """移除注释（以空格占位，保持行号不变），避免注释内容干扰判定。"""

    def _blank(m: "re.Match") -> str:
        return re.sub(r"[^\n]", " ", m.group(0))

    code = re.sub(r"//[^\n]*", _blank, code)
    code = re.sub(r"/\*.*?\*/", _blank, code, flags=re.DOTALL)
    return code


def extract_functions(code: str) -> List[dict]:
    """提取合约中的具名函数（名称/参数/修饰符/函数体/起始行）。

    使用大括号配平提取函数体，嵌套块不会截断，结果稳定。
    """
    functions = []
    for m in _FUNC_HEADER_RE.finditer(code):
        brace_start = m.end() - 1  # '{' 的位置
        depth = 0
        i = brace_start
        while i < len(code):
            ch = code[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        functions.append(
            {
                "name": m.group(1),
                "params": m.group(2),
                "modifiers": m.group(3),
                "body": code[brace_start + 1 : i],
                "line": code[: m.start()].count("\n") + 1,
            }
        )
    return functions


def _has_access_control(fn: dict) -> bool:
    """函数是否带有访问控制：onlyXxx 类修饰符，或函数体内校验 msg.sender。"""
    for ident in re.findall(r"[A-Za-z_]\w*", fn["modifiers"]):
        low = ident.lower()
        if low in _MODIFIER_KEYWORDS:
            continue
        if low in _ACCESS_CONTROL_MODIFIERS or low.startswith("only"):
            return True
    body = fn["body"]
    if re.search(r"require\s*\(\s*(?:msg\.sender|_msgSender\s*\(\s*\))\s*==", body):
        return True
    if re.search(r"if\s*\(\s*msg\.sender\s*!=", body):
        return True
    return False


def _is_sensitive(fn: dict) -> bool:
    """函数是否执行关键操作：转出 ETH、自毁、委托调用，或函数名敏感。"""
    body = fn["body"]
    if re.search(
        r"\.call\s*\{|\.transfer\s*\(|\.send\s*\(|selfdestruct|suicide|delegatecall",
        body,
    ):
        return True
    if _SENSITIVE_NAME_RE.search(fn["name"]):
        return True
    return False


def detect_unauthorized_access(cleaned_code: str, raw_lines: List[str]) -> List[dict]:
    """检测“关键函数任何人都可以调用”：public/external 敏感函数缺少访问控制。"""
    findings = []
    for fn in extract_functions(cleaned_code):
        modifiers = fn["modifiers"]
        if "public" not in modifiers and "external" not in modifiers:
            continue
        if "view" in modifiers or "pure" in modifiers:
            continue  # 只读函数不改变状态，不属于关键写操作
        if _has_access_control(fn):
            continue
        if not _is_sensitive(fn):
            continue
        findings.append(
            {
                "type": UNAUTHORIZED_ACCESS_INFO["type"],
                "severity": UNAUTHORIZED_ACCESS_INFO["severity"],
                "line": fn["line"],
                "description": (
                    f"函数 {fn['name']}() 缺少访问控制检查，任何人都可以调用。"
                ),
                "suggestion": UNAUTHORIZED_ACCESS_INFO["suggestion"],
                "code": _context(raw_lines, fn["line"]),
            }
        )
    return findings


# ---------------------------------------------------------------------------
# 漏洞扫描
# ---------------------------------------------------------------------------


def _context(lines: List[str], line_num: int, radius: int = 2) -> str:
    start = max(0, line_num - 1 - radius)
    end = min(len(lines), line_num + radius)
    return "\n".join(lines[start:end]).strip()


def _has_safe_pragma(cleaned_code: str) -> bool:
    m = re.search(r"pragma\s+solidity\s+([^;]+);", cleaned_code)
    if not m:
        return False
    return bool(re.search(r"0\.[89]", m.group(1)))


def detect_vulnerabilities(code: str) -> List[dict]:
    """扫描合约漏洞。纯函数：同一输入永远得到同一输出。"""
    cleaned = strip_comments(code)
    raw_lines = code.split("\n")
    safe_pragma = _has_safe_pragma(cleaned)

    vulnerabilities = []
    for vp in REGEX_PATTERNS:
        if vp.get("skip_if_safe_pragma") and safe_pragma:
            continue
        for m in re.finditer(vp["pattern"], cleaned, re.MULTILINE):
            line_num = cleaned[: m.start()].count("\n") + 1
            vulnerabilities.append(
                {
                    "type": vp["type"],
                    "severity": vp["severity"],
                    "line": line_num,
                    "description": vp["description"],
                    "suggestion": vp["suggestion"],
                    "code": _context(raw_lines, line_num),
                }
            )

    vulnerabilities.extend(detect_unauthorized_access(cleaned, raw_lines))
    vulnerabilities.sort(key=lambda v: (v["line"], v["type"]))
    return vulnerabilities


# ---------------------------------------------------------------------------
# Gas 分析（基于代码特征的确定性估算，不使用随机数）
# ---------------------------------------------------------------------------


def compute_gas_issues(code: str) -> List[dict]:
    """按函数体特征估算 Gas 并给出优化建议。同一合约结果恒定。"""
    cleaned = strip_comments(code)
    issues = []
    for fn in extract_functions(cleaned):
        body = fn["body"]
        writes = len(re.findall(r"(?<![=!<>+\-*/&|])=(?![=>])", body))
        loops = len(re.findall(r"\b(?:for|while)\s*\(", body))
        ext_calls = len(re.findall(r"\.(?:call|transfer|send)\s*[({]", body))
        conditions = len(re.findall(r"&&|\|\|", body))

        current_gas = (
            21000
            + writes * 5000
            + loops * 8000
            + ext_calls * 2600
            + conditions * 400
        )

        if loops:
            suggestion, ratio = "循环中避免读取/写入storage，使用memory缓存", 0.70
        elif writes >= 2:
            suggestion, ratio = "缓存storage变量到memory，合并storage写入", 0.75
        elif conditions:
            suggestion, ratio = "使用短路逻辑，将低开销条件放在前面", 0.85
        else:
            suggestion, ratio = "使用calldata代替memory存储函数参数", 0.90

        issues.append(
            {
                "functionName": f"{fn['name']}()",
                "currentGas": current_gas,
                "optimizedGas": int(current_gas * ratio),
                "suggestion": suggestion,
            }
        )
    return issues


# ---------------------------------------------------------------------------
# 评分与入口
# ---------------------------------------------------------------------------


def compute_security_score(vulnerabilities: List[dict]) -> int:
    if not vulnerabilities:
        return 100
    severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    deduction = sum(severity_weights.get(v["severity"], 5) for v in vulnerabilities)
    return max(0, 100 - deduction)


def run_audit(code: str) -> dict:
    """执行一次完整审计。输入非法时抛出带明确原因的异常。"""
    if not isinstance(code, str) or not code.strip():
        raise ValueError("合约代码不能为空，审计中止")
    vulnerabilities = detect_vulnerabilities(code)
    gas_issues = compute_gas_issues(code)
    return {
        "score": compute_security_score(vulnerabilities),
        "vulnerabilities": vulnerabilities,
        "gasIssues": gas_issues,
    }
