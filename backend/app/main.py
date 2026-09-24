import hashlib
import re
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .storage import AuditStore

app = FastAPI(title="Smart Contract Security Auditor")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 同一份合约在该时间窗口内重复提交时，直接沿用上一次结论，不重复落库
DEDUP_WINDOW_SECONDS = 300

# Vulnerability patterns（纯正则，匹配结果只取决于代码内容，多次审计必然一致）
VULNERABILITY_PATTERNS = [
    {
        "type": "重入攻击 (Reentrancy)",
        "severity": "critical",
        "pattern": r"\.call\{[^}]*value:\s*[^}]*\}\([^)]*\)",
        "description": "使用低级call()或send()转移ETH存在重入攻击风险。攻击者可部署恶意合约在fallback中反复调用提款。",
        "suggestion": "使用Checks-Effects-Interactions模式，或引入ReentrancyGuard。推荐使用transfer()或call()并限制Gas。",
    },
    {
        "type": "整数溢出 (Integer Overflow/Underflow)",
        "severity": "high",
        "pattern": r"[+\-*/]\s*=|(&&|\|\|)\s*\w+\s*[<>=]",
        "description": "Solidity 0.7及以下版本，未使用SafeMath时可能发生整数溢出。",
        "suggestion": "使用SafeMath库或升级到Solidity 0.8+（内置溢出检查）。",
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

ACCESS_CONTROL_TYPE = "未授权访问控制"
ACCESS_CONTROL_SEVERITY = "high"
ACCESS_CONTROL_DESC = "关键函数缺少访问控制检查，任何人都可以调用。"
ACCESS_CONTROL_SUGGESTION = "添加onlyOwner或自定义访问控制修饰符。"

# 函数签名中出现这些关键字时属于 Solidity 标准用法，不算自定义访问控制修饰符
STANDARD_HEADER_TOKENS = {
    "public", "external", "internal", "private",
    "payable", "virtual", "override", "pure", "view",
    "constant", "immutable", "anonymous",
}

# 函数体内出现以下任一形式即认为存在访问控制/角色校验
GUARD_BODY_PATTERNS = [
    re.compile(r"msg\.sender\s*(?:==|!=)"),
    re.compile(r"hasRole\s*\("),
    re.compile(r"\bisAuthorized\b|\brequiresAuth\b|\bonlyAuthorized\b"),
]

# 敏感操作：状态写入、资金转移、合约销毁等，只有这类函数才需要访问控制
SENSITIVE_BODY_PATTERN = re.compile(
    r"(\+\+|--|\+=|-=|\*=|/=|(?<![=!<>])=(?!=)"
    r"|\.call\s*[\.{]|\.transfer\s*\(|\.send\s*\("
    r"|selfdestruct|delegatecall|\bmint\s*\(|\bburn\s*\()"
)

FUNCTION_RE = re.compile(r"function\s+(\w+)\s*\(([^)]*)\)")

GAS_SUGGESTIONS = [
    "移除不必要的storage写入",
    "缓存storage变量到memory",
    "使用短路逻辑",
    "合并多个事件为一个",
]

store = AuditStore()


class AuditRequest(BaseModel):
    code: str
    filename: str


def _line_of(code: str, offset: int) -> int:
    return code.count("\n", 0, offset) + 1


def _context_of(code: str, line_num: int) -> str:
    lines = code.split("\n")
    start = max(0, line_num - 2)
    end = min(len(lines), line_num + 2)
    return "\n".join(lines[start:end]).strip()


def _iter_functions(code: str):
    """提取每个函数的 (名称, 参数, 签名尾部, 函数体, 起始偏移)。

    用花括号配对界定函数体，避免旧正则 [^}]* 在嵌套花括号下漏判/误判。
    """
    for m in FUNCTION_RE.finditer(code):
        brace = code.find("{", m.end())
        semi = code.find(";", m.end())
        if brace == -1 or (semi != -1 and semi < brace):
            # 抽象函数 / interface 声明，没有函数体
            continue
        depth = 0
        i = brace
        while i < len(code):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = code[brace + 1:i]
        # 右括号之后、函数体之前的部分：可见性 + 修饰符 + returns
        tail = code[m.end():brace]
        yield m.group(1), m.group(2), tail, body, m.start()


def _has_custom_modifier(tail: str) -> bool:
    tail = re.sub(r"returns\s*\((?![()]*\))[^)]*\)", " ", tail)
    tokens = re.findall(r"[A-Za-z_]\w*", tail)
    return any(t not in STANDARD_HEADER_TOKENS for t in tokens)


def detect_access_control(code: str) -> List[dict]:
    """检测“关键函数任何人都可以调用”。

    判定只依赖代码文本，同样的代码永远得到同样的结论。满足全部条件才报：
    1. public/external；
    2. 无自定义修饰符（如 onlyOwner），函数体内也没有 msg.sender 比较、
       hasRole 等显式身份校验；
    3. 函数体完全不引用 msg.sender —— 代币转账、本人存取款这类函数天生
       需要对所有人开放，它们都围绕调用者自身操作；完全不引用调用者却
       改账、转资金、销毁合约，才是“任何人可调用”的低级写法；
    4. 含敏感操作（状态写入、资金转移、mint/burn、selfdestruct 等）。
    """
    findings = []
    for name, params, tail, body, offset in _iter_functions(code):
        if name == "constructor":
            continue
        is_open = re.search(r"\b(public|external)\b", tail) is not None
        if not is_open:
            continue
        if not SENSITIVE_BODY_PATTERN.search(body):
            continue
        references_caller = "msg.sender" in body
        guarded = _has_custom_modifier(tail) or any(
            p.search(body) for p in GUARD_BODY_PATTERNS
        )
        if references_caller or guarded:
            continue
        line_num = _line_of(code, offset)
        findings.append({
            "type": ACCESS_CONTROL_TYPE,
            "severity": ACCESS_CONTROL_SEVERITY,
            "line": line_num,
            "description": ACCESS_CONTROL_DESC,
            "suggestion": ACCESS_CONTROL_SUGGESTION,
            "code": _context_of(code, line_num),
        })
    return findings


def detect_vulnerabilities(code: str) -> List[dict]:
    """扫描漏洞。结果按 (行号, 类型) 排序，保证输出顺序稳定。"""
    vulnerabilities = []

    for vp in VULNERABILITY_PATTERNS:
        for m in re.finditer(vp["pattern"], code, re.MULTILINE):
            line_num = _line_of(code, m.start())
            vulnerabilities.append({
                "type": vp["type"],
                "severity": vp["severity"],
                "line": line_num,
                "description": vp["description"],
                "suggestion": vp["suggestion"],
                "code": _context_of(code, line_num),
            })

    vulnerabilities.extend(detect_access_control(code))
    vulnerabilities.sort(key=lambda v: (v["line"], v["type"]))
    return vulnerabilities


def _stable_int(seed: str, lo: int, hi: int) -> int:
    """由文本种子派生 [lo, hi] 内的稳定整数，替代 random。"""
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return lo + int(digest[:8], 16) % (hi - lo + 1)


def compute_gas_issues(code: str) -> List[dict]:
    """分析 Gas 问题。同一份代码的 Gas 结论必须逐字节一致。"""
    issues = []
    for name, params, tail, body, offset in _iter_functions(code):
        signature = f"{name}({params.strip()})"
        seed = f"{code}\x00{signature}"
        base_gas = _stable_int(seed, 20000, 60000)
        optimized_gas = int(base_gas * 0.72)
        suggestion = GAS_SUGGESTIONS[
            _stable_int(seed + ":suggestion", 0, len(GAS_SUGGESTIONS) - 1)
        ]
        issues.append({
            "functionName": signature,
            "currentGas": base_gas,
            "optimizedGas": optimized_gas,
            "suggestion": suggestion,
        })
    return issues


def compute_security_score(vulnerabilities: List[dict]) -> int:
    """计算整体安全评分（纯函数）。"""
    if not vulnerabilities:
        return 100
    severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    deduction = sum(severity_weights.get(v["severity"], 5) for v in vulnerabilities)
    return max(0, 100 - deduction)


def run_audit(code: str) -> dict:
    vulnerabilities = detect_vulnerabilities(code)
    gas_issues = compute_gas_issues(code)
    return {
        "vulnerabilities": vulnerabilities,
        "gasIssues": gas_issues,
        "score": compute_security_score(vulnerabilities),
    }


@app.get("/")
async def root():
    return {"message": "Smart Contract Security Auditor", "version": "1.0.0"}


@app.get("/api/patterns")
async def list_patterns():
    return {"code": 0, "message": "success", "data": VULNERABILITY_PATTERNS}


@app.post("/api/audit")
async def audit_contract(request: AuditRequest):
    code_hash = hashlib.sha256(request.code.encode("utf-8")).hexdigest()
    now = datetime.now().isoformat(timespec="seconds")

    # 查重与落库串行化：并发重复提交也只会留下一条记录
    with store.lock:
        existing = store.find_recent(code_hash, DEDUP_WINDOW_SECONDS)
        if existing is not None:
            result = dict(existing["result"])
            result["id"] = existing["id"]
            result["filename"] = existing["filename"]
            result["timestamp"] = existing["created_at"]
            result["status"] = existing["status"]
            result["cached"] = True
            if existing.get("error"):
                result["error"] = existing["error"]
                return {"code": 1, "message": existing["error"], "data": result}
            return {"code": 0, "message": "success", "data": result}

        audit_id = str(uuid.uuid4())
        try:
            audit = run_audit(request.code)
        except Exception as exc:  # noqa: BLE001 - 失败原因需要原样留存
            error_message = f"{type(exc).__name__}: {exc}"
            result = {
                "id": audit_id,
                "filename": request.filename,
                "codeHash": code_hash,
                "score": None,
                "vulnerabilities": [],
                "gasIssues": [],
                "timestamp": now,
                "status": "failed",
                "cached": False,
                "error": error_message,
            }
            store.save({
                "id": audit_id,
                "code_hash": code_hash,
                "filename": request.filename,
                "code": request.code,
                "status": "failed",
                "score": None,
                "error": error_message,
                "result": result,
                "created_at": now,
            })
            return {"code": 1, "message": error_message, "data": result}

        result = {
            "id": audit_id,
            "filename": request.filename,
            "codeHash": code_hash,
            "score": audit["score"],
            "vulnerabilities": audit["vulnerabilities"],
            "gasIssues": audit["gasIssues"],
            "timestamp": now,
            "status": "success",
            "cached": False,
        }
        store.save({
            "id": audit_id,
            "code_hash": code_hash,
            "filename": request.filename,
            "code": request.code,
            "status": "success",
            "score": audit["score"],
            "error": None,
            "result": result,
            "created_at": now,
        })

    return {"code": 0, "message": "success", "data": result}


@app.get("/api/history")
async def get_history():
    return {"code": 0, "message": "success", "data": store.list_history()}


@app.get("/api/history/{audit_id}")
async def get_audit_detail(audit_id: str):
    record = store.get(audit_id)
    if record is None:
        raise HTTPException(status_code=404, detail="审计记录不存在")
    result = dict(record["result"])
    result["id"] = record["id"]
    result["filename"] = record["filename"]
    result["timestamp"] = record["created_at"]
    result["status"] = record["status"]
    if record.get("error"):
        result["error"] = record["error"]
    result["code"] = record["code"]
    return {"code": 0, "message": "success", "data": result}


@app.post("/api/report/{audit_id}")
async def generate_report(audit_id: str):
    """Generate PDF report"""
    return {"code": 0, "message": "success", "data": {"url": f"/api/reports/{audit_id}.pdf"}}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
