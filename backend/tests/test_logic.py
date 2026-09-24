"""离线逻辑测试（环境无 fastapi 时用桩模块导入真实业务代码）。"""
import sys
import types
import tempfile
import os

# ---- 桩掉 fastapi 依赖，只测业务逻辑与 storage ----
fastapi = types.ModuleType("fastapi")


class HTTPException(Exception):
    def __init__(self, status_code, detail):
        self.status_code = status_code
        self.detail = detail


class FastAPI:
    def __init__(self, **kw):
        pass

    def add_middleware(self, *a, **kw):
        pass

    def get(self, *a, **kw):
        def deco(f):
            return f
        return deco

    post = get


fastapi.FastAPI = FastAPI
fastapi.HTTPException = HTTPException
sys.modules["fastapi"] = fastapi

mw = types.ModuleType("fastapi.middleware")
cors = types.ModuleType("fastapi.middleware.cors")
cors.CORSMiddleware = object
sys.modules["fastapi.middleware"] = mw
sys.modules["fastapi.middleware.cors"] = cors

pydantic = types.ModuleType("pydantic")


class BaseModel:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


pydantic.BaseModel = BaseModel
sys.modules["pydantic"] = pydantic

os.environ["AUDIT_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.main import (  # noqa: E402
    run_audit,
    detect_vulnerabilities,
    compute_gas_issues,
    detect_access_control,
    store,
    audit_contract,
    get_history,
    get_audit_detail,
)
from app.storage import AuditStore  # noqa: E402

BANK = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleBank {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"""

# 关键函数任何人可调用：无 modifier、无 require/msg.sender 守卫，有状态写入
UNPROTECTED = """pragma solidity ^0.8.0;
contract Owned {
    address public owner;
    mapping(address => uint) public credits;
    function credit(address to, uint v) external {
        credits[to] += v;
    }
    function sweep(address payable to) public {
        to.transfer(address(this).balance);
    }
    function safeSet(address to, uint v) public onlyOwner {
        credits[to] = v;
    }
    function guardedSet(address to, uint v) public {
        require(msg.sender == owner);
        credits[to] = v;
    }
    function viewBal(address a) public view returns (uint) {
        return credits[a];
    }
}
"""

TOKEN = """pragma solidity ^0.8.0;
contract Token {
    mapping(address => uint) public balanceOf;
    function transfer(address to, uint amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
"""

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


# 1. 确定性：同一份合约两次审计结果完全一致
r1 = run_audit(BANK)
r2 = run_audit(BANK)
check("同一合约两次审计结论一致", r1 == r2)

# 2. Gas 稳定（旧实现用 random，每次不同）
g1 = compute_gas_issues(BANK)
g2 = compute_gas_issues(BANK)
check("Gas 分析两次一致", g1 == g2)
check("Gas 覆盖全部函数", [g["functionName"] for g in g1] == ["deposit()", "withdraw(uint amount)"])
check("Gas 值在合理区间", all(20000 <= g["currentGas"] <= 60000 for g in g1))

# 3. 未授权访问判定稳定且正确
ac1 = detect_access_control(UNPROTECTED)
ac2 = detect_access_control(UNPROTECTED)
check("未授权访问两次结论一致", ac1 == ac2)
flagged = {v["line"] for v in ac1}
lines = UNPROTECTED.split("\n")
credit_line = next(i + 1 for i, l in enumerate(lines) if "credit(address to" in l)
sweep_line = next(i + 1 for i, l in enumerate(lines) if "sweep(" in l)
safe_line = next(i + 1 for i, l in enumerate(lines) if "safeSet" in l)
guarded_line = next(i + 1 for i, l in enumerate(lines) if "guardedSet" in l)
view_line = next(i + 1 for i, l in enumerate(lines) if "viewBal" in l)
check("无保护写函数 credit 被标记", credit_line in flagged)
check("无保护资金函数 sweep 被标记", sweep_line in flagged)
check("onlyOwner 修饰符函数不标记", safe_line not in flagged)
check("require(msg.sender==owner) 守卫函数不标记", guarded_line not in flagged)
check("view 只读函数不标记", view_line not in flagged)

# SimpleBank：存取款围绕 msg.sender 自身操作，属于正常开放函数，不应误报；
# 两次审计结论保持一致即可
bank_ac = [v["line"] for v in detect_vulnerabilities(BANK) if v["type"] == "未授权访问控制"]
bank_ac_2 = [v["line"] for v in detect_vulnerabilities(BANK) if v["type"] == "未授权访问控制"]
check("SimpleBank 未授权判定稳定", bank_ac == bank_ac_2)
check("SimpleBank 存/取款不被误判为未授权", bank_ac == [])

# 4. token/transfer 写法判定稳定
t1 = run_audit(TOKEN)
t2 = run_audit(TOKEN)
check("代币合约两次审计一致", t1 == t2)
check("代币 transfer 有余额守卫不判未授权",
      all(v["type"] != "未授权访问控制" for v in t1["vulnerabilities"]))

# 5. 持久化 + 查重 + 历史
import asyncio


def call(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


resp1 = call(audit_contract(type("R", (), {"code": BANK, "filename": "SimpleBank.sol"})()))
resp2 = call(audit_contract(type("R", (), {"code": BANK, "filename": "SimpleBank.sol"})()))
check("首次审计成功", resp1["code"] == 0 and resp1["data"]["status"] == "success")
check("短时间重复提交沿用同一 id", resp1["data"]["id"] == resp2["data"]["id"])
check("重复提交标记 cached", resp2["data"]["cached"] is True)
check("重复提交结论一致",
      (resp1["data"]["score"], resp1["data"]["vulnerabilities"], resp1["data"]["gasIssues"]) ==
      (resp2["data"]["score"], resp2["data"]["vulnerabilities"], resp2["data"]["gasIssues"]))

history = call(get_history())["data"]
check("历史只有一条（未重复记录）", len(history) == 1)
check("历史摘要字段完整", history[0]["filename"] == "SimpleBank.sol" and history[0]["vulnCount"] == len(resp1["data"]["vulnerabilities"]))

detail = call(get_audit_detail(resp1["data"]["id"]))["data"]
check("详情包含漏洞清单与建议",
      detail["status"] == "success"
      and detail["score"] == resp1["data"]["score"]
      and detail["vulnerabilities"] == resp1["data"]["vulnerabilities"]
      and detail["gasIssues"] == resp1["data"]["gasIssues"]
      and detail["code"] == BANK)

# 重启后数据仍在：新建一个 store 实例指向同一 db 文件
store2 = AuditStore(os.environ["AUDIT_DB_PATH"])
h2 = store2.list_history()
check("重启后历史仍可查", len(h2) == 1 and h2[0]["id"] == resp1["data"]["id"])
rec = store2.get(resp1["data"]["id"])
check("重启后结论/清单/建议与当时一致", rec["result"]["vulnerabilities"] == resp1["data"]["vulnerabilities"])

# 不同合约应产生新记录
resp3 = call(audit_contract(type("R", (), {"code": TOKEN, "filename": "Token.sol"})()))
check("不同合约生成新记录", resp3["data"]["id"] != resp1["data"]["id"])
check("历史共两条", len(call(get_history())["data"]) == 2)

# 6. 审计失败：保存原始失败原因，且可在历史/详情中查回
import app.main as main_mod

orig = main_mod.run_audit


def boom(code):
    raise RuntimeError("模拟解析失败 XYZ")


main_mod.run_audit = boom
fail_resp = call(audit_contract(type("R", (), {"code": "contract Broken {", "filename": "Broken.sol"})()))
main_mod.run_audit = orig
check("失败返回 code=1 并保留原因", fail_resp["code"] == 1 and "模拟解析失败 XYZ" in fail_resp["message"] and "模拟解析失败 XYZ" in fail_resp["data"]["error"])
check("失败记录 status=failed", fail_resp["data"]["status"] == "failed")
failed_detail = call(get_audit_detail(fail_resp["data"]["id"]))["data"]
check("失败原因可在详情查回", failed_detail["status"] == "failed" and "模拟解析失败 XYZ" in failed_detail["error"])
# 短时间内重提失败合约同样沿用上次的失败结论
fail_resp2 = call(audit_contract(type("R", (), {"code": "contract Broken {", "filename": "Broken.sol"})()))
check("失败合约重提沿用同一失败记录",
      fail_resp2["data"]["id"] == fail_resp["data"]["id"]
      and "模拟解析失败 XYZ" in fail_resp2["data"].get("error", ""))

# 404
try:
    call(get_audit_detail("nope"))
    check("不存在的 id 返回 404", False)
except Exception as e:
    check("不存在的 id 返回 404", getattr(e, "status_code", None) == 404)

print()
print("FAILED:", failures if failures else "none")
sys.exit(1 if failures else 0)
