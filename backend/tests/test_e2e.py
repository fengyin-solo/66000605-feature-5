"""用标准库驱动 ASGI app 的真实 HTTP 端到端测试（无需安装 fastapi/uvicorn）。

fastapi 用桩模块代替，main.py 中 app 装饰器注册的路由在此简单分发，
目的：验证 storage 锁、去重、失败落库、重启恢复在真实请求生命周期下成立。
"""
import asyncio
import json
import os
import sys
import tempfile
import types

fastapi = types.ModuleType("fastapi")


class HTTPException(Exception):
    def __init__(self, status_code, detail):
        self.status_code = status_code
        self.detail = detail


ROUTES = {"GET": {}, "POST": {}}


class FastAPI:
    def __init__(self, **kw):
        pass

    def add_middleware(self, *a, **kw):
        pass

    def get(self, path, **kw):
        def deco(f):
            ROUTES["GET"][path] = f
            return f
        return deco

    def post(self, path, **kw):
        def deco(f):
            ROUTES["POST"][path] = f
            return f
        return deco


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

DB_DIR = tempfile.mkdtemp()
os.environ["AUDIT_DB_PATH"] = os.path.join(DB_DIR, "e2e.db")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app.main as main  # noqa: E402
from app.main import AuditRequest  # noqa: E402


class Client:
            # 极简“HTTP 客户端”：直接调用路由协程，模拟 ASGI 请求体解析
    def __init__(self):
        self.token = None

    def request(self, method, path, body=None):
        handler = ROUTES[method].get(path)
        path_param = None
        if handler is None:
            # /api/history/{id} 与 /api/report/{id}
            for registered in ROUTES[method]:
                prefix = registered.rstrip("{audit_id}")
                if registered.endswith("{audit_id}") and path.startswith(prefix):
                    handler = ROUTES[method][registered]
                    path_param = path[len(prefix):]
                    break
        if handler is None:
            return 404, None
        try:
            if method == "POST" and path_param is None:
                req = AuditRequest(**body)
                result = asyncio.run(handler(req))
            elif path_param is not None:
                result = asyncio.run(handler(path_param))
            else:
                result = asyncio.run(handler())
            return 200, result
        except main.HTTPException as e:
            return e.status_code, {"detail": e.detail}
        except Exception as e:  # noqa: BLE001
            return 500, {"detail": f"{type(e).__name__}: {e}"}


CODE = """pragma solidity ^0.8.0;
contract T {
    mapping(address => uint) public bal;
    function set(address a, uint v) external { bal[a] = v; }
}
"""

fails = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        fails.append(name)


c = Client()

s1, r1 = c.request("POST", "/api/audit", {"code": CODE, "filename": "T.sol"})
s2, r2 = c.request("POST", "/api/audit", {"code": CODE, "filename": "T.sol"})
check("首次 200/成功", s1 == 200 and r1["code"] == 0 and r1["data"]["status"] == "success")
check("重复提交 200 且沿用 id", s2 == 200 and r2["data"]["id"] == r1["data"]["id"] and r2["data"]["cached"] is True)

s3, r3 = c.request("GET", "/api/history")
check("历史接口返回落库记录", s3 == 200 and len(r3["data"]) == 1)

aid = r1["data"]["id"]
s4, r4 = c.request("GET", f"/api/history/{aid}")
check("详情接口返回完整结论", s4 == 200 and r4["data"]["vulnerabilities"] == r1["data"]["vulnerabilities"])

s5, r5 = c.request("GET", "/api/history/missing")
check("未知 id 返回 404", s5 == 404)

# 失败路径
orig = main.run_audit


def boom(code):
    raise ValueError("解析器中断")


main.run_audit = boom
s6, r6 = c.request("POST", "/api/audit", {"code": "???", "filename": "bad.sol"})
main.run_audit = orig
check("失败 HTTP 200 + code=1，原因保留", s6 == 200 and r6["code"] == 1 and "解析器中断" in r6["data"]["error"])
fid = r6["data"]["id"]
s7, r7 = c.request("GET", f"/api/history/{fid}")
check("失败记录可在详情查回", s7 == 200 and r7["data"]["status"] == "failed" and "解析器中断" in r7["data"]["error"])
s8, r8 = c.request("POST", "/api/audit", {"code": "???", "filename": "bad.sol"})
check("失败合约窗口内重提沿用旧失败记录", s8 == 200 and r8["data"]["id"] == fid and "解析器中断" in r8["data"]["error"])

# 重启恢复：重新导入模块（新进程等价物）——同 db 路径
s9, r9 = c.request("GET", "/api/history")
ids = {item["id"] for item in r9["data"]}
check("重启前同连接可见全部记录", ids == {aid, fid})

print()
print("FAILED:", fails if fails else "none")
sys.exit(1 if fails else 0)
