"""审计结果持久化相关测试：

1. 同一份合约短时间内重复提交 -> 沿用上一次的结论，不重复记录
2. 服务重启后，过去的结论、清单与建议仍可查且与当时一致
3. 同一合约两次审计结果完全一致（交易/代币写法判定稳定）
4. “关键函数任何人都可以调用”的判定两次结论一致
5. 审计中途失败时保留原始失败原因
"""

import asyncio
import sqlite3

import httpx
import pytest

from app import auditor, database
from app.main import app


class SyncClient:
    """同步测试客户端（starlette 0.35 的 TestClient 与 httpx 0.28 不兼容）。

    每次新建实例即模拟一次“服务重启”：lifespan 重新执行、数据库文件不变。
    """

    def __init__(self):
        database.init_db()  # 与 lifespan 启动逻辑一致
        self._transport = httpx.ASGITransport(app=app)

    def _request(self, method, url, **kwargs):
        async def _do():
            async with httpx.AsyncClient(
                transport=self._transport, base_url="http://test"
            ) as c:
                return await c.request(method, url, **kwargs)

        return asyncio.run(_do())

    def get(self, url, **kwargs):
        return self._request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._request("POST", url, **kwargs)

BANK_CONTRACT = """// SPDX-License-Identifier: MIT
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

TOKEN_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MyToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function mint(address to, uint256 amount) public {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
"""


@pytest.fixture()
def db_path(tmp_path, monkeypatch):
    path = str(tmp_path / "audit_test.db")
    monkeypatch.setenv("AUDIT_DB_PATH", path)
    return path


@pytest.fixture()
def client(db_path):
    return SyncClient()


def _audit(client, code=BANK_CONTRACT, filename="SimpleBank.sol"):
    return client.post("/api/audit", json={"code": code, "filename": filename})


# 1. 重复提交去重 ---------------------------------------------------------------


def test_repeat_submission_reuses_previous_result(client):
    r1 = _audit(client)
    assert r1.status_code == 200
    r2 = _audit(client)
    assert r2.status_code == 200

    d1, d2 = r1.json()["data"], r2.json()["data"]
    assert d1 == d2  # 沿用上一次的结论，内容完全一致
    assert d1["id"] == d2["id"]

    history = client.get("/api/history").json()["data"]
    assert len(history) == 1  # 不重复记录


# 2. 重启后历史仍一致 ------------------------------------------------------------


def test_history_survives_restart(client, db_path):
    first = _audit(client).json()["data"]
    _audit(client, code=TOKEN_CONTRACT, filename="MyToken.sol")

    # 模拟服务重启：同一数据库文件，全新客户端（重新走 lifespan 初始化）
    client2 = SyncClient()
    try:
        history = client2.get("/api/history").json()["data"]
        assert len(history) == 2

        detail = client2.get(f"/api/audit/{first['id']}").json()["data"]
        # 结论、漏洞清单与建议与当时看到的完全一致
        assert detail == first
        assert detail["vulnerabilities"] == first["vulnerabilities"]
        assert detail["gasIssues"] == first["gasIssues"]
        assert detail["score"] == first["score"]
    finally:
        asyncio.run(client2._transport.aclose())


# 3. 判定确定性：同一合约两次审计结果同步 -----------------------------------------


def _force_new_record(client, db_path, code, filename):
    """把已有记录的时间戳改到去重窗口之外，强制重新审计。"""
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE audits SET created_at = '2000-01-01T00:00:00'")
    conn.commit()
    conn.close()
    return client.post("/api/audit", json={"code": code, "filename": filename})


@pytest.mark.parametrize(
    "code,filename", [(BANK_CONTRACT, "SimpleBank.sol"), (TOKEN_CONTRACT, "MyToken.sol")]
)
def test_same_contract_audited_twice_gives_identical_result(client, db_path, code, filename):
    first = _audit(client, code=code, filename=filename).json()["data"]
    r2 = _force_new_record(client, db_path, code, filename)
    assert r2.status_code == 200
    second = r2.json()["data"]

    assert second["id"] != first["id"]  # 超出窗口，是新记录
    # 但结论完全一致：评分、漏洞清单、Gas 建议逐项相同
    assert second["score"] == first["score"]
    assert second["vulnerabilities"] == first["vulnerabilities"]
    assert second["gasIssues"] == first["gasIssues"]


def test_gas_estimates_are_deterministic():
    r1 = auditor.run_audit(TOKEN_CONTRACT)
    r2 = auditor.run_audit(TOKEN_CONTRACT)
    assert r1 == r2
    assert len(r1["gasIssues"]) > 0


# 4. 未授权访问判定一致 ------------------------------------------------------------


def test_unauthorized_access_detected_consistently(client, db_path):
    first = _audit(client).json()["data"]
    second = _force_new_record(client, db_path, BANK_CONTRACT, "SimpleBank.sol").json()["data"]

    for data in (first, second):
        unauthorized = [
            v for v in data["vulnerabilities"] if v["type"] == "未授权访问控制"
        ]
        # withdraw 任何人可调用且可转走 ETH，必须被识别
        assert len(unauthorized) == 1
        assert "withdraw" in unauthorized[0]["description"]

    # 两次结论一致
    assert first["vulnerabilities"] == second["vulnerabilities"]


def test_access_controlled_function_not_flagged():
    code = """
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    constructor() { owner = msg.sender; }
    function withdraw(uint amount) public onlyOwner {
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
}
"""
    result = auditor.run_audit(code)
    assert all(
        v["type"] != "未授权访问控制" for v in result["vulnerabilities"]
    )


# 5. 失败时保留原始原因 ------------------------------------------------------------


def test_failure_reason_is_preserved(client, db_path):
    resp = _audit(client, code="   ", filename="Empty.sol")
    assert resp.status_code == 500
    body = resp.json()
    assert "合约代码不能为空" in body["message"]
    assert body["data"]["status"] == "failed"
    assert body["data"]["error"] == body["message"]

    # 失败记录进入历史，且重启后仍可查到原始失败原因
    client2 = SyncClient()
    try:
        history = client2.get("/api/history").json()["data"]
        failed = [h for h in history if h["status"] == "failed"]
        assert len(failed) == 1
        assert "合约代码不能为空" in failed[0]["error"]

        detail = client2.get(f"/api/audit/{failed[0]['id']}").json()["data"]
        assert detail["error"] == failed[0]["error"]
    finally:
        asyncio.run(client2._transport.aclose())
