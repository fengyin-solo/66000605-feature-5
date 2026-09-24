import hashlib
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import auditor, database

# 同一份合约在该时间窗口内重复提交时，沿用上一次的审计结论，不重复记录
DEDUP_WINDOW_SECONDS = 3600

REPORTS_DIR = os.environ.get(
    "AUDIT_REPORTS_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports"),
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    yield


app = FastAPI(title="Smart Contract Security Auditor", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AuditRequest(BaseModel):
    code: str
    filename: str


@app.get("/")
async def root():
    return {"message": "Smart Contract Security Auditor", "version": "1.0.0"}


@app.get("/api/patterns")
async def list_patterns():
    return {"code": 0, "message": "success", "data": auditor.PATTERNS_FOR_DISPLAY}


@app.post("/api/audit")
async def audit_contract(request: AuditRequest):
    code_hash = hashlib.sha256(request.code.encode("utf-8")).hexdigest()

    # 短时间内重复提交同一份合约：直接沿用上一次的结论，不产生新记录
    cached = database.find_recent_success(code_hash, DEDUP_WINDOW_SECONDS)
    if cached:
        return {"code": 0, "message": "success", "data": cached}

    audit_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    record = {
        "id": audit_id,
        "filename": request.filename,
        "codeHash": code_hash,
        "code": request.code,
        "timestamp": timestamp,
    }

    try:
        result = auditor.run_audit(request.code)
        record.update(
            status="success",
            score=result["score"],
            vulnerabilities=result["vulnerabilities"],
            gasIssues=result["gasIssues"],
            error=None,
        )
        database.insert_audit(record)
        # 从库中读回，保证响应与之后查询到的内容完全一致
        return {"code": 0, "message": "success", "data": database.get_audit(audit_id)}
    except Exception as exc:
        # 审计中途失败：保留原始失败原因，落库并原样返回给调用方
        error_msg = f"{type(exc).__name__}: {exc}"
        record.update(
            status="failed",
            score=None,
            vulnerabilities=[],
            gasIssues=[],
            error=error_msg,
        )
        try:
            database.insert_audit(record)
            saved = database.get_audit(audit_id)
        except Exception:
            saved = None
        return JSONResponse(
            status_code=500,
            content={
                "code": 500,
                "message": error_msg,
                "data": saved or database.public_view(record),
            },
        )


@app.get("/api/history")
async def get_history():
    return {"code": 0, "message": "success", "data": database.list_audits()}


@app.get("/api/audit/{audit_id}")
async def get_audit_detail(audit_id: str):
    record = database.get_audit(audit_id)
    if not record:
        raise HTTPException(status_code=404, detail="审计记录不存在")
    return {"code": 0, "message": "success", "data": record}


@app.post("/api/report/{audit_id}")
async def generate_report(audit_id: str):
    """基于已保存的审计记录生成 PDF 报告（内容与当时审计结论一致）。"""
    record = database.get_audit(audit_id)
    if not record:
        raise HTTPException(status_code=404, detail="审计记录不存在")
    if record["status"] != "success":
        raise HTTPException(
            status_code=400, detail=f"该次审计失败，无法生成报告：{record['error']}"
        )
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, f"{audit_id}.pdf")
    _build_pdf(record, path)
    return {
        "code": 0,
        "message": "success",
        "data": {"url": f"/api/reports/{audit_id}.pdf"},
    }


@app.get("/api/reports/{filename}")
async def download_report(filename: str):
    path = os.path.join(REPORTS_DIR, filename)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="报告不存在")
    return FileResponse(path, media_type="application/pdf")


def _build_pdf(record: dict, path: str) -> None:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.pdfgen import canvas

    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    c = canvas.Canvas(path, pagesize=letter)
    y = 750
    c.setFont("STSong-Light", 18)
    c.drawString(72, y, "智能合约安全审计报告")
    y -= 36
    c.setFont("STSong-Light", 12)
    c.drawString(72, y, f"文件：{record['filename']}")
    y -= 20
    c.drawString(72, y, f"时间：{record['timestamp']}")
    y -= 20
    c.drawString(72, y, f"安全评分：{record['score']}")
    y -= 32
    c.drawString(72, y, f"发现漏洞（{len(record['vulnerabilities'])}）：")
    y -= 20
    c.setFont("STSong-Light", 10)
    for v in record["vulnerabilities"]:
        for line in (
            f"[{v['severity']}] {v['type']} (行 {v['line']})",
            f"    {v['description']}",
            f"    建议：{v['suggestion']}",
        ):
            c.drawString(72, y, line)
            y -= 16
            if y < 72:
                c.showPage()
                c.setFont("STSong-Light", 10)
                y = 750
        y -= 4
    c.save()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
