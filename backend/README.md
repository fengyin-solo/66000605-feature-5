# Backend: Python FastAPI

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## 审计结果留存

- 审计结果（成功结论与失败原因）持久化在 SQLite，默认库文件为
  `backend/data/audits.db`，可用环境变量 `AUDIT_DB_PATH` 覆盖；服务重启后
  历史清单、结论与建议保持不变。
- 同一份合约（按代码内容 SHA-256 判定，与文件名无关）在 5 分钟
  （`DEDUP_WINDOW_SECONDS`）内重复提交时，直接沿用上一次结论，返回体
  `cached: true`，不重复落库；失败的审计在窗口内同样沿用上次失败记录。
- 检测结论全部由代码文本确定性推导（Gas 数值由代码哈希派生，不使用
  随机数），同一合约两次审计结果一致。
- 审计中途失败时返回 `code: 1`，原始失败原因保存在 `error` 字段并落库，
  可在历史与详情接口中查回。

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/audit` | 提交审计，支持去重复用 |
| GET | `/api/history` | 历史摘要列表 |
| GET | `/api/history/{id}` | 单次审计详情（含源码、漏洞清单、Gas 建议或失败原因） |
| GET | `/api/patterns` | 漏洞模式库 |

## 离线测试

环境无法安装 fastapi 时，测试用桩模块加载真实业务逻辑：

```bash
python3 tests/test_logic.py
python3 tests/test_e2e.py
```
