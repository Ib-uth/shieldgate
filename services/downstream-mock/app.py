"""Minimal downstream for ShieldGate: responds 200 on GET /health.

Deploy as a separate Render Web Service; set gateway DOWNSTREAM_URL to this service origin.

Run locally: uvicorn app:app --host 0.0.0.0 --port 8001
"""

from fastapi import FastAPI

app = FastAPI(title="ShieldGate downstream mock")


@app.get("/health")
async def health():
    return {"status": "ok"}
