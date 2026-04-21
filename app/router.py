import logging

from fastapi import APIRouter, HTTPException
from app.scan.request import Request
from app.connect.dispatcher import run_scan_xml
from app.connect.parser import parse_nmap_xml
from app.scan.db import save_scan, get_scan_history, get_scan_result

logger = logging.getLogger("nmap_insight.router")

router = APIRouter(tags=["scan"])

import uuid
from pydantic import BaseModel

class CancelRequest(BaseModel):
    request_id: str
    use_privileged: bool

@router.post("/scan")
async def scan(req: Request):
    if not req.request_id:
        req.request_id = f"req_{uuid.uuid4().hex[:12]}"

    logger.info("Scan requested: target=%s scan_type=%s privileged=%s", req.target, req.scan_type, req.use_privileged)
    try:
        xml_text = await run_scan_xml(req)
        result = parse_nmap_xml(xml_text)
        
        command = result.get("metadata", {}).get("args", "")
        db_id = save_scan(req.target, req.scan_type, command, result)
        result["_db_id"] = db_id
        
        logger.info("Scan completed: target=%s hosts=%d db_id=%d", req.target, len(result.get("hosts", [])), db_id)
        return result
    except RuntimeError as e:
        message = str(e)
        logger.error("Scan failed: target=%s e=%r message=%r", req.target, e, message)
        if message.startswith("ELEVATED_FLAG_NOT_ALLOWED"):
            raise HTTPException(status_code=400, detail=message)
        if message.startswith("ELEVATED_PRIVILEGES_REQUIRED"):
            raise HTTPException(status_code=403, detail=message)
        if message.startswith("HELPER_NOT_AVAILABLE"):
            raise HTTPException(status_code=503, detail=message)
        if message.startswith("SCAN_TIMEOUT"):
            raise HTTPException(status_code=408, detail=message)
        raise HTTPException(status_code=500, detail=message)

@router.get("/scans")
async def get_scans():
    return get_scan_history()

@router.get("/scans/{scan_id}")
async def get_scan(scan_id: int):
    result = get_scan_result(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result

from app.connect.dispatcher import cancel_scan_xml

@router.post("/scan/cancel")
async def cancel_scan(payload: CancelRequest):
    logger.info("Cancel requested for request_id=%s", payload.request_id)
    success = await cancel_scan_xml(payload.request_id, payload.use_privileged)
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found or already completed")
    return {"status": "canceled"}
