from fastapi import APIRouter, HTTPException
from backend.scan.request import Request
from backend.connect.runner import run_nmap_xml
from backend.connect.parser import parse_nmap_xml

router = APIRouter(tags=["scan"])

@router.post("/scan")
async def scan(req: Request):
    try:
        xml_text = await run_nmap_xml(req)
        return parse_nmap_xml(xml_text)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))