from app.connect.helper_client import run_privileged_nmap_xml, cancel_privileged_scan
from app.connect.runner import run_nmap_xml, cancel_nmap_scan
from app.scan.request import Request


async def run_scan_xml(req: Request) -> str:
    if req.use_privileged:
        return await run_privileged_nmap_xml(req)
    return await run_nmap_xml(req)

async def cancel_scan_xml(request_id: str, use_privileged: bool) -> bool:
    if use_privileged:
        return await cancel_privileged_scan(request_id)
    return cancel_nmap_scan(request_id)
