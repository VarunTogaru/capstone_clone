from backend.connect.helper_client import run_privileged_nmap_xml
from backend.connect.runner import run_nmap_xml
from backend.scan.request import Request


async def run_scan_xml(req: Request) -> str:
    if req.use_privileged:
        return await run_privileged_nmap_xml(req)
    return await run_nmap_xml(req)
