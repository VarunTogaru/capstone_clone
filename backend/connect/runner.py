import asyncio
from backend.scan.request import Request

SCAN_TYPE_FLAGS = {
    "tcp": ["-sT"],
    "syn": ["-sS"],
    "version": ["-sV"],
}

async def run_nmap_xml(req: Request) -> str:
    if req.scan_type not in SCAN_TYPE_FLAGS:
        raise RuntimeError("Unsupported scan type")

    args = ["nmap", *SCAN_TYPE_FLAGS[req.scan_type]]
    if req.ports:
        args += ["-p", req.ports]

    # XML to stdout
    args += ["-oX", "-", req.target]

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        raise RuntimeError(stderr.decode(errors="ignore") or "Nmap failed")

    return stdout.decode(errors="ignore")