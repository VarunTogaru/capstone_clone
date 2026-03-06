import asyncio
import shutil
from backend.scan.request import Request

SCAN_TYPE_FLAGS = {
    "tcp": ["-sT"],
    "syn": ["-sS"],
    "version": ["-sV"],
    "custom": [],
}

def build_nmap_args(req: Request) -> list[str]:
    if req.scan_type not in SCAN_TYPE_FLAGS:
        raise RuntimeError("Unsupported scan type")

    args = ["nmap", *SCAN_TYPE_FLAGS[req.scan_type]]
    if req.ports:
        args += ["-p", req.ports]
    if req.extra_args:
        args += req.extra_args

    # Force XML output to stdout so the parser can consume it.
    args += ["-oX", "-", req.target]
    return args

async def run_nmap_xml(req: Request) -> str:
    if shutil.which("nmap") is None:
        raise RuntimeError("nmap is not installed or not in PATH")

    args = build_nmap_args(req)

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        raise RuntimeError(stderr.decode(errors="ignore") or "Nmap failed")

    return stdout.decode(errors="ignore")
