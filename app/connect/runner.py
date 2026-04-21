import asyncio
import logging
import shutil
from app.scan.request import Request

logger = logging.getLogger("nmap_insight.runner")

RUNNING_PROCESSES: dict[str, asyncio.subprocess.Process] = {}
CANCELED_REQUESTS: set[str] = set()

def cancel_nmap_scan(request_id: str) -> bool:
    proc = RUNNING_PROCESSES.get(request_id)
    if proc and proc.returncode is None:
        CANCELED_REQUESTS.add(request_id)
        proc.kill()
        logger.info("Canceled standard scan: request_id=%s", request_id)
        return True
    return False

SCAN_TYPE_FLAGS = {
    "tcp": ["-sT"],
    "syn": ["-sS"],
    "version": ["-sV"],
    "custom": [],
}

def build_nmap_args(req: Request) -> list[str]:
    if req.scan_type not in SCAN_TYPE_FLAGS:
        raise RuntimeError("Unsupported scan type")

    default_flags = SCAN_TYPE_FLAGS[req.scan_type]
    args = ["nmap", *default_flags]
    if req.ports:
        args += ["-p", req.ports]
    if req.extra_args:
        for arg in req.extra_args:
            if arg not in default_flags:
                args.append(arg)

    # Force XML output to stdout so the parser can consume it.
    args += ["-oX", "-", req.target]
    return args

async def run_nmap_xml(req: Request) -> str:
    if shutil.which("nmap") is None:
        raise RuntimeError("nmap is not installed or not in PATH")

    args = build_nmap_args(req)
    logger.info("Running nmap: %s", " ".join(args))

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        is_async_proc = True
    except NotImplementedError:
        import subprocess
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        is_async_proc = False
        
    if req.request_id:
        RUNNING_PROCESSES[req.request_id] = proc

    try:
        if is_async_proc:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=req.timeout_seconds,
            )
        else:
            stdout, stderr = await asyncio.wait_for(
                asyncio.to_thread(proc.communicate),
                timeout=req.timeout_seconds,
            )
    except asyncio.TimeoutError as exc:
        proc.kill()
        if is_async_proc:
            await proc.communicate()
        else:
            proc.communicate()
        logger.warning("Nmap scan timed out after %ds", req.timeout_seconds)
        raise RuntimeError("SCAN_TIMEOUT: scan exceeded timeout") from exc
    finally:
        if req.request_id:
            RUNNING_PROCESSES.pop(req.request_id, None)

    if req.request_id and req.request_id in CANCELED_REQUESTS:
        CANCELED_REQUESTS.discard(req.request_id)
        raise RuntimeError("Scan was canceled")

    # If the process was externally killed but not due to a timeout, it will have a negative return code.
    if proc.returncode != 0:
        stderr_text = stderr.decode(errors="ignore").strip()
        stdout_text = stdout.decode(errors="ignore").strip()
        
        error_msg = stderr_text or stdout_text or f"Nmap failed with return code {proc.returncode}"
        
        if "requires root privileges" in error_msg.lower() or "failed to open device" in error_msg.lower():
            error_msg = "ELEVATED_PRIVILEGES_REQUIRED: This scan requires elevated privileges. Please check 'Use privileged helper mode' (Advanced)."
            
        logger.error("Nmap failed (rc=%d): %s", proc.returncode, error_msg)
        raise RuntimeError(error_msg)

    return stdout.decode(errors="ignore")
