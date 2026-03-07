import asyncio
import platform
import shutil
import uuid

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from backend.connect.privileged_allowlist import validate_privileged_command
from backend.connect.runner import build_nmap_args
from backend.scan.request import Request

app = FastAPI(title="Nmap Insight Privileged Helper")

RUNNING_PROCESSES: dict[str, asyncio.subprocess.Process] = {}
CANCELED_REQUESTS: set[str] = set()


class CancelRequest(BaseModel):
    request_id: str


def _command_for_request(req: Request) -> tuple[list[str], list[str]]:
    command = build_nmap_args(req)
    errors = validate_privileged_command(command)
    return command, errors


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "version": "1.0.0",
        "platform": platform.system().lower(),
    }


@app.post("/validate")
async def validate(req: Request) -> dict:
    command, errors = _command_for_request(req)
    return {
        "allowed": len(errors) == 0,
        "errors": errors,
        "command": command,
    }


@app.post("/scan")
async def scan(req: Request) -> dict:
    if shutil.which("nmap") is None:
        raise HTTPException(status_code=500, detail="SCAN_RUNTIME_ERROR: nmap not found in PATH")

    command, errors = _command_for_request(req)
    if errors:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "ELEVATED_FLAG_NOT_ALLOWED",
                "errors": errors,
            },
        )

    request_id = req.request_id or f"req_{uuid.uuid4().hex[:12]}"
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    RUNNING_PROCESSES[request_id] = process

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=req.timeout_seconds,
        )
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.communicate()
        raise HTTPException(
            status_code=408,
            detail="SCAN_TIMEOUT: privileged scan exceeded timeout",
        ) from exc
    finally:
        RUNNING_PROCESSES.pop(request_id, None)

    stderr_text = stderr.decode(errors="ignore")

    if request_id in CANCELED_REQUESTS:
        CANCELED_REQUESTS.discard(request_id)
        return {
            "request_id": request_id,
            "status": "canceled",
            "command": command,
            "xml": "",
            "stderr": stderr_text,
        }

    if process.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "SCAN_RUNTIME_ERROR",
                "stderr": stderr_text or "Nmap failed",
            },
        )

    return {
        "request_id": request_id,
        "status": "completed",
        "command": command,
        "xml": stdout.decode(errors="ignore"),
        "stderr": stderr_text,
    }


@app.post("/cancel")
async def cancel(payload: CancelRequest) -> dict:
    process = RUNNING_PROCESSES.get(payload.request_id)
    if process is None:
        raise HTTPException(status_code=404, detail="Request ID not found")

    CANCELED_REQUESTS.add(payload.request_id)
    if process.returncode is None:
        process.kill()

    return {
        "request_id": payload.request_id,
        "status": "canceled",
    }
