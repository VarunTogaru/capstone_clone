from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from backend.router import router

app = FastAPI()
app.include_router(router)

BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "static" / "index.html"

@app.get("/", include_in_schema=False)
async def serve_frontend() -> FileResponse:
    # Serve the local demo UI from the backend.
    return FileResponse(INDEX_FILE)

@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict:
    return {"status": "ok"}
