from pydantic import BaseModel, Field

class Request(BaseModel):
    target: str = Field(..., examples=["scanme.nmap.org", "192.168.1.10"])
    scan_type: str = Field("tcp", examples=["tcp", "syn", "version"])
    ports: str | None = Field(None, examples=["22,80,443", "1-1024"])