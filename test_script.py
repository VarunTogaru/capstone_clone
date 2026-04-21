import asyncio, sys; sys.path.insert(0, '.'); from app.scan.request import Request; from app.router import scan; req=Request(target='scanme.nmap.org', scan_type='syn'); print(asyncio.run(scan(req)))
