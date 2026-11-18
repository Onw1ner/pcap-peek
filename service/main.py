from __future__ import annotations 

import os
import tempfile
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

from fastapi import FastAPI,UploadFile,File,HTTPException
from starlette.concurrency import run_in_threadpool
from pcappeek.pcapng import PcapngError
from pcappeek.pcap import PcapError
from pcappeek.stats import collect_stats    

logger = logging.getLogger("pcappeek.service")


app = FastAPI(title="pcap-peek service",version="0.1.0")

MAX_UPLOAD = 64*1024*1024
CHUNK = 1024*1024

@app.get("/health")
def health() -> dict[str,str]:
    return {"status": "ok"}


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)) -> dict:
    # 边读边写，顺手卡大小；避免一次性把几个 G 读进内存
    size = 0
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        with open(path, "wb") as out:
            while chunk := await file.read(CHUNK):
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise HTTPException(
                        status_code=413,
                        detail=f"文件超过 {MAX_UPLOAD // (1024 * 1024)} MB 上限",
                    )
                out.write(chunk)

        if size == 0:
            raise HTTPException(status_code=400, detail="文件是空的")

        try:
            # collect_stats 是阻塞的，必须丢到线程池，否则会卡住整个事件循环
            stats = await run_in_threadpool(collect_stats, path)
        except (PcapError, PcapngError) as exc:
            logger.info("解析失败 %s: %s", file.filename, exc)
            raise HTTPException(
                status_code=400, detail=f"不是 pcap 或 pcapng 文件：{exc}"
            ) from exc
        except Exception as exc:                      # noqa: BLE001
            logger.exception("解析器内部错误: %s", file.filename)
            raise HTTPException(status_code=500, detail="解析器内部错误") from exc
    finally:
        try:
            os.unlink(path)
        except OSError:
            logger.warning("临时文件删除失败: %s", path)

    return _to_payload(stats, source=file.filename or "")


def _to_payload(stats: dict, source: str) -> dict:
    """显式映射：只把想给调用方看的字段吐出去。"""
    return {
        "source": source,
        "total": stats["total"],
        "skipped": stats["skipped"],
        "failed": stats["failed"],
        "protocols": dict(stats["proto"]),
        "ethertypes": {f"0x{k:04X}": v for k, v in stats["eths"].items()},
        "top_sources": dict(stats["src"].most_common(10)),
        "dns_top": dict(stats["dns"].most_common(10)),
        "tls": {
            "seen": stats["tls_seen"],
            "ok": stats["tls_ok"],
            "no_sni": stats["tls_no_sni"],
            "bad": stats["tls_bad"],
            "sni_top": dict(stats["sni"].most_common(10)),
        },
        "findings": [
            {
                "rule": f.rule,
                "severity": f.severity,
                "subject": f.subject,
                "detail": f.detail,
                "count": f.count,
            }
            for f in stats["findings"]
        ],
        "sessions": len(stats["flows"]),
        "top_sessions": [
            {
                "a": f"{fl.key.a_ip}:{fl.key.a_port}",
                "b": f"{fl.key.b_ip}:{fl.key.b_port}",
                "protocol": fl.key.protocol,
                "packets": fl.packets,
                "bytes": fl.total_bytes,
            }
            for fl in stats["flows"][:5]
        ],
    }