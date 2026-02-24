"""Cold storage & log rotation — archives old data and maintains DB performance.

Moves logs older than a configurable threshold to compressed archive files,
then removes them from the database to keep queries fast.
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func
from sqlmodel import select

from threattriage.config import ROOT_DIR
from threattriage.database import async_session_factory
from threattriage.logging import get_logger
from threattriage.models.log_entry import LogEntry

logger = get_logger(__name__)

ARCHIVE_DIR = ROOT_DIR / "archives"
DEFAULT_RETENTION_DAYS = 7


async def rotate_logs(
    retention_days: int = DEFAULT_RETENTION_DAYS,
    archive_dir: Path | None = None,
) -> dict[str, Any]:
    """Archive and purge logs older than `retention_days`.

    1. Query all LogEntry rows older than the cutoff.
    2. Serialize them to JSON.
    3. Write a gzip-compressed archive file.
    4. Delete the old rows from the database.

    Returns a summary of what was archived.
    """
    archive_path = archive_dir or ARCHIVE_DIR
    archive_path.mkdir(parents=True, exist_ok=True)

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    async with async_session_factory() as session:
        # Count rows to archive
        count_stmt = (
            select(func.count())
            .select_from(LogEntry)
            .where(LogEntry.created_at < cutoff)
        )
        total = (await session.execute(count_stmt)).scalar() or 0

        if total == 0:
            logger.info("log_rotation_skipped", reason="no old logs to archive")
            return {
                "status": "skipped",
                "reason": "No logs older than cutoff",
                "cutoff": cutoff.isoformat(),
                "archived": 0,
            }

        # Fetch old logs (in batches of 1000 to limit memory)
        stmt = (
            select(LogEntry)
            .where(LogEntry.created_at < cutoff)
            .order_by(LogEntry.created_at.asc())
            .limit(5000)
        )
        results = (await session.execute(stmt)).scalars().all()

        # Serialize
        archive_records = []
        for log in results:
            archive_records.append({
                "id": str(log.id),
                "raw": log.raw,
                "log_type": log.log_type.value if log.log_type else None,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "source_ip": log.source_ip,
                "hostname": log.hostname,
                "username": log.username,
                "message": log.message,
                "is_suspicious": log.is_suspicious,
                "detection_tags": log.detection_tags,
                "created_at": log.created_at.isoformat() if log.created_at else None,
            })

        # Write compressed archive
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        archive_file = archive_path / f"logs_archive_{timestamp_str}.json.gz"

        json_bytes = json.dumps(archive_records, indent=2, default=str).encode("utf-8")
        with gzip.open(archive_file, "wb") as f:
            f.write(json_bytes)

        archive_size = archive_file.stat().st_size

        # Delete archived rows from DB
        ids_to_delete = [log.id for log in results]
        for i in range(0, len(ids_to_delete), 500):
            batch = ids_to_delete[i:i + 500]
            await session.execute(
                delete(LogEntry).where(LogEntry.id.in_(batch))
            )

        await session.commit()

    logger.info(
        "log_rotation_complete",
        archived=len(archive_records),
        archive_file=str(archive_file),
        archive_size_kb=round(archive_size / 1024, 1),
        cutoff=cutoff.isoformat(),
    )

    return {
        "status": "success",
        "archived": len(archive_records),
        "total_eligible": total,
        "archive_file": str(archive_file),
        "archive_size_bytes": archive_size,
        "archive_size_kb": round(archive_size / 1024, 1),
        "cutoff": cutoff.isoformat(),
        "retention_days": retention_days,
    }


async def list_archives(archive_dir: Path | None = None) -> list[dict[str, Any]]:
    """List all archive files with metadata."""
    path = archive_dir or ARCHIVE_DIR
    if not path.exists():
        return []

    archives = []
    for f in sorted(path.glob("logs_archive_*.json.gz"), reverse=True):
        archives.append({
            "filename": f.name,
            "path": str(f),
            "size_bytes": f.stat().st_size,
            "size_kb": round(f.stat().st_size / 1024, 1),
            "created": datetime.fromtimestamp(
                f.stat().st_mtime, tz=timezone.utc
            ).isoformat(),
        })

    return archives


async def get_storage_stats() -> dict[str, Any]:
    """Get database and archive storage statistics."""
    async with async_session_factory() as session:
        total_logs = (await session.execute(
            select(func.count()).select_from(LogEntry)
        )).scalar() or 0

    archives = await list_archives()
    total_archive_size = sum(a["size_bytes"] for a in archives)

    return {
        "active_logs": total_logs,
        "archive_count": len(archives),
        "total_archive_size_bytes": total_archive_size,
        "total_archive_size_mb": round(total_archive_size / (1024 * 1024), 2),
        "retention_days": DEFAULT_RETENTION_DAYS,
    }
