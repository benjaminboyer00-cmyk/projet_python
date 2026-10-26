"""Fixtures partagées par les tests."""

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from logstream.models import LogRecord
from logstream.parsing import build_record

BASE_TIME = datetime(2026, 10, 20, 12, 0, 0)


def make_record(ip: str = "10.0.0.5", level: str = "INFO",
                payload: Any = "message", port: int = 22,
                protocol: str = "SSH", user: str | None = "alice",
                seconds: int = 0) -> LogRecord:
    """Construit un LogRecord minimal pour les tests."""
    return build_record(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        level=level,
        source=(ip, port, protocol),
        user_id=user,
        payload=payload,
        origin_format="raw",
    )


def login(ip: str, status: str, seconds: int,
          user: str = "root") -> LogRecord:
    """Enregistrement de tentative de connexion."""
    return make_record(ip=ip, level="WARNING", user=user, seconds=seconds,
                       payload={"event": "login", "status": status})


@pytest.fixture
def sample_log_file(tmp_path: Path) -> Path:
    """Petit fichier de logs mêlant les trois formats et du bruit."""
    content = "\n".join([
        "2026-10-20T08:00:00 | INFO | 10.0.0.2:5000/TCP | bob | "
        '{"method": "GET", "path": "/", "status": 200}',
        "",
        "# commentaire",
        '{"timestamp": "2026-10-20T08:00:05", "level": "ERROR", '
        '"code": 500, "ip": "10.0.0.3", "message": "boom"}',
        "CONN 2026-10-20T08:00:10 203.0.113.66 23 TCP",
        "ligne corrompue",
        "2026-10-20T08:00:15 | DEBUGX | 10.0.0.4:80/TCP | - | niveau ko",
        "2026-10-20T08:00:20 | critical | 10.0.0.9:0/udp |  CAROL | "
        "  Disque   plein  ",
    ])
    path = tmp_path / "sample.log"
    path.write_text(content + "\n", encoding="utf-8")
    return path
