"""Isolated file-backed databases exercise the same persistence path as production."""

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

MD5 = "d41d8cd98f00b204e9800998ecf8427e"


@pytest.fixture
def settings(tmp_path):
    return Settings(
        _env_file=None, db_path=tmp_path / "threats.db", api_key=None, rate_limit_requests=10_000
    )


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


@pytest.fixture
def payload():
    return {
        "md5": MD5,
        "name": "Trojan.Win32.Generic",
        "description": "Collects browser credentials",
        "threat_type": "trojan",
        "severity": "high",
        "tags": ["windows", "banking"],
        "first_seen": "2026-01-02T12:00:00+03:00",
        "last_seen": "2026-01-03T09:00:00Z",
    }
