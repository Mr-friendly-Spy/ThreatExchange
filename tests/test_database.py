"""Database invariants and migration safety that HTTP-only tests cannot exercise."""

import sqlite3

import pytest

from app.database import Database, ThreatRepository
from app.models import ThreatCreateRequest


def test_newer_schema_is_not_overwritten(tmp_path):
    database = Database(tmp_path / "future.db")
    with database.connection() as connection:
        connection.execute("PRAGMA user_version=2")
    with pytest.raises(RuntimeError, match="Unsupported database schema version"):
        database.initialize()
    with database.connection() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2


def test_constraint_failure_is_not_reported_as_duplicate(tmp_path):
    database = Database(tmp_path / "threats.db")
    database.initialize()
    repository = ThreatRepository(database)
    data = ThreatCreateRequest(md5="a" * 32, name="Valid").model_dump(mode="json")
    data["name"] = ""
    with pytest.raises(sqlite3.IntegrityError):
        repository.create(data)
    with database.connection() as connection:
        assert connection.execute("SELECT count(*) FROM threats").fetchone()[0] == 0
