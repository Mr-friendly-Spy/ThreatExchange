"""SQLite persistence with a versioned migration and short, per-operation transactions."""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from app.errors import ThreatAlreadyExists, ThreatNotFound
from app.generated.models import ThreatResponse

MIGRATIONS = Path(__file__).with_name("migrations")
MUTABLE_COLUMNS = (
    "name",
    "description",
    "threat_type",
    "severity",
    "tags",
    "first_seen",
    "last_seen",
)


class Database:
    """A connection factory; no connection is shared between request threads."""

    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        """Apply schema v1 atomically. Refuse databases from a newer application version."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("BEGIN IMMEDIATE")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > 1:
                raise RuntimeError(f"Unsupported database schema version: {version}")
            if version == 0:
                connection.execute((MIGRATIONS / "001_initial.sql").read_text(encoding="utf-8"))
                connection.execute("PRAGMA user_version=1")

    def check_ready(self) -> None:
        """Check both connectivity and the actual application table."""
        with self.connection() as connection:
            connection.execute("SELECT md5 FROM threats LIMIT 1").fetchone()


class ThreatRepository:
    """Transactional CRUD. The primary key arbitrates concurrent creates, without a pre-check."""

    def __init__(self, database: Database):
        self.database = database

    @staticmethod
    def _response(row: sqlite3.Row) -> ThreatResponse:
        data = dict(row)
        data["tags"] = json.loads(data["tags"])
        return ThreatResponse.model_validate(data)

    @staticmethod
    def _values(data: dict) -> list:
        return [json.dumps(data[key]) if key == "tags" else data[key] for key in MUTABLE_COLUMNS]

    def get(self, md5: str) -> ThreatResponse:
        with self.database.connection() as connection:
            row = connection.execute("SELECT * FROM threats WHERE md5 = ?", (md5,)).fetchone()
            if row is None:
                raise ThreatNotFound
            return self._response(row)

    def create(self, data: dict) -> ThreatResponse:
        now = datetime.now(UTC).isoformat()
        try:
            with self.database.connection() as connection:
                row = connection.execute(
                    """INSERT INTO threats
                       (md5, name, description, threat_type, severity, tags,
                        first_seen, last_seen, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *""",
                    [data["md5"], *self._values(data), now, now],
                ).fetchone()
                return self._response(row)
        except sqlite3.IntegrityError as error:
            if error.sqlite_errorname in {
                "SQLITE_CONSTRAINT_PRIMARYKEY",
                "SQLITE_CONSTRAINT_UNIQUE",
            }:
                raise ThreatAlreadyExists from error
            raise

    def replace(self, md5: str, data: dict) -> ThreatResponse:
        with self.database.connection() as connection:
            row = connection.execute(
                """UPDATE threats SET name = ?, description = ?, threat_type = ?, severity = ?,
                   tags = ?, first_seen = ?, last_seen = ?, updated_at = ?
                   WHERE md5 = ? RETURNING *""",
                [*self._values(data), datetime.now(UTC).isoformat(), md5],
            ).fetchone()
            if row is None:
                raise ThreatNotFound
            return self._response(row)
