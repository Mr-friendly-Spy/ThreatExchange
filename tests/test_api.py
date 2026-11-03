"""HTTP integration tests against a real temporary SQLite database."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import MD5


def test_create_read_replace(client, payload):
    response = client.post("/info", json={**payload, "md5": MD5.upper()})
    assert response.status_code == 201
    assert response.headers["location"] == f"/info/{MD5}"
    created = response.json()
    assert created["md5"] == MD5
    assert created["first_seen"] == "2026-01-02T09:00:00Z"
    assert created["created_at"] == created["updated_at"]
    assert client.get(f"/info/{MD5.upper()}").json() == created

    response = client.put(f"/info/{MD5.upper()}", json={"name": " Updated threat "})
    assert response.status_code == 200
    updated = response.json()
    assert updated["name"] == "Updated threat"
    assert updated["created_at"] == created["created_at"]
    assert datetime.fromisoformat(updated["updated_at"]) >= datetime.fromisoformat(
        created["updated_at"]
    )
    assert {
        key: updated[key]
        for key in ("description", "severity", "threat_type", "tags", "first_seen", "last_seen")
    } == {
        "description": "",
        "severity": "unknown",
        "threat_type": "unknown",
        "tags": [],
        "first_seen": None,
        "last_seen": None,
    }
    assert client.get(f"/info/{MD5}").json() == updated


def test_duplicate_is_case_insensitive_and_does_not_overwrite(client, payload):
    first = client.post("/info", json=payload).json()
    response = client.post("/info", json={**payload, "md5": MD5.upper(), "name": "Other"})
    assert response.status_code == 409
    assert set(response.json()) == {"message", "details"}
    assert client.get(f"/info/{MD5}").json() == first


@pytest.mark.parametrize("method", ["get", "put"])
def test_missing_threat(client, method):
    kwargs = {"json": {"name": "Missing"}} if method == "put" else {}
    response = getattr(client, method)(f"/info/{MD5}", **kwargs)
    assert response.status_code == 404
    assert response.json()["message"] == "Threat not found"


@pytest.mark.parametrize("md5", ["bad", "g" * 32, "0" * 31, "0" * 33, "0" * 31 + " "])
@pytest.mark.parametrize("method", ["get", "put"])
def test_invalid_path_md5_returns_400(client, method, md5):
    kwargs = {"json": {"name": "Invalid"}} if method == "put" else {}
    assert getattr(client, method)(f"/info/{md5}", **kwargs).status_code == 400


@pytest.mark.parametrize(
    "patch",
    [
        {"md5": "bad"},
        {"md5": 123},
        {"name": ""},
        {"name": "   \t\n"},
        {"name": "a" * 201},
        {"name": 123},
        {"name": None},
        {"description": None},
        {"description": "a" * 4001},
        {"severity": "extreme"},
        {"severity": None},
        {"threat_type": "invalid"},
        {"threat_type": None},
        {"tags": None},
        {"tags": "windows"},
        {"tags": ["windows", "windows"]},
        {"tags": ["Windows"]},
        {"tags": ["a\n"]},
        {"tags": [""]},
        {"tags": ["a" * 51]},
        {"tags": [123]},
        {"tags": [f"tag-{number}" for number in range(21)]},
        {"first_seen": "2026-01-02"},
        {"first_seen": "2026-01-02T00:00:00"},
        {"first_seen": 1234567890},
        {"first_seen": "1234567890"},
        {"first_seen": "2026-02-30T00:00:00Z"},
        {"first_seen": None, "last_seen": "2026-01-03T00:00:00Z"},
        {"last_seen": "2026-01-01T00:00:00Z"},
        {"created_at": "2026-01-01T00:00:00Z"},
        {"unexpected": True},
    ],
)
def test_invalid_create_does_not_persist(client, payload, patch):
    response = client.post("/info", json={**payload, **patch})
    assert response.status_code == 400, response.text
    assert set(response.json()) == {"message", "details"}
    assert client.get(f"/info/{MD5}").status_code == 404


@pytest.mark.parametrize("body", [{}, {"md5": MD5}, {"name": "Threat"}, [], None])
def test_missing_fields_or_wrong_body(client, body):
    response = client.post(
        "/info",
        content=__import__("json").dumps(body),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400


def test_invalid_update_is_atomic(client, payload):
    previous = client.post("/info", json=payload).json()
    for body in (
        {"name": "Replacement", "md5": "0" * 32},
        {"severity": "low"},
        {"name": "Replacement", "tags": ["same", "same"]},
    ):
        assert client.put(f"/info/{MD5}", json=body).status_code == 400
        assert client.get(f"/info/{MD5}").json() == previous


@pytest.mark.parametrize("body", [b"{", b"", b'{"name":"\xff"}', b'{"name":NaN}'])
def test_malformed_json(client, body):
    response = client.post("/info", content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert set(response.json()) == {"message", "details"}


def test_data_survives_application_restart(settings, payload):
    with TestClient(create_app(settings)) as first:
        expected = first.post("/info", json=payload).json()
    with TestClient(create_app(settings)) as second:
        assert second.get(f"/info/{MD5}").json() == expected


def test_concurrent_duplicate_create_is_atomic(client, payload):
    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(lambda _: client.post("/info", json=payload), range(8)))
    assert sorted(response.status_code for response in responses) == [201] + [409] * 7
    assert client.get(f"/info/{MD5}").status_code == 200


def test_sql_text_is_data(client):
    name = "Robert'); DROP TABLE threats; --"
    assert client.post("/info", json={"md5": MD5, "name": name}).status_code == 201
    assert client.get(f"/info/{MD5}").json()["name"] == name
    assert client.get("/health").json() == {"status": "ok"}


def test_internal_errors_hide_details(client, app, monkeypatch):
    def fail(md5):
        raise RuntimeError("internal-secret-password")

    monkeypatch.setattr(app.state.repository, "get", fail)
    response = client.get(f"/info/{MD5}")
    assert response.status_code == 500
    assert "internal-secret-password" not in response.text
    assert set(response.json()) == {"message", "details"}


def test_unavailable_database_readiness(client, app):
    with app.state.database.connection() as connection:
        connection.execute("DROP TABLE threats")
    response = client.get("/health")
    assert response.status_code == 503
    assert set(response.json()) == {"message", "details"}


def test_http_errors_have_consistent_format(client):
    for method, path, status in [("get", "/absent", 404), ("delete", f"/info/{MD5}", 405)]:
        response = client.request(method, path)
        assert response.status_code == status
        assert set(response.json()) == {"message", "details"}
