"""Test admission control independently and at the HTTP boundary."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.main import create_app
from app.security import RateLimiter
from tests.conftest import MD5

KEY = "test-only-" + "a" * 32


def test_rate_limiter_window_and_independent_clients():
    now = [0.0]
    limiter = RateLimiter(2, 10, 2, clock=lambda: now[0])
    assert limiter.check("one") is None
    assert limiter.check("one") is None
    assert limiter.check("one") == 10
    assert limiter.check("two") is None
    assert limiter.check("three") == 10  # Capacity exhaustion never evicts a counter.
    now[0] = 9.5
    assert limiter.check("one") == 1
    now[0] = 10.0
    assert limiter.check("three") is None
    assert limiter.check("one") is None
    assert len(limiter.clients) == 2


def test_api_key_guards_all_operations(settings, payload):
    settings.api_key = Settings(_env_file=None, api_key=KEY).api_key
    with TestClient(create_app(settings)) as client:
        for method, url, body in [
            ("GET", f"/info/{MD5}", None),
            ("POST", "/info", payload),
            ("PUT", f"/info/{MD5}", {"name": "Updated"}),
        ]:
            for headers in ({}, {"X-API-Key": "incorrect"}):
                assert client.request(method, url, json=body, headers=headers).status_code == 401
        headers = {"X-API-Key": KEY}
        assert client.post("/info", json=payload, headers=headers).status_code == 201
        assert client.get(f"/info/{MD5}", headers=headers).status_code == 200
        assert client.put(f"/info/{MD5}", json={"name": "New"}, headers=headers).status_code == 200
        assert client.get("/health").status_code == 200
        assert client.get("/openapi.json").json()["security"] == [{"ApiKey": []}]


def test_rate_limit_counts_failed_auth_and_ignores_forwarded_headers(settings):
    settings.rate_limit_requests = 2
    settings.api_key = Settings(_env_file=None, api_key=KEY).api_key
    with TestClient(create_app(settings)) as client:
        assert client.get(f"/info/{MD5}").status_code == 401
        assert client.get(f"/info/{MD5}").status_code == 401
        response = client.get(f"/info/{MD5}", headers={"X-Forwarded-For": "1.2.3.4"})
        assert response.status_code == 429
        assert 1 <= int(response.headers["retry-after"]) <= 60
        assert client.get("/health").status_code == 200


@pytest.mark.parametrize("content_type", ["text/plain", "application/xml", ""])
def test_unsupported_media_type(client, content_type):
    assert (
        client.post("/info", content="{}", headers={"Content-Type": content_type}).status_code
        == 415
    )


def test_body_size_with_and_without_content_length(settings):
    settings.max_body_bytes = 128
    with TestClient(create_app(settings)) as client:
        for content in (b"x" * 129, iter([b"x" * 100, b"x" * 100])):
            response = client.post(
                "/info", content=content, headers={"Content-Type": "application/json"}
            )
            assert response.status_code == 413
        assert (
            client.post(
                "/info",
                content=b"x" * 129,
                headers={"Content-Type": "application/json", "Content-Length": "1"},
            ).status_code
            == 413
        )


@pytest.mark.parametrize("length", ["-1", "invalid"])
def test_invalid_content_length(client, length):
    response = client.post(
        "/info",
        content="{}",
        headers={"Content-Type": "application/json", "Content-Length": length},
    )
    assert response.status_code == 400


def test_security_headers(client):
    response = client.get(f"/info/{MD5}")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "no-store" in response.headers["cache-control"]


@pytest.mark.parametrize("value", ["short", "a" * 31, " " * 32, "я" * 32])
def test_weak_api_key_configuration_rejected(value):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, api_key=value)


@pytest.mark.parametrize(
    "key",
    [
        "rate_limit_requests",
        "rate_limit_window_seconds",
        "rate_limit_max_clients",
        "max_body_bytes",
    ],
)
def test_invalid_limit_configuration_rejected(key):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{key: 0})
