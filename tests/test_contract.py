"""Validate both the source specification and actual HTTP responses against OpenAPI 3.0."""

import yaml
from fastapi.routing import APIRoute
from openapi_schema_validator import OAS30Validator, oas30_format_checker
from openapi_spec_validator import validate

from app.main import SPEC_PATH
from tests.conftest import MD5


def test_specification_is_valid_and_routes_match(app):
    spec = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
    validate(spec)
    expected = {
        (path, method.upper(), operation["operationId"])
        for path, path_item in spec["paths"].items()
        for method, operation in path_item.items()
        if method in {"get", "post", "put"}
    }
    actual = {
        (route.path, method, route.operation_id)
        for route in app.routes
        if isinstance(route, APIRoute) and route.include_in_schema
        for method in route.methods
    }
    assert actual == expected


def test_success_and_error_responses_match_contract(client, payload):
    spec = client.get("/openapi.json").json()
    responses = [
        (client.post("/info", json=payload), 201, "ThreatResponse"),
        (client.get(f"/info/{MD5}"), 200, "ThreatResponse"),
        (client.put(f"/info/{MD5}", json={"name": "New"}), 200, "ThreatResponse"),
        (client.post("/info", json=payload), 409, "ErrorResponse"),
        (client.get("/info/invalid"), 400, "ErrorResponse"),
        (client.get(f"/info/{'0' * 32}"), 404, "ErrorResponse"),
        (client.get("/health"), 200, "HealthResponse"),
    ]
    for response, status, schema_name in responses:
        assert response.status_code == status
        OAS30Validator(
            spec["components"]["schemas"][schema_name], format_checker=oas30_format_checker
        ).validate(response.json())


def test_published_yaml_and_json_match(client):
    assert yaml.safe_load(client.get("/openapi.yaml").text) == client.get("/openapi.json").json()
    assert client.get("/docs").status_code == 200
    assert client.get("/redoc").status_code == 200
