"""Application factory and HTTP adapters for the contract-first threat service."""

import logging
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

import yaml
from fastapi import FastAPI, Request, Response
from fastapi import Path as PathParameter
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException

from app.config import Settings
from app.database import Database, ThreatRepository
from app.errors import ThreatAlreadyExists, ThreatNotFound
from app.generated.models import HealthResponse, ThreatResponse
from app.models import ThreatCreateRequest, ThreatUpdateRequest
from app.security import SecurityMiddleware

logger = logging.getLogger(__name__)
SPEC_PATH = Path(__file__).with_name("openapi.yaml")
Md5 = Annotated[str, PathParameter(pattern=r"^[a-fA-F0-9]{32}$", min_length=32, max_length=32)]


def error_response(status: int, message: str, details: str, headers=None) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"message": message, "details": details},
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            **(headers or {}),
        },
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    """Construct an isolated app; open/migrate its persistent database during lifespan."""
    settings = settings if settings is not None else Settings()
    database = Database(settings.db_path)
    repository = ThreatRepository(database)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        database.initialize()
        logging.getLogger("uvicorn.error").info(
            "Swagger UI: %s/docs", str(settings.public_url).rstrip("/")
        )
        yield

    app = FastAPI(title="Information Exchange Service", version="1.0.0", lifespan=lifespan)
    app.state.database = database
    app.state.repository = repository
    app.add_middleware(SecurityMiddleware, settings=settings)

    contract = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
    contract["security"] = [{"ApiKey": []}] if settings.api_key is not None else []
    app.openapi = lambda: contract

    @app.get("/", include_in_schema=False)
    def open_docs() -> RedirectResponse:
        """Open Swagger when the user follows Uvicorn's base URL."""
        return RedirectResponse(url="/docs")

    @app.get("/openapi.yaml", include_in_schema=False)
    def openapi_yaml() -> Response:
        return Response(yaml.safe_dump(contract, allow_unicode=True), media_type="application/yaml")

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, error: RequestValidationError):
        # Do not serialize exc.errors() wholesale: it includes the submitted input.
        details = "; ".join(
            f"{'.'.join(str(part) for part in item['loc']) or 'body'}: {item['msg']}"
            for item in error.errors()[:10]
        )
        return error_response(400, "Invalid request", details[:1500])

    @app.exception_handler(ThreatNotFound)
    async def not_found(request: Request, error: ThreatNotFound):
        return error_response(404, "Threat not found", "No threat with the supplied MD5 found")

    @app.exception_handler(ThreatAlreadyExists)
    async def conflict(request: Request, error: ThreatAlreadyExists):
        return error_response(409, "Threat already exists", "A threat with this MD5 already exists")

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, error: HTTPException):
        return error_response(error.status_code, "Request failed", str(error.detail), error.headers)

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, error: Exception):
        logger.exception("Unhandled request error", exc_info=error)
        return error_response(500, "Internal server error", "The request could not be completed")

    @app.get("/health", response_model=HealthResponse, operation_id="health")
    def health():
        try:
            database.check_ready()
        except sqlite3.Error:
            logger.exception("Database readiness check failed")
            return error_response(503, "Service unavailable", "Database is unavailable")
        return {"status": "ok"}

    @app.get("/info/{md5}", response_model=ThreatResponse, operation_id="getInfoByMd5")
    def get_info(md5: Md5) -> ThreatResponse:
        return repository.get(md5.lower())

    @app.post("/info", response_model=ThreatResponse, status_code=201, operation_id="createThreat")
    def create_threat(payload: ThreatCreateRequest, response: Response) -> ThreatResponse:
        result = repository.create(payload.model_dump(mode="json"))
        response.headers["Location"] = f"/info/{result.md5}"
        return result

    @app.put("/info/{md5}", response_model=ThreatResponse, operation_id="updateThreat")
    def update_threat(md5: Md5, payload: ThreatUpdateRequest) -> ThreatResponse:
        return repository.replace(md5.lower(), payload.model_dump(mode="json"))

    return app
