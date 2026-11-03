"""Pure ASGI guards: bounded request buffering, optional API key and per-IP rate limiting."""

import hmac
import math
import time
from collections import OrderedDict
from collections.abc import Callable

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import Settings


class RateLimiter:
    """Fixed windows in one worker, bounded by max_clients; no background cleanup task.

    Called synchronously on the ASGI event loop. New clients fail closed when capacity
    is full, so rotating addresses cannot evict an existing client's counter.
    """

    def __init__(
        self, limit: int, window: int, max_clients: int, clock: Callable[[], float] = time.monotonic
    ):
        self.limit = limit
        self.window = window
        self.max_clients = max_clients
        self.clock = clock
        self.clients: OrderedDict[str, tuple[float, int]] = OrderedDict()

    def check(self, client: str) -> int | None:
        """Return Retry-After seconds on rejection; None means allowed."""
        now = self.clock()
        while self.clients:
            start, _ = next(iter(self.clients.values()))
            if now - start < self.window:
                break
            self.clients.popitem(last=False)
        if client in self.clients:
            start, count = self.clients[client]
            if count >= self.limit:
                return max(1, math.ceil(start + self.window - now))
            self.clients[client] = (start, count + 1)
            return None
        if len(self.clients) >= self.max_clients:
            start, _ = next(iter(self.clients.values()))
            return max(1, math.ceil(start + self.window - now))
        self.clients[client] = (now, 1)
        return None


class SecurityMiddleware:
    """Guard /info before parsing JSON, including chunked bodies without Content-Length."""

    def __init__(self, app: ASGIApp, settings: Settings):
        self.app = app
        self.settings = settings
        self.limiter = RateLimiter(
            settings.rate_limit_requests,
            settings.rate_limit_window_seconds,
            settings.rate_limit_max_clients,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def secure_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() not in {b"x-content-type-options", b"cache-control"}
                ] + [
                    (b"x-content-type-options", b"nosniff"),
                    (b"cache-control", b"no-store"),
                ]
            await send(message)

        async def reject(status: int, message: str, details: str, headers=None) -> None:
            response = JSONResponse(
                status_code=status,
                content={"message": message, "details": details},
                headers=headers,
            )
            await response(scope, receive, secure_send)

        path = scope["path"]
        if path != "/info" and not path.startswith("/info/"):
            await self.app(scope, receive, secure_send)
            return

        client = scope.get("client")
        retry_after = self.limiter.check(client[0] if client else "unknown")
        if retry_after is not None:
            await reject(
                429,
                "Too many requests",
                "Request rate limit exceeded",
                {"Retry-After": str(retry_after)},
            )
            return

        headers = Headers(scope=scope)
        if self.settings.api_key is not None:
            supplied = headers.get("x-api-key", "").encode("utf-8")
            expected = self.settings.api_key.get_secret_value().encode("utf-8")
            if not hmac.compare_digest(supplied, expected):
                await reject(401, "Unauthorized", "A valid X-API-Key header is required")
                return

        if scope["method"] not in {"POST", "PUT"}:
            await self.app(scope, receive, secure_send)
            return
        if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            await reject(415, "Unsupported media type", "Use Content-Type: application/json")
            return
        if "content-length" in headers:
            try:
                length = int(headers["content-length"])
                if length < 0:
                    raise ValueError
            except ValueError:
                await reject(400, "Invalid request", "Invalid Content-Length")
                return
            if length > self.settings.max_body_bytes:
                await reject(413, "Request too large", "Request body exceeds the configured limit")
                return

        # Count actual bytes as well: the client may omit or misreport Content-Length.
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.settings.max_body_bytes:
                await reject(413, "Request too large", "Request body exceeds the configured limit")
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, secure_send)
