"""Request guard: defences for an API that usually listens on localhost (THREAT_MODEL.md).

A service on 127.0.0.1 is reachable from every web page the user opens, through
the user's own browser. Three checks run before any route:

* **Host allowlist (DNS rebinding).** A malicious site can re-resolve its own
  domain to 127.0.0.1; the browser then treats the API as same-origin with the
  attacker's page. Such requests carry the attacker's name in ``Host``, so only
  loopback names and explicitly allowed hosts are accepted.
* **Cross-origin writes (CSRF).** Browsers send some cross-site requests
  without a CORS preflight ("simple requests", e.g. ``Content-Type:
  text/plain``). A state-changing request whose ``Origin`` is not this server
  is refused. Requests without ``Origin`` (curl, scripts) are unaffected.
* **Body size.** Everything except the capture upload (which streams with its
  own cap) is limited to ``MAX_BODY`` bytes, counted while reading, so a
  chunked request cannot bypass a ``Content-Length`` check.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from typing import Any
from urllib.parse import urlsplit

from starlette.exceptions import HTTPException

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
App = Callable[[Scope, Receive, Send], Awaitable[None]]

MAX_BODY = 1024 * 1024
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]", "::1"})
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _host_only(value: str) -> str:
    """'Example.org:8000' -> 'example.org'; '[::1]:8000' -> '[::1]'."""
    value = value.strip().lower()
    if value.startswith("["):
        return value[: value.find("]") + 1]
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


class RequestGuard:
    def __init__(self, app: App, allowed_hosts: Iterable[str], streamed_paths: Iterable[str] = ()) -> None:
        self.app = app
        self.allowed = LOOPBACK_HOSTS | {_host_only(h) for h in allowed_hosts if h}
        self.streamed = tuple(streamed_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        host = _host_only(headers.get("host", ""))
        if host not in self.allowed:
            await _reject(send, 421, "unknown host name (allow it with --allowed-host if this is intended)")
            return
        method = scope["method"]
        origin = headers.get("origin")
        if method in UNSAFE_METHODS and origin is not None and _host_only(urlsplit(origin).netloc) != host:
            await _reject(send, 403, "cross-origin request refused")
            return
        path = scope.get("path", "")
        if any(path == p or path.startswith(p + "?") for p in self.streamed) or method not in UNSAFE_METHODS:
            await self.app(scope, receive, send)
            return
        declared = headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > MAX_BODY:
            await _reject(send, 413, f"request body larger than {MAX_BODY} bytes")
            return
        seen = 0

        async def limited() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > MAX_BODY:
                    # Raised inside the app's body read, so the framework turns it into a 413.
                    raise HTTPException(status_code=413, detail=f"request body larger than {MAX_BODY} bytes")
            return message

        await self.app(scope, limited, send)


async def _reject(send: Send, status: int, detail: str) -> None:
    body = ('{"detail": "' + detail.replace('"', "'") + '"}').encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": body})
