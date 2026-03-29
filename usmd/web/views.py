"""Django views for the USMD-RDSH web dashboard.

Authentication uses simple username/password stored in Django settings
(sourced from NodeConfig.web.username / web.password).  No database is
required: session state is stored in a signed cookie.

Remote node data is fetched via the NCP REQUEST_SNAPSHOT command (ID 9),
querying each address found in the local NIT.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from functools import wraps
from typing import AsyncGenerator

from django.conf import settings
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseRedirect,
    JsonResponse,
    StreamingHttpResponse,
)
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from .node_snapshots import collect_all_nodes, extract_promotions, resolve_node_snapshot
from .state import get_state

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------

_LOGIN_URL = "/login/"
_DASHBOARD_URL = "/dashboard/"


def _is_authenticated(request: HttpRequest) -> bool:
    return request.session.get("authenticated", False) is True


def login_required(view_fn):
    """Decorator: redirect to login if the session has no 'authenticated' flag."""

    @wraps(view_fn)
    async def wrapper(request: HttpRequest, *args, **kwargs):
        if not _is_authenticated(request):
            return HttpResponseRedirect(_LOGIN_URL)
        return await view_fn(request, *args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------


def index(request: HttpRequest) -> HttpResponse:
    """Redirect / → dashboard (or login if not authenticated)."""
    if _is_authenticated(request):
        return HttpResponseRedirect(_DASHBOARD_URL)
    return HttpResponseRedirect(_LOGIN_URL)


@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    """Login page — GET: show form, POST: validate credentials."""
    if _is_authenticated(request):
        return HttpResponseRedirect(_DASHBOARD_URL)

    error = ""
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        if (
            username == settings.USMD_WEB_USERNAME
            and password == settings.USMD_WEB_PASSWORD
        ):
            request.session["authenticated"] = True
            request.session.set_expiry(0)  # expire on browser close
            return HttpResponseRedirect(_DASHBOARD_URL)
        error = "Incorrect username or password."

    return render(request, "login.html", {"error": error})


def logout_view(request: HttpRequest) -> HttpResponse:
    """Clear the session and redirect to login."""
    request.session.flush()
    return HttpResponseRedirect(_LOGIN_URL)


@login_required
async def dashboard(request: HttpRequest) -> HttpResponse:
    """Main dashboard — all nodes with resource bars."""
    nodes = await collect_all_nodes()
    promotions = extract_promotions(nodes)
    return render(
        request,
        "dashboard.html",
        {
            "nodes": nodes,
            "promotions": promotions,
            "now": time.time(),
        },
    )


@login_required
async def node_detail(request: HttpRequest, address: str) -> HttpResponse:
    """Detail page for a single node: NIT, NAL, NEL, resources."""
    snap, err = await resolve_node_snapshot(address)
    if err:
        return render(
            request,
            "node_detail.html",
            {"error": err, "address": address},
        )

    return render(
        request,
        "node_detail.html",
        {"node_data": snap, "address": address, "error": None},
    )


@login_required
async def api_node_snapshot(_request: HttpRequest, address: str) -> JsonResponse:
    """JSON snapshot for a single node — used by the node detail page (polling).

    Avoids ``/api/nodes/`` + ``find()`` so same address or differing JSON types
    cannot mix two nodes or corrupt the NRT "reference" column.
    """
    snap, err = await resolve_node_snapshot(address)
    if err or snap is None:
        return JsonResponse({"error": err or "unknown"}, status=503)
    return JsonResponse({"node": snap, "ts": time.time()})


@login_required
async def api_nodes(_request: HttpRequest) -> JsonResponse:
    """JSON endpoint — list of all nodes with their latest snapshot."""
    nodes = await collect_all_nodes()
    return JsonResponse(
        {
            "nodes": nodes,
            "promotions": extract_promotions(nodes),
            "ts": time.time(),
        }
    )


@login_required
async def api_stream(_request: HttpRequest) -> StreamingHttpResponse:
    """Server-Sent Events endpoint — pushes node data every 5 seconds."""

    async def event_generator() -> AsyncGenerator[bytes, None]:
        while True:
            try:
                nodes = await collect_all_nodes()
                payload = json.dumps(
                    {
                        "nodes": nodes,
                        "promotions": extract_promotions(nodes),
                        "ts": time.time(),
                    }
                )
                yield f"data: {payload}\n\n".encode()
            except Exception as exc:
                logger.warning("SSE generator error: %s", exc)
                yield f"data: {json.dumps({'error': str(exc)})}\n\n".encode()
            await asyncio.sleep(5)

    response = StreamingHttpResponse(
        event_generator(),
        content_type="text/event-stream",
    )
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return response


@login_required
async def mutation_publish(request: HttpRequest) -> HttpResponse:
    """Publish a mutation definition (YAML) — USD operator."""
    state = get_state()
    error: str | None = None
    success: str | None = None
    services: list = []
    usd_version = 0
    min_services = 0
    max_services: int | None = None

    if state is None:
        error = "Daemon state unavailable."
    else:
        usd = state.usd
        services = usd.mutation_catalog.all_services()
        usd_version = usd.config.version
        min_services = usd.config.min_services
        max_services = usd.config.max_services

        if request.method == "POST":
            fn = state.mutation_apply_fn
            if fn is None:
                error = "Mutation submit unavailable (handler not wired)."
            else:
                svc_name = (request.POST.get("service_name") or "").strip()
                yaml_t = request.POST.get("yaml") or ""
                apply_locally = request.POST.get("apply_locally") == "on"
                ok, msg = await fn(svc_name, yaml_t, apply_locally)
                if ok:
                    success = msg
                else:
                    error = msg
                services = usd.mutation_catalog.all_services()
                usd_version = usd.config.version

    return render(
        request,
        "mutation.html",
        {
            "error": error,
            "success": success,
            "services": services,
            "usd_version": usd_version,
            "min_services": min_services,
            "max_services": max_services,
        },
    )
