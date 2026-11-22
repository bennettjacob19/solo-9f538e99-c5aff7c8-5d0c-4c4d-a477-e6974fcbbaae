"""FastAPI application exposing the dual-egress routing precheck."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse

from . import routing
from .models import PrecheckRequest, PrecheckResponse

app = FastAPI(
    title="Dual-Egress Routing Precheck",
    version="1.0.0",
    description=(
        "Counts how many (source, destination) address pairs change their "
        "forwarding result between two Linux IPv4 policy-routing snapshots. "
        "Submit the parsed JSON of `ip -j -4 rule show` and "
        "`ip -j -4 route show table all` (before and after the planned change) "
        "plus a source and destination IPv4 CIDR. The local table and rules "
        "pointing to it are ignored; computation is symbolic, so `/0` CIDRs "
        "are cheap. Unsupported features (multipath, fwmark selectors, "
        "non-unicast/throw/blackhole routes, ...) are rejected with HTTP 400."
    ),
)


@app.get("/", include_in_schema=False)
def index() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/healthz", tags=["meta"])
def healthz() -> dict:
    return {"status": "ok"}


@app.post(
    "/precheck",
    response_model=PrecheckResponse,
    tags=["precheck"],
    responses={
        200: {"description": "Changed address pairs grouped by before/after result"},
        400: {"description": "Unsupported or invalid input"},
        422: {"description": "Request body does not match the schema"},
    },
)
def precheck(req: PrecheckRequest) -> dict:
    try:
        return routing.run_precheck(
            req.source_cidr,
            req.destination_cidr,
            req.before.rules,
            req.before.routes,
            req.after.rules,
            req.after.routes,
        )
    except routing.UnsupportedInput as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
