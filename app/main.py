"""FastAPI app: admin REST API, door-controller WebSocket, camera linkage and unlock approvals.

Run: uvicorn app.main:app --reload
"""
from __future__ import annotations

import logging
import os
import queue
import threading
import time as clock_time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal
from zoneinfo import ZoneInfo

from fastapi import APIRouter, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import AfterValidator, BaseModel, Field, model_validator
from sqlalchemy import func, insert, select

from . import engine as rules_engine
from . import video
from .auth import ROLE_RANK, Principal, hash_token, new_api_token, principal_from_token, require
from .auth import router as oidc_router
from .db import (AccessEvent, AccessRule, ApiToken, AuditLog, Base, Credential, Door, Membership, Org, Schedule,
                 Session, Site, UnlockRequest, User, engine, row, utcnow)

log = logging.getLogger("access")


def now() -> datetime:  # tests monkeypatch this to pin schedule evaluation
    return datetime.now(timezone.utc)


# --- policy cache -----------------------------------------------------------------------------

def load_policy(org_id: int) -> rules_engine.Policy:
    with Session() as s:
        q = lambda m: s.scalars(select(m).where(m.org_id == org_id))  # noqa: E731
        return rules_engine.Policy.build(
            [rules_engine.Door(d.id, d.site_id, d.mode, d.camera_id) for d in q(Door)],
            [rules_engine.Credential(c.id, c.badge, c.status, frozenset(c.groups or ()), c.valid_from, c.valid_until)
             for c in q(Credential)],
            [rules_engine.Schedule(x.id, x.timezone, rules_engine.parse_windows(x.windows)) for x in q(Schedule)],
            [rules_engine.Rule(r.id, r.effect, r.door_id, r.site_id, r.credential_id, r.group, r.schedule_id)
             for r in q(AccessRule)],
        )


class PolicyCache:
    """Compiled policy per org. Any admin write invalidates; a version check stops a load that raced
    an invalidation from caching stale rules (a revoked badge must never stay granted).
    ponytail: in-process only; with several API replicas, fan invalidations out via Postgres LISTEN/NOTIFY."""

    def __init__(self):
        self._policies: dict[int, rules_engine.Policy] = {}
        self._versions: dict[int, int] = {}
        self._lock = threading.Lock()

    def get(self, org_id: int) -> rules_engine.Policy:
        if (p := self._policies.get(org_id)) is not None:
            return p
        version = self._versions.get(org_id, 0)
        p = load_policy(org_id)
        with self._lock:
            if self._versions.get(org_id, 0) == version:
                self._policies[org_id] = p
        return p

    def invalidate(self, org_id: int) -> None:
        with self._lock:
            self._versions[org_id] = self._versions.get(org_id, 0) + 1
            self._policies.pop(org_id, None)


# --- batched event writer ---------------------------------------------------------------------

class EventWriter:
    """Decisions are answered from memory; rows are bulk-inserted every 50 ms off the hot path.
    Reads call flush() first, so the API always sees its own writes.
    ponytail: a crash loses at most one unflushed batch; controllers should buffer and replay unacked events."""

    def __init__(self):
        self.q: queue.SimpleQueue = queue.SimpleQueue()
        self._lock = threading.Lock()

    def put(self, model, values: dict) -> None:
        self.q.put((model, values))

    def flush(self) -> None:
        with self._lock:
            batch = []
            while True:
                try:
                    batch.append(self.q.get_nowait())
                except queue.Empty:
                    break
            if not batch:
                return
            by_model: dict = {}
            for model, values in batch:
                by_model.setdefault(model, []).append(values)
            try:
                with Session() as s:
                    for model, rows in by_model.items():
                        s.execute(insert(model), rows)
                    s.commit()
            except Exception:
                log.exception("event flush failed; re-queueing %d rows", len(batch))
                for item in batch:
                    self.q.put(item)

    def run(self, stop: threading.Event) -> None:
        while not stop.wait(0.05):
            self.flush()
        self.flush()


policies = PolicyCache()
writer = EventWriter()
counter = video.PersonCounter()
controllers: dict[int, WebSocket] = {}  # door_id -> live controller socket (this replica only)


def audit(s, p: Principal | str, action: str, target: str, **detail) -> None:
    actor = p if isinstance(p, str) else p.sub
    org_id = detail.pop("org_id", None) if isinstance(p, str) else p.org_id
    s.add(AuditLog(org_id=org_id, actor=actor, action=action, target=target, detail=jsonable_encoder(detail)))


# --- seed data --------------------------------------------------------------------------------

def seed_demo() -> None:
    """Demo org with dev identities. Well-known dev tokens are for local runs only (SEED_DEMO=0 disables)."""
    with Session() as s:
        if s.scalar(select(func.count()).select_from(Org)):
            return
        demo, other = Org(name="Demo Org"), Org(name="Second Org")
        users = [User(email=f"{n.lower()}@example.test", name=n) for n in ("Alice", "Bob", "Carol", "Dave")]
        s.add_all([demo, other, *users])
        s.flush()
        s.add_all([Membership(user_id=users[0].id, org_id=demo.id, role="admin"),
                   Membership(user_id=users[1].id, org_id=demo.id, role="operator"),
                   Membership(user_id=users[2].id, org_id=demo.id, role="viewer"),
                   Membership(user_id=users[3].id, org_id=other.id, role="admin"),
                   Membership(user_id=users[0].id, org_id=other.id, role="viewer")])
        hq = Site(org_id=demo.id, name="HQ", timezone="America/Los_Angeles")
        s.add(hq)
        s.flush()
        names = ["Lobby", "Server Room", "Loading Dock", "Roof Hatch"]
        doors = [Door(org_id=demo.id, site_id=hq.id, name=n, camera_id=f"cam-{i + 1}") for i, n in enumerate(names)]
        extra = int(os.getenv("SEED_DOORS", "0"))
        if extra:
            campus = Site(org_id=demo.id, name="Bench Campus", timezone="UTC")
            s.add(campus)
            s.flush()
            doors += [Door(org_id=demo.id, site_id=campus.id, name=f"Door {i}", camera_id=f"bench-{i}")
                      for i in range(extra)]
        s.add_all(doors)
        hours = Schedule(org_id=demo.id, name="Business hours", timezone="America/Los_Angeles",
                         windows=[{"days": [0, 1, 2, 3, 4], "start": "07:00", "end": "19:00"}])
        creds = [Credential(org_id=demo.id, holder="Ada Admin", badge="1001", groups=["staff", "it"]),
                 Credential(org_id=demo.id, holder="Grace Staff", badge="1002", groups=["staff"]),
                 Credential(org_id=demo.id, holder="Linus Contractor", badge="1003", groups=["contractor"],
                            valid_until=utcnow() - timedelta(days=1)),
                 Credential(org_id=demo.id, holder="Sam Suspended", badge="1004", groups=["staff"],
                            status="suspended")]
        s.add_all([hours, *creds])
        s.flush()
        rules = [AccessRule(org_id=demo.id, effect="allow", site_id=hq.id, group="staff", schedule_id=hours.id),
                 AccessRule(org_id=demo.id, effect="allow", door_id=doors[1].id, group="it"),
                 AccessRule(org_id=demo.id, effect="allow", door_id=doors[0].id, group="staff"),
                 AccessRule(org_id=demo.id, effect="deny", door_id=doors[3].id, group="staff")]
        if extra:
            rules.append(AccessRule(org_id=demo.id, effect="allow", site_id=campus.id, group="staff"))
        s.add_all(rules)
        for name, role, env in [("dev-controller", "controller", "SEED_CONTROLLER_TOKEN"),
                                ("dev-mcp", "operator", "SEED_MCP_TOKEN")]:
            value = os.getenv(env, f"acc_{name.replace('-', '_')}")
            s.add(ApiToken(org_id=demo.id, name=name, role=role, token_hash=hash_token(value), created_by="seed"))
        s.commit()


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(engine)
    if os.getenv("SEED_DEMO", "1") == "1":
        seed_demo()
    stop = threading.Event()
    t = threading.Thread(target=writer.run, args=(stop,), daemon=True)
    t.start()
    yield
    stop.set()
    t.join()


app = FastAPI(title="Access Control Cloud", lifespan=lifespan)
app.include_router(oidc_router)
api = APIRouter(prefix="/api")


# --- schemas ----------------------------------------------------------------------------------

def _tz(v: str) -> str:
    try:
        ZoneInfo(v)
    except Exception:
        raise ValueError(f"unknown timezone {v!r}") from None
    return v


Name = Annotated[str, Field(min_length=1, max_length=200)]
TZ = Annotated[str, AfterValidator(_tz)]


class SiteIn(BaseModel):
    name: Name
    timezone: TZ = "UTC"


class DoorIn(BaseModel):
    site_id: int
    name: Name
    camera_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9-]{1,64}$")] | None = None


class DoorPatch(BaseModel):
    mode: Literal["normal", "lockdown"]


class CredentialIn(BaseModel):
    holder: Name
    badge: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
    groups: list[Annotated[str, Field(min_length=1, max_length=64)]] = []
    valid_from: datetime | None = None
    valid_until: datetime | None = None


class CredentialPatch(BaseModel):
    status: Literal["active", "suspended", "lost", "revoked"]


class WindowIn(BaseModel):
    days: list[Annotated[int, Field(ge=0, le=6)]] = Field(min_length=1)
    start: time
    end: time


class ScheduleIn(BaseModel):
    name: Name
    timezone: TZ = "UTC"
    windows: list[WindowIn] = Field(min_length=1)


class RuleIn(BaseModel):
    effect: Literal["allow", "deny"]
    door_id: int | None = None
    site_id: int | None = None
    credential_id: int | None = None
    group: str | None = None
    schedule_id: int | None = None

    @model_validator(mode="after")
    def _one_each(self):
        if (self.door_id is None) == (self.site_id is None):
            raise ValueError("set exactly one of door_id, site_id")
        if (self.credential_id is None) == (self.group is None):
            raise ValueError("set exactly one of credential_id, group")
        return self


class UnlockIn(BaseModel):
    reason: Annotated[str, Field(min_length=3, max_length=500)]


class TokenIn(BaseModel):
    name: Name
    role: Literal["viewer", "operator", "admin", "controller"]


# --- helpers ----------------------------------------------------------------------------------

def owned(s, model, obj_id: int | None, p: Principal):
    """Fetch a row in the caller's org or 404. Also guards cross-org references in request bodies."""
    obj = s.get(model, obj_id) if obj_id is not None else None
    if obj is None or obj.org_id != p.org_id:
        raise HTTPException(404, f"{model.__tablename__} {obj_id} not found")
    return obj


def create(model, data: dict, p: Principal) -> dict:
    with Session() as s:
        obj = model(org_id=p.org_id, **data)
        s.add(obj)
        s.flush()
        audit(s, p, f"create:{model.__tablename__}", f"{model.__tablename__}:{obj.id}", **data)
        s.commit()
        out = row(obj)
    policies.invalidate(p.org_id)
    return out


def list_rows(model, p: Principal, *where) -> list[dict]:
    with Session() as s:
        return [row(o) for o in s.scalars(select(model).where(model.org_id == p.org_id, *where).order_by(model.id))]


def patch(model, obj_id: int, data: dict, p: Principal) -> dict:
    with Session() as s:
        obj = owned(s, model, obj_id, p)
        for k, v in data.items():
            setattr(obj, k, v)
        audit(s, p, f"update:{model.__tablename__}", f"{model.__tablename__}:{obj_id}", **data)
        s.commit()
        out = row(obj)
    policies.invalidate(p.org_id)
    return out


# --- routes -----------------------------------------------------------------------------------

@app.get("/healthz")
def healthz():
    return {"ok": True, "detector": counter.backend, "controllers_connected": len(controllers)}


@api.get("/me")
def me(p: Principal = require("viewer")):
    return {"sub": p.sub, "org_id": p.org_id, "role": p.role, "kind": p.kind}


@api.get("/sites")
def list_sites(p: Principal = require("viewer")):
    return list_rows(Site, p)


@api.post("/sites", status_code=201)
def create_site(body: SiteIn, p: Principal = require("admin")):
    return create(Site, body.model_dump(), p)


@api.get("/doors")
def list_doors(site_id: int | None = None, p: Principal = require("viewer")):
    rows = list_rows(Door, p, *([Door.site_id == site_id] if site_id else []))
    for r in rows:
        r["online"] = r["id"] in controllers
    return rows


@api.post("/doors", status_code=201)
def create_door(body: DoorIn, p: Principal = require("admin")):
    with Session() as s:
        owned(s, Site, body.site_id, p)
    return create(Door, body.model_dump(), p)


@api.patch("/doors/{door_id}")
def set_door_mode(door_id: int, body: DoorPatch, p: Principal = require("operator")):
    return patch(Door, door_id, body.model_dump(), p)


@api.get("/credentials")
def list_credentials(p: Principal = require("viewer")):
    return list_rows(Credential, p)


@api.post("/credentials", status_code=201)
def create_credential(body: CredentialIn, p: Principal = require("admin")):
    with Session() as s:
        if s.scalar(select(Credential.id).where(Credential.org_id == p.org_id, Credential.badge == body.badge)):
            raise HTTPException(409, "badge already enrolled")
    return create(Credential, body.model_dump(), p)


@api.patch("/credentials/{cred_id}")
def set_credential_status(cred_id: int, body: CredentialPatch, p: Principal = require("operator")):
    return patch(Credential, cred_id, body.model_dump(), p)


@api.get("/schedules")
def list_schedules(p: Principal = require("viewer")):
    return list_rows(Schedule, p)


@api.post("/schedules", status_code=201)
def create_schedule(body: ScheduleIn, p: Principal = require("admin")):
    return create(Schedule, body.model_dump(mode="json"), p)


@api.get("/rules")
def list_rules(p: Principal = require("viewer")):
    return list_rows(AccessRule, p)


@api.post("/rules", status_code=201)
def create_rule(body: RuleIn, p: Principal = require("admin")):
    with Session() as s:
        for model, ref in [(Door, body.door_id), (Site, body.site_id), (Credential, body.credential_id),
                           (Schedule, body.schedule_id)]:
            if ref is not None:
                owned(s, model, ref, p)
    return create(AccessRule, body.model_dump(), p)


@api.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: int, p: Principal = require("admin")):
    with Session() as s:
        s.delete(owned(s, AccessRule, rule_id, p))
        audit(s, p, "delete:access_rules", f"access_rules:{rule_id}")
        s.commit()
    policies.invalidate(p.org_id)


@api.get("/events")
def search_events(door_id: int | None = None, badge: str | None = None, granted: bool | None = None,
                  tailgate: bool | None = None, since: datetime | None = None, until: datetime | None = None,
                  limit: int = Query(100, ge=1, le=500), p: Principal = require("viewer")):
    writer.flush()
    q = select(AccessEvent).where(AccessEvent.org_id == p.org_id)
    for col, val in [(AccessEvent.door_id, door_id), (AccessEvent.badge, badge), (AccessEvent.granted, granted),
                     (AccessEvent.tailgate, tailgate)]:
        if val is not None:
            q = q.where(col == val)
    if since:
        q = q.where(AccessEvent.ts >= since)
    if until:
        q = q.where(AccessEvent.ts < until)
    with Session() as s:
        return [row(e) for e in s.scalars(q.order_by(AccessEvent.ts.desc()).limit(limit))]


@api.get("/events/{event_id}")
def get_event(event_id: str, p: Principal = require("viewer")):
    writer.flush()
    with Session() as s:
        return row(owned(s, AccessEvent, event_id, p))


@api.get("/clips/{clip_id}")
def get_clip(clip_id: str, p: Principal = require("viewer")):
    writer.flush()
    with Session() as s:
        ev = s.scalar(select(AccessEvent).where(AccessEvent.clip_id == clip_id, AccessEvent.org_id == p.org_id))
    if ev is None:
        raise HTTPException(404, "clip not found")
    return {**video.clip_for(clip_id, ev.people_count), "event_id": ev.id, "door_id": ev.door_id,
            "people_count": ev.people_count, "tailgate": ev.tailgate, "detector": counter.backend}


@api.get("/audit")
def list_audit(limit: int = Query(100, ge=1, le=1000), p: Principal = require("admin")):
    writer.flush()
    with Session() as s:
        q = select(AuditLog).where(AuditLog.org_id == p.org_id).order_by(AuditLog.id.desc()).limit(limit)
        return [row(a) for a in s.scalars(q)]


@api.get("/tokens")
def list_tokens(p: Principal = require("admin")):
    return [{k: v for k, v in t.items() if k != "token_hash"} for t in list_rows(ApiToken, p)]


@api.post("/tokens", status_code=201)
def create_token(body: TokenIn, p: Principal = require("admin")):
    if ROLE_RANK[body.role] > ROLE_RANK[p.role]:
        raise HTTPException(403, "cannot mint a token above your own role")
    value = new_api_token()
    with Session() as s:
        t = ApiToken(org_id=p.org_id, name=body.name, role=body.role, token_hash=hash_token(value), created_by=p.sub)
        s.add(t)
        s.flush()
        audit(s, p, "create:api_tokens", f"api_tokens:{t.id}", name=body.name, role=body.role)
        s.commit()
        return {"id": t.id, "name": t.name, "role": t.role, "token": value}  # shown once


@api.delete("/tokens/{token_id}", status_code=204)
def revoke_token(token_id: int, p: Principal = require("admin")):
    patch(ApiToken, token_id, {"revoked": True}, p)


@api.post("/doors/{door_id}/unlock-requests", status_code=201)
def request_unlock(door_id: int, body: UnlockIn, p: Principal = require("operator")):
    """Remote unlock is two-step: anyone with operator can ask, a *different* admin must approve."""
    with Session() as s:
        owned(s, Door, door_id, p)
        r = UnlockRequest(org_id=p.org_id, door_id=door_id, reason=body.reason, requested_by=p.sub)
        s.add(r)
        s.flush()
        audit(s, p, "unlock:requested", f"doors:{door_id}", request_id=r.id, reason=body.reason)
        s.commit()
        return row(r)


@api.get("/unlock-requests")
def list_unlock_requests(status: Literal["pending", "approved", "denied"] | None = None,
                         p: Principal = require("viewer")):
    return list_rows(UnlockRequest, p, *([UnlockRequest.status == status] if status else []))


@api.get("/unlock-requests/{req_id}")
def get_unlock_request(req_id: int, p: Principal = require("viewer")):
    with Session() as s:
        return row(owned(s, UnlockRequest, req_id, p))


@api.post("/unlock-requests/{req_id}/approve")
async def approve_unlock(req_id: int, p: Principal = require("admin")):
    return await decide_unlock(req_id, "approve", p)


@api.post("/unlock-requests/{req_id}/deny")
async def deny_unlock(req_id: int, p: Principal = require("admin")):
    return await decide_unlock(req_id, "deny", p)


async def decide_unlock(req_id: int, decision: str, p: Principal) -> dict:
    with Session() as s:
        r = owned(s, UnlockRequest, req_id, p)
        if r.status != "pending":
            raise HTTPException(409, f"request already {r.status}")
        if r.requested_by == p.sub:
            raise HTTPException(403, "requester cannot approve their own unlock")
        r.status, r.decided_by, r.decided_at = ("approved" if decision == "approve" else "denied"), p.sub, utcnow()
        delivered = False
        if r.status == "approved" and (ws := controllers.get(r.door_id)):
            try:
                await ws.send_json({"type": "unlock", "request_id": r.id, "duration_s": 5})
                delivered = True
            except Exception:
                log.warning("unlock delivery failed for door %s", r.door_id)
        audit(s, p, f"unlock:{r.status}", f"doors:{r.door_id}", request_id=r.id, delivered=delivered)
        s.commit()
        return {**row(r), "delivered": delivered}


app.include_router(api)


# --- door controllers -------------------------------------------------------------------------

@app.websocket("/ws/controllers/{door_id}")
async def controller_socket(ws: WebSocket, door_id: int, token: str = ""):
    """Protocol: controller sends {"type":"badge","badge":"1001","req_id":1}; server answers
    {"type":"decision","req_id":1,"granted":true,"reason":"rule_allow","event_id":"..."}.
    `sim_people` on a badge message is a simulation hook: how many people the fake camera sees."""
    scheme, _, header_token = ws.headers.get("authorization", "").partition(" ")
    try:
        p = principal_from_token(header_token if scheme.lower() == "bearer" else token)
        with Session() as s:
            door = owned(s, Door, door_id, p)
        if p.role not in ("controller", "admin"):
            raise HTTPException(403)
    except HTTPException:
        await ws.close(code=1008)
        return
    org_id, camera_id = door.org_id, door.camera_id
    await ws.accept()
    controllers[door_id] = ws
    try:
        while True:
            msg = await ws.receive_json()
            if msg.get("type") != "badge":
                continue
            badge = msg.get("badge")
            if not isinstance(badge, str) or not 0 < len(badge) <= 64:
                await ws.send_json({"type": "error", "req_id": msg.get("req_id"), "error": "invalid badge"})
                continue
            t0 = clock_time.perf_counter()
            at = now()
            d = rules_engine.decide(policies.get(org_id), door_id, badge, at)
            event_id = uuid.uuid4().hex
            await ws.send_json({"type": "decision", "req_id": msg.get("req_id"), "event_id": event_id,
                                "granted": d.granted, "reason": d.reason})
            latency_ms = (clock_time.perf_counter() - t0) * 1000

            # Off the decision path: pair with a clip and run the tailgating detector.
            clip_id, people, tailgate = None, 0, False
            if camera_id:
                clip_id = video.clip_id_for(camera_id, at, event_id)
                observed = int(msg.get("sim_people", 1))
                people = counter.max_people(video.clip_for(clip_id, observed)["frames"])
                tailgate = video.is_tailgate(d.granted, people)
            writer.put(AccessEvent, dict(id=event_id, org_id=org_id, door_id=door_id, ts=at, badge=badge,
                                         credential_id=d.credential_id, granted=d.granted, reason=d.reason,
                                         rule_id=d.rule_id, latency_ms=latency_ms, clip_id=clip_id,
                                         people_count=people, tailgate=tailgate))
            if tailgate:
                writer.put(AuditLog, dict(org_id=org_id, ts=at, actor="detector", action="tailgate:detected",
                                          target=f"doors:{door_id}",
                                          detail={"event_id": event_id, "people": people, "clip_id": clip_id}))
    except WebSocketDisconnect:
        pass
    finally:
        if controllers.get(door_id) is ws:
            del controllers[door_id]


# --- admin UI (built React app) ---------------------------------------------------------------

UI_DIST = Path(__file__).resolve().parent.parent / "ui" / "dist"
if UI_DIST.is_dir():
    @app.get("/callback", include_in_schema=False)
    def spa_callback():
        return FileResponse(UI_DIST / "index.html")

    app.mount("/", StaticFiles(directory=UI_DIST, html=True), name="ui")
