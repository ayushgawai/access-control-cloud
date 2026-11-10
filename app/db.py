"""SQLAlchemy models. PostgreSQL in Docker Compose, SQLite for tests and quick local runs."""
from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./access.db")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def make_engine(url: str = DATABASE_URL):
    if url.startswith("sqlite"):
        return create_engine(url, connect_args={"check_same_thread": False})
    return create_engine(url, pool_size=10, max_overflow=20, pool_pre_ping=True)


engine = make_engine()
Session = sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    type_annotation_map = {datetime: DateTime(timezone=True)}


class Org(Base):
    __tablename__ = "orgs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(unique=True)
    name: Mapped[str]


class Membership(Base):
    __tablename__ = "memberships"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), primary_key=True)
    role: Mapped[str]  # viewer | operator | admin


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    name: Mapped[str]
    role: Mapped[str]  # viewer | operator | admin | controller
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_by: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class Site(Base):
    __tablename__ = "sites"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    name: Mapped[str]
    timezone: Mapped[str] = mapped_column(default="UTC")


class Door(Base):
    __tablename__ = "doors"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id"), index=True)
    name: Mapped[str]
    camera_id: Mapped[str | None]
    mode: Mapped[str] = mapped_column(default="normal")  # normal | lockdown


class Credential(Base):
    __tablename__ = "credentials"
    __table_args__ = (UniqueConstraint("org_id", "badge"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    holder: Mapped[str]
    badge: Mapped[str]
    status: Mapped[str] = mapped_column(default="active")
    groups: Mapped[list] = mapped_column(JSON, default=list)
    valid_from: Mapped[datetime | None]
    valid_until: Mapped[datetime | None]


class Schedule(Base):
    __tablename__ = "schedules"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    name: Mapped[str]
    timezone: Mapped[str] = mapped_column(default="UTC")
    windows: Mapped[list] = mapped_column(JSON)  # [{"days": [0..6], "start": "08:00", "end": "18:00"}]


class AccessRule(Base):
    __tablename__ = "access_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    effect: Mapped[str]  # allow | deny
    door_id: Mapped[int | None] = mapped_column(ForeignKey("doors.id"))
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id"))
    credential_id: Mapped[int | None] = mapped_column(ForeignKey("credentials.id"))
    group: Mapped[str | None]
    schedule_id: Mapped[int | None] = mapped_column(ForeignKey("schedules.id"))


class AccessEvent(Base):
    """Every badge decision. This table is the access audit trail; `audit_log` covers admin actions."""

    __tablename__ = "access_events"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    org_id: Mapped[int] = mapped_column(Integer, index=True)
    door_id: Mapped[int] = mapped_column(Integer, index=True)
    ts: Mapped[datetime] = mapped_column(index=True)
    badge: Mapped[str]
    credential_id: Mapped[int | None]
    granted: Mapped[bool]
    reason: Mapped[str]
    rule_id: Mapped[int | None]
    latency_ms: Mapped[float] = mapped_column(Float)
    clip_id: Mapped[str | None] = mapped_column(index=True)
    people_count: Mapped[int] = mapped_column(default=0)
    tailgate: Mapped[bool] = mapped_column(default=False)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(Integer, index=True)
    ts: Mapped[datetime] = mapped_column(default=utcnow)
    actor: Mapped[str]
    action: Mapped[str]
    target: Mapped[str]
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class UnlockRequest(Base):
    __tablename__ = "unlock_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    door_id: Mapped[int] = mapped_column(ForeignKey("doors.id"))
    reason: Mapped[str]
    requested_by: Mapped[str]
    status: Mapped[str] = mapped_column(default="pending")  # pending | approved | denied
    decided_by: Mapped[str | None]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    decided_at: Mapped[datetime | None]


def row(obj) -> dict:
    return {c.key: getattr(obj, c.key) for c in obj.__table__.columns}
