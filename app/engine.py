"""Access decision engine.

Pure stdlib on purpose: the hot path (badge -> grant/deny) never touches the
database. The API compiles each org's rows into a `Policy` once and evaluates
badges against it in memory, so the engine can be tested and benchmarked alone.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from functools import lru_cache
from zoneinfo import ZoneInfo


@dataclass(frozen=True)
class Window:
    days: frozenset[int]  # 0 = Monday
    start: time
    end: time  # end <= start means the window runs past midnight


def parse_windows(raw: list[dict]) -> tuple[Window, ...]:
    return tuple(
        Window(frozenset(w["days"]), time.fromisoformat(w["start"]), time.fromisoformat(w["end"]))
        for w in raw
    )


@lru_cache(maxsize=None)
def _zone(name: str) -> ZoneInfo:
    return ZoneInfo(name)


@dataclass(frozen=True)
class Schedule:
    id: int
    tz: str
    windows: tuple[Window, ...]

    def active(self, at: datetime) -> bool:
        local = at.astimezone(_zone(self.tz))
        t, day = local.time(), local.weekday()
        for w in self.windows:
            if w.start < w.end:
                if day in w.days and w.start <= t < w.end:
                    return True
            elif (day in w.days and t >= w.start) or ((day - 1) % 7 in w.days and t < w.end):
                return True
        return False


@dataclass(frozen=True)
class Credential:
    id: int
    badge: str
    status: str = "active"  # active | suspended | lost | revoked
    groups: frozenset[str] = frozenset()
    valid_from: datetime | None = None
    valid_until: datetime | None = None


@dataclass(frozen=True)
class Door:
    id: int
    site_id: int
    mode: str = "normal"  # normal | lockdown
    camera_id: str | None = None


@dataclass(frozen=True)
class Rule:
    id: int
    effect: str  # allow | deny
    door_id: int | None = None
    site_id: int | None = None
    credential_id: int | None = None
    group: str | None = None
    schedule_id: int | None = None  # None = always

    def targets(self, cred: Credential) -> bool:
        return self.credential_id == cred.id if self.credential_id is not None else self.group in cred.groups


@dataclass(frozen=True)
class Decision:
    granted: bool
    reason: str
    credential_id: int | None = None
    rule_id: int | None = None


@dataclass
class Policy:
    doors: dict[int, Door] = field(default_factory=dict)
    credentials: dict[str, Credential] = field(default_factory=dict)  # by badge
    schedules: dict[int, Schedule] = field(default_factory=dict)
    rules_by_door: dict[int, list[Rule]] = field(default_factory=dict)
    rules_by_site: dict[int, list[Rule]] = field(default_factory=dict)

    @classmethod
    def build(cls, doors, credentials, schedules, rules) -> "Policy":
        p = cls(
            doors={d.id: d for d in doors},
            credentials={c.badge: c for c in credentials},
            schedules={s.id: s for s in schedules},
        )
        for r in rules:
            index = p.rules_by_door if r.door_id is not None else p.rules_by_site
            index.setdefault(r.door_id if r.door_id is not None else r.site_id, []).append(r)
        return p


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def decide(policy: Policy, door_id: int, badge: str, at: datetime) -> Decision:
    """Default deny. Deny rules beat allow rules; schedules gate both."""
    door = policy.doors.get(door_id)
    if door is None:
        return Decision(False, "unknown_door")
    cred = policy.credentials.get(badge)
    if cred is None:
        return Decision(False, "unknown_credential")
    if door.mode == "lockdown":
        return Decision(False, "door_lockdown", cred.id)
    if cred.status != "active":
        return Decision(False, f"credential_{cred.status}", cred.id)
    if cred.valid_from and at < _aware(cred.valid_from):
        return Decision(False, "credential_not_yet_valid", cred.id)
    if cred.valid_until and at >= _aware(cred.valid_until):
        return Decision(False, "credential_expired", cred.id)

    allow: Rule | None = None
    outside_schedule = False
    for rule in policy.rules_by_door.get(door.id, []) + policy.rules_by_site.get(door.site_id, []):
        if not rule.targets(cred):
            continue
        sched = policy.schedules.get(rule.schedule_id) if rule.schedule_id is not None else None
        if rule.schedule_id is not None and (sched is None or not sched.active(at)):
            outside_schedule |= rule.effect == "allow"
            continue
        if rule.effect == "deny":
            return Decision(False, "rule_deny", cred.id, rule.id)
        allow = allow or rule
    if allow:
        return Decision(True, "rule_allow", cred.id, allow.id)
    return Decision(False, "outside_schedule" if outside_schedule else "no_matching_rule", cred.id)
