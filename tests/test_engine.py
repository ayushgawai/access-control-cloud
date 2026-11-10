"""Decision engine and detector tests. Stdlib only, so they also run without the web stack."""
from datetime import datetime, timezone

from app import video
from app.engine import Credential, Door, Policy, Rule, Schedule, decide, parse_windows

UTC = timezone.utc
WED_NOON_UTC = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)  # Wednesday
SAT_NOON_UTC = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)  # Saturday

weekdays = Schedule(1, "UTC", parse_windows([{"days": [0, 1, 2, 3, 4], "start": "08:00", "end": "18:00"}]))
night = Schedule(2, "UTC", parse_windows([{"days": [2], "start": "22:00", "end": "06:00"}]))  # Wed 22:00 -> Thu 06:00
la = Schedule(3, "America/Los_Angeles", parse_windows([{"days": [2], "start": "09:00", "end": "10:00"}]))

ada = Credential(1, "1001", groups=frozenset({"staff", "it"}))
grace = Credential(2, "1002", groups=frozenset({"staff"}))
expired = Credential(3, "1003", groups=frozenset({"staff"}), valid_until=datetime(2026, 1, 1, tzinfo=UTC))
future = Credential(4, "1004", groups=frozenset({"staff"}), valid_from=datetime(2027, 1, 1))  # naive = UTC
lost = Credential(5, "1005", status="lost", groups=frozenset({"staff"}))

lobby, server_room, roof = Door(1, 10), Door(2, 10), Door(3, 10)
locked = Door(4, 10, mode="lockdown")

policy = Policy.build(
    [lobby, server_room, roof, locked],
    [ada, grace, expired, future, lost],
    [weekdays, night],
    [Rule(1, "allow", site_id=10, group="staff", schedule_id=1),
     Rule(2, "allow", door_id=2, group="it"),
     Rule(3, "deny", door_id=3, group="staff"),
     Rule(4, "allow", door_id=3, credential_id=1)],
)


def test_schedule_windows():
    assert weekdays.active(WED_NOON_UTC)
    assert not weekdays.active(SAT_NOON_UTC)
    assert not weekdays.active(datetime(2026, 11, 11, 18, 0, tzinfo=UTC))  # end is exclusive
    assert night.active(datetime(2026, 11, 11, 23, 0, tzinfo=UTC))  # Wed night
    assert night.active(datetime(2026, 11, 12, 5, 59, tzinfo=UTC))  # Thu early morning, carried over
    assert not night.active(datetime(2026, 11, 12, 23, 0, tzinfo=UTC))  # Thu night is not in the window
    assert la.active(datetime(2026, 11, 11, 17, 30, tzinfo=UTC))  # 09:30 PST
    assert not la.active(datetime(2026, 11, 11, 9, 30, tzinfo=UTC))


def test_allow_inside_schedule_and_reason_outside():
    d = decide(policy, 1, "1002", WED_NOON_UTC)
    assert d.granted and d.reason == "rule_allow" and d.rule_id == 1
    d = decide(policy, 1, "1002", SAT_NOON_UTC)
    assert not d.granted and d.reason == "outside_schedule"


def test_door_rule_without_schedule_is_always():
    d = decide(policy, 2, "1001", SAT_NOON_UTC)
    assert d.granted and d.rule_id == 2


def test_deny_beats_allow():
    # Ada is staff (deny on roof) and also has a credential-specific allow; deny wins.
    d = decide(policy, 3, "1001", WED_NOON_UTC)
    assert not d.granted and d.reason == "rule_deny" and d.rule_id == 3


def test_credential_states():
    assert decide(policy, 1, "1003", WED_NOON_UTC).reason == "credential_expired"
    assert decide(policy, 1, "1004", WED_NOON_UTC).reason == "credential_not_yet_valid"
    assert decide(policy, 1, "1005", WED_NOON_UTC).reason == "credential_lost"
    assert decide(policy, 1, "nope", WED_NOON_UTC).reason == "unknown_credential"
    assert decide(policy, 99, "1001", WED_NOON_UTC).reason == "unknown_door"


def test_lockdown_and_default_deny():
    assert decide(policy, 4, "1001", WED_NOON_UTC).reason == "door_lockdown"
    only_it = Policy.build([lobby], [grace], [], [Rule(1, "allow", door_id=1, group="it")])
    assert decide(only_it, 1, "1002", WED_NOON_UTC).reason == "no_matching_rule"


def test_clip_linkage_and_tailgate():
    at = datetime(2026, 11, 11, 12, 0, 0, 123000, tzinfo=UTC)
    clip_id = video.clip_id_for("cam-lobby-2", at)
    clip = video.clip_for(clip_id, people=2)
    assert clip["camera_id"] == "cam-lobby-2"
    assert clip["start"] == "2026-11-11T11:59:55.123000+00:00"
    counter = video.PersonCounter("stub")
    assert counter.backend == "stub"
    assert counter.max_people(clip["frames"]) == 2
    assert counter.max_people(video.clip_for(clip_id, people=1)["frames"]) == 1
    assert video.is_tailgate(True, 2) and not video.is_tailgate(True, 1) and not video.is_tailgate(False, 3)
