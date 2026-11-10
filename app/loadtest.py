"""Door-controller simulator and load test.

  python -m app.loadtest inproc --doors 5000   # stdlib only: engine + detector + batched SQLite writer
  python -m app.loadtest ws --doors 5000       # real controllers over WebSockets against a running API

Each simulated door badges at random (exponential gaps, mean --interval seconds) and
times every request -> decision round trip. ~3% of reads are tailgates (two people, one badge).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import sqlite3
import statistics
import tempfile
import threading
import time
from datetime import datetime, timezone

from . import engine as rules_engine
from . import video

BADGES = ["1001", "1002", "1003", "1004", "9999"]  # granted, granted, expired, suspended, unknown


def summarize(label: str, lat_s: list[float], wall_s: float, extra: str = "") -> str:
    ms = sorted(x * 1000 for x in lat_s)
    q = statistics.quantiles(ms, n=100, method="inclusive")
    return (f"{label}: {len(ms)} decisions in {wall_s:.1f}s ({len(ms) / wall_s:,.0f}/s)  "
            f"p50={q[49]:.2f}ms p95={q[94]:.2f}ms p99={q[98]:.2f}ms max={ms[-1]:.2f}ms{extra}")


def message(i: int, rng: random.Random, tailgate_rate: float) -> dict:
    return {"type": "badge", "badge": rng.choice(BADGES), "req_id": i,
            "sim_people": 2 if rng.random() < tailgate_rate else 1}


# --- in-process: same engine, clip linkage, detector and batching as the API, no network --------

class SqliteWriter:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("create table access_events (id text primary key, door_id int, ts text, badge text,"
                        " granted int, reason text, latency_ms real, clip_id text, people int, tailgate int)")
        self.buf: list[tuple] = []
        self.lock = threading.Lock()

    def put(self, row: tuple) -> None:
        with self.lock:
            self.buf.append(row)

    def flush(self) -> None:
        with self.lock:
            rows, self.buf = self.buf, []
        if rows:
            self.db.executemany("insert into access_events values (?,?,?,?,?,?,?,?,?,?)", rows)
            self.db.commit()


def bench_policy(n_doors: int) -> rules_engine.Policy:
    doors = [rules_engine.Door(i, 1, camera_id=f"bench-{i}") for i in range(n_doors)]
    creds = [rules_engine.Credential(1, "1001", groups=frozenset({"staff", "it"})),
             rules_engine.Credential(2, "1002", groups=frozenset({"staff"})),
             rules_engine.Credential(3, "1003", groups=frozenset({"contractor"}),
                                     valid_until=datetime(2020, 1, 1, tzinfo=timezone.utc)),
             rules_engine.Credential(4, "1004", status="suspended", groups=frozenset({"staff"}))]
    hours = rules_engine.Schedule(1, "UTC", rules_engine.parse_windows(
        [{"days": list(range(7)), "start": "00:00", "end": "23:59:59"}]))
    rules = [rules_engine.Rule(1, "allow", site_id=1, group="staff", schedule_id=1),
             rules_engine.Rule(2, "deny", door_id=0, group="contractor")]
    return rules_engine.Policy.build(doors, creds, [hours], rules)


async def run_inproc(args) -> None:
    policy = bench_policy(args.doors)
    counter = video.PersonCounter("stub")
    with tempfile.TemporaryDirectory() as tmp:
        writer = SqliteWriter(os.path.join(tmp, "bench.db"))
        latencies: list[float] = []
        tailgates = 0

        async def handle(door_id: int, msg: dict) -> dict:
            # Mirrors app.main.controller_socket: decide, answer, then clip + detector + enqueue row.
            t0 = time.perf_counter()
            at = datetime.now(timezone.utc)
            d = rules_engine.decide(policy, door_id, msg["badge"], at)
            reply = {"type": "decision", "req_id": msg["req_id"], "granted": d.granted, "reason": d.reason}
            await asyncio.sleep(0)  # yield like a socket send would
            clip_id = video.clip_id_for(f"bench-{door_id}", at)
            people = counter.max_people(video.clip_for(clip_id, msg["sim_people"])["frames"])
            tailgate = video.is_tailgate(d.granted, people)
            writer.put((os.urandom(16).hex(), door_id, at.isoformat(), msg["badge"], d.granted, d.reason,
                        (time.perf_counter() - t0) * 1000, clip_id, people, tailgate))
            return reply | {"tailgate": tailgate}

        async def door(door_id: int) -> None:
            nonlocal tailgates
            rng = random.Random(door_id)
            for i in range(args.events):
                await asyncio.sleep(rng.expovariate(1 / args.interval))
                t0 = time.perf_counter()
                reply = await handle(door_id, message(i, rng, args.tailgate_rate))
                latencies.append(time.perf_counter() - t0)
                tailgates += reply["tailgate"]

        stop = threading.Event()

        def flusher():
            while not stop.wait(0.05):
                writer.flush()

        t = threading.Thread(target=flusher, daemon=True)
        t.start()
        start = time.perf_counter()
        await asyncio.gather(*(door(i) for i in range(args.doors)))
        wall = time.perf_counter() - start
        stop.set()
        t.join()
        writer.flush()
        stored = writer.db.execute("select count(*) from access_events").fetchone()[0]
        print(summarize(f"inproc doors={args.doors}", latencies, wall,
                        f"  rows_written={stored} tailgates_flagged={tailgates}"))


# --- over the wire ----------------------------------------------------------------------------

async def run_ws(args) -> None:
    import httpx
    import websockets

    headers = {"Authorization": f"Bearer {args.api_token}"}
    async with httpx.AsyncClient(base_url=args.url, headers=headers) as http:
        doors = (await http.get("/api/doors")).raise_for_status().json()
    door_ids = [d["id"] for d in doors][: args.doors]
    if len(door_ids) < args.doors:
        print(f"only {len(door_ids)} doors exist; start the API with SEED_DOORS={args.doors} on a fresh DB")
    ws_url = args.url.replace("http", "ws", 1)
    latencies: list[float] = []
    connected = asyncio.Event()
    ready, start = 0, 0.0
    sem = asyncio.Semaphore(200)  # don't SYN-flood the API while connecting

    async def door(door_id: int) -> None:
        nonlocal ready, start
        rng = random.Random(door_id)
        async with sem:
            ws = await websockets.connect(f"{ws_url}/ws/controllers/{door_id}?token={args.controller_token}",
                                          open_timeout=60, ping_interval=None)
        async with ws:
            ready += 1
            if ready == len(door_ids):
                start = time.perf_counter()
                connected.set()
            await connected.wait()
            for i in range(args.events):
                await asyncio.sleep(rng.expovariate(1 / args.interval))
                t0 = time.perf_counter()
                await ws.send(json.dumps(message(i, rng, args.tailgate_rate)))
                while True:
                    reply = json.loads(await ws.recv())
                    if reply.get("type") == "decision" and reply.get("req_id") == i:
                        break
                    if reply.get("type") == "unlock":
                        print(f"door {door_id}: remote unlock (request {reply['request_id']})")
                latencies.append(time.perf_counter() - t0)

    await asyncio.gather(*(door(d) for d in door_ids))
    print(summarize(f"ws doors={len(door_ids)}", latencies, time.perf_counter() - start))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["inproc", "ws"])
    ap.add_argument("--doors", type=int, default=5000)
    ap.add_argument("--events", type=int, default=5, help="badge reads per door")
    ap.add_argument("--interval", type=float, default=1.0, help="mean seconds between reads per door")
    ap.add_argument("--tailgate-rate", type=float, default=0.03)
    ap.add_argument("--url", default=os.getenv("ACC_API_URL", "http://localhost:8000"))
    ap.add_argument("--controller-token", default=os.getenv("ACC_CONTROLLER_TOKEN", "acc_dev_controller"))
    ap.add_argument("--api-token", default=os.getenv("ACC_API_TOKEN", "acc_dev_mcp"))
    args = ap.parse_args()
    asyncio.run(run_inproc(args) if args.mode == "inproc" else run_ws(args))


if __name__ == "__main__":
    main()
