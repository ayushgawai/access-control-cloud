"""Simulated video service and tailgating detector.

The "NVR" here is stateless: a clip id encodes camera and timestamp, and the
synthetic frames are rebuilt from (clip id, observed people). A real deployment
would swap `clip_for` for an NVR/VMS API call and feed real frames to YOLO.

Usage: python -m app.video photo.jpg   # count people with YOLO if installed
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

PRE_ROLL_S, POST_ROLL_S, FPS = 5, 10, 2


def clip_id_for(camera_id: str, at: datetime, event_id: str = "") -> str:
    # event suffix keeps clips unique when reads share a millisecond (or a pinned test clock)
    suffix = f"_{event_id[:8]}" if event_id else ""
    return f"clip_{camera_id}_{round(at.timestamp() * 1000)}{suffix}"


def clip_for(clip_id: str, people: int) -> dict:
    """Clip metadata with synthetic frames: people walk into view after the badge read."""
    segs = clip_id.removeprefix("clip_").rsplit("_", 2)
    if len(segs) == 3 and segs[1].isdigit():  # trailing segment is the event suffix
        camera_id, ms = segs[0], segs[1]
    else:
        camera_id, ms = clip_id.removeprefix("clip_").rsplit("_", 1)
    at = datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc)
    n = (PRE_ROLL_S + POST_ROLL_S) * FPS
    frames = []
    for i in range(n):
        offset = i / FPS - PRE_ROLL_S
        # Before the read only the badge holder is in view; afterwards everyone who walks through.
        frames.append({"t": round(offset, 2), "people": min(people, 1) if offset < 1 else people})
    return {
        "clip_id": clip_id,
        "camera_id": camera_id,
        "start": (at - timedelta(seconds=PRE_ROLL_S)).isoformat(),
        "end": (at + timedelta(seconds=POST_ROLL_S)).isoformat(),
        "url": f"sim://nvr/{camera_id}/{ms}.mp4",
        "frames": frames,
    }


class PersonCounter:
    """YOLO (ultralytics) when installed and a frame carries an image; deterministic stub otherwise."""

    def __init__(self, mode: str | None = None):
        self.mode = mode or os.getenv("TAILGATE_MODEL", "auto")  # auto | yolo | stub
        self._model = None
        if self.mode != "stub":
            try:
                from ultralytics import YOLO  # optional, heavy

                self._model = YOLO(os.getenv("YOLO_WEIGHTS", "yolov8n.pt"))
            except Exception:
                if self.mode == "yolo":
                    raise
        self.backend = "yolo" if self._model else "stub"

    def count(self, frame: dict) -> int:
        if self._model is not None and frame.get("image"):
            result = self._model(frame["image"], classes=[0], verbose=False)[0]  # class 0 = person
            return len(result.boxes)
        return int(frame.get("people", 0))

    def max_people(self, frames: list[dict]) -> int:
        return max((self.count(f) for f in frames), default=0)


def is_tailgate(granted: bool, people: int) -> bool:
    """One granted badge read, two or more people through the door."""
    return granted and people >= 2


if __name__ == "__main__":
    counter = PersonCounter("yolo")
    for path in sys.argv[1:]:
        print(path, counter.count({"image": path}))
