"""Append-only checkpoints: an interrupted action is never silently repeated."""
from pathlib import Path
from copy import deepcopy
import json
import os
import tempfile

from ..semantic_discovery.models import canonical, digest
from .models import VERSION


def _exclusive(path, value):
    data = (canonical(value) + "\n").encode()
    path = Path(path)
    # A failed write must not leave a partial event under its final sequence
    # name. Publish an already flushed file with exclusive creation semantics.
    descriptor, temporary = tempfile.mkstemp(prefix=".checkpoint-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


class Checkpoint:
    def __init__(self, directory, identity, *, resume=False):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        header = {"schema_version": 1, "policy_version": VERSION, "identity": identity}
        header["checkpoint_digest"] = digest(header)
        marker = self.directory / "checkpoint.json"
        if resume:
            if json.loads(marker.read_text()) != header:
                raise ValueError("checkpoint source/FT/strategy/build/budget identity changed")
        else:
            _exclusive(marker, header)
        self.header, self.events = header, []
        previous = header["checkpoint_digest"]
        for number, path in enumerate(sorted(self.directory.glob("event_*.json"))):
            if path.name != f"event_{number:05d}.json":
                raise ValueError("checkpoint event sequence is incomplete")
            event = json.loads(path.read_text())
            if (event.get("sequence") != number or event.get("previous_digest") != previous
                    or event.get("event_digest") != digest({key: value for key, value in event.items() if key != "event_digest"})):
                raise ValueError("checkpoint event chain is invalid")
            self.events.append(event)
            previous = event["event_digest"]
        self.previous_digest = previous

    def append(self, kind, payload):
        event = {"sequence": len(self.events), "kind": kind, "payload": deepcopy(payload),
                 "previous_digest": self.previous_digest}
        event["event_digest"] = digest(event)
        _exclusive(self.directory / f"event_{len(self.events):05d}.json", event)
        self.events.append(event)
        self.previous_digest = event["event_digest"]
        return event

    def pending_actions(self):
        started = {event["payload"]["action_id"] for event in self.events if event["kind"] == "action_started"}
        finished = {event["payload"]["action_id"] for event in self.events if event["kind"] == "action_finished"}
        return sorted(started - finished)

    def result(self):
        path = self.directory / "result.json"
        if not path.exists():
            return None
        marker = json.loads(path.read_text())
        if (marker.get("final_event_digest") != self.previous_digest
                or marker.get("result_digest") != digest(marker.get("result"))):
            raise ValueError("checkpoint result identity is invalid")
        return marker["result"]

    def finish(self, result):
        _exclusive(self.directory / "result.json", {"result": result, "result_digest": digest(result),
                   "final_event_digest": self.previous_digest})
