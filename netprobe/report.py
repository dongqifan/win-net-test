import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


class ProbeError(Exception):
    pass


class ProbeTimeout(ProbeError):
    pass


def safe_text(value):
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in str(value))


class Report:
    def __init__(self, command, stream=None):
        self.stream = stream if stream is not None else sys.stdout
        self.started = time.monotonic()
        self.data = {"command": command, "started": datetime.now(timezone.utc).isoformat(),
                     "success": False, "events": [], "result": {}}

    def event(self, stage, direction, message, **fields):
        elapsed = round(time.monotonic() - self.started, 3)
        event = {"elapsed": elapsed, "stage": stage, "direction": direction,
                 "message": message, **fields}
        self.data["events"].append(event)
        suffix = " ".join(f"{k}={safe_text(v)}" for k, v in fields.items())
        print(f"[{elapsed:8.3f}] {stage:12} {direction:5} {safe_text(message)} {suffix}".rstrip(),
              file=self.stream, flush=True)

    def finish(self, success, result=None, error=None):
        self.data["success"] = success
        if result is not None:
            self.data["result"] = result
        if error is not None:
            self.data["error"] = str(error)
        self.event("RESULT", "PASS" if success else "FAIL", error or "Completed")

    def save(self, path):
        Path(path).write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
