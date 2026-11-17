"""Private preflight cause witness; deliberately does not import the shipped oracle."""
import csv
import hashlib
import io
import json
from pathlib import Path

HEADER = "index,intended,work_units,planned_failure,observed,actual_send,enqueue,service_start,completion,admitted"
RANGES = {"count": (1, 200000), "periodUs": (1, 1000000), "capacity": (1, 4096),
          "rawCapacity": (1, 200000), "latenessBudgetUs": (0, 5000000),
          "drainUs": (0, 5000000), "deadlineUs": (1, 10000000),
          "warmupCount": (0, 10000), "seed": (0, 4294967295)}

def require(ok, message):
    if not ok:
        raise ValueError(message)

def bounded(path, limit):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "regular file required")
    with path.open("rb") as f:
        value = f.read(limit + 1)
    require(len(value) <= limit, "byte limit")
    return value

def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result

def summary(directory):
    return json.loads(bounded(Path(directory) / "summary.json", 32768),
                      object_pairs_hook=no_duplicates)

def configuration(data, expected):
    require(type(data) is dict and set(data) == set(RANGES), "configuration fields")
    for key, (low, high) in RANGES.items():
        require(type(data[key]) is int and low <= data[key] <= high, "configuration range: " + key)
    require((data["count"] - 1) * data["periodUs"] + data["drainUs"] <= 30000000,
            "nominal duration")
    require(data == expected, "configuration differs from independently fixed invocation")

def validate(directory, expected, invocation):
    """Return only preflight-envelope proof, never complete-run or latency proof."""
    d = summary(directory)
    configuration(d.get("configuration"), expected)
    require(type(d.get("schema")) is int and d["schema"] == 1, "schema")
    require(d.get("mode") == "healthy", "mode")
    require(invocation["argvTail"] == ["run", "healthy", invocation["outputDirectory"],
            "100", "100", "64", str(expected["rawCapacity"]), "20261109"], "external argv")
    require(invocation["returncode"] == 4, "actual exit")
    require(len(invocation["cliSha256"]) == 64, "bound executable identity")
    require(expected["count"] > expected["rawCapacity"], "raw cap must actually be exceeded")
    require(d.get("status") == "INCOMPLETE", "not INCOMPLETE")
    require(d.get("reason") == "RAW_RECORD_CAP_BEFORE_START", "wrong incomplete cause")
    require(d.get("statistics", "missing") is None, "statistics must be explicit null")
    require(d.get("cutoffTicks") in ("0", 0) and type(d["cutoffTicks"]) is not bool, "cutoff")
    require(d.get("offeredScheduleSha256") == "", "unstarted schedule digest")
    for name in ("warmupPlanned", "warmupCompleted"):
        require(type(d.get(name)) is int and d[name] == 0, "warmup must not have started")
    raw = bounded(Path(directory) / "raw.csv", 65536)
    require(raw in ((HEADER + "\n").encode("ascii"), (HEADER + "\r\n").encode("ascii")),
            "preflight raw must be exactly header only")
    return {"status": "PASS_INDEPENDENT_PREFLIGHT_CAUSE", "records": 0, "statistics": None,
            "rawSha256": hashlib.sha256(raw).hexdigest(),
            "limitation": "Envelope/invocation proof only; not a proof of zero internal allocations/threads."}
