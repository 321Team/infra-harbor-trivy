#!/usr/bin/env python3
"""Bounded read-only observations; deliberately never an automatic-recovery gate."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import uuid

SCHEMA = "fds.harbor.startup-observation.v1"
NAMES = ("harbor-log", "harbor-db", "redis", "registry", "registryctl",
         "harbor-core", "harbor-portal", "harbor-jobservice", "trivy-adapter", "nginx")
FORMAT = ('{"id":{{json .Id}},"name":{{json .Name}},'
          '"status":{{json .State.Status}},"started_at":{{json .State.StartedAt}},'
          '"exit_code":{{json .State.ExitCode}},'
          '"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}}}')
DOCKER = ["docker", "--host=unix:///var/run/docker.sock", "inspect", "--type", "container", "--format", FORMAT, *NAMES]
LISTENER = ["ss", "-H", "-ltn4", "sport", "=", ":1514"]
COMMAND_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def now():
    return dt.datetime.now(dt.timezone(dt.timedelta(hours=9))).isoformat()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def decode(text):
    return json.loads(text, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))


def containers(text):
    rows = [decode(line) for line in text.splitlines() if line.strip()]
    if len(rows) != len(NAMES):
        raise ValueError("container count")
    for row in rows:
        if set(row) != {"id", "name", "status", "started_at", "exit_code", "health"}:
            raise ValueError("container fields")
        if not isinstance(row["id"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["id"]):
            raise ValueError("container id")
        if row["status"] not in ("created", "restarting", "running", "removing", "paused", "exited", "dead"):
            raise ValueError("container status")
        if row["health"] not in (None, "starting", "healthy", "unhealthy"):
            raise ValueError("container health")
        if type(row["exit_code"]) is not int or not isinstance(row["started_at"], str):
            raise ValueError("container state")
        # Docker timestamps may contain nanoseconds or the zero-time sentinel.
        if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", row["started_at"]):
            raise ValueError("container timestamp")
    if {row["name"] for row in rows} != {"/" + name for name in NAMES}:
        raise ValueError("container names")
    if len({row["id"] for row in rows}) != len(NAMES):
        raise ValueError("duplicate identity")
    return sorted(rows, key=lambda row: row["name"])


def listener(text):
    found = False
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 5 or parts[0] != "LISTEN" or not parts[1].isdigit() or not parts[2].isdigit():
            raise ValueError("listener shape")
        if not parts[3].endswith(":1514"):
            raise ValueError("listener port")
        found |= parts[3] == "127.0.0.1:1514"
    return found


def probe(command, parser, run=subprocess.run):
    begin = time.monotonic_ns()
    result = {"begin_ns": begin}
    try:
        p = run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="strict", timeout=4, check=False, env=COMMAND_ENV)
        result["rc"] = p.returncode
        if p.returncode:
            result["error"] = "COMMAND_FAILED"
        elif len(p.stdout.encode("utf-8")) > 65536:
            result["error"] = "OUTPUT_LIMIT"
        else:
            result["value"] = parser(p.stdout)
    except subprocess.TimeoutExpired:
        result.update(rc=None, error="TIMEOUT")
    except (OSError, UnicodeError):
        result.update(rc=None, error="COMMAND_UNAVAILABLE")
    except (ValueError, TypeError, KeyError):
        result["error"] = "INVALID_SELECTED_FIELDS"
    result["end_ns"] = time.monotonic_ns()
    return result


def sample(index):
    return {"kind": "sample", "index": index, "observed_at_kst": now(),
            "docker": probe(DOCKER, containers), "listener": probe(LISTENER, listener)}


def write_record(stream, record):
    stream.write(json.dumps(record, sort_keys=True, ensure_ascii=True) + "\n")
    stream.flush()
    os.fsync(stream.fileno())


def collect(path, count, interval, expected_host):
    if not 1 <= count <= 61 or not 5 <= interval <= 10:
        raise ValueError("sampling bounds")
    host = socket.gethostname()
    if host != expected_host:
        raise ValueError("host mismatch")
    # Exclusive creation refuses existing files and symlinks. No service writes.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    errors = 0
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        write_record(stream, {"kind": "header", "schema": SCHEMA, "run_id": str(uuid.uuid4()),
                              "host": host, "uid": os.getuid() if hasattr(os, "getuid") else None,
                              "started_at_kst": now(), "samples": count, "interval_seconds": interval,
                              "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                              "commands": {"docker": DOCKER, "listener": LISTENER}})
        for i in range(count):
            if i:
                time.sleep(interval)
            row = sample(i)
            errors += int(any("error" in row[key] for key in ("docker", "listener")))
            write_record(stream, row)
        write_record(stream, {"kind": "footer", "finished_at_kst": now(),
                              "samples": count, "samples_with_errors": errors})
    return 2 if errors else 0


def summarize(path):
    # This reports observed facts, not provenance authentication or an AC verdict.
    raw = Path(path).read_bytes()
    if len(raw) > 2 * 1024 * 1024 or not raw.endswith(b"\n"):
        raise ValueError("incomplete or oversized input")
    records = [decode(line) for line in raw.decode("utf-8").splitlines()]
    header, footer = records[0], records[-1]
    if header["kind"] != "header" or header["schema"] != SCHEMA or footer["kind"] != "footer":
        raise ValueError("incomplete capture")
    count = header["samples"]
    if type(count) is not int or not 1 <= count <= 61 or len(records) != count + 2 or footer["samples"] != count:
        raise ValueError("sample count")
    if header["commands"] != {"docker": DOCKER, "listener": LISTENER}:
        raise ValueError("command binding")
    if not re.fullmatch(r"[0-9a-f]{64}", header["source_sha256"]):
        raise ValueError("source binding")
    errors, candidate_indices, running_indices, identities = [], [], [], []
    last_end = -1
    for i, row in enumerate(records[1:-1]):
        if row["kind"] != "sample" or type(row["index"]) is not int or row["index"] != i:
            raise ValueError("sample sequence")
        for key in ("docker", "listener"):
            p = row[key]
            if type(p["begin_ns"]) is not int or type(p["end_ns"]) is not int or not last_end <= p["begin_ns"] <= p["end_ns"]:
                raise ValueError("monotonic sequence")
            last_end = p["end_ns"]
            if "error" not in p and (type(p["rc"]) is not int or p["rc"] != 0):
                raise ValueError("failed command without error")
            if "error" in p and "value" in p:
                raise ValueError("ambiguous command result")
        if any("error" in row[key] for key in ("docker", "listener")):
            errors.append(i)
            continue
        rows = containers("\n".join(json.dumps(r) for r in row["docker"]["value"]))
        if type(row["listener"]["value"]) is not bool:
            raise ValueError("listener value")
        identities.append({r["name"]: r["id"] for r in rows})
        log = next(r for r in rows if r["name"] == "/harbor-log")
        if log["status"] == "running" and log["health"] == "healthy" and row["listener"]["value"]:
            candidate_indices.append(i)
        if all(r["status"] == "running" for r in rows):
            running_indices.append(i)
    if type(footer["samples_with_errors"]) is not int or footer["samples_with_errors"] != len(errors):
        raise ValueError("error count")
    return {"schema": SCHEMA + ".summary", "capture_sha256": hashlib.sha256(raw).hexdigest(),
            "source_sha256": header["source_sha256"], "host": header["host"], "run_id": header["run_id"],
            "capture": "COMPLETE_WITH_ERRORS" if errors else "COMPLETE", "error_sample_indices": errors,
            "logger_healthy_and_ipv4_listener_sample_indices": candidate_indices,
            "all_containers_running_sample_indices": running_indices,
            "identity_comparable_samples": len(identities),
            "identity_change_observed": any(ids != identities[0] for ids in identities[1:]),
            "AUTOSTART": "NOT_EVALUATED", "SYSLOG_INGESTION": "NOT_TESTED", "AC04": "NOT_EVALUATED",
            "limitations": ["Sequential observations are not an atomic snapshot.",
                            "Polling cannot prove event order or exclude changes between samples.",
                            "No independent T0, manual-recovery or daemon-journal binding."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--output", required=True)
    c.add_argument("--expected-host", default="harbor01")
    c.add_argument("--samples", type=int, choices=range(1, 62), default=1)
    c.add_argument("--interval", type=int, choices=range(5, 11), default=5)
    s = sub.add_parser("summarize")
    s.add_argument("input")
    args = parser.parse_args()
    try:
        if args.mode == "collect":
            return collect(args.output, args.samples, args.interval, args.expected_host)
        result = summarize(args.input)
        print(json.dumps(result, sort_keys=True))
        return 2 if result["error_sample_indices"] else 0
    except (OSError, ValueError, TypeError, KeyError, IndexError, UnicodeError):
        print('{"error":"OBSERVATION_FAILED","AUTOSTART":"NOT_EVALUATED"}')
        return 2
    except KeyboardInterrupt:
        print('{"error":"INTERRUPTED","AUTOSTART":"NOT_EVALUATED"}')
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
