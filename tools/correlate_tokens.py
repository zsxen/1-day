#!/usr/bin/env python3
"""Correlate WinDbg EV logs for token root-cause validation.

The parser is intentionally tolerant: it accepts partial logs, unknown offsets,
and manually edited WinDbg output. It only reasons over tagged lines emitted by
the scripts in ../windbg.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


EVENT_RE = re.compile(r"^EV\s+(?P<kind>\S+)(?P<body>.*)$")
PAIR_RE = re.compile(r"(?P<key>[A-Za-z0-9_]+)=(?P<value>\"[^\"]*\"|\S+)")
HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F`]+$")
DUMP_RE = re.compile(r"^\s*([0-9a-fA-F`]+)\s+((?:[0-9a-fA-F`]{4,16}\s*)+)$")

MUTATION_KINDS = {
    "MUT_COUNT_BEFORE",
    "MUT_COUNT_AFTER",
    "MUT_TAIL_COPY_BEFORE",
    "MUT_TAIL_COPY_AFTER",
    "MUT_INDEX_FIX",
}


@dataclass
class Event:
    index: int
    kind: str
    fields: dict[str, str]
    raw: str

    def get(self, key: str, default: str = "") -> str:
        return self.fields.get(key, default)


def normalize_ptr(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip().strip('"').replace("`", "").lower()
    if value in {"0", "0x0", "(null)", "null", "????????"}:
        return "0x0"
    if HEX_RE.match(value):
        try:
            return f"0x{int(value, 16):x}"
        except ValueError:
            return value
    return value


def parse_events(lines: Iterable[str]) -> tuple[list[Event], list[list[str]]]:
    events: list[Event] = []
    dumps: list[list[str]] = []
    current_dump: list[str] | None = None

    for line in lines:
        line = line.rstrip("\n")
        match = EVENT_RE.match(line)
        if match:
            if current_dump:
                dumps.append(current_dump)
                current_dump = None
            body = match.group("body")
            fields = {m.group("key"): m.group("value").strip('"') for m in PAIR_RE.finditer(body)}
            events.append(Event(len(events), match.group("kind"), fields, line))
            continue

        dump_match = DUMP_RE.match(line)
        if dump_match:
            if current_dump is None:
                current_dump = []
            words = dump_match.group(2).split()
            current_dump.extend(normalize_ptr(w) or w for w in words)
        elif current_dump:
            dumps.append(current_dump)
            current_dump = None

    if current_dump:
        dumps.append(current_dump)
    return events, dumps


def load_offsets(path: Path | None) -> dict:
    if not path:
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def print_table(title: str, rows: list[dict[str, str]], columns: list[str], limit: int | None = None) -> None:
    print(f"\n## {title}")
    if not rows:
        print("(none)")
        return
    if limit is not None:
        rows = rows[:limit]
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in columns}
    header = " | ".join(c.ljust(widths[c]) for c in columns)
    sep = "-+-".join("-" * widths[c] for c in columns)
    print(header)
    print(sep)
    for row in rows:
        print(" | ".join(str(row.get(c, "")).ljust(widths[c]) for c in columns))


def same_thread_correlations(events: list[Event]) -> list[dict[str, str]]:
    dup_entries_by_tid: dict[str, list[Event]] = defaultdict(list)
    callsites_by_tid: dict[str, list[Event]] = defaultdict(list)
    smteo_by_tid: dict[str, list[Event]] = defaultdict(list)

    for event in events:
        tid = normalize_ptr(event.get("tid")) or event.get("tid")
        if event.kind == "SEP_DUP_ENTRY":
            dup_entries_by_tid[tid].append(event)
        elif event.kind == "SEP_DUP_SMTEO_CALLSITE":
            callsites_by_tid[tid].append(event)
        elif event.kind in {"SMTEO_ENTRY", "SMTEO_RESOURCE"}:
            smteo_by_tid[tid].append(event)

    rows: list[dict[str, str]] = []
    for tid, smteos in smteo_by_tid.items():
        for smteo in smteos:
            prior_dup = next((e for e in reversed(dup_entries_by_tid.get(tid, [])) if e.index < smteo.index), None)
            prior_call = next((e for e in reversed(callsites_by_tid.get(tid, [])) if e.index < smteo.index), None)
            old_token = normalize_ptr(prior_dup.get("old_token")) if prior_dup else None
            old_uag = normalize_ptr(prior_dup.get("old_uag")) if prior_dup else None
            call_token = normalize_ptr(prior_call.get("token") or prior_call.get("rcx")) if prior_call else None
            smteo_token = normalize_ptr(smteo.get("token") or smteo.get("rcx"))
            smteo_uag = normalize_ptr(smteo.get("uag"))
            rows.append(
                {
                    "tid": tid,
                    "dup_event": str(prior_dup.index) if prior_dup else "",
                    "call_event": str(prior_call.index) if prior_call else "",
                    "smteo_event": str(smteo.index),
                    "old_token": old_token or "",
                    "call_token": call_token or "",
                    "smteo_token": smteo_token or "",
                    "old_eq_smteo": str(old_token == smteo_token) if old_token and smteo_token else "unknown",
                    "call_eq_smteo": str(call_token == smteo_token) if call_token and smteo_token else "unknown",
                    "old_uag": old_uag or "",
                    "smteo_uag": smteo_uag or "",
                    "uag_equal": str(old_uag == smteo_uag) if old_uag and smteo_uag else "unknown",
                }
            )
    return rows


def resource_correlations(events: list[Event]) -> list[dict[str, str]]:
    releases_by_tid: dict[str, list[Event]] = defaultdict(list)
    rows: list[dict[str, str]] = []
    for event in events:
        tid = normalize_ptr(event.get("tid")) or event.get("tid")
        if event.kind == "RELEASE_RESOURCE":
            releases_by_tid[tid].append(event)
        elif event.kind == "SMTEO_RESOURCE":
            prior = next((e for e in reversed(releases_by_tid.get(tid, [])) if e.index < event.index), None)
            smteo_resource = normalize_ptr(event.get("resource"))
            released = normalize_ptr(prior.get("resource")) if prior else None
            rows.append(
                {
                    "tid": tid,
                    "release_event": str(prior.index) if prior else "",
                    "smteo_event": str(event.index),
                    "released_resource": released or "",
                    "smteo_resource": smteo_resource or "",
                    "same_resource": str(released == smteo_resource) if released and smteo_resource else event.get("same_resource", "unknown"),
                    "script_same_thread": event.get("same_thread", ""),
                    "script_same_resource": event.get("same_resource", ""),
                }
            )
    return rows


def mutation_sequences(events: list[Event]) -> list[dict[str, str]]:
    interesting = {"RELEASE_RESOURCE", "SMTEO_ENTRY", "SMTEO_RESOURCE", "HASH_REBUILD"} | MUTATION_KINDS
    per_tid: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.kind in interesting:
            tid = normalize_ptr(event.get("tid")) or event.get("tid")
            per_tid[tid].append(event)

    rows: list[dict[str, str]] = []
    wanted = ["RELEASE_RESOURCE", "SMTEO_ENTRY", "MUT_COUNT_AFTER", "MUT_TAIL_COPY_AFTER", "MUT_INDEX_FIX", "HASH_REBUILD"]
    for tid, evs in per_tid.items():
        kinds = [e.kind for e in evs]
        pos = []
        cursor = -1
        for kind in wanted:
            found = next((i for i, k in enumerate(kinds) if i > cursor and k == kind), None)
            if found is None:
                break
            pos.append(evs[found].index)
            cursor = found
        if len(pos) >= 4:
            rows.append(
                {
                    "tid": tid,
                    "sequence_events": "->".join(map(str, pos)),
                    "complete": str(len(pos) == len(wanted)),
                    "kinds_seen": "->".join(kinds),
                }
            )
    return rows


def count_changes(events: list[Event]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    last_by_tid_token: dict[tuple[str, str], Event] = {}
    for event in events:
        if event.kind not in MUTATION_KINDS and event.kind not in {"SMTEO_ENTRY", "SMTEO_RESOURCE"}:
            continue
        count = event.get("uag_count")
        token = normalize_ptr(event.get("token"))
        tid = normalize_ptr(event.get("tid")) or event.get("tid")
        if not count or not token:
            continue
        key = (tid, token)
        prev = last_by_tid_token.get(key)
        if prev and prev.get("uag_count") != count:
            rows.append(
                {
                    "tid": tid,
                    "token": token,
                    "from_event": str(prev.index),
                    "to_event": str(event.index),
                    "from_kind": prev.kind,
                    "to_kind": event.kind,
                    "from_count": prev.get("uag_count"),
                    "to_count": count,
                }
            )
        last_by_tid_token[key] = event
    return rows


def duplicate_dump_pointers(dumps: list[list[str]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for i, dump in enumerate(dumps):
        values = [v for v in dump if v and v != "0x0"]
        counts = Counter(values)
        for ptr, count in counts.items():
            if count > 1:
                rows.append({"dump": str(i), "ptr": ptr, "count": str(count)})
    return rows


def concurrent_rows(events: list[Event]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for event in events:
        if event.kind in {"CONCURRENT_SEP_DUP", "CONCURRENT_TOKEN_DELETE", "TOKEN_FREE"}:
            rows.append(
                {
                    "event": str(event.index),
                    "kind": event.kind,
                    "tid": normalize_ptr(event.get("tid")) or event.get("tid"),
                    "owner_tid": normalize_ptr(event.get("owner_tid")) or event.get("owner_tid"),
                    "target": normalize_ptr(event.get("target")) or "",
                    "same_token": event.get("same_token", ""),
                    "ptr": normalize_ptr(event.get("ptr")) or "",
                    "ret": normalize_ptr(event.get("ret")) or "",
                }
            )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="WinDbg log file")
    parser.add_argument("--offsets", type=Path, help="tools/token_offsets.json")
    parser.add_argument("--limit", type=int, default=30, help="max rows per table")
    args = parser.parse_args()

    offsets = load_offsets(args.offsets)
    events, dumps = parse_events(args.log.read_text(encoding="utf-8", errors="replace").splitlines())

    print(f"# Token Correlation Summary")
    print(f"log: {args.log}")
    if offsets:
        env = offsets.get("environment", {})
        print(f"target: {env.get('target', 'unknown')} build={env.get('build', 'unknown')}")
    print(f"events: {len(events)} dumps: {len(dumps)}")

    print_table(
        "SepDuplicateToken Entry Events",
        [
            {
                "event": str(e.index),
                "tid": normalize_ptr(e.get("tid")) or "",
                "old_token": normalize_ptr(e.get("old_token")) or normalize_ptr(e.get("rcx")) or "",
                "old_uag": normalize_ptr(e.get("old_uag")) or "",
                "old_uag_count": e.get("old_uag_count", ""),
            }
            for e in events
            if e.kind == "SEP_DUP_ENTRY"
        ],
        ["event", "tid", "old_token", "old_uag", "old_uag_count"],
        args.limit,
    )

    print_table(
        "SMTEO Events",
        [
            {
                "event": str(e.index),
                "kind": e.kind,
                "tid": normalize_ptr(e.get("tid")) or "",
                "token": normalize_ptr(e.get("token")) or normalize_ptr(e.get("rcx")) or "",
                "resource": normalize_ptr(e.get("resource")) or "",
                "uag": normalize_ptr(e.get("uag")) or "",
                "uag_count": e.get("uag_count", ""),
            }
            for e in events
            if e.kind in {"SEP_DUP_SMTEO_CALLSITE", "SMTEO_ENTRY", "SMTEO_RESOURCE"}
        ],
        ["event", "kind", "tid", "token", "resource", "uag", "uag_count"],
        args.limit,
    )

    print_table(
        "Same-Thread Token Correlations",
        same_thread_correlations(events),
        ["tid", "dup_event", "call_event", "smteo_event", "old_eq_smteo", "call_eq_smteo", "uag_equal", "old_token", "smteo_token"],
        args.limit,
    )

    print_table(
        "Resource Correlations",
        resource_correlations(events),
        ["tid", "release_event", "smteo_event", "same_resource", "released_resource", "smteo_resource"],
        args.limit,
    )

    print_table(
        "UserAndGroupCount Changes",
        count_changes(events),
        ["tid", "token", "from_event", "to_event", "from_kind", "to_kind", "from_count", "to_count"],
        args.limit,
    )

    print_table(
        "Duplicate Pointer Candidates In Dumps",
        duplicate_dump_pointers(dumps),
        ["dump", "ptr", "count"],
        args.limit,
    )

    print_table(
        "Mutation/Hash Sequences",
        mutation_sequences(events),
        ["tid", "complete", "sequence_events", "kinds_seen"],
        args.limit,
    )

    print_table(
        "Concurrent/Free Path Evidence",
        concurrent_rows(events),
        ["event", "kind", "tid", "owner_tid", "target", "same_token", "ptr", "ret"],
        args.limit,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

