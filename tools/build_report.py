#!/usr/bin/env python3
"""Build a markdown root-cause evidence report from WinDbg logs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from correlate_tokens import (
    concurrent_rows,
    count_changes,
    duplicate_dump_pointers,
    mutation_sequences,
    parse_events,
    resource_correlations,
    same_thread_correlations,
)


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def md_table(headers: list[str], rows: list[dict[str, str]], limit: int = 20) -> str:
    if not rows:
        return "_No tagged evidence found._\n"
    rows = rows[:limit]
    out = []
    out.append("| " + " | ".join(headers) + " |")
    out.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        out.append("| " + " | ".join(str(row.get(h, "")).replace("|", "\\|") for h in headers) + " |")
    return "\n".join(out) + "\n"


def conclusion(identity: list[dict[str, str]], resources: list[dict[str, str]], mutations: list[dict[str, str]], concurrent: list[dict[str, str]]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    has_identity = any(r.get("call_eq_smteo") == "True" for r in identity)
    has_old_result = any(r.get("old_eq_smteo") in {"True", "False"} for r in identity)
    has_resource = any(r.get("same_resource") in {"True", "1"} for r in resources)
    has_mutation = bool(mutations)
    has_concurrent = any(r.get("same_token") in {"True", "1"} or r.get("kind") == "TOKEN_FREE" for r in concurrent)

    if has_identity:
        reasons.append("SMTEO argument identity is correlated between call-site and function entry.")
    if has_old_result:
        reasons.append("OldToken versus SMTEO token comparison has at least one concrete result.")
    if has_resource:
        reasons.append("Released resource matches the SMTEO token resource candidate in at least one same-thread trace.")
    if has_mutation:
        reasons.append("Mutation/hash sequence evidence is present.")
    if has_concurrent:
        reasons.append("Concurrent duplication/delete/free-path evidence is present.")

    if has_identity and has_resource and has_mutation and has_concurrent:
        return "Confirmed", reasons
    if has_identity or has_resource or has_mutation or has_concurrent:
        return "Partially confirmed", reasons
    return "Not confirmed", ["No decisive tagged evidence was found in the supplied log."]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path, help="WinDbg EV log")
    parser.add_argument("--offsets", required=True, type=Path, help="tools/token_offsets.json")
    parser.add_argument("--dump-analysis", type=Path, help="Optional crash dump analysis text")
    parser.add_argument("--out", default=Path("results/root_cause_report.md"), type=Path)
    args = parser.parse_args()

    offsets = load_json(args.offsets)
    lines = args.log.read_text(encoding="utf-8", errors="replace").splitlines()
    events, dumps = parse_events(lines)

    identity_rows = same_thread_correlations(events)
    resource_rows = resource_correlations(events)
    count_rows = count_changes(events)
    dup_ptr_rows = duplicate_dump_pointers(dumps)
    mutation_rows = mutation_sequences(events)
    concurrent = concurrent_rows(events)
    result, reasons = conclusion(identity_rows, resource_rows, mutation_rows, concurrent)

    env = offsets.get("environment", {})
    token_offsets = offsets.get("token_offsets", {})
    ranges = offsets.get("function_ranges", {})
    call_sites = offsets.get("call_sites", {})
    mutation_sites = offsets.get("smteo_mutation_sites", {})

    dump_excerpt = ""
    if args.dump_analysis and args.dump_analysis.exists():
        text = args.dump_analysis.read_text(encoding="utf-8", errors="replace")
        dump_excerpt = text[:6000]

    report = f"""# Root Cause Evidence Report

## Environment

- Target: {env.get("target", "TODO")}
- Build: {env.get("build", "TODO")}
- WinDbg log: `{args.log}`
- Crash dump analysis: `{args.dump_analysis}` if provided

## Symbol Status

TODO: Paste `.reload`, `lm m nt`, and relevant `x nt!...` output summary here.

## Offsets Used

```json
{json.dumps(token_offsets, indent=2)}
```

## Key Call-Site Addresses

```json
{json.dumps({"function_ranges": ranges, "call_sites": call_sites, "smteo_mutation_sites": mutation_sites}, indent=2)}
```

## OldToken vs SMTEO Token

{md_table(["tid", "dup_event", "call_event", "smteo_event", "old_eq_smteo", "call_eq_smteo", "uag_equal", "old_token", "smteo_token"], identity_rows)}

## UserAndGroups Equality / Deep-Copy Evidence

- Pointer equality is represented by `uag_equal` in the table above.
- Duplicate SID or pointer candidates from raw dumps:

{md_table(["dump", "ptr", "count"], dup_ptr_rows)}

## Resource Release vs SMTEO Resource

{md_table(["tid", "release_event", "smteo_event", "same_resource", "released_resource", "smteo_resource"], resource_rows)}

## Mutation Sequence Evidence

{md_table(["tid", "complete", "sequence_events", "kinds_seen"], mutation_rows)}

## UserAndGroupCount Changes

{md_table(["tid", "token", "from_event", "to_event", "from_kind", "to_kind", "from_count", "to_count"], count_rows)}

## Concurrent Path Evidence

{md_table(["event", "kind", "tid", "owner_tid", "target", "same_token", "ptr", "ret"], concurrent)}

## Free / Double-Free Evidence

TODO: Fill from crash dump and `TOKEN_FREE` / `MANUAL_TOKEN_FREE` events.

Crash dump excerpt:

```text
{dump_excerpt if dump_excerpt else "No crash dump analysis text supplied."}
```

## Conclusion

Result: **{result}**

Reasons:

{chr(10).join(f"- {reason}" for reason in reasons)}

## Next Missing Evidence

- TODO: Confirm any `null` offsets or placeholder call-sites.
- TODO: Attach symbol discovery log.
- TODO: Attach identity/resource/mutation/concurrent logs.
- TODO: Attach screenshots of manual `!locks`, `_ERESOURCE`, and crash dump inspection where relevant.
"""

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    print(f"Wrote {args.out}")
    print(f"Conclusion: {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

