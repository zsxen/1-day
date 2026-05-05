# Results Collection Template

Create one subfolder per run, for example:

```text
results/2026-05-05-win11-26100.7019-run01/
```

## Environment

- VM OS:
- Build:
- Symbols path:
- WinDbg version:
- Kernel debugging transport:
- Verifier settings:
- Harness command:
- Start time:
- Duration:

## Offset / Call-Site Evidence

- `windbg/symbol_discovery.wds` log:
- `tools/token_offsets.json` snapshot:
- Screenshots of `dt nt!_TOKEN`, if fields are available:
- Screenshots or text of disassembly used to fill call-sites:

## Identity Evidence

- Token identity log:
- Parser command:
- Parser output:
- `OldToken == SMTEO token`:
- `OldToken.UserAndGroups == SMTEO.UserAndGroups`:
- Inner SID pointer overlap:

## Resource Evidence

- Resource state log:
- Released resource:
- SMTEO token resource:
- Same thread:
- Same resource:
- Manual `!locks <resource>` screenshot/log:
- Manual `dt nt!_ERESOURCE <resource>` screenshot/log:

## Mutation Evidence

- Mutation trace log:
- Count decrement before/after:
- Tail copy before/after:
- Index fix-up evidence:
- Hash rebuild after mutation:
- Duplicate SID pointer candidate:

## Concurrent Path Evidence

- Concurrent path log:
- Thread A SMTEO token:
- Thread B path:
- Same-token duplication/delete observed:
- Free path pointer:
- Return address:
- Stack:

## Crash / Double-Free Evidence

- Stop code:
- Dump path:
- Suspected pointer:
- First free stack:
- Second free stack:
- Token address:
- UserAndGroups pointer:
- Duplicated SID pointer, if observed:
- Exact interleaving sequence:

WinDbg crash checklist:

```text
!analyze -v
kv
r
!thread
!process 0 1
!pool <suspect_ptr>
!poolval <suspect_ptr>
!verifier
```

## Conclusion

- Confirmed / Partially confirmed / Not confirmed:
- Missing evidence:
- Next run changes:

