# Token Stress Harness

`token_stress.cpp` is a crash-only user-mode stress skeleton for documented Windows APIs. It is meant to create debugger-observable token duplication/effective-only adjacent activity in a lab VM.

Build from a Visual Studio Developer Command Prompt:

```cmd
cl /EHsc /W4 /DUNICODE /D_UNICODE token_stress.cpp advapi32.lib
```

Example:

```cmd
token_stress.exe --threads 8 --seconds 300 --yield --verbose
```

Optional CPU affinity:

```cmd
token_stress.exe --threads 8 --seconds 300 --affinity 0x0000000f --sleep-ms 0
```

Notes:

- Uses documented APIs only.
- Does not attempt privilege escalation or kernel memory manipulation.
- `CreateRestrictedToken` and `DuplicateTokenEx` may not reach the exact internal path on every build/token type. Confirm with `windbg/token_identity_trace.wds`.
- If the confirmed path requires a different documented API sequence, add it as a TODO-backed mode and keep the harness crash-only.

