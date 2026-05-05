# Root Cause Validation Plan

Target: Windows 11 Pro 24H2, build 26100.7019.

Scope: defensive root-cause confirmation for the suspected race around `SepDuplicateToken`, `SepMakeTokenEffectiveOnly`, token `UserAndGroups` filtering, token resource scope, and follow-on SID hash rebuild work. This plan is for a controlled local VM only. It does not attempt privilege escalation, token stealing, arbitrary kernel writes, or payload execution.

## Repository Inventory

Current repository contents observed before adding this framework:

- `Root Cause 2fb66137f693802e833af70359a60c0f.md`: primary markdown note containing current analysis, screenshots referenced as `Root Cause/image*.png`, IDA/WinDbg observations, and the working hypothesis around `ExReleaseResourceLite`, `SepMakeTokenEffectiveOnly`, and destructive `UserAndGroups` compaction.
- No committed source files were present before this framework.
- `.DS_Store` is untracked local metadata and was left untouched.

Generated framework folders:

- `docs/`: this plan.
- `windbg/`: WinDbg command scripts and templates.
- `tools/`: log correlation and report generation helpers.
- `harness/`: crash-only documented-API user-mode stress harness skeleton.
- `results/`: evidence collection template and generated report output location.

## Phase 1: Symbol and Offset Discovery

Goal: prove what symbols and structure fields are available on the exact VM build, then manually fill any missing offsets. Do not assume offsets from IDA, blogs, or another build.

1. Boot the lab VM with kernel debugging enabled.
2. In WinDbg, set the symbol path to Microsoft public symbols plus your cache:

   ```text
   .symfix
   .sympath+ srv*C:\symbols*https://msdl.microsoft.com/download/symbols
   .reload /f nt
   ```

3. Run:

   ```text
   $$><windbg\symbol_discovery.wds
   ```

4. Save the output log. The script prints:

   - `nt!SepDuplicateToken`
   - `nt!SepMakeTokenEffectiveOnly`
   - nearest `Sep*Delete*Token` / `Sep*Free*Token` symbols
   - `nt!RtlSidHashInitialize`
   - `nt!ExReleaseResourceLite`
   - `nt!ExFreePoolWithTag`
   - `dt nt!_TOKEN` output, if public symbols expose it

5. Fill `windbg/token_offsets.wds` and `tools/token_offsets.json` from the discovered `dt` output and disassembly. If public symbols do not expose private token fields, leave unknown values as `null` in JSON and `TODO_*` in WDS until manually confirmed.

Fields to confirm:

- token resource / lock field candidate
- `UserAndGroups`
- `UserAndGroupCount`
- `RestrictedSids` / `RestrictedSidCount`
- `Capabilities` / `CapabilityCount`
- default-owner / primary-group / index-like fields, if exposed

Call sites to confirm:

- `SepDuplicateToken` start/end
- `SepMakeTokenEffectiveOnly` start/end
- `SepDuplicateToken` `ExAcquireResourceSharedLite` call-site, if used
- `SepDuplicateToken` `ExReleaseResourceLite` call-site
- `SepDuplicateToken` `SepMakeTokenEffectiveOnly` call-site
- `RtlSidHashInitialize` call-sites inside `SepDuplicateToken`
- mutation instruction addresses inside `SepMakeTokenEffectiveOnly`

## Phase 2: Confirm SepMakeTokenEffectiveOnly Argument Identity

Use `windbg/token_identity_trace.wds` after filling offsets and the SMTEO call-site address.

Default run:

```text
.logopen /t C:\kdlogs\token_identity.log
$$><windbg\token_offsets.wds
$$><windbg\token_identity_trace.wds
g
```

Evidence to extract:

- `SepDuplicateToken` entry: current thread, process, `rcx/rdx/r8/r9`, return address, short stack, `OldToken.UserAndGroups`, and `OldToken.UserAndGroupCount`.
- `SepMakeTokenEffectiveOnly` call-site inside `SepDuplicateToken`: `rcx` as the exact argument, callee-saved registers for correlation, `UserAndGroups`, and count.
- `SepMakeTokenEffectiveOnly` entry: token pointer, thread/process, return address, stack, resource candidate, `UserAndGroups`, and count.

Then run:

```powershell
python tools\correlate_tokens.py C:\kdlogs\token_identity.log --offsets tools\token_offsets.json
```

Interpretation:

- Strong identity evidence if the SMTEO call-site `rcx` equals the SMTEO entry `rcx` on the same thread and return path.
- If SMTEO token equals the `SepDuplicateToken` entry `rcx`, that supports "SMTEO mutates OldToken".
- If SMTEO token differs from entry `rcx`, that supports "SMTEO mutates NewToken or another derived token".
- If `OldToken.UserAndGroups` equals `SMTEO.UserAndGroups`, the array is shared at that point.
- If array pointers differ, inspect SID pointer dumps to determine whether entries are deep-copied or share inner SID pointers.

## Phase 3: Confirm Lock/Resource State at SMTEO

Use `windbg/resource_state_trace.wds` after filling the `SepDuplicateToken` `ExReleaseResourceLite` call-site and `TOKEN_RESOURCE_PTR_OFF`.

Default run:

```text
.logopen /t C:\kdlogs\resource_state.log
$$><windbg\token_offsets.wds
$$><windbg\resource_state_trace.wds
g
```

Expected strong evidence:

- `EV RELEASE_RESOURCE` resource pointer equals the `EV SMTEO_RESOURCE` resource candidate for the same thread.
- The release event occurs before the SMTEO entry event on the same thread.

Stronger evidence:

- The same token resource is no longer held by the current thread while SMTEO mutates `UserAndGroups`.
- Manual pause mode confirms this with `!locks <resource>`, `dt nt!_ERESOURCE <resource>`, `!thread`, and `kv`.

Manual mode:

```text
$$><windbg\resource_state_manual.wds
g
```

At each break, inspect:

```text
!locks <resource>
dt nt!_ERESOURCE <resource>
!thread
kv
```

Keep `!locks` out of high-frequency default traces because it can be slow and noisy.

## Phase 4: Identify and Instrument SMTEO Mutation Points

Use IDA and WinDbg disassembly to fill the placeholders in `windbg/smteo_mutation_template.wds`.

Recommended workflow:

1. Disassemble `nt!SepMakeTokenEffectiveOnly`.
2. Find the token base register used throughout the function.
3. Find the count decrement point for `UserAndGroupCount`.
4. Find the instruction just after the decrement where the new count is visible.
5. Find the tail-entry swap/copy instruction or helper call.
6. Find the instruction just after the copy where the destination entry can be dumped.
7. Find index fix-up instructions for owner/group/index-like fields.
8. Find `RtlSidHashInitialize` call-sites after SMTEO in `SepDuplicateToken`.
9. Fill the template placeholders and run the resulting script.

The template emits:

- `EV MUT_COUNT_BEFORE`
- `EV MUT_COUNT_AFTER`
- `EV MUT_TAIL_COPY_BEFORE`
- `EV MUT_TAIL_COPY_AFTER`
- `EV MUT_INDEX_FIX`
- `EV HASH_REBUILD`

The parser flags:

- same SID pointer appearing in more than one `UserAndGroups` entry dump
- `UserAndGroupCount` changes across adjacent events
- hash rebuild events after mutation
- suspicious sequence: `ExReleaseResourceLite -> SMTEO entry -> Count decrement -> Tail copy -> Index fix-up -> RtlSidHashInitialize`

## Phase 5: Concurrent Reader/Free Path Detection

Use `windbg/concurrent_paths_trace.wds` only after narrowing the target token or enabling the target marker from SMTEO. This script avoids global noisy logging by filtering around configured function ranges and a tracked token pointer.

Evidence to collect:

- Thread A enters SMTEO with token X and logs `EV TARGET_TOKEN_SET`.
- Thread B enters `SepDuplicateToken`, `SepDeleteToken`, or nearby free/delete path with token X before Thread A logs `EV SMTEO_EXIT`.
- `ExFreePoolWithTag` frees a suspect `UserAndGroups` or SID-related allocation from a return address inside the configured token ranges.

Manual free inspection:

```text
$$><windbg\free_path_manual.wds
g
```

At the break:

```text
kv
r
!thread
!pool <suspect_ptr>
!poolval <suspect_ptr>
```

## Phase 6: Crash-Only Double-Free Evidence

This phase is verifier-oriented and should only be used in a disposable lab VM snapshot.

Enable evidence-friendly crash dumps:

```cmd
wmic recoveros set DebugInfoType = 1
wmic recoveros set AutoReboot = False
```

Special Pool / Driver Verifier guidance:

- Prefer GUI for careful selection: `verifier.exe`.
- Select Special Pool and pool tracking options.
- If selecting drivers manually, be conservative and use the exact VM snapshot for rollback.
- Record every verifier setting in `results/README.md` before running the stress harness.

Rollback if boot-looping:

1. Boot into recovery or Safe Mode.
2. Run:

   ```cmd
   verifier /reset
   ```

3. Reboot.
4. If needed, revert the VM snapshot.

Crash dump checklist:

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

WinDbg free-path filtering:

- Filter `ExFreePoolWithTag` by return address range inside `SepDuplicateToken`, `SepDeleteToken`, or token cleanup ranges.
- Add an optional pointer filter after a duplicate SID pointer or suspect allocation is found.
- Do not enable broad global free logging during long stress runs.

Strong crash-only evidence:

- First free and second free stacks point into token duplication/effective-only/cleanup paths.
- The suspect pointer appears as a `UserAndGroups` entry SID pointer or nearby token variable-length allocation.
- The crash interleaving includes SMTEO mutation before hash rebuild or cleanup.

## Phase 7: Register-State Dataflow Confirmation

Use `windbg/register_trace.wds` after filling all key call-sites.

Questions to answer:

- Which register holds `OldToken` at `SepDuplicateToken` entry?
- Which register holds `NewToken` after object creation?
- Which register is passed as `rcx` to `SepMakeTokenEffectiveOnly`?
- Which register or memory expression is passed to `ExReleaseResourceLite`?
- Does `rdi+0x30` actually resolve to the released resource on this build?
- Which register is used as token base inside SMTEO?
- Which registers hold `UserAndGroups`, count, current index, tail index, and entry pointers around mutation?

The script only logs dataflow and does not manipulate registers.

## Phase 8: Crash-Only Stress Harness

`harness/token_stress.cpp` is a documented-API skeleton. It repeatedly exercises token duplication and effective-only impersonation-token creation paths through Windows APIs such as `OpenProcessToken`, `DuplicateTokenEx`, `CreateRestrictedToken`, `ImpersonateLoggedOnUser`, and `RevertToSelf`.

Build from a Visual Studio Developer Command Prompt:

```cmd
cd harness
cl /EHsc /W4 /DUNICODE /D_UNICODE token_stress.cpp advapi32.lib
```

Example run:

```cmd
token_stress.exe --threads 8 --seconds 300 --yield --verbose
```

Optional affinity:

```cmd
token_stress.exe --threads 8 --seconds 300 --affinity 0x0000000f --sleep-ms 0
```

The harness contains no payload and no kernel memory manipulation. If debugger evidence shows the API path does not reach the needed vulnerable flow, add a TODO-backed variant rather than forcing undocumented behavior into this harness.

## Phase 9: Evidence Report Generation

Generate a report:

```powershell
python tools\build_report.py --log C:\kdlogs\token_identity.log --offsets tools\token_offsets.json --dump-analysis C:\kdlogs\crash_analysis.txt --out results\root_cause_report.md
```

The report includes:

- environment
- symbol status
- offsets used
- key call-site addresses
- OldToken vs SMTEO token result
- `UserAndGroups` equality/deep-copy result
- resource release vs SMTEO resource comparison
- mutation sequence evidence
- concurrent path evidence
- free/double-free evidence
- conclusion: Confirmed, Partially confirmed, or Not confirmed
- next missing evidence

## Evidence Thresholds

Confirmed:

- SMTEO token identity is proven.
- Resource released before SMTEO equals the token resource candidate.
- Mutation events occur after release and before hash rebuild.
- Concurrent reader/free path or crash dump shows a conflicting access/free of the same token or SID-related allocation.

Partially confirmed:

- Control flow and lock release timing are proven, but no concurrent conflicting access/free is captured.
- Or mutation sequence is proven but resource identity remains unresolved.

Not confirmed:

- SMTEO mutates a separately locked token, or the resource remains held across mutation.
- No count/copy/index mutation sequence is observed in the suspected function on this build.
- Crashes/free events cannot be tied back to token `UserAndGroups` or SID allocations.

