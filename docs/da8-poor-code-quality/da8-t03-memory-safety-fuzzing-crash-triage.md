# Memory Safety, Fuzzing, and Crash Triage

| Field | Value |
| --- | --- |
| Test Case ID | DA8-T03 |
| Primary OWASP Category | DA8 - Poor Code Quality |
| Secondary Categories | DA1 - Injections; DA3 - Sensitive Data Exposure; DA6 - Security Misconfiguration |
| Platforms | Native Win32, mixed-mode .NET, Electron native modules, parsers, codecs, and protocol handlers |

## Scope

This test identifies memory corruption, unsafe resource handling, and security-relevant crashes in native or unsafe code reachable through files, messages, IPC, network protocols, plug-ins, devices, and application APIs. It covers reproducible input testing, runtime verification, fuzzing, minimization, deduplication, and exploitability-oriented triage without developing weaponized exploits.

## Objective and Threat Model

Determine whether attacker-controlled input can cause out-of-bounds access, use-after-free, double free, invalid handle use, integer overflow, uninitialized use, race-related corruption, stack exhaustion, uncontrolled allocation, or a crash that crosses a meaningful availability or privilege boundary.

## Prerequisites and Safety

- Use an isolated, restorable Windows lab with synthetic corpora and no production connectivity.
- Obtain authorization for automated malformed-input testing and define rate/resource limits.
- Record exact binaries, symbols, mitigations, architecture, configuration, corpus, harness, and tool versions.
- Treat dumps and crashing inputs as sensitive; do not publish them before coordinated remediation.

## Testing Methodology

1. Inventory native/unsafe attack surfaces and prioritize privileged, remotely reachable, automatically invoked, file-preview, codec, archive, document, IPC, and update parsers.
2. Build a deterministic harness or workflow that exercises one input boundary with timeouts, clean state, crash capture, and observable completion.
3. Create a seed corpus from valid minimal inputs covering format versions and feature branches; exclude real sensitive data.
4. Run baseline negative tests for empty, truncated, oversized, nested, malformed length/count/offset, integer boundary, encoding, ordering, concurrency, and cancellation cases.
5. Enable Application Verifier checks appropriate to the target, and use page heap or sanitizers in supported test builds. Record performance changes and never assume custom heaps receive full coverage.
6. Fuzz within approved CPU, memory, disk, network, and time budgets. Measure meaningful coverage where instrumentation permits; iteration count alone is not evidence of adequacy.
7. Capture first- and second-chance exception, code, faulting instruction/module, registers, stack, heap/verifier stop, process integrity, input hash, and reproduction command.
8. Minimize each crashing input while preserving behavior, reproduce on the exact release build, and deduplicate by root-cause evidence rather than filename or top frame alone.
9. Classify access violation direction, attacker control of data/address, mitigations, privileges, trigger, user interaction, persistence, and affected boundary. A crash is not automatically exploitable, but reproducible memory corruption is a security finding even without a finished exploit.
10. Retest fixed and neighboring paths, add the minimized input to regression tests, and verify the fix does not merely catch the exception while leaving corruption present.

## Evidence to Collect

Attack-surface inventory; harness and corpus hashes; configuration and resource limits; coverage evidence; minimized input; reproduction rate; dump and debugger/verifier output; affected module/function; release-versus-instrumented comparison; deduplication rationale; privilege/trigger; cleanup; and regression result.

## Pass/Fail Criteria

### Pass

In-scope malformed inputs are rejected safely within resource limits, runtime verification reports no relevant corruption, crashes are not reproducible, and discovered defects have regression coverage.

### Fail

Fail for reproducible memory corruption, use-after-free, double free, out-of-bounds access, attacker-influenced invalid control/data flow, privileged parser crash, uncontrolled resource exhaustion with meaningful impact, or exception handling that conceals continuing corrupted state.

### Needs Further Investigation

Use when a crash is non-reproducible, occurs only under instrumentation, lacks the exact release binary, has uncertain attacker control, or cannot yet be separated from environmental failure.

## Remediation Guidance

- Prefer memory-safe implementations for new parsers and high-risk components.
- Validate lengths, offsets, counts, arithmetic, ownership, lifetime, recursion, and allocations before use.
- Use sanitizers, Application Verifier, static analysis, and continuous coverage-guided fuzzing in CI.
- Fail closed at the component boundary; do not continue after detected corruption.
- Preserve minimized security regression cases and retest every supported architecture.

## References

- [Microsoft: Application Verifier](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/application-verifier)
- [Microsoft: Debugging Application Verifier stops](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/application-verifier-debugging-application-verifier-stops)
- [Microsoft PowerToys: Fuzzing testing](https://github.com/microsoft/PowerToys/blob/main/doc/devdocs/tools/fuzzingtesting.md)
