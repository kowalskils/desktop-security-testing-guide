# OS Command and Argument Injection

| Field | Value |
| --- | --- |
| Test Case ID | DA1-T01 |
| Primary OWASP Category | DA1 - Injections |
| Secondary Categories | DA5 - Improper Authorization; DA6 - Security Misconfiguration |
| Platforms | Native Win32, .NET, Electron, and Windows helpers |

## Scope

This test follows untrusted desktop input into process creation, command interpreters, and external-tool arguments. Include import/export, converters, archive utilities, diagnostics, updater helpers, file associations, custom URIs, and IPC-triggered operations.

Use [DA6-T02](../da6-security-misconfiguration/da6-t02-file-handler-uri-parser.md) to discover activation surfaces and [DA5-T02](../da5-improper-authorization/da5-t02-process-service-privileges.md) for privilege boundaries. SQL, directory queries, and rendered-content injection require separate tests.

## Objective and Threat Model

Determine whether an attacker-controlled value can change the intended command, executable, argument boundaries, or privileged tool behavior rather than remaining an authorized data operand.

Record the input source, validation point, execution sink, caller, consumer identity, and required user interaction. Consider imported content, another local account, a browser-triggered URI, and an untrusted IPC client. Same-user execution is not automatically privilege escalation; explain the actual boundary crossed.

## Prerequisites and Safety

- Use an isolated Windows lab, the exact release build, synthetic files, and a restorable snapshot.
- Obtain authorization for the affected workflows and any instrumented helper substitution.
- Prefer argument capture and inert output markers. Do not use reverse shells, persistence, credential access, external callbacks, or destructive commands.
- Disable external connectivity where compatible with the test and document the difference from production.
- Bound input length and execution time. Avoid options that write outside the approved test directory, load plug-ins, or invoke additional programs.
- Record architecture, runtime and external-tool versions, account, working directory, and relevant environment without dumping secrets.

## Tools

Use Process Monitor process-creation capture, Process Explorer, source/static review, an approved debugger, and product-specific diagnostics. Where allowed, a benign argument-recorder helper can capture received argument indexes and values without executing them.

A command-line trace shows the serialized launch string, not necessarily the argument array or downstream parser decisions. A replacement helper only models the original target if its parsing behavior matches; document this limitation and confirm impact against the real tool safely.

## Testing Methodology

### Step 1 - Map Input to Execution

1. Inventory every workflow that launches an external executable, batch file, script, or interpreter.
2. Record the original input, decoding/normalization, concatenation, validation, and any intermediate IPC messages.
3. Identify the executable path separately from its arguments. Determine whether the caller can influence either.
4. Capture a valid baseline with the process tree, executable hashes, command line, outcome, and consumer privileges.
5. Include delayed/background tasks: validation in the UI may differ from validation in a service.

### Step 2 - Identify Every Parser

1. Determine whether the path uses direct process creation, Windows shell activation, cmd.exe, PowerShell, or another interpreter.
2. For direct launches, inspect the target application's own option parser. One safely quoted argument can still become a dangerous option.
3. Record nested interpretation, such as a helper that launches a batch file after initially receiving separate arguments.
4. Review decoding order for file/URI inputs. An encoded value may become syntax only after later decoding.
5. Do not apply POSIX escaping rules to Windows. Quoting and metacharacter behavior depend on the actual parser and context.

Technology-specific checks:

- Native: CreateProcessW accepts an executable name and command-line string, not a universal argument array. Use a trusted explicit executable path and validate the target's parsing rules. Microsoft C runtime quoting rules are not guaranteed for every executable.
- .NET: inspect FileName, Arguments or ArgumentList, and UseShellExecute. ArgumentList handles argument serialization but does not validate tool options or make interpreter command text safe. UseShellExecute refers to Windows shell activation, not proof that cmd.exe is involved; setting it false still permits explicitly launching an interpreter.
- Electron/Node.js: inspect child_process exec, execFile, spawn, shell options, and Windows-specific argument handling. exec uses a shell; execFile and spawn can avoid one, but wrappers, batch files, or explicit shell options can reintroduce interpretation. Verify the actual bundled Node version.

### Step 3 - Exercise a Bounded Input Matrix

Change one input property at a time and preserve a valid control:

| Input class | Question to answer |
| --- | --- |
| Spaces, tabs, empty values, Unicode | Is the intended value preserved as one operand? |
| Embedded quotes and trailing backslashes | Do argument boundaries change in the actual target parser? |
| Literal shell metacharacters | Are they data, rejected input, or interpreter syntax? |
| Leading option prefixes | Can a data field select an unintended tool option? |
| Response-file or configuration-file notation | Does the tool read additional instructions from a user-selected file? |
| Encoded URI values | Does decoding after validation introduce executable syntax? |
| Input reused by an elevated helper | Is the same restriction enforced at the consumer? |

Use parser-specific cases, not a generic payload spray. Windows filenames cannot contain every character a free-text field can; test through a valid input surface rather than trying to create impossible filenames. Do not use UNC paths that could trigger unintended authentication.

### Step 4 - Validate Argument Injection Without a Shell

1. Select a tool option documented as harmless in the exact version, such as help or version output where available.
2. Supply it through a field intended only for a data operand.
3. Compare the received arguments and behavior with the baseline. Determine whether an extra argument was created or one operand was reinterpreted as an option.
4. If a response-file mechanism is relevant, use an approved local fixture containing only inert options.
5. Explain the security consequence supported by evidence. Help output can establish parser influence but does not by itself prove arbitrary code execution.
6. Check whether an end-of-options delimiter is actually supported by this tool; do not assume all Windows programs honor it.

### Step 5 - Confirm Command Interpretation Safely

1. Only after identifying an interpreter, choose an approved inert marker appropriate to its grammar and the exact quoting context.
2. Prefer a marker printed to already captured output. If a file marker is necessary, use a unique path inside the disposable test directory with no overwrite.
3. Submit the value through the real application input, not by manually running a constructed command in the tester's shell.
4. Compare a literal-data control and the candidate. Record whether the marker was executed, merely echoed, logged, or rejected.
5. Correlate interpreter behavior with process creation, debugger evidence, or output attribution. Shell built-ins need not create a separate child process.
6. Reproduce with a fresh marker. Stop after the minimal proof; no malicious payload is needed.

An error, crash, metacharacter in a trace, or unexpected output alone is not confirmed command injection.

### Step 6 - Validate Context and Remediation

1. Record the successful trigger, consumer identity/integrity level, executable, target operation, and required interaction.
2. Retest the same case through supported alternate entry points and helper paths using the authorized accounts.
3. After remediation, repeat the original candidate and valid inputs containing legitimate spaces or Unicode.
4. Confirm the fix removes interpretation or rejects unauthorized semantics without merely blocking one marker.
5. Preserve the minimized input, expected argument structure, and allowed behavior as regression cases.
6. Remove only test artifacts and restore any approved helper substitution. Retain sanitized traces and cleanup evidence.

## Evidence to Collect

Retain release/tool hashes and versions, input provenance, exact input bytes or encoding, parser chain, launch API/configuration, process tree, received arguments where observable, benign proof, controls, account/privilege context, and before/after results.

## Pass/Fail Criteria

### Pass

For the recorded workflows, untrusted values remain authorized data operands or are rejected before execution. The executable and allowed options are controlled, downstream interpreters do not reinterpret data as code, and valid inputs still work.

### Fail

Fail for reproducible unauthorized command interpretation, executable selection, or argument/option manipulation that violates the intended operation boundary. Distinguish argument influence, command execution, and privilege escalation; report only the impact established.

### Needs Further Investigation

Use when only serialized command lines, errors, an approximate helper model, or unconfirmed parser behavior are available. Document what observation is needed to confirm the boundary change.

## Expected Findings

- An export label is concatenated into interpreter command text.
- A filename field becomes an unintended option to a directly launched utility.
- A URI is validated before decoding, then reinterpreted by a helper.
- The UI validates arguments but a privileged IPC consumer accepts the same input unchecked.
- Separate arguments and tool-specific validation preserve legitimate data: expected behavior.

## Remediation Guidance

- Prefer a library or platform API over external command execution.
- Use a fixed trusted executable and separate arguments where supported.
- Validate argument semantics, allowed operations, target paths, and lengths at the consuming boundary.
- Avoid passing untrusted values into interpreter source text; escaping alone is not a universal solution.
- Apply target-specific end-of-options handling only when supported and tested.
- Minimize privileges and isolate helpers without treating sandboxing as a substitute for correct input handling.
- Test nested parsers, alternate entry points, and harmless regression inputs continuously.

## References

- [OWASP: OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [Microsoft: CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
- [Microsoft: C command-line argument parsing](https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments?view=msvc-170)
- [Microsoft: ProcessStartInfo.ArgumentList](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist)
- [Microsoft: ProcessStartInfo.UseShellExecute](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.useshellexecute)
- [Node.js: child_process](https://nodejs.org/api/child_process.html)
