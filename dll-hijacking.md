# DLL Hijacking and Unsafe Dependency Loading

| Field | Value |
| --- | --- |
| Test Case ID | DA8-T01 |
| Primary OWASP Category | DA8 - Poor Code Quality |
| Secondary Categories | DA5 - Improper Authorization; DA6 - Security Misconfiguration |
| Platforms | Native Win32, .NET, and Electron on Windows |

## Scope
This document focuses on identifying and assessing DLL hijacking, search-order hijacking, and unsafe dependency loading vulnerabilities in Windows desktop applications. These issues can lead to critical security risks, including privilege escalation vulnerabilities and arbitrary code execution.

It applies to:

- Native Win32 applications that use Windows APIs for DLL loading
- .NET applications, including WinForms, WPF, and mixed-mode assemblies that load native libraries
- Electron-based Windows applications that bundle native dependencies or interact with the Windows loader

Note: This document is focused on security testing and risk identification rather than exploitation techniques. It assumes an understanding of Windows application behavior and the DLL loading process.

## Objective

The main goal is to identify potential vulnerabilities related to unsafe DLL loading practices and assess the risks associated with those vulnerabilities.

The specific areas to examine are:

- DLLs Loaded from Unsafe or User-Writable Locations:
    Checking whether the application loads DLLs from directories that could be modified by a local attacker, such as `%TEMP%`, `%APPDATA%`, or the current working directory.

- Use of Relative Paths Instead of Absolute Paths:
    Ensuring that the application doesn't rely on relative paths when loading dynamic dependencies, which may allow an attacker to place a malicious DLL in a location that gets loaded instead of the legitimate one.

- Dependence on Default Windows DLL Search Order without Hardening:
    Verifying that the application doesn't depend on the default DLL search order without implementing security measures (e.g., `SafeDllSearchMode` or `SetDllDirectory`), which can lead to DLL hijacking vulnerabilities.

Ensure that all dynamic dependencies (DLLs) are securely loaded from trusted, well-defined locations, and that Windows' search order behavior is hardened to prevent exploitation.

## Threat Model

The threat model assumes that an attacker has local access and can write files to user-writable directories but cannot modify the application binary itself. This setup is common in internal network environments where users have limited privileges but are still able to write to locations like the `%TEMP%` or `%APPDATA%` directories.

### Assumptions

- Local Attacker:
    The attacker is a local user on the machine (e.g., an unprivileged user or one with limited access).

- Write Access to User-Writable Directories:
    The attacker can write files to certain directories, but they do not have system-wide write access or the ability to modify the application binary directly. The attacker can exploit the ability to drop a malicious DLL into user-writable paths like `%TEMP%`, `%APPDATA%`, or the current working directory.

- No Direct Modification of Application Binary:
    The attacker cannot modify the application itself (e.g., alter the executable or directly inject code into the application binary), but they may influence the dynamic loading of dependencies.


### Potential Attacks

- Local Privilege Escalation:
    If an attacker can load a malicious DLL from a trusted directory (or manipulate the search order), they could escalate their privileges, potentially executing code with higher system privileges (depending on the context in which the application runs).

- Arbitrary Code Execution in the Application Context:
    An attacker could trick the application into loading their malicious DLL, which could then execute arbitrary code. This code could be designed to do anything from data theft to system manipulation within the context of the vulnerable application.

- Persistence Mechanisms:
    Malicious DLLs could be used as part of persistence mechanisms. By hijacking DLL loading, an attacker might ensure that their malicious code runs every time the application is launched, even if the original infection vector is removed.


> Note: These vulnerabilities primarily exist in applications that don't harden their DLL loading behavior (e.g., relying on the default search order or not using absolute paths). Applications that do harden their loading process (e.g., by using `SafeDllSearchMode` or specifying absolute paths for DLLs) are less vulnerable to such attacks.


## Prerequisites and Safety

- Obtain the exact installer or release build under assessment and record its version and SHA-256 hash.
- Use an isolated Windows test environment and take a restorable snapshot before validation.
- Test with a representative standard-user account and, when relevant, the privileged account used by the application or service.
- Record the executable's launch method and current working directory because both can affect DLL resolution.
- Obtain authorization before placing any test DLL on the system. Use a benign proof of load that performs no persistence, network communication, or destructive action.
- Restore modified files and directories after testing and confirm that the application returns to its original state.

## Tools

1. Dependency Walker
   * Purpose: Identifies missing dependencies in executable files and helps track down DLLs that an application relies on.
   * Usage: Useful for mapping out the entire chain of DLL dependencies and checking if any are loaded from untrusted locations, which is a key vector in DLL hijacking.

2. Sigcheck
   * Purpose: A command-line utility from Sysinternals used to verify the authenticity and integrity of executables and DLLs.
   * Usage: Helps ensure that the loaded DLLs are digitally signed and haven't been tampered with. In the context of hijacking, you’d look for unsigned or suspiciously modified DLLs.

3. PowerShell
   * Purpose: A powerful scripting language for automating tasks, including security analysis.
   * Usage: Can be used to script the inspection of DLL load paths, automate the search for hijacked DLLs, and gather system information. Custom scripts can be written to analyze loaded DLLs, check their hashes, or automate the process of comparing them against known safe lists.

4. ProcMon (Process Monitor)
   * Purpose: A tool for real-time file system, registry, and process/thread activity monitoring.
   * Usage: Vital for capturing DLL loading events in real-time. It can help identify DLLs being loaded from potentially insecure paths or unexpected directories (e.g., the current working directory). Monitoring for unexpected loads can help detect hijacking attempts in progress.

5. ProcXP (Process Explorer)
   * Purpose: Displays detailed information about processes and their associated handles and DLLs.
   * Usage: You can use ProcXP to inspect the full list of loaded DLLs for any process in real-time and verify their source. It's crucial for identifying unusual or unauthorized DLLs loaded by an application.


## Expected Findings

* Normal DLL Load Locations:
  * Application Installation Directory:
    The DLLs associated with a given application should be located in the directory where the application was installed. This is a trusted location controlled by the application, ensuring that the correct versions of DLLs are used.

  * Windows System Directories:
    The Windows system directories (e.g., `C:\Windows\System32` or `C:\Windows\SysWow64`) are generally reserved for system-provided DLLs. These directories should be trusted, and any attempt to load DLLs from here should be scrutinized for legitimacy.

  * Other Trusted Locations:
    This might include directories defined by security policies (e.g., network share directories with restricted access) or non-writable application-specific directories. If these directories are writable, they might become a target for attackers.

* Unusual DLL Load Locations (Potential Indicators of Hijacking):
  * Current Working Directory:
    This is one of the most common locations targeted for DLL hijacking. Attackers often place malicious DLLs in the current working directory, knowing that a vulnerable application will search here before system directories.

  * User-Writable Paths:
    Directories such as `%TEMP%`, `%APPDATA%`, `%USERPROFILE%`, or any other locations that users have write access to are also common targets. These paths often allow attackers to drop a malicious DLL that will be loaded by the vulnerable application.

  * DLLs Loaded from Non-Writable Locations:
    Anomalies such as DLLs loaded from directories that should be non-writable (e.g., system directories, certain application directories) can indicate that the attacker has escalated privileges or exploited a vulnerability.


-------

## Testing Methodology

### Step 1 - Identify Loaded DLLs in the application

1. Launch the application in a controlled lab environment.
2. Open Process Explorer and select the target process.
3. Navigate to the DLLs tab to enumerate loaded modules.
4. Note the full path, signature status, and vendor of each DLL.

### Step 2 - Monitor Runtime DLL Resolution

1. Start **Process Monitor** with filters:
   * Process Name is <Application.exe>
   * Operation is `Load Image`
2. Restart the application to capture early DLL load activity.
3. Observe:
   * Missing DLLs
   * Repeated load attempts in multiple directories
   * Attempts to load from user-writable locations

### Step 3 - Identify Unsafe Search Paths
1. For each DLL loaded without a full path, identify all directories searched.
2. Check permissions on each directory using PowerShell:

```powershell
icacls "C:\Path\To\Directory"
```

3. Flag any directory where a standard user has write permissions.


### Step 4 - Validate Dependency Hardening

Review whether the application:

* Uses absolute paths in `LoadLibrary` / `DllImport`
* Calls `SetDefaultDllDirectories` or equivalent APIs
* Restricts DLL loading to trusted locations

For .NET applications, inspect P/Invoke declarations for relative DLL names.

### Step 5 - Validate a Candidate Safely

1. Select a missing or ambiguously resolved DLL name observed during normal application behavior.
2. Confirm that a standard user can write to a directory searched before the legitimate DLL location.
3. Place a benign test DLL in the candidate directory only when authorized.
4. Launch the application using the same method and working directory recorded during discovery.
5. Capture Process Monitor `Load Image` events and the resulting module path.
6. Remove the test DLL immediately after validation and restore the test environment.

Do not use a payload that opens a shell, establishes persistence, contacts an external system, or performs privileged actions. Demonstrating controlled loading from an attacker-writable location is sufficient to validate the unsafe resolution condition.

## Evidence to Collect

- Application version, architecture, executable path, and SHA-256 hash
- Launch method, process identity, integrity level, and current working directory
- Process Monitor events showing each attempted DLL path and the final `Load Image` result
- Process Explorer module information showing the loaded path, signer, and version
- ACL output for every attacker-influenceable directory in the relevant search sequence
- Static-analysis evidence for applicable imports, P/Invoke declarations, manifests, and loader API usage
- Before-and-after hashes for any file introduced during controlled validation
- Cleanup confirmation and the exact workflow required to reproduce the behavior

## Pass/Fail Criteria

### Pass

The test passes when DLLs are resolved only from trusted locations, attacker-influenceable directories do not precede trusted locations for relevant loads, application-controlled dependency directories are protected by appropriate ACLs, and loader hardening prevents a standard user from causing an unauthorized DLL to load.

### Fail

The test fails when a standard user can cause the application to load an unintended DLL from a user-writable or otherwise attacker-controlled location. The finding's severity should reflect the privileges, integrity level, trigger, user interaction, persistence, and security boundary affected by the application process.

### Needs Further Investigation

Use this outcome when a suspicious search path is observed but the tester cannot establish write access, load precedence, a reliable trigger, or the security context in which the candidate DLL would execute.

## Remediation Guidance

- Load application-controlled libraries by validated absolute path where feasible.
- Use supported Windows loader-hardening APIs and restrict the default search directories.
- Avoid adding the current working directory or user-writable locations to the DLL search path.
- Install executables and dependencies in directories that standard users cannot modify.
- Review relative native-library declarations in .NET and native modules bundled with Electron.
- Remove obsolete or missing dependency references that cause unnecessary search attempts.
- Sign release artifacts and verify integrity where the application's trust model requires it.
- Retest each supported launch method, updater path, service context, and application architecture after remediation.



## References
- OWASP Desktop Application Security Top 10
- Microsoft: Dynamic-Link Library Search Order
- Microsoft: SetDefaultDllDirectories API
- Sysinternals Process Monitor Documentation
