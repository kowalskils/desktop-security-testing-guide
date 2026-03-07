# DLL Hijacking and Unsafe Dependency Loading

## Scope
This document focuses on identifying and assessing DLL hijacking, search-order hijacking, and unsafe dependency loading vulnerabilities in Windows desktop applications. These issues can lead to critical security risks, including privilege escalation vulnerabilities and arbitrary code execution.

It's applicable for:
- Native Win32 applications
- .NET applications (WinForms, WPF, mixed-mode)
- Electron-based Windows applications

It's applicable for:
- Native Win32 Applications: Applications are typically written in languages like C or C++ and rely on the Windows API for DLL loading.
- .NET Applications: Applications built with WinForms, WPF, or mixed-mode assemblies that interact with native code.
- Electron-based Windows Applications: Applications may be vulnerable due to the way they bundle native dependencies or interact with Windows' dynamic linking process.

Note: This document is focused on security testing and risk identification rather than exploitation techniques. It assumes an understanding of Windows application behavior and the DLL loading process.

### Objective

The main goal is to identify potential vulnerabilities related to unsafe DLL loading practices and assess the risks associated with those vulnerabilities.

The specific areas to examine are:

- DLLs Loaded from Unsafe or User-Writable Locations:
    Checking whether the application loads DLLs from directories that could be modified by a local attacker, such as `%TEMP%`, `%APPDATA%`, or the current working directory.

- Use of Relative Paths Instead of Absolute Paths:
    Ensuring that the application doesn't rely on relative paths when loading dynamic dependencies, which may allow an attacker to place a malicious DLL in a location that gets loaded instead of the legitimate one.

- Dependence on Default Windows DLL Search Order without Hardening:
    Verifying that the application doesn't depend on the default DLL search order without implementing security measures (e.g., `SafeDllSearchMode` or `SetDllDirectory`), which can lead to DLL hijacking vulnerabilities.

Ensure that all dynamic dependencies (DLLs) are securely loaded from trusted, well-defined locations, and that Windows' search order behavior is hardened to prevent exploitation.

### Threat Model

The threat model assumes that an attacker has local access and can write files to user-writable directories but cannot modify the application binary itself. This setup is common in internal network environments where users have limited privileges but are still able to write to locations like the `%TEMP%` or `%APPDATA%` directories.

#### Assumptions:

- Local Attacker:
    The attacker is a local user on the machine (e.g., an unprivileged user or one with limited access).

- Write Access to User-Writable Directories:
    The attacker can write files to certain directories, but they do not have system-wide write access or the ability to modify the application binary directly. The attacker can exploit the ability to drop a malicious DLL into user-writable paths like `%TEMP%`, `%APPDATA%`, or the current working directory.

- No Direct Modification of Application Binary:
    The attacker cannot modify the application itself (e.g., alter the executable or directly inject code into the application binary), but they may influence the dynamic loading of dependencies.


#### Potential Attacks:

- Local Privilege Escalation:
    If an attacker can load a malicious DLL from a trusted directory (or manipulate the search order), they could escalate their privileges, potentially executing code with higher system privileges (depending on the context in which the application runs).

- Arbitrary Code Execution in the Application Context:
    An attacker could trick the application into loading their malicious DLL, which could then execute arbitrary code. This code could be designed to do anything from data theft to system manipulation within the context of the vulnerable application.

- Persistence Mechanisms:
    Malicious DLLs could be used as part of persistence mechanisms. By hijacking DLL loading, an attacker might ensure that their malicious code runs every time the application is launched, even if the original infection vector is removed.


> Note: These vulnerabilities primarily exist in applications that don't harden their DLL loading behavior (e.g., relying on the default search order or not using absolute paths). Applications that do harden their loading process (e.g., by using `SafeDllSearchMode` or specifying absolute paths for DLLs) are less vulnerable to such attacks.


### Tools

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


### Expected Findings

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

## Testing Methodology - #TO-DO

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



## References
- OWASP Desktop Application Security Top 10
- Microsoft: Dynamic-Link Library Search Order
- Microsoft: SetDefaultDllDirectories API
- Sysinternals Process Monitor Documentation
