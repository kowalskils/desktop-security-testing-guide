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


## Objective

Determine whether an application:

* Loads DLLs from unsafe or user-writable locations
* Uses relative paths instead of absolute paths when loading dependencies
* Relies on default Windows DLL search order without hardening

**Goal:** Ensure all dynamic dependencies are loaded securely from trusted locations.

## Threat Model
* Local attacker with the ability to write files to user-writable directories
* Attacker cannot modify the application binary directly
* Attacker attempts to influence DLL resolution to execute unintended code

Such issues commonly lead to:
* Local privilege escalation
* Arbitrary code execution in application context
* Persistence mechanisms



## Toools
Dependency Walker
Sigcheck
Powershell
ProcMon
ProcXP



### Tools

1. **Dependency Walker**
   * **Purpose**: Identifies missing dependencies in executable files and helps track down DLLs that an application relies on.
   * **Usage**: Useful for mapping out the entire chain of DLL dependencies and checking if any are loaded from untrusted locations, which is a key vector in DLL hijacking.

2. **Sigcheck**
   * **Purpose**: A command-line utility from Sysinternals used to verify the authenticity and integrity of executables and DLLs.
   * **Usage**: Helps ensure that the loaded DLLs are digitally signed and haven't been tampered with. In the context of hijacking, you’d look for unsigned or suspiciously modified DLLs.

3. **PowerShell**
   * **Purpose**: A powerful scripting language for automating tasks, including security analysis.
   * **Usage**: Can be used to script the inspection of DLL load paths, automate the search for hijacked DLLs, and gather system information. Custom scripts can be written to analyze loaded DLLs, check their hashes, or automate the process of comparing them against known safe lists.

4. **ProcMon (Process Monitor)**
   * **Purpose**: A tool for real-time file system, registry, and process/thread activity monitoring.
   * **Usage**: Vital for capturing DLL loading events in real-time. It can help identify DLLs being loaded from potentially insecure paths or unexpected directories (e.g., the current working directory). Monitoring for unexpected loads can help detect hijacking attempts in progress.

5. **ProcXP (Process Explorer)**
   * **Purpose**: Displays detailed information about processes and their associated handles and DLLs.
   * **Usage**: You can use ProcXP to inspect the full list of loaded DLLs for any process in real-time and verify their source. It's crucial for identifying unusual or unauthorized DLLs loaded by an application.


### Expected Findings

* **Normal DLL Load Locations:**
  * **Application Installation Directory**:
    The DLLs associated with a given application should be located in the directory where the application was installed. This is a trusted location controlled by the application, ensuring that the correct versions of DLLs are used.

  * **Windows System Directories**:
    The Windows system directories (e.g., `C:\Windows\System32` or `C:\Windows\SysWow64`) are generally reserved for system-provided DLLs. These directories should be trusted, and any attempt to load DLLs from here should be scrutinized for legitimacy.

  * **Other Trusted Locations**:
    This might include directories defined by security policies (e.g., network share directories with restricted access) or non-writable application-specific directories. If these directories are writable, they might become a target for attackers.

* **Unusual DLL Load Locations (Potential Indicators of Hijacking):**
  * **Current Working Directory**:
    This is one of the most common locations targeted for DLL hijacking. Attackers often place malicious DLLs in the current working directory, knowing that a vulnerable application will search here before system directories.

  * **User-Writable Paths**:
    Directories such as `%TEMP%`, `%APPDATA%`, `%USERPROFILE%`, or any other locations that users have write access to are also common targets. These paths often allow attackers to drop a malicious DLL that will be loaded by the vulnerable application.

  * **DLLs Loaded from Non-Writable Locations**:
    Anomalies such as DLLs loaded from directories that should be non-writable (e.g., system directories, certain application directories) can indicate that the attacker has escalated privileges or exploited a vulnerability.

### Expected findings 
- All DLLs are loaded from:
  - Application installation directory
  - Windows system directories
  - Other trusted, non-writable locations

- No DLL load attempts from:
  - Current working directory
  - User-writable paths (e.g., `%TEMP%`, `%APPDATA%`)

## Testing Methodology - #TO-DO

## References
- OWASP Desktop Application Security Top 10
- Microsoft: Dynamic-Link Library Search Order
- Microsoft: SetDefaultDllDirectories API
- Sysinternals Process Monitor Documentation
