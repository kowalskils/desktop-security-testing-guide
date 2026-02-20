# DLL Hijacking and Unsafe Dependency Loading

## Scope
This doc describes how to identify and assess DLL hijacking, search-order hijacking, and unsafe dependency loading issues in Windows desktop applications.

It's applicable for:
- Native Win32 applications
- .NET applications (WinForms, WPF, mixed-mode)
- Electron-based Windows applications

Obs.: The focus is on security testing and risk identification, not exploitation.


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


## Testing Methodology - #TO-DO

#### Expected findings 
- All DLLs are loaded from:
  - Application installation directory
  - Windows system directories
  - Other trusted, non-writable locations

- No DLL load attempts from:
  - Current working directory
  - User-writable paths (e.g., `%TEMP%`, `%APPDATA%`)


## References
- OWASP Desktop Application Security Top 10
- Microsoft: Dynamic-Link Library Search Order
- Microsoft: SetDefaultDllDirectories API
- Sysinternals Process Monitor Documentation
