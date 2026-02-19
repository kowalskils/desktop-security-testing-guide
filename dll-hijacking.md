# DLL Hijacking and Unsafe Dependency Loading

## Scope
This doc describes how to identify and assess DLL hijacking, search-order hijacking, and unsafe dependency loading issues in Windows desktop applications.

It's applicable for:
- Native Win32 applications
- .NET applications (WinForms, WPF, mixed-mode)
- Electron-based Windows applications

Obs.: The focus is on security testing and risk identification, not exploitation.

## References
- OWASP Desktop Application Security Top 10
- Microsoft: Dynamic-Link Library Search Order
- Microsoft: SetDefaultDllDirectories API
- Sysinternals Process Monitor Documentation
