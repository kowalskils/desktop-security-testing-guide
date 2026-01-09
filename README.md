# Desktop Security Testing Guide (based on OWASP Top 10 Desktop Application Security Risks)

### Description
Although OWASP provides testing guides for web and mobile applications, there is currently no comprehensive, structured methodology for assessing the security of Windows desktop applications. Organizations developing thick-client applications lack vendor-neutral best practices and repeatable testing procedures, leading to inconsistent security assessments and preventable vulnerabilities.

This project addresses the gap between the OWASP Desktop Application Security Top 10 and real-world security testing practice, as well the lack of a proper security testing guide for these applications.

No current OWASP project delivers this as a security testing methodology

## Why This Project Exists
Desktop applications remain critical across industries such as:
- Finance
- Healthcare
- Industrial software
- Security tooling
- Enterprise internal systems

However, security testing for these applications is often:
- Ad-hoc
- Tool-driven without methodology
- Dependent on undocumented tribal knowledge

This leads to:
- Inconsistent assessments
- Missed vulnerabilities
- High-impact local and supply-chain security risks

### OWASP Email Address
Related OWASP email address: **luis.stefan@owasp.org**

Related Top Ten: https://owasp.org/www-project-desktop-app-security-top-10/


## Project Purpose
The purpose of this project is to produce a practical, repeatable, and accessible security testing methodology for Windows desktop applications, designed for:
- Penetration testers
- Red teamers
- Application security engineers
- Software engineers building secure desktop software


### Project Deliverables*
This project will provide a structured Security Testing Guide (similar format to OWASP WSTG and MSTG) for Desktop (Windows .NET) applications.
- Windows-specific security testing workflows 
- Tools and repeatable test procedures 
- Remediation patterns developers can apply immediately

Covering step-by-step security tests for:
-	Memory analysis
-	Binary & resource inspection
-	DLL hijacking risk validation
-	Local storage and registry security
-	Dependency and SBOM hygiene

License https://creativecommons.org/licenses/by-sa/4.0/ - CC BY-SA
