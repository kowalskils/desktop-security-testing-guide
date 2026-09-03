# Rendered Content Injection and Native Bridge Boundaries

| Field | Value |
| --- | --- |
| Test Case ID | DA1-T04 |
| Primary OWASP Category | DA1 - Injections |
| Secondary Categories | DA3 - Sensitive Data Exposure; DA5 - Improper Authorization; DA6 - Security Misconfiguration |
| Platforms | Electron, WebView2, and embedded HTML renderers in Windows desktop applications |

## Scope

This test follows untrusted content into HTML, DOM, JavaScript, URL, and template contexts. Include search results, messages, imported documents, Markdown previews, reports, notifications, error pages, and saved content rendered later.

It also evaluates the privileges available to affected content. Use [DA5-T03](../da5-improper-authorization/da5-t03-local-ipc.md) for detailed IPC authorization and [DA6-T02](../da6-security-misconfiguration/da6-t02-file-handler-uri-parser.md) for external activation. Server-side template execution requires a separate engine-specific assessment.

## Objective and Threat Model

Determine whether data is interpreted as unauthorized markup or script and whether the affected renderer can invoke capabilities beyond its intended trust level.

Record who controls the content, how it reaches another user or trusted view, the document origin, frame, process, account, and available bridge. Distinguish intended rendering of an untrusted HTML document in an isolated viewer from injection into trusted application UI.

HTML injection, renderer script execution, and native code execution are different findings. Do not infer native execution from a JavaScript marker or the mere presence of Electron.

## Prerequisites and Safety

- Use the release build in a disposable Windows environment with synthetic accounts and documents.
- Record Electron/Chromium or WebView2 runtime versions, renderer settings, content policy, navigation policy, and test-only overrides.
- Use inert visual or DOM markers. Do not read credentials, tokens, private files, clipboard contents, or real user records.
- Block external requests unless a specific lab destination is authorized. Avoid external image URLs, credential prompts, downloads, and custom schemes that launch other applications.
- Restrict bridge tests to an approved harmless operation or disposable fixture. Do not invoke generic shell, filesystem, or administrative operations for proof.
- Keep developer tools and debugger use observational. Manually executing code in a console is not evidence that application input can execute it.

## Tools

Use approved renderer inspection, source maps/source review where supplied, DOM snapshots, console/CSP diagnostics, and host-side IPC/message traces. Preserve the actual input path and execution context. An ordinary browser harness does not validate a desktop host's bridge or origin configuration.

## Testing Methodology

### Step 1 - Map Sources, Sinks, and Trust Levels

1. Inventory input from UI fields, documents, synchronization, IPC, URLs, metadata, and stored records.
2. Trace it through decoding, Markdown/template conversion, sanitization, and insertion into the rendered document.
3. Identify text-only APIs, HTML parsing sinks, event-handler construction, JavaScript evaluation, and URL-bearing attributes.
4. Record the origin, frame, process, navigation state, and privileges of every affected view, including previews and secondary windows.
5. Note deliberate rich-content features and their allowed markup. Rendering permitted formatting is not itself injection.

### Step 2 - Establish Literal and Markup Controls

1. Render a unique plain-text label through the normal workflow and confirm its location.
2. For a field intended only as text, submit an inert formatting fixture:

~~~html
<b data-dstg="render-01">DSTG-RENDER-01</b>
~~~

3. Inspect the DOM to distinguish literal text from a newly created element. If formatting is intended, compare against the documented allowed set instead.
4. Test quotes, ampersands, Unicode, and encoding boundaries one at a time. Record decoding after sanitization or repeated conversion.
5. Inspect resulting attributes and links without activating external targets.
6. Preserve valid rich-content controls so rejection of all input is not mistaken for a correct functional fix.

### Step 3 - Confirm Script Interpretation Safely

1. After identifying the insertion context, select a bounded context-appropriate fixture whose only effect is to set a unique DOM attribute or display an inert label.
2. Submit it through the real input source. Do not inject it manually through developer tools or host script-execution APIs.
3. Verify whether execution occurs automatically or requires a documented click, hover, reload, or later preview. Record the exact interaction.
4. Compare a non-executing literal control and repeat with a fresh marker.
5. Capture the responsible frame and script origin, DOM change, and applicable content-policy diagnostics.
6. Distinguish blocked execution from absent injection. CSP may prevent a particular script while unauthorized markup remains; report the supported effect.

Lack of execution from a single script tag is not a comprehensive XSS test: insertion mechanisms and policies differ. Do not disable the application's protections to manufacture a successful result.

### Step 4 - Test Context-Specific Handling

| Context | Validation target |
| --- | --- |
| Plain text | Data does not become DOM structure |
| Intended rich HTML/Markdown | Allowed formatting survives while unauthorized active content is removed |
| Attribute values | Input cannot create another attribute or handler |
| URLs | Parsed scheme and destination meet policy before activation |
| JavaScript/template source | Data is not concatenated into executable source |
| Stored content | Later views apply the same trust and sanitization rules |

1. Review sanitizer configuration and dependency version, not just its presence.
2. Check whether application code mutates or decodes sanitized content before insertion.
3. Exercise stored values after restart and in a second synthetic user's view where authorized.
4. Check export/preview and error paths that may use a different renderer or template.
5. Treat encoding as context-specific: HTML escaping does not automatically secure JavaScript or URL semantics.

### Step 5 - Evaluate Desktop Privileges

#### Electron

- Inspect actual settings for each window/view: Node integration, context isolation, sandboxing, preload code, and exposed contextBridge methods. Do not rely on defaults from another Electron version.
- Review navigation, new-window creation, permission handlers, and external-link handling.
- Check that host IPC handlers validate sender/frame context and authorize each operation.
- Context isolation separates JavaScript worlds; it does not remove a dangerous method deliberately exposed to page content.

#### WebView2

- Inventory web messaging, host objects, injected host scripts, and virtual-host mappings.
- Validate the message source and current document trust before acting on a web message.
- Verify navigation and frame changes do not leave privileged host objects or callbacks available to an unintended page.
- Inspect host script construction for untrusted data concatenated into executable JavaScript. Use supported structured messaging/serialization appropriately instead.

For both platforms, a valid origin is not sufficient authorization for every operation. Injected script in a trusted page may share that page's origin; validate operations and objects according to the application's threat model.

### Step 6 - Prove Only the Available Capability

1. From the affected content, test only a preapproved harmless bridge call, if one exists.
2. Capture host-side receipt, authorization decision, and result. A method name visible in JavaScript does not prove the operation succeeds.
3. Test the same operation from an intentionally untrusted lab frame or navigation state where supported and authorized.
4. If no safe operation exists, inspect the contract and report the remaining uncertainty. Do not escalate to shell execution merely to increase severity.
5. Record script execution separately from any proven host authorization weakness, with links to the same reproduction evidence.

### Step 7 - Retest and Restore

Repeat the original input, legitimate punctuation/formatting, stored-content path, and affected secondary views after remediation. Confirm restrictions work under normal release settings without debug overrides. Remove only synthetic records and fixtures; restore approved configuration and preserve sanitized evidence.

## Evidence to Collect

Retain exact inputs and encoding, source-to-sink trace, expected rendering contract, before/after DOM snapshots, script-marker evidence, frame/origin and user interaction, runtime/settings, sanitizer/CSP results, approved bridge outcomes, and remediation retests.

## Pass/Fail Criteria

### Pass

For the tested contexts, untrusted data remains text or permitted sanitized content, unauthorized script does not execute, and native capabilities remain limited to authorized operations and trusted contexts. State untested views and platform limits.

### Fail

Fail for reproducible unauthorized markup with demonstrated security impact, script execution through untrusted application input, or an unauthorized native bridge operation. Report each established boundary separately; absence of native execution does not make confirmed renderer XSS acceptable.

### Needs Further Investigation

Use for reflected strings without a confirmed sink, blocked probes with unclear remaining effects, developer-console-only execution, unknown rich-content policy, or a bridge whose actual authorization cannot be observed.

## Expected Findings

- A Markdown preview permits active content outside its formatting contract.
- A saved record is safe in the main view but executes script in an export preview.
- A context-isolated renderer exposes an overbroad privileged bridge.
- Navigation changes document trust without updating host-message restrictions.
- Text remains literal and permitted rich formatting survives sanitization: expected behavior.

## Remediation Guidance

- Use text-only insertion for text and maintained sanitization for intentionally supported HTML.
- Avoid building JavaScript from strings containing untrusted values.
- Validate URL semantics and limit navigation and secondary windows.
- Keep renderer privileges minimal and expose narrow, independently authorized host methods.
- Use CSP as defense in depth, not as a replacement for correct sinks and sanitization.
- Apply the same protections to stored content, previews, exports, errors, and alternate renderers.
- Add safe marker-based regression tests without production data or external callbacks.

## References

- [Electron: Security](https://www.electronjs.org/docs/latest/tutorial/security)
- [Microsoft: Develop secure WebView2 apps](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/security)
- [OWASP: DOM-based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [OWASP: Cross-Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
