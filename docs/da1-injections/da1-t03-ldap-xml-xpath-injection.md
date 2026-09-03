# LDAP, XML, and XPath Injection

| Field | Value |
| --- | --- |
| Test Case ID | DA1-T03 |
| Primary OWASP Category | DA1 - Injections |
| Secondary Categories | DA3 - Sensitive Data Exposure; DA5 - Improper Authorization; DA6 - Security Misconfiguration |
| Platforms | Native Win32, .NET, Electron, and Windows application services |

## Scope

This chapter contains three independently assessed tracks: LDAP query/name construction, XML structure and external-resource processing, and XPath expression construction. Include directory lookup, configuration import, XML reports, document processing, and service requests initiated by a desktop application.

External entity resolution is not the same defect as changing an XPath predicate. Report the actual parser and mechanism. Use [DA6-T02](../da6-security-misconfiguration/da6-t02-file-handler-uri-parser.md) for activation and parser configuration, and [DA1-T02](da1-t02-sql-query-injection.md) for SQL.

## Objective and Threat Model

Determine whether untrusted data becomes query syntax, alters document structure, selects unintended directory entries or XML nodes, or causes unauthorized resource access.

Record the input source, parser/version, validation point, consumer identity, and authorized result scope. Consider imported files, IPC values, synchronized content, and values stored for later use. Distinguish a malformed-input error from a demonstrated boundary violation.

## Prerequisites and Safety

- Use a disposable Windows environment and synthetic XML documents and directory entries.
- Obtain separate authorization for any directory server or remote consumer. Do not query or modify a production Active Directory tree for proof.
- Keep LDAP tests read-only and constrain base DN, scope, result count, and timeout.
- Use only a dedicated synthetic marker file for local XML resolution tests. Never target credentials, system files, or unrelated user documents.
- Block external access by default. Use a controlled lab listener only when network resolution testing is explicitly approved; do not use public callbacks or UNC paths that may transmit credentials.
- Do not use exponential entity expansion or machine-wide resource exhaustion. Apply small input, depth, time, and result limits.
- Preserve originals and record test-only configuration differences.

## Tools

Use source review, parser/library diagnostics, approved LDAP query traces, XML-aware tree inspection, XPath evaluation diagnostics, and scoped file/network observation. A different parser used in a standalone harness illustrates behavior but does not validate the shipped application's configuration.

## Testing Methodology

### Step 1 - Map Each Interpretation Boundary

1. Identify directory filters, distinguished names, XML writers/readers, XPath evaluators, schema validators, and transformation engines.
2. Record decoding and normalization order, query templates, namespaces, search base, and consumer privileges.
3. Determine whether data is interpreted more than once, such as an imported XML value later inserted into XPath.
4. Identify the actual native, .NET, or Node module and version. Electron itself does not define every XML or LDAP parser's security defaults.
5. Establish a valid baseline and known no-match case for each applicable track. Mark unsupported tracks not applicable with a rationale rather than passing them implicitly.

### Step 2 - Validate LDAP Search Filters

1. Populate an approved test subtree with distinguishable entries, including a literal asterisk value if the chosen attribute permits it.
2. Exercise an exact-match search using a normal value, a no-match value, an asterisk, parentheses, backslashes, and valid Unicode.
3. Capture the constructed filter and returned entry identifiers. Verify escaping at the assertion-value boundary rather than applying escaping to the entire completed filter.
4. For a field intended as an exact cn value, compare the intended literal-star filter with a presence filter:

~~~text
(cn=\2a)
(cn=*)
~~~

The first represents a literal asterisk assertion value; the second asks for entries containing cn. If a user-supplied asterisk unexpectedly creates the second form, investigate unauthorized query broadening. A documented wildcard-search feature is not automatically injection.

5. Keep attribute names, Boolean structure, base DN, and search scope controlled by trusted application choices.
6. Verify that any decoded or stored input receives the correct treatment when a later query is built. An LDAP bind or TLS connection does not make string concatenation safe.

### Step 3 - Validate Distinguished Name Construction

1. Identify values inserted into a DN or relative DN rather than a search filter.
2. Test valid synthetic names containing commas, plus signs, leading/trailing spaces, and a leading number sign where supported.
3. Inspect the resulting name and selected entry. Confirm one intended value does not introduce another name component or redirect the operation.
4. Apply DN-specific construction rules; filter escaping and DN escaping are not interchangeable.
5. If the application intentionally accepts complete DNs, separately validate allowed directory scope and authorization.

### Step 4 - Validate XML Structure

1. Trace where untrusted text becomes element content, an attribute value, a node name, or a complete document.
2. Test bounded values containing angle brackets, ampersands, quotes, and Unicode through the normal input path.
3. Compare the resulting parsed tree with the expected tree. One data value must not become an additional trusted element or attribute.
4. Review serializers and XML writer APIs; raw string concatenation needs separate scrutiny.
5. Distinguish an intended user-supplied XML document from a field intended only as text. Schema validity alone does not establish authorization or prevent resource resolution during parsing.

### Step 5 - Validate External Resources

1. Record DTD processing, resolver behavior, entity handling, and resource limits for the exact reader and every later validation/transformation stage.
2. Submit a valid document without a DTD as a positive control.
3. Use a small internal-entity fixture to observe DTD handling without external access. Acceptance of an internal entity does not prove external entity exposure.
4. Where explicitly authorized, use a single external entity referencing only the dedicated marker file. Record whether access was attempted, succeeded, and whether marker content reached the parsed result or output.
5. Distinguish denied OS access from parser-level prohibition. A blocked read does not prove the resolver would reject all other resources.
6. Inspect external schemas, XInclude, and transformation document loading separately where implemented; disabling external entities in one reader does not certify every resource-loading feature.
7. For .NET XmlReader-based paths, verify explicit DtdProcessing and XmlResolver settings. DtdProcessing.Prohibit rejects DTDs; a null resolver prevents that reader from resolving external resources. Recheck settings when wrappers or later stages create another reader.

If a business feature requires resolution, test its narrowly permitted resource policy instead of imposing an unsupported blanket requirement. Use bounded fixtures and record skipped dynamic checks.

### Step 6 - Validate XPath Construction

1. Prepare a small XML fixture with known node IDs and text containing legitimate apostrophes and double quotes.
2. Identify the XPath version, expression template, context node, and namespace bindings.
3. Where values are concatenated into predicates, use paired read-only controls matched to that expression.
4. For the isolated template /records/record[name='<input>'], with one name DSTG-ALPHA and neither complete control string stored as a name, compare:

~~~text
DSTG-ALPHA' and '1'='1
DSTG-ALPHA' and '1'='2
~~~

These controls change the predicate only in that concatenated context. Properly supplied data values should remain literal names. Do not copy SQL escaping rules into XPath or assume every XPath API exposes variable binding.

5. Prefer fixed expressions with supported variable binding, or fixed tree traversal with value comparison. Compiling a concatenated expression does not parameterize it.
6. Check node names, paths, and user-selected expressions against the intended feature contract.
7. Confirm result changes are not namespace errors, context-node differences, caching, or missing authorization.

### Step 7 - Confirm and Retest

1. Record the minimal input, expected and observed filter/tree/node set, actual consumer, and affected boundary.
2. Distinguish query broadening, structure injection, attempted resolution, successful marker reading, and downstream disclosure. Do not claim effects that were not observed.
3. Repeat relevant cases after remediation, including legitimate punctuation and Unicode.
4. Test stored/delayed values and alternate import or IPC paths.
5. Restore approved configuration and remove only synthetic fixtures. Preserve sanitized traces and regression cases.

## Evidence to Collect

Retain parser/library versions, input bytes and encoding, query/name templates, resulting LDAP filters and entry IDs, XML tree comparisons, XPath expressions and node IDs, resolver settings, marker access observations, privileges, controls, and retest results.

## Pass/Fail Criteria

### Pass

For each applicable track, data remains in its intended context, query/document structure stays within the authorized operation, and external resources are rejected or constrained by a validated policy. Report track-specific coverage and limitations.

### Fail

Fail for demonstrated unauthorized directory query/name changes, XML structure changes, XPath selection changes, or resource access beyond the defined policy. Explain the actual result and account rather than equating every parser error with exploitation.

### Needs Further Investigation

Use for ambiguous results, inaccessible query construction, unknown parser settings, blocked-but-attempted resource access with uncertain policy, or a harness that does not match the released consumer.

## Expected Findings

- A literal LDAP value becomes a presence or compound filter.
- A DN value is escaped using filter rules and changes the target name.
- XML text introduces an unintended trusted element.
- A later reader resolves resources despite restrictions in the initial parser.
- A stored value alters a later XPath predicate.

## Remediation Guidance

- Use context-specific LDAP filter and DN construction mechanisms.
- Keep query structure and directory scope separate from untrusted values.
- Use XML serializers/writers for text and attribute values.
- Disable unnecessary DTD/resource features explicitly at every processing stage.
- Use fixed XPath expressions with supported binding or safe tree/value comparison.
- Preserve least privilege and authorization independently of injection controls.
- Add bounded regression fixtures for each parser context and delayed consumer.

## References

- [OWASP: LDAP Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
- [RFC 4515: LDAP search filters](https://www.rfc-editor.org/rfc/rfc4515)
- [RFC 4514: LDAP distinguished names](https://www.rfc-editor.org/rfc/rfc4514)
- [OWASP: XML External Entity Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [Microsoft: DtdProcessing](https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreadersettings.dtdprocessing)
- [Microsoft: XmlResolver](https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreadersettings.xmlresolver)
- [W3C: XPath 1.0](https://www.w3.org/TR/xpath-10/)
