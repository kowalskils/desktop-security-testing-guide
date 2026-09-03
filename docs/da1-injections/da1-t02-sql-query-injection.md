# SQL Query Injection

| Field | Value |
| --- | --- |
| Test Case ID | DA1-T02 |
| Primary OWASP Category | DA1 - Injections |
| Secondary Categories | DA3 - Sensitive Data Exposure; DA5 - Improper Authorization |
| Platforms | Native Win32, .NET, and Electron applications using local or remote SQL databases |

## Scope

This test validates separation of SQL syntax from untrusted data in searches, filters, reports, imports, exports, saved preferences, offline queues, and synchronization. Include embedded databases, direct database connections, and SQL-consuming services invoked by the desktop.

NoSQL operators, LDAP filters, XPath, and rendered content require parser-specific tests and are outside this chapter. A desktop request can expose a service-side defect; identify the component that constructs the unsafe query.

## Objective and Threat Model

Determine whether an attacker-controlled value changes SQL structure or semantics beyond the operation permitted by the application. Consider input from the UI, imported files, IPC, synchronized records, and previously stored values reused in later queries.

Define the attacker account, intended record scope, database principal, and target operation. Parameterization does not provide authorization: a safely bound record ID can still reference another user's data. Conversely, direct modification of an owner-writable local database is not automatically SQL injection.

## Prerequisites and Safety

- Use a disposable database containing only synthetic records and preserve its baseline.
- Obtain authorization for each local database and remote test service. A desktop assessment does not authorize testing a production database.
- Record application, database, provider/driver, ORM, schema, and deployment versions.
- Prefer bounded read-only queries. Use write-path tests only on approved fixtures; rollback is not a universal safety guarantee because triggers or external effects may escape it.
- Do not extract real data, enumerate production schemas, issue destructive statements, invoke OS/database extensions, or use external callbacks.
- Avoid timing probes and expensive queries. Establish row, duration, and request limits.
- Capture only scoped synthetic query evidence; diagnostic SQL logging can expose secrets.

## Tools

Use source review, provider/ORM diagnostics, approved database traces, an authorized test-service proxy, and fixture result comparison. Process Monitor can identify a local database file but does not reveal its SQL statements.

Save SQL templates and parameter metadata separately when possible. Some diagnostic tools render bound parameters inline for display; an expanded log string alone does not establish string concatenation.

## Testing Methodology

### Step 1 - Trace Inputs to Query Construction

1. Inventory search fields, filter builders, sort/group selectors, report templates, import columns, IPC fields, and stored settings.
2. Identify where each input becomes a query: desktop process, local service, remote API, or stored procedure.
3. Record decoding, type conversion, normalization, validation, and any later reuse.
4. Distinguish values from identifiers and SQL fragments. Table names, column names, ordering direction, and operator choices require controlled construction rather than ordinary value binding.
5. For remote consumers, confirm server-side enforcement rather than relying on disabled UI controls.

### Step 2 - Establish Synthetic Controls

1. Create a small fixture with known IDs and text values, including a legitimate apostrophe, Unicode, and wildcard characters.
2. If relevant, create two synthetic users or tenants with explicitly different allowed records.
3. Record expected results for an exact match, no match, and each permitted filter.
4. Capture the query template, parameter names/types/values, returned IDs, and database/application identity where available.
5. Repeat the baseline to exclude caching, pagination, and asynchronous synchronization effects.

### Step 3 - Test Data Boundaries

1. Change one field at a time using quotes, parentheses, SQL-like text, empty/null values, numeric boundaries, and encoded equivalents valid for that entry point.
2. Compare the result with the documented search semantics and the fixture. Literal SQL-like input should remain data or be rejected without unintended query changes.
3. Use paired logical controls only after confirming the actual dialect and query context.
4. For an isolated equality-search fixture whose unsafe template would be SELECT Id FROM Records WHERE Name = '<input>', compare these two read-only values:

~~~text
DSTG-ALPHA' AND '1'='1
DSTG-ALPHA' AND '1'='2
~~~

The fixture must contain DSTG-ALPHA and no row named after either full test string. In that specific concatenated template, the controls change the predicate while keeping the query read-only. With value binding, both are literal names and should not match. This is a teaching fixture, not a universal payload for unknown queries.

5. Corroborate any difference with template/parameter evidence or repeated controlled behavior. Do not infer injection from a single syntax error.
6. Distinguish LIKE wildcard behavior from SQL syntax injection. Broad matching may be intentional, or a separate search-policy defect, even when values are safely bound.

### Step 4 - Inspect Dynamic Structure

1. Test sort column, direction, grouping, report selection, and dynamic field selectors against the documented allowed set.
2. Verify user choices map to fixed trusted expressions rather than becoming raw query text.
3. Exercise list filters and pagination with bounded values. Check placeholder generation and binding for each list element.
4. Inspect raw SQL escape hatches inside otherwise safe ORM workflows.
5. Review stored procedures that construct dynamic SQL; invoking a procedure through parameters does not secure SQL concatenated inside it.
6. Treat intended query-builder features according to their contract. An authorized report designer accepting expressions is not automatically a vulnerability; prove an unintended capability or boundary violation.

### Step 5 - Test Stored and Delayed Inputs

1. Store a uniquely labeled SQL-like value through an authorized fixture workflow.
2. Confirm it was initially stored as data.
3. Trigger its later use in a search, export, report, background task, or synchronization step.
4. Observe whether the later consumer binds it again or incorporates it into query syntax.
5. Capture both stages and the final consumer identity. Safe insertion does not make stored content safe for later concatenation.

### Step 6 - Apply Technology-Specific Checks

- Native SQLite: inspect prepared statements and sqlite3_bind_* use. Preparing an already concatenated string is not parameterization; binding applies to placeholders in the statement.
- Other native drivers: inspect the exact ODBC/OLE DB or vendor provider's binding API and parameter ordering/type behavior. Do not assume all drivers use identical placeholder syntax.
- .NET: inspect command parameters and types, dynamic SQL, and raw ORM APIs. EF Core parameter-aware APIs can preserve values as parameters, while raw SQL with preconstructed strings needs separate review. API names and overloads vary with the installed version.
- Microsoft.Data.Sqlite: verify values are supplied through supported parameter placeholders. Parameters represent literal values, not arbitrary SQL syntax.
- Electron: identify the actual SQLite/database module or back-end service, then review its documented binding mechanism. An IPC bridge or JavaScript string template does not itself provide SQL parameterization.

### Step 7 - Confirm Impact and Retest

1. Record the minimal input and demonstrated change: predicate alteration, unintended records, or another unauthorized query operation.
2. Separate SQL injection from missing row/tenant authorization and from expected wildcard behavior. Report multiple proven defects separately.
3. Review database privileges without exercising dangerous capabilities. A read-only account limits writes but does not prevent injected reads.
4. After remediation, repeat paired controls, legitimate apostrophes/Unicode, dynamic selectors, and delayed-use cases.
5. Confirm the executed structure and allowed record scope remain correct. A fix that rejects one marker but still concatenates other values is insufficient.
6. Restore the disposable database and remove only approved fixtures. Preserve sanitized evidence and regression inputs.

## Evidence to Collect

Retain fixture schema/data, expected and observed result IDs, exact inputs and encoding, query construction location, templates and binding evidence, driver/ORM versions, principal/tenant context, delayed-use sequence, and before/after results. State inaccessible server-side observations explicitly.

## Pass/Fail Criteria

### Pass

In the tested workflows, untrusted values remain bound data or are rejected safely, structural choices map to authorized expressions, and delayed consumers preserve the same separation. Legitimate inputs and required authorization boundaries remain functional.

### Fail

Fail when reproducible evidence shows untrusted input changes SQL beyond the authorized operation. Describe the actual result and executing principal; do not claim database takeover or OS execution without evidence.

### Needs Further Investigation

Use for isolated errors, ambiguous result differences, unknown dialects, diagnostic display expansion, or unavailable query-construction evidence. An unverified scanner alert is not a confirmed injection.

## Expected Findings

- A local search concatenates a text field despite using prepared statements elsewhere.
- A raw sorting clause accepts arbitrary user-controlled structure.
- A report later concatenates a value that was safely stored earlier.
- A parameterized procedure constructs unsafe dynamic SQL internally.
- Legitimate apostrophes remain searchable while SQL-like fixture inputs stay literal: expected behavior.

## Remediation Guidance

- Bind values using the actual provider's supported APIs, including delayed consumers.
- Map dynamic identifiers and operators to fixed authorized choices.
- Avoid concatenation in raw ORM queries and stored-procedure internals.
- Apply least-privilege database access and enforce row/tenant authorization independently.
- Treat wildcard semantics separately when literal matching is required.
- Add fixture-based regression checks for query structure, result scope, and legitimate edge-case input.

## References

- [OWASP: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Microsoft: EF Core SQL queries](https://learn.microsoft.com/en-us/ef/core/querying/sql-queries)
- [Microsoft: Microsoft.Data.Sqlite parameters](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/parameters)
- [SQLite: binding values to prepared statements](https://www.sqlite.org/c3ref/bind_blob.html)
