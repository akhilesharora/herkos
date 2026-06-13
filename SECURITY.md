# Security

Herkos is a reference implementation of a deny-by-default MCP broker with a signed audit log.
It is honest about its limits: the security model publishes exactly what gets past it (the
Security page, `site/docs/security.html`). Read that first.

## Reporting a vulnerability or a bypass

If you find a way past the broker, the content gate, or the audit log that is not already on
the published bypass list, that is the kind of report worth filing.

- For a non-sensitive bypass (something already possible by design that the docs fail to
  mention), open a public issue using the "Bypass / false negative" template.
- For a sensitive issue (a way to forge a signed receipt, defeat the fail-closed invariant, or
  otherwise break a stated guarantee), email the maintainer rather than opening a public issue,
  and allow a reasonable window before disclosure.

Include the version or commit, the exact config or input, what you expected, and what
happened. A reproduction beats a description.

## Scope

Herkos enforces in userspace by default; `serve --isolate` adds a kernel network namespace on
Linux. It does not claim to stop prompt injection, and it cannot mediate HTTP/SSE remote MCP
servers (the broker is stdio-only). These are documented limits, not vulnerabilities.
