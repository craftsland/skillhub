# Generic Exception Log User Attribution Design

## Scope

Issue ISSUE-112 removes stable platform user identifiers from generic operational exception logs. API responses, dedicated audit records, metrics, authentication behavior, and request-body redaction remain unchanged.

## Design

`GlobalExceptionHandler` will replace the `userId` field in handled, unhandled, and object-storage failure log messages with an `authentication` field whose value is either `authenticated` or `anonymous`. The value is derived only from whether the servlet request exposes an authenticated Spring Security principal; no principal name or platform user ID is formatted.

This keeps request ID, status, method, sanitized path, error code, storage operation, and storage key diagnostics intact while making the identity dimension low-cardinality.

## Testing

Focused unit tests will attach an in-memory appender to the handler logger and exercise authenticated and anonymous failures. Assertions will verify that formatted messages retain correlation and diagnosis fields, expose the expected authentication state, and never contain the authenticated principal's stable user ID. Account-merge handled failures will use the same generic logging path, so representative 401, 409, and 503 responses will be checked without changing response behavior.
