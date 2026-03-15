# Repository Improvements

## Completed

- [x] Authorization codes not invalidated after use (RFC 6749 §4.1.2 requires one-time use)
  - Added `IsRedeemed` flag to `AuthorizationCodeRecord`
  - `ValidateCode` now marks codes as redeemed and rejects reuse
- [x] Authorization codes never expire (should expire after ~10 minutes)
  - Added `CreatedAt` timestamp to `AuthorizationCodeRecord`
  - `ValidateCode` rejects codes older than 10 minutes
- [x] HTML template injection / XSS in login form (query params embedded without escaping)
  - All user-supplied values in the login form are now HTML-encoded via `WebUtility.HtmlEncode`
- [x] State parameter ignored (CSRF protection gap)
  - Client generates a random `state` parameter, stores it in sessionStorage
  - Auth server passes `state` through the login form and redirect
  - Client validates `state` on callback to detect CSRF attacks
- [x] No tests (add basic test suite for PKCE validation and JWT round-trip)
  - Added `AuthServer.Tests` xUnit project with tests for:
    - PKCE code generation and validation (correct verifier, wrong verifier, invalid code)
    - One-time use enforcement (second redemption returns null)
    - Unique code generation
    - JWT structure, claims, signature verification, and expiration
- [x] sessionStorage token storage lacks security comment noting XSS trade-off
  - Added security note recommending BFF pattern, HTTP-only cookies, and CSP
