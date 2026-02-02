# Minimal OAuth 2.0 + PKCE End-to-End Example (Auth Server + SPA + Resource API)

A runnable, debuggable OAuth 2.0 Authorization Code + PKCE example with multi-tenancy, scope enforcement, and JWT validation.

This repository includes:

* An **Authorization Server**
* A **Single Page Application (SPA) Client**
* A **Resource API**

The goal is clarity and observability, not production hardening. This project is designed to help you step through the full flow in a debugger and understand how the pieces fit together.

---

## What This Demonstrates

* OAuth 2.0 Authorization Code Flow
* PKCE (Proof Key for Code Exchange)
* Multi-tenancy concepts
* App registrations
* Scope issuance and enforcement
* JWT signing and validation
* Audience validation in a protected API

---

# Run the Lab

You can run this in two modes:

* **Debug Mode (recommended for learning)**: run each service individually and set breakpoints.
* **Docker Mode**: run everything with one command.

---

## Debug Mode (VS Code – Recommended)

Open three terminals in the repository root.

### Terminal 1 – Authorization Server

```bash
cd AuthServer
dotnet run
# Listening on: http://localhost:5001
```

### Terminal 2 – Resource API

```bash
cd ResourceServer
dotnet run
# Listening on: http://localhost:5002
```

### Terminal 3 – SPA Client

```bash
cd WebClientServer
dotnet run
# Listening on: http://localhost:5003
```

Then open:

```
http://localhost:5003
```

### Suggested Breakpoints

* `AuthServer/AuthorizationCodeHandler.cs`: where the authorization code is created and where the `code_challenge` is validated
* `AuthServer/JwtHandler.cs`: where the JWT is generated and signed
* `ResourceServer/JwtValidator.cs`: where the JWT is decoded and `aud` + `scope` are validated

Step through the flow and observe the values moving between components.

---

## Docker Mode

```bash
docker compose up --build
```

### Default Ports

* Authorization Server: [http://localhost:5001](http://localhost:5001)
* Resource API: [http://localhost:5002](http://localhost:5002)
* SPA Client: [http://localhost:5003](http://localhost:5003)

---

# The OAuth 2.0 + PKCE Flow

```
Browser              SPA Client              Auth Server             Resource API
  │                      │                        │                        │
  │ Click Login          │                        │                        │
  ├─────────────────────>│                        │                        │
  │                      │ GET /authorize         │                        │
  │                      ├───────────────────────>│                        │
  │                      │                        │ stores code_challenge  |
  │                      │                        │                        │
  │                      │<───────────────────────┤ 302 redirect + code    │
  │                      │                        │                        │
  │                      │ POST /token            │                        │
  │                      ├───────────────────────>│ validate code_verifier │
  │                      │                        │ issue JWT              │
  │                      │<───────────────────────┤ access_token           │
  │                      │                        │                        │
  │                      │ GET /api/resource      │                        │
  │                      │ Authorization: Bearer JWT                       │
  │                      ├────────────────────────────────────────────────>│
  │                      │                        │ validate aud + scope   │
  │                      │<────────────────────────────────────────────────┤
  │ Display data         │                        │                        │
```

PKCE occurs in two steps:

1. The SPA sends a `code_challenge` (derived from a `code_verifier`) to `/authorize`.
2. The SPA later sends the original `code_verifier` to `/token`, where the server recomputes and validates it.

---

# What to Observe

These are the mechanics that matter.

## 1. Code Challenge (Authorization Request)

* Inspect the request to `/authorize`.
* Note the `code_challenge` and `state` parameters.
* In `AuthorizationCodeHandler.cs`, observe how the challenge is stored.

## 2. Code Verifier (Token Request)

* Inspect the POST to `/token`.
* Observe the `code_verifier`.
* The server hashes it and compares it to the stored `code_challenge`.
* If they do not match, the request is rejected.

## 3. JWT Structure

* Copy the `access_token`.
* Decode it at [https://jwt.io](https://jwt.io).
* Observe claims such as:

  * `aud` (audience)
  * `scope`
  * `sub` (subject)
  * `iat`, `exp`

## 4. Scope Enforcement

* Request a token with different scopes (e.g., `read`, `write`).
* Decode the JWT.
* Observe how scope claims appear.
* Watch how the Resource API checks them.

## 5. Audience Validation

* Inspect `JwtValidator.cs`.
* The API validates that `aud` matches its configured identifier.
* This prevents tokens intended for one API from being used on another.

---

# Break It On Purpose

Modify the system and observe failures. This is where real understanding happens.

## 1. Change the Redirect URI

* Modify the redirect URI in the SPA request.
* The Authorization Server will reject it.
* Why: authorization codes are bound to registered redirect URIs.

## 2. Modify the Code Verifier

* Change the `code_verifier` before sending it to `/token`.
* The server rejects the request.
* Why: PKCE prevents authorization code interception attacks.

## 3. Remove a Scope

* Request fewer scopes.
* Decode the JWT and observe missing claims.
* Call an endpoint requiring the removed scope.
* The API rejects it.

## 4. Use an Expired Token

* Observe the `exp` claim.
* Wait until expiration or simulate clock drift.
* The API rejects the token.

## 5. Change the Audience

* Modify the `aud` claim during token generation.
* Call the Resource API.
* The request fails audience validation.

---

# References

* OAuth 2.0 (RFC 6749): [https://www.rfc-editor.org/rfc/rfc6749](https://www.rfc-editor.org/rfc/rfc6749)
* PKCE (RFC 7636): [https://www.rfc-editor.org/rfc/rfc7636](https://www.rfc-editor.org/rfc/rfc7636)
* JWT (RFC 7519): [https://www.rfc-editor.org/rfc/rfc7519](https://www.rfc-editor.org/rfc/rfc7519)
* Microsoft Identity Platform – Authorization Code Flow: [https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)

---

This repository is intentionally minimal and focused on clarity. It is not intended for direct production use without additional security hardening.
