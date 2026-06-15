# Product Requirements Document (PRD)
## Username & Password Validator

**Version:** 1.0
**Status:** Draft
**Owner:** TBD
**Last Updated:** June 2026

---

## 1. Overview

This document defines the requirements for a Username & Password Validator module. The module is responsible for validating user-provided credentials during registration, login, and password change flows, and for ensuring those credentials are stored and processed securely throughout their lifecycle.

The module must balance usability (clear, helpful feedback) with security (resistance to enumeration, brute-force, credential stuffing, and storage compromise).

---

## 2. Goals

- Enforce consistent, secure validation rules for usernames and passwords across all entry points (sign-up, login, password reset, password change).
- Prevent common attack vectors: enumeration, timing attacks, brute-force, credential stuffing, injection.
- Ensure passwords are never stored or transmitted in a recoverable form.
- Provide clear, non-leaky error messaging to end users.
- Be reusable as a shared library/service across applications.

### Non-Goals

- This PRD does not cover multi-factor authentication (MFA) design, though hooks for MFA should not be blocked by this module.
- This PRD does not cover session management or token issuance.

---

## 3. Username Requirements

### 3.1 Format Rules

| Rule | Requirement |
|---|---|
| Length | 3–20 characters |
| Allowed characters | Letters (a–z, A–Z), digits (0–9), underscore (`_`), hyphen (`-`) |
| Starting character | Must start with a letter |
| Case handling | Stored as entered, but compared case-insensitively (normalized to lowercase for uniqueness checks) |
| Reserved words | Reject usernames matching a configurable blocklist (e.g., `admin`, `root`, `support`, `system`) |
| Unicode | Restrict to ASCII alphanumeric + `_`/`-` to avoid homoglyph/impersonation attacks. If Unicode usernames are required, apply Unicode normalization (NFKC) before validation and storage |

### 3.2 Uniqueness Handling (Security-Aware)

- Username availability checks must not be used to enumerate accounts where usernames double as login identifiers and account existence is sensitive.
- If enumeration risk is high, consider decoupling "display username" from "login identifier," or rate-limit availability check endpoints.

---

## 4. Password Requirements

### 4.1 Format Rules

| Rule | Requirement |
|---|---|
| Minimum length | 12 characters |
| Maximum length | 128 characters (no artificial low cap — supports passphrases) |
| Character requirements | At least one uppercase, one lowercase, one digit, one special character (configurable; NIST guidance favors length over forced complexity) |
| Unicode support | Allow full Unicode (excluding spaces) so passphrases and non-English passwords are supported |
| Whitespace | Leading/trailing whitespace should be trimmed before validation; internal whitespace permitted |

### 4.2 Breach & Blocklist Checks

- Reject passwords found in known-breach databases (e.g., via the Have I Been Pwned Pwned Passwords API, using k-anonymity so the full password is never sent to a third party).
- Reject passwords that are identical or substantially similar to the username, email, or other profile fields.
- Maintain a blocklist of top common passwords (e.g., "password123", "qwerty123") rejected outright regardless of complexity score.

### 4.3 Password Strength Feedback

- Provide real-time strength feedback (e.g., weak/medium/strong) using an entropy-based estimator (such as zxcvbn) rather than rigid rule-counting, to encourage genuinely strong passwords without forcing predictable patterns.

---

## 5. Security Process Requirements

### 5.1 Password Storage

- **Hashing algorithm:** Argon2id (preferred) or bcrypt as fallback. Never use unsalted hashes, reversible encryption, or fast general-purpose hashes (MD5, SHA-1, SHA-256) for password storage.
- **Salting:** Each password must be hashed with a unique, cryptographically random salt, generated and stored per-record (most modern algorithms embed the salt in the hash output).
- **Work factor / cost parameters:** Configurable and periodically reviewed to keep pace with hardware improvements (e.g., Argon2id memory cost, iterations, parallelism tuned per current OWASP recommendations).
- **Rehashing on login:** If a stored hash uses outdated parameters, transparently rehash with current parameters on the user's next successful login.
- **No plaintext logging:** Passwords must never appear in logs, error messages, analytics events, or stack traces. Logging middleware must explicitly redact password fields.

### 5.2 Transmission Security

- All credential submission endpoints must require TLS (HTTPS) — no exceptions, including internal services.
- Passwords must not be passed as URL query parameters (avoid appearing in server/proxy logs).
- Consider client-side pre-hashing only as a defense-in-depth measure, not a substitute for server-side hashing (server must still hash whatever it receives).

### 5.3 Enumeration & Timing Attack Prevention

- Login failure messages must be generic: "Invalid username or password" — never distinguish "user not found" from "wrong password."
- When a username does not exist, the system must still perform a dummy password hash comparison (e.g., against a precomputed dummy hash) to keep response times consistent with valid-username attempts.
- Registration "username taken" checks must be rate-limited and/or use CAPTCHA after repeated checks to prevent enumeration sweeps.
- Password reset flows must respond identically regardless of whether the email/username exists ("If an account exists, a reset link has been sent").

### 5.4 Brute-Force & Credential Stuffing Protection

- **Rate limiting:** Limit login attempts per account (e.g., 5 attempts before temporary lockout) and per source IP/device.
- **Progressive delays:** Increase delay between attempts after repeated failures (exponential backoff).
- **CAPTCHA / challenge:** Trigger after a threshold of failed attempts.
- **Account lockout policy:** Temporary lockout (e.g., 15 minutes) rather than permanent, to avoid denial-of-service via deliberate lockout abuse. Notify the account owner of lockout events via a secondary channel (email).
- **Anomaly detection:** Flag and optionally challenge logins from new devices, IPs, or geographies.

### 5.5 Injection Prevention

- All username/password inputs must be passed to data stores via parameterized queries or ORM-safe methods — never via string concatenation into SQL/NoSQL queries.
- Usernames rendered in UI (profiles, mentions, admin panels) must be output-encoded to prevent stored XSS.

### 5.6 Input Validation Layering

- **Client-side validation:** Provides immediate UX feedback (format, length, strength meter) but is not trusted.
- **Server-side validation:** Authoritative; all rules in Sections 3–4 must be re-enforced server-side regardless of client checks.
- **API/service-layer validation:** If the validator is a shared library/service, it must validate inputs independent of any calling application's assumptions.

### 5.7 Audit & Monitoring

- Log authentication events (success, failure, lockout, password change, password reset) with timestamps, source IP, and user agent — without logging credential values.
- Alert on patterns indicating credential stuffing (high failure rates across many accounts from shared IP ranges) or targeted brute-force (high failure rates against a single account).
- Retain audit logs per data retention policy and applicable regulations (e.g., GDPR).

### 5.8 Session Token Management & Expiration

- **Token issuance:** On successful authentication, issue a session token (e.g., a signed JWT or an opaque, server-validated token) rather than re-validating the username/password on every request. This avoids repeated slow hashing operations (Argon2id) on each request, which protects against artificial latency from rapid/repeated login-like requests.
- **Idle timeout:** If no activity is detected for a configurable period (e.g., 15–30 minutes), the session automatically expires, regardless of the absolute timeout.
- **Absolute timeout:** Regardless of activity, a session expires after a maximum configurable duration (e.g., 12–24 hours), requiring full re-authentication.
- **Session expiration behavior:** When a session token expires or is rejected as invalid:
  - The server must reject the token and return an authentication-required response (not a generic error).
  - The client must discard the expired token and redirect the user to the login screen.
  - The user must re-authenticate (re-enter username and password) to obtain a new session token — effectively "restarting" the session.
- **Rapid/repeated login throttling:** Repeated login attempts (whether from automation or accidental rapid retries) must be throttled per Section 5.4 (rate limiting, progressive delays, lockout) independent of session token logic — session tokens do not bypass these protections, since each new login attempt still goes through full credential validation.
- **Token storage:** Session tokens must be stored securely on the client (e.g., `HttpOnly`, `Secure`, `SameSite=Strict` cookies, or secure platform-specific storage for mobile apps) — never in `localStorage` or other JavaScript-accessible storage, to reduce XSS-based token theft risk.
- **Token rotation:** On renewal (e.g., refresh-token flow), issue a new token and invalidate the old one to limit the value of a stolen token.
- **Server-side revocation:** Maintain the ability to invalidate active sessions server-side (e.g., on password change, logout, or detected compromise), even for stateless tokens (via a denylist/short expiry + refresh model).
- **Re-authentication after expiration:** After a session expires and the user re-authenticates, treat it as a new login event for audit/monitoring purposes (Section 5.7) and reset any session-specific counters, while account-level lockout counters (Section 5.4) persist independently of session state.

---

## 6. Functional Flow Summary

1. **Registration**
   - Validate username format → check blocklist → check uniqueness (rate-limited).
   - Validate password format → check breach database → check similarity to username/email.
   - Hash password (Argon2id) with unique salt → store hash only.
2. **Login**
   - Look up username (normalized).
   - If not found, perform dummy hash comparison (timing consistency) → generic error.
   - If found, compare submitted password against stored hash.
   - On success: rehash if parameters outdated; reset failure counters; log event.
   - On failure: increment failure counter; apply backoff/lockout if threshold reached; generic error; log event.
3. **Password Change / Reset**
   - Re-validate new password against all rules (format, breach list, similarity).
   - Require current password (for change) or valid reset token (for reset).
   - Hash and store new password; invalidate existing sessions/tokens as appropriate; notify user via email.

---

## 7. Error Messaging Guidelines

| Scenario | User-Facing Message |
|---|---|
| Invalid username format | "Usernames must be 3–20 characters and contain only letters, numbers, underscores, or hyphens, starting with a letter." |
| Username taken | "That username is unavailable. Try another." (rate-limited check) |
| Weak password | "Password must be at least 12 characters and include a mix of letters, numbers, and symbols." |
| Breached password | "This password has appeared in a data breach. Please choose a different one." |
| Login failure (any reason) | "Invalid username or password." |
| Account locked | "Too many attempts. Please try again in 15 minutes." (no confirmation of which credential was wrong) |
| Password reset request | "If an account exists for that username/email, a reset link has been sent." |

---

## 8. Non-Functional Requirements

- **Performance:** Hashing operations should complete within an acceptable latency budget (typically 100–500ms) — tune Argon2id parameters accordingly.
- **Configurability:** Validation rules (length, complexity, blocklists, rate limits) should be configurable per environment without code changes.
- **Internationalization:** Error messages and password rules must support non-English locales and Unicode passphrases.
- **Compliance:** Align with OWASP Authentication Cheat Sheet and NIST SP 800-63B guidance; support GDPR/CCPA data handling requirements for stored audit logs.

---

## 9. Open Questions

- Should usernames be mutable after account creation, and if so, how does this affect login identifiers vs. display names?
- What is the acceptable lockout duration and escalation policy for repeated lockouts on the same account?
- Will MFA be mandatory for all accounts or risk-based (triggered by anomaly detection)?

---

## 10. References

- OWASP Authentication Cheat Sheet
- NIST SP 800-63B Digital Identity Guidelines
- Have I Been Pwned — Pwned Passwords API (k-anonymity model)
