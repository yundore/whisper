# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Instead, use GitHub's private vulnerability reporting (the "Report a vulnerability" button under the repository's Security tab), or contact the maintainer directly.

Include a description, reproduction steps, and the impact you see. You will get an acknowledgement, and a fix or explanation once the report is assessed.

## Scope

whisper is a library plus an example server. The threat model, including what whisper does and does not defend against, is documented in [PRIVACY.md](PRIVACY.md). Reports that fall inside that model are in scope.

Out of scope: missing TLS in your own deployment, a misconfigured `trust proxy`, weak passwords chosen by users, and compromise of the host running the code. These are deployment responsibilities, called out in the README and PRIVACY.md.

## Hardening checklist for operators

- Run behind TLS.
- Set `trust proxy` (Node) to match the number of proxies in front of you, so rate limiting keys on the real client and cannot be spoofed.
- Use a strong password hashing setting for your hardware: bcrypt cost 12 or higher, or `algorithm: 'argon2'`.
- Schedule `cleanupExpiredSessions()` and `cleanupExpiredGuestPurchases()` (the example server does this hourly).
- Keep dependencies current and `npm audit` clean.
