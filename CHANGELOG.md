# Changelog

## 2.0.0

A security and privacy overhaul that makes the project live up to its stated ethos, plus a restructure into a real, runnable package. See [docs/AUDIT.md](docs/AUDIT.md) for the audit that drove these changes.

### Privacy and security

- Enable SQLite `PRAGMA foreign_keys = ON` so account deletion actually cascades. Previously the `ON DELETE` clauses were silently ignored and deleting a user left sessions and purchases behind.
- `deleteUser` / `delete_user` now fully erase the account, its sessions, and its purchases in one transaction (right to erasure).
- Store only a SHA-256 hash of session tokens and guest tokens. Raw tokens are returned to the caller once and never persisted.
- Move session and guest-purchase expiry to integer epoch milliseconds, fixing a date-comparison bug that let sessions stay valid up to a day past expiry, and an off-by-timezone bug in Python.
- Revoke all existing sessions when a password changes.
- Equalize login timing so usernames cannot be enumerated by response time.
- Raise the default bcrypt cost to 12 and reject passwords longer than 72 bytes (bcrypt's truncation boundary).
- Add argon2id as an optional hashing algorithm, auto-detected on verify so a database can mix algorithms during a migration.
- Enable `PRAGMA secure_delete` and, for file databases, WAL mode.
- Drop the account `created_at` column by default so a user is stored as exactly a username and a password hash. Opt back in with `timestamps: true`.
- Guest purchases now expire and are purged by `cleanupExpiredGuestPurchases`.
- Example server: rate-limit by a salted hash of the client IP rather than the raw IP; add `helmet`, a 10 KB JSON body limit, input validation, generic error responses, an explicit `trust proxy` setting, and rate limits on every write endpoint including guest purchases. Removed the public user-count endpoint.

### Packaging

- Restructure the concatenated blob files into a real tree: `src/`, `tests/`, `examples/`, `docs/`. The repository now installs and runs.
- Migrate the Node core from the unmaintained `sqlite3` to `better-sqlite3`, and update `bcrypt` to a version with no known advisories. `npm audit` is clean.
- Move `express` and `express-rate-limit` to runtime dependencies so the example server runs after a plain install.
- Fix the Python `requirements.txt`, which previously declared Flask packages the code never used.
- Add `PRIVACY.md`, `SECURITY.md`, a corrected `README.md` and `CONTRIBUTING.md`, and a single `.gitignore`.
