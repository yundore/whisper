# Whisper Privacy & Security Audit

> Audit of https://github.com/yundore/whisper performed 2026-06-12 by Claude Opus 4.8 (subagent), cross-checked and extended by Claude Fable 5 (orchestrator). Graded against the project's own stated privacy ethos (README: "stores ONLY username + password hash, no tracking, GDPR-friendly by design") plus privacy-by-design and security best practice.

> **Status: remediated in 2.0.0.** This is the pre-2.0 audit, kept as a record of why the project was rebuilt. Every Critical, High, and Medium finding, plus the orchestrator addenda (X-1 to X-3), is addressed in the 2.0.0 rewrite. See [CHANGELOG.md](../CHANGELOG.md) for the mapping from finding to fix.

## 1. Verdict

**No — Whisper does not live up to its own privacy ethos today, and several of its headline claims are false as written.** The two foreign-key `ON DELETE CASCADE`/`SET NULL` clauses that the entire "GDPR-friendly / right-to-erasure" promise rests on are **silently inert**, because neither the Node nor the Python implementation issues `PRAGMA foreign_keys = ON` (SQLite disables FK enforcement by default in both `node-sqlite3` and Python's `sqlite3` stdlib). The result: deleting a user **orphans their sessions and purchases instead of erasing/anonymizing them**, the README's "what we DON'T store" list is contradicted by `created_at` timestamps, plaintext session tokens, purchase amounts/transaction IDs, and client-IP processing in the example server, and the "bcrypt/argon2," "payment processor integration," and `guest_purchases.expires_at` features are either never implemented or wrong. It is a tidy, readable, but unhardened prototype masquerading as an audited privacy product.

## 2. Findings Table

| ID | Severity | Dimension | Title |
|----|----------|-----------|-------|
| C-1 | Critical | Lifecycle / FK | `PRAGMA foreign_keys` never enabled → CASCADE/SET NULL dead → deleteUser orphans sessions + purchases (both impls) |
| C-2 | Critical | Privacy claim | Right-to-erasure cannot be honored; deleted users leave live sessions + retained purchase rows |
| C-3 | Critical | Security | Session tokens stored in plaintext at rest; DB leak = full account takeover of every live session |
| H-1 | High | Privacy claim | README "stores ONLY username + hash / no tracking" is false: timestamps, tokens, purchase amounts, txn IDs, client IPs all stored/processed |
| H-2 | High | Security | Username enumeration via timing (bcrypt.compare only runs when user exists) + distinct register error message |
| H-3 | High | Security | bcrypt cost factor 10 = bare OWASP minimum; no 72-byte truncation guard / max-length validation |
| H-4 | High | Packaging | Repo is unrunnable as published: concatenated blob files, no `src/`, `example/`, `tests/` tree; `npm test`/`npm start` fail immediately |
| H-5 | High | Dependencies | `express` + `express-rate-limit` in devDependencies but `npm start` runs the server requiring them → prod install crashes |
| H-6 | High | Example server | Guest-purchase + guest-purchase-read endpoints have no auth and no rate limit → DB-fill DoS + enumeration |
| M-1 | Medium | Example server | `express-rate-limit` without `trust proxy` config → IP-based limits trivially bypassed (or wrong) behind any proxy |
| M-2 | Medium | Privacy | Rate limiting keys on raw client IP — direct contradiction of "no tracking"; no privacy-preserving alternative |
| M-3 | Medium | Example server | `/api/stats` publicly discloses total user count; no auth |
| M-4 | Medium | Lifecycle | `guest_purchases.expires_at` (README) does not exist in code; no purchase purge anywhere; `guestTokenExpiry` config is dead |
| M-5 | Medium | Security | No expired/revoked-session story in Python (cleanup exists but never scheduled); Node cleanup only in example server |
| M-6 | Medium | Security | Missing SQLite hardening: no WAL/secure_delete; deleted rows remain in DB pages/`-wal` (forensic recovery) |
| M-7 | Medium | Example server | No input validation on `amount` (negative/zero/NaN), `currency` format, or request body size |
| M-8 | Medium | Dependencies | `sqlite3 ^5.1.6` stale; 5.1.x line had a high-sev transitive CVE; Python requirements.txt declares Flask/flask-limiter that the code never imports |
| M-9 | Medium | Security | Username case-folding to lowercase silently collides distinct usernames; no normalization disclosure |
| L-1 | Low | Hygiene | README Purchases/Guest-Purchases table headings are swapped vs the SQL beneath them |
| L-2 | Low | Hygiene | "bcrypt/argon2" and "Payment processor integration" advertised but argon2 absent, no processor integration exists |
| L-3 | Low | Hygiene | CONTRIBUTING titled "MinimalAuth"; broken sentence ("who make who"); `author: "Your Name"` placeholder |
| L-4 | Low | Hygiene | Duplicate/garbled `.gitignore` + `custom .gitignore` (the latter is a markdown code-block, not a real ignore file) |
| L-5 | Low | Hygiene | AI-generated disclaimer at top of README ("made with Claude Opus 4… might be some mistakes") shipped as line 1 |
| L-6 | Low | Privacy | No `PRIVACY.md` / threat model despite "privacy-first" + "easy to audit" positioning |
| X-1 | High | Security (orchestrator addendum) | Node session-expiry comparison is lexicographically broken: ISO `T` separator vs `datetime('now')` space → expired sessions stay valid up to ~24h, cleanup delayed a day |
| X-2 | Medium | Security (orchestrator addendum) | Python sessions use naive LOCAL `datetime.now()` but verify against UTC `datetime('now')` → expiry off by the machine's UTC offset |
| X-3 | Medium | Security (orchestrator addendum) | `changePassword` does not revoke existing sessions → a hijacked session survives the victim changing their password |

## 3. Detailed Findings

### C-1 — Foreign keys never enabled; CASCADE / SET NULL are dead clauses (Critical)
**Evidence:** `node.js whisper` lines 58 (`FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE` on `sessions`) and 70 (`ON DELETE SET NULL` on `purchases`); `other` lines 33 and 45 (identical clauses in Python). The constructors (`node.js whisper` lines 39–41; `other` lines 13–15) open the DB and call `setupDatabase()` **without ever issuing `PRAGMA foreign_keys = ON`**. SQLite ships with FK enforcement OFF by default, and this is true for both `node-sqlite3` and Python's `sqlite3` stdlib — the pragma must be set per-connection or the cascade is **silently ignored** (verified, sources below).
**Why it matters:** Every privacy guarantee about deletion is built on these two clauses, and they do nothing. `deleteUser` (`node.js whisper` 189–200) / `delete_user` (`other` 135–140) issue a bare `DELETE FROM users WHERE id = ?`. With FKs off: the user row vanishes but **all their session rows remain** (tokens + timestamps persist) and **all their purchase rows remain with the original `user_id` intact** (not nulled). The README's "Even if breached, no personal information is exposed" is then false: a breach exposes retained purchase history keyed to a deleted account.
**Fix:** Immediately after opening the connection, run `this.db.run('PRAGMA foreign_keys = ON')` (Node) / `self.conn.execute("PRAGMA foreign_keys = ON")` (Python) **before** `setupDatabase()`. Add a regression test that creates a user + session + purchase, deletes the user, and asserts zero session rows and `user_id IS NULL` on the purchase. Note the Node call is async/serialized — wrap setup in `db.serialize()` so the pragma lands before inserts.

### C-2 — Right-to-erasure is unimplementable; sessions outlive the account (Critical)
**Evidence:** Same delete methods as C-1. There is no code path that deletes sessions or purchases when a user is removed, and no "erase all my data" method exists. `verifySession` (`node.js whisper` 224–240; `other` 165–186) only filters on `expires_at > datetime('now')` — because the user row is gone the `JOIN users` yields no row, so the orphaned session fails closed *for auth*. However the orphaned **rows physically persist** in the `sessions` table (token + timestamps) and in `purchases` (amount, currency, txn id, original user_id) indefinitely.
**Why it matters:** GDPR Article 17 erasure requires the data actually be removed/anonymized. A deleted user's purchase amounts and transaction IDs — which are personal data when linkable — survive. The "GDPR-friendly by design" claim (README line 27) is unsupported.
**Fix:** Ship an explicit `eraseUser(userId)` that, in a transaction, deletes sessions, then either deletes or anonymizes purchases (`UPDATE purchases SET user_id = NULL, guest_token = NULL WHERE user_id = ?` if financial records must be retained for accounting, else `DELETE`). Even with C-1 fixed, CASCADE handles sessions but `SET NULL` only nulls `user_id` — the purchase **row and amount remain**, so a true erasure still needs an explicit policy decision documented in PRIVACY.md.

### C-3 — Session tokens stored in plaintext at rest (Critical)
**Evidence:** `createSession` inserts the raw token (`node.js whisper` 213–215; `other` 154–157); `verifySession` looks it up by raw equality (`node.js whisper` 232; `other` 175). The token column is the literal bearer credential.
**Why it matters:** The README leans hard on "even if breached, nothing is exposed." But a DB leak hands the attacker **every live session token in plaintext** → instant takeover of all logged-in users without touching the password hashes. For a self-described privacy/security tool this is the highest-impact at-rest exposure, worse than the (correctly hashed) passwords.
**Fix:** Store `sha256(token)` (a fast hash is fine — tokens are already 256-bit random, no brute-force risk). On `createSession`, return the raw token to the caller but persist only the hash. On `verifySession`, hash the incoming token and look up by hash. This is the single highest-leverage privacy upgrade in the repo.

### H-1 — "Stores ONLY username + password hash / no tracking" is false (High)
**Evidence — every datum actually stored/processed/returned:**
- `users`: `created_at TIMESTAMP` (`node.js whisper` 49; `other` 24) — a per-account **account-creation timestamp**, never mentioned in the README's "what we store" (lines 16–19) and directly enabling temporal correlation the manifesto disclaims.
- `sessions`: `token` (plaintext, C-3), `expires_at`, `created_at` (`node.js whisper` 52–58) — login-time activity trail per user.
- `purchases`: `transaction_id`, `amount`, `currency`, `status`, `created_at`, plus `user_id`/`guest_token` linkage (`node.js whisper` 61–71). Purchase **amounts and transaction IDs are personal/financial data**; the README's "DOES NOT store… Credit card information / Any other personal information" (lines 86–93) glosses that transaction metadata is retained and linkable via the payment processor.
- **API responses** echo `guest_token` back to clients (`/api/guest-purchase`, `test and example` 327) and return full purchase rows including amounts.
- **Example server inherently processes client IPs**: `express-rate-limit` (`test and example` 146–156) keys on `req.ip` by default — the system **does** ingest and bucket by IP (see M-2). "No tracking" is incompatible with default IP-keyed rate limiting.
- **Console logging**: `console.error('Database setup error:', err)` (`node.js whisper` 81) and the cleanup log (`test and example` 392) — low risk but DB errors can leak query/schema fragments to logs.
**Fix:** Either (a) make timestamps optional/opt-in (`recordTimestamps: false` constructor flag) and document every retained datum honestly in README + PRIVACY.md, or (b) rewrite the marketing to stop claiming "only username + hash" and "no tracking." The claim and the schema cannot both stand.

### H-2 — Username enumeration via timing + error messages (High)
**Evidence:** `verifyUser` (`node.js whisper` 139–147; `other` 104–112) calls `bcrypt.compare` **only when the user row exists**; when the user is absent it returns `null` immediately. bcrypt comparison is ~tens-of-ms; the absent-user path is a sub-ms DB miss. An attacker measures response time to enumerate valid usernames. Separately, `createUser` throws the distinct `'Username already exists'` (`node.js whisper` 115; `other` 92), a direct positive oracle. The login endpoint's generic `'Invalid credentials'` (`test and example` 188) is good, but registration and timing both leak.
**Why it matters:** Usernames are the *only* identifier in an "anonymity-first" system. Enumerable usernames partially defeat the anonymity selling point and seed credential-stuffing.
**Fix:** In the no-user branch, run a dummy `bcrypt.compare` against a constant fake hash to equalize timing, then return null (both impls). For registration enumeration the honest options are limited (uniqueness must be reported somehow) — at minimum rate-limit registration (already done) and document the tradeoff.

### H-3 — bcrypt cost 10, no 72-byte handling (High)
**Evidence:** `saltRounds = 10` default (`node.js whisper` 36; `other` 10). Passwords passed straight to `bcrypt.hash`/`bcrypt.hashpw` (`node.js whisper` 106; `other` 77) with only a **minimum** length check (≥8) and **no maximum**. README line 24 advertises "bcrypt/argon2."
**Why it matters:** OWASP's current Password Storage guidance sets bcrypt's *minimum* work factor at 10 and recommends tuning upward; 10 is the floor, not a good default for a security-branded library. bcrypt **silently truncates input at 72 bytes** — distinct long passphrases sharing a 72-byte prefix hash identically. argon2 is advertised but entirely absent.
**Fix:** Raise default cost to 12 (configurable). Reject passwords whose **UTF-8 byte length** exceeds 72 with a clear error (OWASP discourages the SHA-256 pre-hash workaround due to password shucking). Either implement argon2id (OWASP-preferred: 19 MiB / t=2 / p=1) behind a config switch, or delete the "argon2" claim.

### H-4 — Repo is not runnable as published (High)
**Evidence:** `git ls-files` shows the only tracked files are `README.md`, `LICENSE`, `contribution`, `custom .gitignore`, `node.js whisper`, `other`, `test and example`, `.gitignore`. There is **no `src/index.js`, no `example/server.js`, no `tests/whisper.test.js`, no real `package.json` on disk** — they exist only as `// === path ===`-delimited sections concatenated inside extension-less, space-containing blob files. `npm install` has no manifest to read; `npm test`/`npm start` fail instantly.
**Why it matters:** "Easy to audit and understand" (README line 28) is undercut when the project cannot be installed or executed at all. Nobody can verify the security claims by running it.
**Fix:** Restructure into a real tree: `package.json`, `src/index.js`, `examples/python/whisper.py`, `examples/python/example_usage.py`, `examples/python/requirements.txt`, `example/server.js`, `tests/whisper.test.js`, `docs/API.md`, `CONTRIBUTING.md`. Delete the blob files. Verify `npm install && npm test && npm start` work end-to-end.

### H-5 — express/express-rate-limit miscategorized as devDependencies (High)
**Evidence:** `package.json` (`node.js whisper` 16–25): `express` and `express-rate-limit` under `devDependencies`; runtime deps only `bcrypt` + `sqlite3`. Yet `"start": "node example/server.js"` runs the server which `require`s both (`test and example` 136–138).
**Fix:** Either move them to `dependencies`, or move the example server into its own `examples/` package with its own manifest so the core library stays dependency-light.

### H-6 — Guest endpoints unauthenticated and unthrottled → DoS + enumeration (High)
**Evidence:** `POST /api/guest-purchase` (`test and example` 315–335) has **no `authenticate` middleware and no rate limiter**. `GET /api/guest-purchases/:guestToken` (355–369) likewise unauthenticated. `recordPurchase` requires only `transactionId` + `amount`.
**Why it matters:** Anyone can POST unlimited guest purchases with arbitrary values, filling the DB indefinitely (no purge exists — M-4) → storage-exhaustion DoS. The read endpoint lets anyone holding a `guestToken` read purchase history with no rate limit on guessing.
**Fix:** Add a dedicated rate limiter to both guest endpoints. Validate `amount`/`currency` (M-7). Add purchase TTL + purge (M-4) to bound growth.

### M-1 — Rate limiting will misfire behind a proxy (no `trust proxy`) (Medium)
**Evidence:** `app` is created with no `app.set('trust proxy', …)` (`test and example` 140); rate limiters use defaults (146–156), keying on `req.ip`.
**Why it matters:** Behind any reverse proxy, `req.ip` is the proxy's IP → all users share one bucket (mass lockout) OR, if `trust proxy` is naively `true`, `X-Forwarded-For` is attacker-controlled and limits are trivially bypassed. No TLS/deployment guidance exists anywhere.
**Fix:** Set an explicit, correct `trust proxy` value for the deployment; on express-rate-limit v7+ use the `ipKeyGenerator` helper for correct IPv6 bucketing. Add a deployment note requiring TLS.

### M-2 — IP-keyed rate limiting contradicts "no tracking" (Medium)
**Evidence:** Default `req.ip` keying (`test and example` 146–156).
**Why it matters:** IP addresses are personal data under GDPR — exactly the identifier "no tracking / privacy-first" implies you avoid. The repo never acknowledges that its only abuse-prevention layer fingerprints users by IP.
**Fix:** Document the tradeoff honestly. Offer privacy-friendlier options: salted-hash+truncate IPs as keys (never store raw), short non-persistent windows, proof-of-work or anonymous-token (Privacy Pass-style) abuse prevention, /64 bucketing for IPv6. Never log or persist raw IPs.

### M-3 — Public user-count disclosure (Medium)
**Evidence:** `GET /api/stats` returns `userCount` with no auth (`test and example` 372–386).
**Fix:** Remove, gate behind auth, or return a coarse bucket. Don't expose exact counts publicly by default.

### M-4 — `expires_at` purchase column doesn't exist; no purge; dead config (Medium)
**Evidence:** README schema shows `guest_purchases.expires_at` (README line 52). The actual `purchases` table has **no `expires_at` column** (`node.js whisper` 61–71; `other` 36–46). The constructor stores `guestTokenExpiry` (`node.js whisper` 37) but **nothing ever reads it**; no purchase-purge method exists. Guest purchases persist forever.
**Fix:** Add `expires_at` to `purchases`, populate from `guestTokenExpiry` on guest purchases, add `cleanupExpiredGuestPurchases()` scheduled alongside session cleanup. Or remove the column from the README and the dead config.

### M-5 — Expired-session retention; cleanup not wired in Python (Medium)
**Evidence:** Node `cleanupExpiredSessions` (`node.js whisper` 255–265) is scheduled only in the **example** server (`test and example` 389–396). Python `cleanup_expired_sessions` (`other` 195–200) is **never called anywhere**.
**Fix:** Provide a built-in optional cleanup timer or lazy deletion on access; wire cleanup into the Python example; document that purging is otherwise the host app's responsibility.

### M-6 — No SQLite secure-delete / WAL hygiene; deleted data forensically recoverable (Medium)
**Evidence:** No `PRAGMA secure_delete`, no journal configuration anywhere (constructors at `node.js whisper` 39–41; `other` 13–15).
**Why it matters:** By default SQLite leaves deleted row content in freed pages and journal/`-wal` files. After a "deletion," usernames/hashes/purchase data can be recovered from the file on disk — undercutting erasure claims.
**Fix:** `PRAGMA secure_delete = ON`; document the `-wal`/`-shm` files in deployment guidance; ensure gitignore covers them.

### M-7 — No purchase input validation (amount/currency/body size) (Medium)
**Evidence:** `recordPurchase` checks only truthy `transactionId` + `amount` (`node.js whisper` 270–272; JS `!amount` rejects `0` but accepts negative numbers). No currency format check. `express.json()` (`test and example` 143) sets no `limit`.
**Fix:** Validate `amount` is a finite number > 0; validate `currency` against `/^[A-Z]{3}$/` or an ISO-4217 allowlist; set `express.json({ limit: '10kb' })`. Apply in both library and route layers.

### M-8 — Stale/floating dependency versions; requirements.txt mismatch (Medium)
**Evidence:** `sqlite3 ^5.1.6` (`node.js whisper` 18) — stale line that carried a high-severity transitive CVE (CVE-2022-43441 region per Snyk). Python `requirements.txt` (`other` 324–326) declares `flask==3.0.0` and `flask-limiter==3.5.0` **that the Python code never imports** (it only needs `bcrypt`); `bcrypt==4.1.2` is pinned-but-old.
**Fix:** Bump `sqlite3` (or migrate to `better-sqlite3` — synchronous, faster, avoids the callback-ordering hazards). Strip unused Flask deps or ship a real Flask example. Add `npm audit`/`pip-audit` to CI.

### M-9 — Silent username case-folding collision (Medium)
**Evidence:** Usernames stored and looked up `.toLowerCase()` / `.lower()` (`node.js whisper` 111, 134; `other` 83, 102), no Unicode normalization.
**Fix:** Document the lowercase policy; apply NFKC normalization before lowercasing. (Low risk today because the regex restricts to ASCII — keep them consistent if the charset ever widens.)

### L-1 — README purchase table headings swapped (Low)
**Evidence:** README line 42 "Purchases Table" is followed by `CREATE TABLE guest_purchases`; line 56 "Guest Purchases Table" is followed by `CREATE TABLE purchases`.
**Fix:** Swap the headings.

### L-2 — Advertised features not implemented (Low)
**Evidence:** README line 24 "bcrypt/argon2" — no argon2. Line 26 "Payment processor integration" — none exists; `recordPurchase` stores a caller-supplied string. Line 27 "GDPR-friendly by design" — refuted by C-1/C-2.
**Fix:** Remove or implement each claim.

### L-3 — CONTRIBUTING leftovers and placeholders (Low)
**Evidence:** `contribution` line 1 "Contributing to **MinimalAuth**" (rename artifact); line 3 broken grammar ("who make who such a great tool"); `package.json` `author: "Your Name"`.
**Fix:** Rename, fix the sentence, set a real author.

### L-4 — Duplicate / malformed gitignore files (Low)
**Evidence:** `.gitignore` (real) plus `custom .gitignore` — the latter is a markdown document with a fenced code block, and its filename contains a space, so git never applies it.
**Fix:** Merge the useful patterns into `.gitignore`; delete `custom .gitignore`.

### L-5 — AI-generated disclaimer shipped as README line 1 (Low)
**Evidence:** README lines 1–2: "This was made with Claude Opus 4, just a brain dump idea… there might be some mistakes."
**Fix:** Remove from the top once the Critical/High issues are fixed; move attribution to CONTRIBUTING if desired.

### L-6 — No PRIVACY.md / threat model (Low, but central to the ethos)
**Fix:** Add `PRIVACY.md`: full data inventory (every column + why it exists), retention/erasure policy, what's logged, the IP-rate-limit tradeoff, and the threat model (what Whisper does and does not defend against).

---

## 3b. Orchestrator addendum — findings the subagent missed (verified against source)

### X-1 — Node session expiry is only enforced at day granularity (High)
**Evidence:** `createSession` stores `expiresAt.toISOString()` → `'2026-06-19T14:30:00.000Z'` (`node.js whisper` 210–215). `verifySession` compares `expires_at > datetime('now')` where `datetime('now')` yields `'2026-06-19 14:30:00'` (space separator, no `T`). SQLite compares TEXT lexicographically: on the expiry **day**, position 10 is `'T'` (0x54) vs `' '` (0x20), so the stored value always compares greater — **a session that expired at 00:01 UTC still verifies until the date rolls over**, up to ~24h late. Symmetrically, `cleanupExpiredSessions` (`expires_at < datetime('now')`) won't purge a session on its expiry day.
**Fix:** Store expiry in SQLite's own format (`strftime('%Y-%m-%d %H:%M:%S', ...)`), or store epoch milliseconds as INTEGER and compare numerically (preferred — unambiguous). Add a test that creates a session expiring 1 second in the past on the same UTC day and asserts `verifySession` returns null.

### X-2 — Python session expiry mixes naive local time with UTC (Medium)
**Evidence:** `create_session` computes `datetime.now() + timedelta(...)` — naive **local** time (`other` 148–151) — stored via the default adapter as `'YYYY-MM-DD HH:MM:SS.ffffff'`. `verify_session` compares against `datetime('now')`, which is **UTC** (`other` 175). On a UTC+X machine sessions live X hours longer than promised; on UTC−X they expire early. (Also: the implicit datetime adapter is deprecated since Python 3.12.)
**Fix:** Use `datetime.now(timezone.utc)` and store an explicit UTC string (or epoch INTEGER, matching the Node fix). One canonical representation across both implementations.

### X-3 — Password change does not revoke existing sessions (Medium)
**Evidence:** `changePassword` (`node.js whisper` 154–187) / `change_password` (`other` 114–133) update the hash and return — no session invalidation. OWASP session-management guidance: invalidate (at least all *other*) sessions on password change, because the primary reason users change passwords is suspected compromise — and today the attacker's stolen session keeps working for up to 7 more days.
**Fix:** Inside `changePassword`, after the hash update and in the same transaction: `DELETE FROM sessions WHERE user_id = ?` (optionally excluding the current token). Issue a fresh session to the caller.

## 4. Prioritized Optimization Plan

**Tier 0 — Make it true (do before any release):**
1. **Enable `PRAGMA foreign_keys = ON`** at connection open in both impls (C-1). Without this, everything about deletion is theater.
2. **Hash session tokens at rest** (C-3) — store `sha256(token)`, look up by hash. Highest at-rest-leak ROI.
3. **Implement real erasure** (`eraseUser`) that removes sessions and deletes/anonymizes purchases in a transaction (C-2); decide + document the purchase-retention policy.
4. **Restructure the repo into runnable files** (H-4) and fix dependency placement (H-5) so `npm install && npm test && npm start` actually work — the claims become verifiable.

**Tier 1 — Close exploitable gaps:**
5. Fix session-expiry comparison (X-1) and Python UTC handling (X-2) — store epoch INTEGER in both impls.
6. Revoke sessions on password change (X-3).
7. Timing-safe user verification (dummy bcrypt.compare on the no-user path) (H-2).
8. bcrypt cost 12 + 72-byte UTF-8 max-length validation; implement argon2id or drop the claim (H-3).
9. Auth/rate limits/input validation on guest endpoints; bound DB growth (H-6, M-7).

**Tier 2 — Hardening:**
10. Correct `trust proxy` + IPv6 keying; TLS/deployment guidance (M-1).
11. Purchase TTL + scheduled purge; wire cleanup into the library and Python example (M-4, M-5).
12. `PRAGMA secure_delete = ON`; document `-wal`/`-shm` (M-6).
13. Bump/migrate sqlite3; fix requirements.txt; `npm audit`/`pip-audit` in CI (M-8).
14. Remove/gate `/api/stats` (M-3); document username normalization (M-9).

**Tier 3 — Make the marketing honest + first-principles upgrades:**
15. Rewrite README data claims to match reality (H-1, L-1, L-2); fix CONTRIBUTING/author/gitignore/disclaimer (L-3, L-4, L-5).
16. Add **PRIVACY.md**: data inventory, retention policy, logging policy, threat model (L-6).
17. Privacy-maximal features worth attempting: optional/no timestamps flag; anonymous abuse prevention (salted-hashed truncated IP keys, PoW, or Privacy Pass-style tokens) instead of raw-IP limits; automatic data-expiry as a first-class concept across sessions *and* purchases; anonymized-by-default guest purchases (salted txn-id hash + amount bucket); encrypted-at-rest option (SQLCipher); ship the hardened design as the default, not opt-in.

## 5. Sources
- SQLite foreign keys disabled by default (node-sqlite3): https://github.com/TryGhost/node-sqlite3/pull/660 and https://github.com/TryGhost/node-sqlite3/issues/896
- SQLite FK constraints disabled by default (general + Python sqlite3): https://nicolaiarocci.com/sqlite-foreign-key-constraints-are-disabled-by-default/ and https://sqlite.org/forum/forumpost/06932f397c4e3dd5
- Python sqlite3 cascade silently ignored without the pragma: https://github.com/sqlalchemy/sqlalchemy/issues/4858
- OWASP Password Storage Cheat Sheet (bcrypt work factor, 72-byte limit, Argon2id preferred): https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- bcrypt 72-byte silent truncation (real-world auth bypass): https://pentesterlab.com/blog/freshrss-bcrypt-truncation-auth-bypass
- sqlite3 npm version/vuln status: https://security.snyk.io/package/npm/sqlite3 and https://security.snyk.io/package/npm/sqlite3/5.1.7
- express-rate-limit trust-proxy bypass + IPv6 keying: https://express-rate-limit.mintlify.app/reference/error-codes
- SQLite lexicographic TEXT date comparison semantics: https://sqlite.org/lang_datefunc.html (date/time strings compare correctly only in the same format)
