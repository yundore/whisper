# Privacy model

Whisper is built so that a stolen database, or a subpoena, yields as little about a person as possible. This document is the source of truth for what is stored, for how long, and what Whisper does and does not protect against.

## Data inventory

Every column the library can write, and why it exists.

### `users`

| Column | Stored | Why | Personal data? |
|--------|--------|-----|----------------|
| `id` | always | primary key, internal | no (a row number) |
| `username` | always | the only human-chosen identifier | only if the user picks an identifying name |
| `password_hash` | always | bcrypt or argon2id hash, never the password | no (one-way hash) |
| `created_at` | only if `timestamps: true` | optional account-age signal for operators who need it | a behavioral timestamp; off by default |

### `sessions`

| Column | Stored | Why | Notes |
|--------|--------|-----|-------|
| `id` | always | primary key | |
| `user_id` | always | links a session to its account | removed by CASCADE when the user is erased |
| `token_hash` | always | SHA-256 of the session token | the raw token is returned to the caller once and never stored |
| `expires_at` | always | integer epoch ms; sessions stop verifying after it | expired rows are purged by `cleanupExpiredSessions` |

### `purchases`

| Column | Stored | Why | Notes |
|--------|--------|-----|-------|
| `id` | always | primary key | |
| `user_id` | for account purchases | links to the buyer | deleted outright when the user is erased |
| `guest_token_hash` | for guest purchases | SHA-256 of the guest token | the raw guest token is returned once and never stored |
| `transaction_id` | always | the payment processor's reference | supply a non-identifying reference if you can |
| `amount`, `currency`, `status` | always | the minimum to represent a purchase | |
| `expires_at` | for guest purchases | integer epoch ms; auto-purged after it | account purchases have no expiry and live until the account is erased |

Whisper never stores: real names, emails, phone numbers, addresses, birth dates, card numbers, or IP addresses.

## Retention and erasure

- **Sessions** stop verifying at `expires_at` and are deleted by `cleanupExpiredSessions()`. The example server runs this hourly.
- **Guest purchases** are deleted by `cleanupExpiredGuestPurchases()` once past `expires_at` (30 days by default).
- **Account erasure** (`deleteUser` / `delete_user`) deletes the account, all of its sessions (via `ON DELETE CASCADE`), and all of its purchases, in a single transaction. Nothing linkable to the user is left behind. This is the design choice that lets a right-to-erasure request be honored truthfully.
- **`secure_delete = ON`** is set on every connection so that freed pages are zeroed and deleted rows cannot be recovered from the database file.

## Logging

The library logs nothing. The example server logs only generic operational lines (server start, cleanup errors) and never logs usernames, tokens, request bodies, or IP addresses.

## The rate-limiting tradeoff

Abuse prevention needs some notion of "who is making these requests," and the usual answer is the client IP, which is personal data. The example server keeps the protection without keeping the identifier:

- requests are bucketed by a **salted SHA-256 hash of the IP**, truncated, using a salt generated fresh on each process start,
- the raw IP is never used as a key, never logged, and never written to disk,
- buckets are in-memory and expire with the rate-limit window.

This means an operator cannot reconstruct a user's IP from rate-limit state, and the state does not survive a restart. If you need stronger anonymity, swap the IP-derived key for an anonymous-token scheme (for example Privacy Pass) or proof-of-work.

## Threat model

**Whisper is designed to protect against:**

- **Database theft at rest.** Passwords are slow-hashed, tokens are stored only as hashes, accounts carry no personal data, and freed pages are zeroed. A stolen database file yields usernames and hashes, no usable tokens, and no personal information.
- **Username enumeration.** Login is timing-equalized and the login endpoint returns one generic error for both unknown user and wrong password.
- **Session theft surviving a password change.** Changing a password revokes every existing session.
- **Unbounded data growth.** Sessions and guest purchases expire and are purged.

**Whisper does NOT protect against, and you must handle elsewhere:**

- **A compromised live host or a malicious operator.** Anyone who can run code in the process can read tokens as they arrive and read the plaintext database.
- **Network interception.** Run behind TLS. Whisper does not provide transport security.
- **Weak passwords or credential stuffing.** Encourage strong passphrases; consider a breached-password check and a second factor.
- **Traffic analysis and metadata at the network layer** (who connects, when, from where). That is outside the library.
- **An identifying username.** If a user puts their real name in the username field, that is stored as chosen. Whisper minimizes what it collects; it cannot un-identify a self-identifying value.

## Username handling

Usernames are lowercased before storage and lookup, so `Alice` and `alice` are the same account. The character set is restricted to letters, numbers, underscores, and hyphens, which avoids Unicode look-alike collisions.
