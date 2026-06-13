# Whisper API

The Node and Python implementations share this API. Node methods are `async` (they return Promises); Python methods are synchronous. Names are camelCase in Node and snake_case in Python.

## Constructor

```js
new Whisper({ dbPath, saltRounds, algorithm, timestamps, sessionTTL, guestTokenExpiry })
```

| Option | Default | Description |
|--------|---------|-------------|
| `dbPath` / `db_path` | `:memory:` | SQLite file path, or in-memory. |
| `saltRounds` / `salt_rounds` | `12` | bcrypt cost factor. |
| `algorithm` | `'bcrypt'` | `'bcrypt'` or `'argon2'`. argon2 needs the optional `argon2` / `argon2-cffi` package. |
| `timestamps` | `false` | When true, store a `created_at` on accounts. Off keeps a user to username + hash only. |
| `sessionTTL` / `session_ttl_ms` | `604800000` (7 days) | Default session lifetime in ms. |
| `guestTokenExpiry` / `guest_token_expiry_ms` | `2592000000` (30 days) | Guest-purchase lifetime in ms. |

## User management

### `createUser(username, password)`
Creates an account. Username is 3 to 50 characters, letters/numbers/underscore/hyphen, stored lowercased. Password is 8 characters minimum and at most 72 bytes. Returns `{ id, username }`. Throws `Username already exists` on a duplicate.

### `verifyUser(username, password)`
Returns `{ id, username }` if the credentials are valid, otherwise `null`. Timing is equalized so an unknown username and a wrong password cost the same.

### `changePassword(userId, oldPassword, newPassword)`
Verifies the old password, sets the new one, and revokes every existing session for that user in one transaction. Returns `true`. Throws if the old password is wrong.

### `deleteUser(userId)`
Erases the account, its sessions (via `ON DELETE CASCADE`), and its purchases, in one transaction. Returns `true` if a user was deleted.

## Session management

### `createSession(userId, expiresIn?)`
Creates a session. `expiresIn` is milliseconds (defaults to `sessionTTL`). Returns `{ token, expiresAt }`. The raw `token` is returned once and only its SHA-256 hash is stored.

### `verifySession(token)`
Returns `{ userId, username }` if the token maps to a live session, otherwise `null`.

### `revokeSession(token)`
Deletes the session. Returns `true` if one was removed.

### `cleanupExpiredSessions()`
Deletes all expired sessions. Returns the number removed.

## Purchase management

### `recordPurchase(transactionId, amount, currency?, userId?, guestToken?)`
Records a purchase. `amount` must be a positive finite number; `currency` must be a 3-letter ISO 4217 code (default `USD`). With no `userId`, a guest token is generated (or the one you pass is used) and the purchase is given an expiry. Returns `{ id, transactionId, guestToken, amount, currency }` where `guestToken` is the raw token (returned once) or `null` for account purchases. Throws `Transaction already recorded` on a duplicate `transactionId`.

### `getUserPurchases(userId)`
Returns the user's purchases, newest first.

### `getGuestPurchases(guestToken)`
Returns the guest's purchases (looked up by the token's hash), newest first.

### `cleanupExpiredGuestPurchases()`
Deletes expired guest purchases. Account purchases are never touched. Returns the number removed.

## Utility

### `getUserCount()`
Returns the total number of users. Not exposed by the example server, since a public exact count is unnecessary disclosure.

### `close()`
Closes the database connection.

## Example REST API

The example server in `examples/node-server.js` wraps these methods. All responses are JSON with a `success` boolean.

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| POST | `/api/register` | none | Rate limited. Returns a session token. |
| POST | `/api/login` | none | Rate limited. One generic error for any failure. |
| POST | `/api/logout` | Bearer | Revokes the current session. |
| POST | `/api/change-password` | Bearer | Revokes all sessions, returns a fresh token. |
| DELETE | `/api/account` | Bearer | Erases the account. |
| POST | `/api/purchase` | Bearer | Rate limited. |
| POST | `/api/guest-purchase` | none | Rate limited. Returns a guest token. |
| GET | `/api/purchases` | Bearer | The caller's purchases. |
| GET | `/api/guest-purchases/:guestToken` | none | Rate limited. |
| GET | `/api/health` | none | Liveness check. |

Rate limiting keys on a salted hash of the client IP, not the raw IP. See [PRIVACY.md](../PRIVACY.md).
