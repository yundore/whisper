# whisper 🔐

A privacy-first authentication library that stores only what it needs: a username and a password hash. No emails, no real names, no personal information, and no timestamps on accounts by default.

Available for Node.js (`src/index.js`) and Python (`examples/python/whisper.py`), with a matching API and the same on-disk format.

## Philosophy

- Collect only what is essential.
- Respect privacy by default, not as an opt-in.
- Make anonymity easy.
- Keep the code small enough to read in one sitting.

## What it stores

Per account, the `users` table holds exactly three things:

- a user id,
- a username,
- a password hash (bcrypt by default, argon2id optional).

That is it. There is no `created_at` on accounts unless you opt in with `timestamps: true`. There are no email, name, phone, address, or payment-card columns anywhere in the schema.

Two supporting tables exist for functionality, and both are designed to leak as little as possible if the database is ever stolen:

- `sessions` stores a SHA-256 hash of each session token (never the raw token) and an integer expiry.
- `purchases` stores a transaction id, amount, currency, and a link to either a user or a SHA-256 hash of a guest token. Guest purchases carry an expiry and are purged automatically.

See [PRIVACY.md](PRIVACY.md) for the full data inventory, retention policy, and threat model.

## Install and run (Node.js)

Requires Node.js 18 or newer.

```bash
npm install
npm test            # runs the Jest suite
npm start           # runs the example server on http://localhost:3000
```

```js
const Whisper = require('./src/index');

const auth = new Whisper({ dbPath: './whisper.db' });

const user = await auth.createUser('cooluser123', 'a-strong-passphrase');
const session = await auth.createSession(user.id); // session.token is shown once
const who = await auth.verifySession(session.token);

await auth.deleteUser(user.id); // erases the account, its sessions, and its purchases
```

## Install and run (Python)

```bash
cd examples/python
pip install -r requirements.txt
python -m unittest -v      # runs the test suite
python example_usage.py    # runs the walkthrough
```

```python
from whisper import Whisper

auth = Whisper(db_path="whisper.db")
user = auth.create_user("cooluser123", "a-strong-passphrase")
session = auth.create_session(user["id"])
auth.delete_user(user["id"])
```

## Configuration

| Option | Default | Purpose |
|--------|---------|---------|
| `dbPath` / `db_path` | `:memory:` | SQLite file path, or in-memory. |
| `algorithm` | `bcrypt` | Password hashing: `bcrypt` or `argon2`. |
| `saltRounds` / `salt_rounds` | `12` | bcrypt cost factor. |
| `timestamps` | `false` | Record an account `created_at`. Off keeps accounts to username + hash only. |
| `sessionTTL` / `session_ttl_ms` | 7 days | Default session lifetime. |
| `guestTokenExpiry` / `guest_token_expiry_ms` | 30 days | Guest-purchase lifetime before auto-purge. |

To use argon2id (OWASP's preferred algorithm for new systems), install the optional dependency and pass `algorithm: 'argon2'`:

```bash
npm install argon2          # Node
pip install argon2-cffi     # Python
```

Hashes are self-describing, so a database can hold a mix of bcrypt and argon2 hashes during a migration and both will verify.

## What it does NOT store

Real names, email addresses, phone numbers, physical addresses, birth dates, credit-card data, IP addresses, or any other personal information. The example server rate-limits by a salted hash of the client IP rather than the raw IP, so it does not retain a durable network identifier either (see [PRIVACY.md](PRIVACY.md)).

## Security notes

- Passwords are validated for length and capped at 72 bytes (bcrypt's truncation boundary) so no input is silently shortened.
- Login is timing-equalized: a wrong username and a wrong password take the same time, so usernames cannot be enumerated by latency.
- Session and guest tokens are stored only as SHA-256 hashes. A database leak exposes no usable token.
- Changing a password revokes every existing session.
- Foreign keys, `secure_delete`, and (for file databases) WAL mode are enabled on every connection.

This is a small reference library, not a hosted service. Run it behind TLS, set `trust proxy` to match your deployment, and read [SECURITY.md](SECURITY.md) before relying on it.

## License

MIT. See [LICENSE](LICENSE).
