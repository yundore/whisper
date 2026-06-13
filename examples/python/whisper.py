"""Privacy-first authentication that stores only a username and a password hash.

Python port of the Whisper library. Mirrors the Node implementation: foreign
keys enabled, session and guest tokens hashed at rest, integer (UTC-epoch)
expiry, full erasure on delete, and timing-equalized login.
"""

import hashlib
import re
import secrets
import sqlite3
import time
from typing import Any, Dict, List, Optional

import bcrypt

# bcrypt silently truncates past 72 bytes, so longer passwords are rejected.
MAX_PASSWORD_BYTES = 72

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")


def _now_ms() -> int:
    """Milliseconds since the UTC epoch (matches the Node implementation)."""
    return int(time.time() * 1000)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Whisper:
    def __init__(
        self,
        db_path: str = ":memory:",
        salt_rounds: int = 12,
        algorithm: str = "bcrypt",
        timestamps: bool = False,
        session_ttl_ms: int = 7 * 24 * 60 * 60 * 1000,
        guest_token_expiry_ms: int = 30 * 24 * 60 * 60 * 1000,
    ):
        if algorithm not in ("bcrypt", "argon2"):
            raise ValueError(f"Unknown algorithm: {algorithm}")
        self.db_path = db_path
        self.salt_rounds = salt_rounds
        self.algorithm = algorithm
        self.timestamps = timestamps
        self.session_ttl_ms = session_ttl_ms
        self.guest_token_expiry_ms = guest_token_expiry_ms
        self._argon2 = _load_argon2() if algorithm == "argon2" else None
        self._dummy_hash: Optional[str] = None

        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        if db_path != ":memory:":
            self.conn.execute("PRAGMA journal_mode = WAL")
        # Load-bearing: without this, ON DELETE CASCADE / SET NULL are ignored.
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA secure_delete = ON")
        self.setup_database()

    def setup_database(self) -> None:
        created_at = ", created_at INTEGER" if self.timestamps else ""
        self.conn.executescript(
            f"""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL{created_at}
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS purchases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                guest_token_hash TEXT,
                transaction_id TEXT UNIQUE NOT NULL,
                amount REAL NOT NULL,
                currency TEXT NOT NULL DEFAULT 'USD',
                status TEXT NOT NULL DEFAULT 'completed',
                expires_at INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
            CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_purchases_user ON purchases(user_id);
            CREATE INDEX IF NOT EXISTS idx_purchases_guest ON purchases(guest_token_hash);
            CREATE INDEX IF NOT EXISTS idx_purchases_expires ON purchases(expires_at);
            """
        )
        self.conn.commit()

    # === PASSWORD HASHING ===

    def _hash_password(self, password: str) -> str:
        if self.algorithm == "argon2":
            return self._argon2.hash(password)
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(self.salt_rounds)).decode(
            "utf-8"
        )

    def _verify_password(self, password: str, stored_hash: str) -> bool:
        if stored_hash.startswith("$argon2"):
            try:
                return _load_argon2().verify(stored_hash, password)
            except Exception:
                return False
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))

    def _get_dummy_hash(self) -> str:
        # A throwaway hash compared against when no user exists, so login latency
        # doesn't reveal whether a username is registered.
        if self._dummy_hash is None:
            self._dummy_hash = self._hash_password(secrets.token_hex(16))
        return self._dummy_hash

    def _validate_password(self, password: str) -> None:
        if not password:
            raise ValueError("Password is required")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
            raise ValueError(f"Password must be at most {MAX_PASSWORD_BYTES} bytes long")

    # === USER MANAGEMENT ===

    def create_user(self, username: str, password: str) -> Dict[str, Any]:
        if not username or not password:
            raise ValueError("Username and password are required")
        if len(username) < 3 or len(username) > 50:
            raise ValueError("Username must be between 3 and 50 characters")
        if not USERNAME_RE.match(username):
            raise ValueError(
                "Username can only contain letters, numbers, underscores, and hyphens"
            )
        self._validate_password(password)

        password_hash = self._hash_password(password)
        uname = username.lower()
        try:
            cur = self.conn.cursor()
            if self.timestamps:
                cur.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (uname, password_hash, _now_ms()),
                )
            else:
                cur.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (uname, password_hash),
                )
            self.conn.commit()
            return {"id": cur.lastrowid, "username": uname}
        except sqlite3.IntegrityError:
            raise ValueError("Username already exists")

    def verify_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        if not username or not password:
            return None
        row = self.conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username.lower(),),
        ).fetchone()

        if row is None:
            # Equalize timing with the found-user path.
            self._verify_password(password, self._get_dummy_hash())
            return None
        if self._verify_password(password, row["password_hash"]):
            return {"id": row["id"], "username": row["username"]}
        return None

    def change_password(self, user_id: int, old_password: str, new_password: str) -> bool:
        self._validate_password(new_password)
        row = self.conn.execute(
            "SELECT password_hash FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if row is None:
            raise ValueError("User not found")
        if not self._verify_password(old_password, row["password_hash"]):
            raise ValueError("Current password is incorrect")

        new_hash = self._hash_password(new_password)
        # Revoke every session in the same transaction as the hash change.
        with self.conn:
            self.conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id)
            )
            self.conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        return True

    def delete_user(self, user_id: int) -> bool:
        """Erase the account, its sessions (via CASCADE), and its purchases."""
        with self.conn:
            self.conn.execute("DELETE FROM purchases WHERE user_id = ?", (user_id,))
            cur = self.conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cur.rowcount > 0

    # === SESSION MANAGEMENT ===

    def generate_token(self) -> str:
        return secrets.token_urlsafe(32)

    def create_session(self, user_id: int, expires_in_ms: Optional[int] = None) -> Dict[str, Any]:
        token = self.generate_token()
        expires_at = _now_ms() + (self.session_ttl_ms if expires_in_ms is None else expires_in_ms)
        with self.conn:
            self.conn.execute(
                "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                (user_id, _hash_token(token), expires_at),
            )
        return {"token": token, "expires_at": expires_at}

    def verify_session(self, token: str) -> Optional[Dict[str, Any]]:
        if not token:
            return None
        row = self.conn.execute(
            """SELECT s.user_id AS user_id, u.username AS username
               FROM sessions s JOIN users u ON s.user_id = u.id
               WHERE s.token_hash = ? AND s.expires_at > ?""",
            (_hash_token(token), _now_ms()),
        ).fetchone()
        if row:
            return {"user_id": row["user_id"], "username": row["username"]}
        return None

    def revoke_session(self, token: str) -> bool:
        with self.conn:
            cur = self.conn.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (_hash_token(token),)
            )
        return cur.rowcount > 0

    def cleanup_expired_sessions(self) -> int:
        with self.conn:
            cur = self.conn.execute("DELETE FROM sessions WHERE expires_at < ?", (_now_ms(),))
        return cur.rowcount

    # === PURCHASE MANAGEMENT ===

    def generate_guest_token(self) -> str:
        return f"guest_{secrets.token_urlsafe(16)}"

    def _validate_purchase(self, transaction_id: str, amount: float, currency: str) -> None:
        if not transaction_id or not isinstance(transaction_id, str):
            raise ValueError("Transaction ID is required")
        if not isinstance(amount, (int, float)) or isinstance(amount, bool) or amount <= 0:
            raise ValueError("Amount must be a positive number")
        if not CURRENCY_RE.match(currency):
            raise ValueError("Currency must be a 3-letter ISO 4217 code")

    def record_purchase(
        self,
        transaction_id: str,
        amount: float,
        currency: str = "USD",
        user_id: Optional[int] = None,
        guest_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._validate_purchase(transaction_id, amount, currency)

        returned_guest_token = None
        guest_token_hash = None
        if not user_id:
            returned_guest_token = guest_token or self.generate_guest_token()
            guest_token_hash = _hash_token(returned_guest_token)
        expires_at = None if user_id else _now_ms() + self.guest_token_expiry_ms

        try:
            with self.conn:
                cur = self.conn.execute(
                    """INSERT INTO purchases
                       (user_id, guest_token_hash, transaction_id, amount, currency, expires_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (user_id, guest_token_hash, transaction_id, amount, currency, expires_at),
                )
            return {
                "id": cur.lastrowid,
                "transaction_id": transaction_id,
                "guest_token": returned_guest_token,
                "amount": amount,
                "currency": currency,
            }
        except sqlite3.IntegrityError:
            raise ValueError("Transaction already recorded")

    def get_user_purchases(self, user_id: int) -> List[Dict]:
        rows = self.conn.execute(
            """SELECT id, transaction_id, amount, currency, status
               FROM purchases WHERE user_id = ? ORDER BY id DESC""",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_guest_purchases(self, guest_token: str) -> List[Dict]:
        if not guest_token:
            return []
        rows = self.conn.execute(
            """SELECT id, transaction_id, amount, currency, status
               FROM purchases WHERE guest_token_hash = ? ORDER BY id DESC""",
            (_hash_token(guest_token),),
        ).fetchall()
        return [dict(r) for r in rows]

    def cleanup_expired_guest_purchases(self) -> int:
        with self.conn:
            cur = self.conn.execute(
                "DELETE FROM purchases WHERE expires_at IS NOT NULL AND expires_at < ?",
                (_now_ms(),),
            )
        return cur.rowcount

    # === UTILITY ===

    def get_user_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]

    def close(self) -> None:
        self.conn.close()


def _load_argon2():
    try:
        from argon2 import PasswordHasher

        # OWASP-recommended argon2id parameters.
        return PasswordHasher(memory_cost=19456, time_cost=2, parallelism=1)
    except ImportError:
        raise RuntimeError(
            "The 'argon2' algorithm needs the optional 'argon2-cffi' package. "
            "Install it with: pip install argon2-cffi"
        )
