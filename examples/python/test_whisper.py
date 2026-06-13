"""Stdlib unittest suite for the Whisper Python library.

Run from this directory with:  python -m unittest -v
"""

import hashlib
import unittest

from whisper import Whisper


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class WhisperTest(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = Whisper(db_path=":memory:")

    def tearDown(self) -> None:
        self.auth.close()

    # --- users ---

    def test_create_and_verify(self):
        user = self.auth.create_user("testuser", "password123")
        self.assertEqual(user["username"], "testuser")
        self.assertIsNotNone(self.auth.verify_user("testuser", "password123"))
        self.assertIsNone(self.auth.verify_user("testuser", "wrong-password"))

    def test_lowercases_username(self):
        self.assertEqual(self.auth.create_user("TestUser", "password123")["username"], "testuser")

    def test_rejects_duplicate(self):
        self.auth.create_user("dupe", "password123")
        with self.assertRaises(ValueError):
            self.auth.create_user("dupe", "password456")

    def test_rejects_long_password(self):
        with self.assertRaises(ValueError):
            self.auth.create_user("longpw", "a" * 73)

    def test_unknown_user_returns_none(self):
        self.assertIsNone(self.auth.verify_user("ghost", "whatever123"))

    def test_password_stored_hashed(self):
        user = self.auth.create_user("hashpw", "password123")
        row = self.auth.conn.execute(
            "SELECT password_hash FROM users WHERE id = ?", (user["id"],)
        ).fetchone()
        self.assertNotEqual(row["password_hash"], "password123")

    def test_no_created_at_by_default(self):
        cols = {r["name"] for r in self.auth.conn.execute("PRAGMA table_info(users)").fetchall()}
        self.assertEqual(cols, {"id", "username", "password_hash"})

    # --- sessions ---

    def test_session_roundtrip(self):
        user = self.auth.create_user("sess", "password123")
        session = self.auth.create_session(user["id"])
        self.assertEqual(self.auth.verify_session(session["token"])["user_id"], user["id"])

    def test_session_token_stored_hashed(self):
        user = self.auth.create_user("toks", "password123")
        session = self.auth.create_session(user["id"])
        row = self.auth.conn.execute(
            "SELECT token_hash FROM sessions WHERE user_id = ?", (user["id"],)
        ).fetchone()
        self.assertNotEqual(row["token_hash"], session["token"])
        self.assertEqual(row["token_hash"], sha256(session["token"]))

    def test_expired_session(self):
        user = self.auth.create_user("exp", "password123")
        session = self.auth.create_session(user["id"], expires_in_ms=-1000)
        self.assertIsNone(self.auth.verify_session(session["token"]))

    def test_change_password_revokes_sessions(self):
        user = self.auth.create_user("changer", "oldpassword")
        session = self.auth.create_session(user["id"])
        self.auth.change_password(user["id"], "oldpassword", "newpassword")
        self.assertIsNone(self.auth.verify_session(session["token"]))

    # --- erasure ---

    def test_delete_user_erases_everything(self):
        user = self.auth.create_user("eraseme", "password123")
        session = self.auth.create_session(user["id"])
        self.auth.record_purchase("tx_erase", 10, "USD", user["id"])
        self.assertTrue(self.auth.delete_user(user["id"]))
        sessions = self.auth.conn.execute(
            "SELECT COUNT(*) AS c FROM sessions WHERE user_id = ?", (user["id"],)
        ).fetchone()["c"]
        purchases = self.auth.conn.execute(
            "SELECT COUNT(*) AS c FROM purchases WHERE user_id = ?", (user["id"],)
        ).fetchone()["c"]
        self.assertEqual(sessions, 0)
        self.assertEqual(purchases, 0)
        self.assertIsNone(self.auth.verify_session(session["token"]))

    # --- purchases ---

    def test_guest_purchase_hashed_token(self):
        p = self.auth.record_purchase("tx_guest", 5, "USD")
        self.assertTrue(p["guest_token"].startswith("guest_"))
        self.assertEqual(len(self.auth.get_guest_purchases(p["guest_token"])), 1)
        row = self.auth.conn.execute(
            "SELECT guest_token_hash FROM purchases WHERE transaction_id = ?", ("tx_guest",)
        ).fetchone()
        self.assertEqual(row["guest_token_hash"], sha256(p["guest_token"]))

    def test_rejects_bad_amount_and_currency(self):
        with self.assertRaises(ValueError):
            self.auth.record_purchase("tx_neg", -5, "USD")
        with self.assertRaises(ValueError):
            self.auth.record_purchase("tx_zero", 0, "USD")
        with self.assertRaises(ValueError):
            self.auth.record_purchase("tx_cur", 5, "usd")

    def test_duplicate_transaction(self):
        self.auth.record_purchase("tx_dupe", 1, "USD")
        with self.assertRaises(ValueError):
            self.auth.record_purchase("tx_dupe", 1, "USD")

    def test_cleanup_expired_guest_purchases(self):
        a = Whisper(db_path=":memory:", guest_token_expiry_ms=-1000)
        user = a.create_user("keeper", "password123")
        a.record_purchase("tx_user", 5, "USD", user["id"])
        a.record_purchase("tx_guest_exp", 5, "USD")
        self.assertEqual(a.cleanup_expired_guest_purchases(), 1)
        self.assertEqual(len(a.get_user_purchases(user["id"])), 1)
        a.close()


if __name__ == "__main__":
    unittest.main()
