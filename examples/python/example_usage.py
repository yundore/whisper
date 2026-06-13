"""Minimal walkthrough of the Whisper Python library."""

from whisper import Whisper


def main() -> None:
    auth = Whisper(db_path="whisper.db")
    try:
        print("Creating user...")
        user = auth.create_user("demo_user", "secure_password123")
        print(f"  created: {user}")

        print("Verifying credentials...")
        print(f"  login ok: {auth.verify_user('demo_user', 'secure_password123') is not None}")

        print("Creating session...")
        session = auth.create_session(user["id"])
        print(f"  token (shown once): {session['token'][:12]}...")

        print("Verifying session...")
        print(f"  session valid for: {auth.verify_session(session['token'])}")

        print("Recording a purchase...")
        purchase = auth.record_purchase("tx_12345", 99.99, "USD", user["id"])
        print(f"  recorded: {purchase['transaction_id']} ({purchase['amount']} {purchase['currency']})")
        print(f"  user has {len(auth.get_user_purchases(user['id']))} purchase(s)")

        print("Recording a guest purchase...")
        guest = auth.record_purchase("tx_67890", 49.99)
        print(f"  guest token (shown once): {guest['guest_token'][:18]}...")

        print("Erasing the account (right to be forgotten)...")
        auth.delete_user(user["id"])
        print(f"  session still valid after erasure: {auth.verify_session(session['token']) is not None}")
        print(f"  total users: {auth.get_user_count()}")
    finally:
        auth.close()


if __name__ == "__main__":
    main()
