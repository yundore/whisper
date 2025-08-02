This was made with Claude Opus 4. Just a brain dump idea I had that seemed pretty useful.


# whisper 🔐

A privacy-first authentication system that stores only what's necessary: usernames and password hashes. No emails, no personal information, no tracking.

## 🎯 Philosophy

**I believe in:**
- Collecting only what's essential
- Respecting user privacy by default
- Making anonymity easy
- Keeping things simple

**What it will store:**
- Username
- Password hash
- That's it.

##  Features

- ✅ Minimal data collection (username + password only)
- ✅ Secure password hashing (bcrypt/argon2)
- ✅ Guest checkout support
- ✅ Payment processor integration (without storing personal data)
- ✅ GDPR-friendly by design
- ✅ Easy to audit and understand

##  Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
