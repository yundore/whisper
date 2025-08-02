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

CREATE TABLE guest_purchases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guest_token VARCHAR(100) UNIQUE NOT NULL,
    transaction_id VARCHAR(100) NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    currency VARCHAR(3) DEFAULT 'USD',
    status VARCHAR(20) DEFAULT 'completed',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE TABLE purchases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    transaction_id VARCHAR(100) NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    currency VARCHAR(3) DEFAULT 'USD',
    status VARCHAR(20) DEFAULT 'completed',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
