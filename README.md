This was made with Claude Opus 4, just a brain dump idea I had that seemed pretty useful. So do keep in mind that there might be some mistakes.


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

```
### Purchases Table 
```sql
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
```

### Guest Purchases Table
```sql
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
```
# Minimal User Database - Only Username & Password

## 🗄️ User Database Table

| ID | Username     | Password (Hashed)           |
|----|--------------|-----------------------------|
| 1  | cooluser123  | `$2b$10$YZxy89...hashed...` |
| 2  | gamer456     | `$2b$10$ABcd12...hashed...` |
| 3  | ninja789     | `$2b$10$QRst34...hashed...` |

---

### ✅ What This Database DOES Store:
- **Username** – The unique identifier for each user
- **Password Hash** – An encrypted version of the password (never the actual password)
- **User ID** – A simple number to identify each record

### ❌ What This Database DOES NOT Store:
- Real names
- Email addresses
- Phone numbers
- Physical addresses
- Birth dates
- Credit card information
- Any other personal information

---

### 🔒 Privacy & Security Benefits:
- Minimal data collection = minimal privacy risk
- Even if breached, no personal information is exposed
- Passwords are hashed, so they can't be read even by database admins
- Perfect for anonymous services or privacy-focused applications

---

#### Simple Database Schema Example

```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL
);
```
