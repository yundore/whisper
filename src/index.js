'use strict';

const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
const crypto = require('crypto');

// bcrypt silently truncates input past 72 bytes, so longer passwords are
// rejected outright rather than hashed in a silently-shortened form.
const MAX_PASSWORD_BYTES = 72;

// OWASP-recommended argon2id parameters: 19 MiB memory, 2 iterations, 1 lane.
// type 2 === argon2id in the `argon2` package.
const ARGON2_OPTIONS = { type: 2, memoryCost: 19456, timeCost: 2, parallelism: 1 };

const USERNAME_RE = /^[a-zA-Z0-9_-]+$/;
const CURRENCY_RE = /^[A-Z]{3}$/;

class Whisper {
  /**
   * @param {object} [options]
   * @param {string}  [options.dbPath=':memory:']     SQLite file path, or ':memory:'.
   * @param {number}  [options.saltRounds=12]          bcrypt cost factor (ignored for argon2).
   * @param {'bcrypt'|'argon2'} [options.algorithm='bcrypt']  password hashing algorithm.
   * @param {boolean} [options.timestamps=false]       store a created_at on accounts. Off by
   *                                                    default so the database holds only a
   *                                                    username and a password hash per user.
   * @param {number}  [options.sessionTTL]             default session lifetime in ms (7 days).
   * @param {number}  [options.guestTokenExpiry]       guest-purchase lifetime in ms (30 days).
   */
  constructor(options = {}) {
    this.dbPath = options.dbPath || ':memory:';
    this.saltRounds = options.saltRounds || 12;
    this.algorithm = options.algorithm || 'bcrypt';
    this.timestamps = options.timestamps === true;
    this.sessionTTL = options.sessionTTL || 7 * 24 * 60 * 60 * 1000;
    this.guestTokenExpiry = options.guestTokenExpiry || 30 * 24 * 60 * 60 * 1000;

    if (this.algorithm !== 'bcrypt' && this.algorithm !== 'argon2') {
      throw new Error(`Unknown algorithm: ${this.algorithm}`);
    }
    if (this.algorithm === 'argon2') this._argon2 = loadArgon2();

    this.db = new Database(this.dbPath);
    if (this.dbPath !== ':memory:') this.db.pragma('journal_mode = WAL');
    // Load-bearing for the privacy promise: without this, ON DELETE CASCADE and
    // ON DELETE SET NULL are silently ignored and deletions leave data behind.
    this.db.pragma('foreign_keys = ON');
    // Zero out freed pages so deleted rows can't be recovered from the file.
    this.db.pragma('secure_delete = ON');
    this.setupDatabase();

    this._dummyHashPromise = null; // computed lazily, see verifyUser().
  }

  setupDatabase() {
    const createdAt = this.timestamps ? ',\n        created_at INTEGER' : '';
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL${createdAt}
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
    `);
  }

  // === PASSWORD HASHING ===

  async _hashPassword(password) {
    if (this.algorithm === 'argon2') return this._argon2.hash(password, ARGON2_OPTIONS);
    return bcrypt.hash(password, this.saltRounds);
  }

  // The stored hash's prefix decides which verifier runs, so a database may hold
  // a mix of bcrypt and argon2 hashes (e.g. during a migration) and both verify.
  async _verifyPassword(password, storedHash) {
    if (typeof storedHash === 'string' && storedHash.startsWith('$argon2')) {
      return loadArgon2().verify(storedHash, password);
    }
    return bcrypt.compare(password, storedHash);
  }

  // A throwaway hash to compare against when no user is found, so login latency
  // doesn't reveal whether a username exists. Computed once, lazily.
  _dummyHash() {
    if (!this._dummyHashPromise) {
      this._dummyHashPromise = this._hashPassword(crypto.randomBytes(16).toString('hex'));
    }
    return this._dummyHashPromise;
  }

  _validatePassword(password) {
    if (!password) throw new Error('Password is required');
    if (password.length < 8) throw new Error('Password must be at least 8 characters long');
    if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) {
      throw new Error(`Password must be at most ${MAX_PASSWORD_BYTES} bytes long`);
    }
  }

  // === USER MANAGEMENT ===

  async createUser(username, password) {
    if (!username || !password) throw new Error('Username and password are required');
    if (username.length < 3 || username.length > 50) {
      throw new Error('Username must be between 3 and 50 characters');
    }
    if (!USERNAME_RE.test(username)) {
      throw new Error('Username can only contain letters, numbers, underscores, and hyphens');
    }
    this._validatePassword(password);

    const hash = await this._hashPassword(password);
    const uname = username.toLowerCase();
    try {
      const info = this.timestamps
        ? this.db
            .prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)')
            .run(uname, hash, Date.now())
        : this.db
            .prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
            .run(uname, hash);
      return { id: Number(info.lastInsertRowid), username: uname };
    } catch (err) {
      if (/UNIQUE constraint failed/.test(err.message)) {
        throw new Error('Username already exists');
      }
      throw err;
    }
  }

  async verifyUser(username, password) {
    if (!username || !password) return null;
    const user = this.db
      .prepare('SELECT id, username, password_hash FROM users WHERE username = ?')
      .get(username.toLowerCase());

    if (!user) {
      // Run a comparison anyway so the no-user path costs the same as a real one.
      await this._verifyPassword(password, await this._dummyHash());
      return null;
    }
    const ok = await this._verifyPassword(password, user.password_hash);
    return ok ? { id: user.id, username: user.username } : null;
  }

  async changePassword(userId, oldPassword, newPassword) {
    this._validatePassword(newPassword);
    const user = this.db.prepare('SELECT password_hash FROM users WHERE id = ?').get(userId);
    if (!user) throw new Error('User not found');
    const ok = await this._verifyPassword(oldPassword, user.password_hash);
    if (!ok) throw new Error('Current password is incorrect');

    const hash = await this._hashPassword(newPassword);
    // Changing a password is how a user evicts an attacker, so every existing
    // session is revoked in the same transaction as the hash update.
    const tx = this.db.transaction((id, h) => {
      this.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(h, id);
      this.db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
    });
    tx(userId, hash);
    return true;
  }

  /**
   * Erase a user completely: the account, its sessions (via CASCADE), and its
   * purchases. Nothing linkable to the user survives, which is what a right-to-
   * erasure request requires.
   * @returns {Promise<boolean>} true if a user was deleted.
   */
  async deleteUser(userId) {
    const tx = this.db.transaction((id) => {
      this.db.prepare('DELETE FROM purchases WHERE user_id = ?').run(id);
      // Deleting the user cascades to sessions because foreign keys are enabled.
      return this.db.prepare('DELETE FROM users WHERE id = ?').run(id).changes > 0;
    });
    return tx(userId);
  }

  // === SESSION MANAGEMENT ===

  generateToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  _hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  async createSession(userId, expiresIn = this.sessionTTL) {
    const token = this.generateToken();
    const expiresAt = Date.now() + expiresIn;
    // Only the hash is stored; the raw token is handed back to the caller once.
    this.db
      .prepare('INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)')
      .run(userId, this._hashToken(token), expiresAt);
    return { token, expiresAt: new Date(expiresAt) };
  }

  async verifySession(token) {
    if (!token) return null;
    const row = this.db
      .prepare(
        `SELECT s.user_id AS userId, u.username
         FROM sessions s JOIN users u ON s.user_id = u.id
         WHERE s.token_hash = ? AND s.expires_at > ?`
      )
      .get(this._hashToken(token), Date.now());
    return row ? { userId: row.userId, username: row.username } : null;
  }

  async revokeSession(token) {
    return (
      this.db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(this._hashToken(token))
        .changes > 0
    );
  }

  async cleanupExpiredSessions() {
    return this.db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now()).changes;
  }

  // === PURCHASE MANAGEMENT ===

  generateGuestToken() {
    return 'guest_' + crypto.randomBytes(16).toString('hex');
  }

  _validatePurchase(transactionId, amount, currency) {
    if (!transactionId || typeof transactionId !== 'string') {
      throw new Error('Transaction ID is required');
    }
    if (typeof amount !== 'number' || !Number.isFinite(amount) || amount <= 0) {
      throw new Error('Amount must be a positive number');
    }
    if (!CURRENCY_RE.test(currency)) {
      throw new Error('Currency must be a 3-letter ISO 4217 code');
    }
  }

  async recordPurchase(transactionId, amount, currency = 'USD', userId = null, guestToken = null) {
    this._validatePurchase(transactionId, amount, currency);

    let returnedGuestToken = null;
    let guestTokenHash = null;
    if (!userId) {
      returnedGuestToken = guestToken || this.generateGuestToken();
      guestTokenHash = this._hashToken(returnedGuestToken);
    }
    // Guest purchases expire so guest data doesn't accumulate forever; purchases
    // tied to an account are kept until the account is erased.
    const expiresAt = userId ? null : Date.now() + this.guestTokenExpiry;

    try {
      const info = this.db
        .prepare(
          `INSERT INTO purchases (user_id, guest_token_hash, transaction_id, amount, currency, expires_at)
           VALUES (?, ?, ?, ?, ?, ?)`
        )
        .run(userId, guestTokenHash, transactionId, amount, currency, expiresAt);
      return {
        id: Number(info.lastInsertRowid),
        transactionId,
        guestToken: returnedGuestToken,
        amount,
        currency,
      };
    } catch (err) {
      if (/UNIQUE constraint failed/.test(err.message)) {
        throw new Error('Transaction already recorded');
      }
      throw err;
    }
  }

  async getUserPurchases(userId) {
    return this.db
      .prepare(
        `SELECT id, transaction_id, amount, currency, status
         FROM purchases WHERE user_id = ? ORDER BY id DESC`
      )
      .all(userId);
  }

  async getGuestPurchases(guestToken) {
    if (!guestToken) return [];
    return this.db
      .prepare(
        `SELECT id, transaction_id, amount, currency, status
         FROM purchases WHERE guest_token_hash = ? ORDER BY id DESC`
      )
      .all(this._hashToken(guestToken));
  }

  async cleanupExpiredGuestPurchases() {
    return this.db
      .prepare('DELETE FROM purchases WHERE expires_at IS NOT NULL AND expires_at < ?')
      .run(Date.now()).changes;
  }

  // === UTILITY ===

  async getUserCount() {
    return this.db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
  }

  async close() {
    this.db.close();
  }
}

function loadArgon2() {
  try {
    return require('argon2');
  } catch (err) {
    throw new Error(
      "The 'argon2' algorithm needs the optional 'argon2' package. Install it with: npm install argon2"
    );
  }
}

module.exports = Whisper;
