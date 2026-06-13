'use strict';

const crypto = require('crypto');
const Whisper = require('../src/index');

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

describe('Whisper', () => {
  let auth;

  beforeEach(() => {
    auth = new Whisper({ dbPath: ':memory:' });
  });

  afterEach(async () => {
    await auth.close();
  });

  describe('User management', () => {
    test('creates a new user', async () => {
      const user = await auth.createUser('testuser', 'password123');
      expect(user).toHaveProperty('id');
      expect(user.username).toBe('testuser');
    });

    test('lowercases usernames', async () => {
      const user = await auth.createUser('TestUser', 'password123');
      expect(user.username).toBe('testuser');
    });

    test('rejects duplicate usernames', async () => {
      await auth.createUser('testuser', 'password123');
      await expect(auth.createUser('testuser', 'password456')).rejects.toThrow(
        'Username already exists'
      );
    });

    test('validates username format', async () => {
      await expect(auth.createUser('ab', 'password123')).rejects.toThrow(
        'Username must be between 3 and 50 characters'
      );
      await expect(auth.createUser('user@name', 'password123')).rejects.toThrow(
        'Username can only contain letters, numbers, underscores, and hyphens'
      );
    });

    test('validates password length', async () => {
      await expect(auth.createUser('testuser', 'short')).rejects.toThrow(
        'Password must be at least 8 characters long'
      );
    });

    test('rejects passwords longer than 72 bytes (bcrypt truncation guard)', async () => {
      await expect(auth.createUser('longpw', 'a'.repeat(73))).rejects.toThrow(/72 bytes/);
    });

    test('verifies valid credentials', async () => {
      await auth.createUser('testuser', 'password123');
      const verified = await auth.verifyUser('testuser', 'password123');
      expect(verified).toHaveProperty('id');
      expect(verified.username).toBe('testuser');
    });

    test('rejects invalid credentials', async () => {
      await auth.createUser('testuser', 'password123');
      expect(await auth.verifyUser('testuser', 'wrongpassword')).toBeNull();
    });

    test('returns null for an unknown user without throwing (timing-safe path)', async () => {
      expect(await auth.verifyUser('ghost', 'whatever123')).toBeNull();
    });

    test('changes password', async () => {
      const user = await auth.createUser('testuser', 'oldpassword');
      await auth.changePassword(user.id, 'oldpassword', 'newpassword');
      expect(await auth.verifyUser('testuser', 'newpassword')).toBeTruthy();
      expect(await auth.verifyUser('testuser', 'oldpassword')).toBeNull();
    });

    test('passwords are stored hashed, never in plaintext', async () => {
      const user = await auth.createUser('hashpw', 'password123');
      const row = auth.db.prepare('SELECT password_hash FROM users WHERE id = ?').get(user.id);
      expect(row.password_hash).not.toBe('password123');
      expect(row.password_hash.startsWith('$2')).toBe(true); // bcrypt prefix
    });

    test('does not store a created_at by default (only username + hash)', async () => {
      const cols = auth.db.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
      expect(cols.sort()).toEqual(['id', 'password_hash', 'username']);
    });
  });

  describe('Session management', () => {
    test('creates and verifies a session', async () => {
      const user = await auth.createUser('testuser', 'password123');
      const session = await auth.createSession(user.id);
      expect(session).toHaveProperty('token');
      expect(session).toHaveProperty('expiresAt');

      const verified = await auth.verifySession(session.token);
      expect(verified.userId).toBe(user.id);
      expect(verified.username).toBe('testuser');
    });

    test('stores session tokens hashed, never in plaintext', async () => {
      const user = await auth.createUser('toks', 'password123');
      const { token } = await auth.createSession(user.id);
      const row = auth.db.prepare('SELECT token_hash FROM sessions WHERE user_id = ?').get(user.id);
      expect(row.token_hash).not.toBe(token);
      expect(row.token_hash).toBe(sha256(token));
    });

    test('does not verify an expired session (sub-second precision)', async () => {
      const user = await auth.createUser('expuser', 'password123');
      const { token } = await auth.createSession(user.id, -1000); // already expired
      expect(await auth.verifySession(token)).toBeNull();
    });

    test('revokes a session', async () => {
      const user = await auth.createUser('testuser', 'password123');
      const { token } = await auth.createSession(user.id);
      expect(await auth.revokeSession(token)).toBe(true);
      expect(await auth.verifySession(token)).toBeNull();
    });

    test('changePassword revokes existing sessions', async () => {
      const user = await auth.createUser('changer', 'oldpassword');
      const { token } = await auth.createSession(user.id);
      await auth.changePassword(user.id, 'oldpassword', 'newpassword');
      expect(await auth.verifySession(token)).toBeNull();
    });

    test('cleanupExpiredSessions removes expired rows', async () => {
      const user = await auth.createUser('cleanup', 'password123');
      await auth.createSession(user.id, -1000);
      await auth.createSession(user.id, 60_000);
      expect(await auth.cleanupExpiredSessions()).toBe(1);
    });
  });

  describe('Right to erasure', () => {
    test('deleteUser removes the account, its sessions, and its purchases', async () => {
      const user = await auth.createUser('eraseme', 'password123');
      const session = await auth.createSession(user.id);
      await auth.recordPurchase('tx_erase', 10, 'USD', user.id);

      expect(await auth.deleteUser(user.id)).toBe(true);

      const sessionCount = auth.db
        .prepare('SELECT COUNT(*) AS c FROM sessions WHERE user_id = ?')
        .get(user.id).c;
      const purchaseCount = auth.db
        .prepare('SELECT COUNT(*) AS c FROM purchases WHERE user_id = ?')
        .get(user.id).c;
      expect(sessionCount).toBe(0);
      expect(purchaseCount).toBe(0);
      expect(await auth.verifySession(session.token)).toBeNull();
      expect(await auth.verifyUser('eraseme', 'password123')).toBeNull();
    });

    test('deleteUser returns false for an unknown id', async () => {
      expect(await auth.deleteUser(99999)).toBe(false);
    });
  });

  describe('Purchase management', () => {
    test('records a user purchase', async () => {
      const user = await auth.createUser('testuser', 'password123');
      const purchase = await auth.recordPurchase('tx_123', 99.99, 'USD', user.id);
      expect(purchase.transactionId).toBe('tx_123');
      expect(purchase.amount).toBe(99.99);
      expect(purchase.guestToken).toBeNull();
    });

    test('records a guest purchase and returns a guest token', async () => {
      const purchase = await auth.recordPurchase('tx_456', 49.99);
      expect(purchase.guestToken).toMatch(/^guest_/);
    });

    test('stores guest tokens hashed; retrievable by the raw token', async () => {
      const p = await auth.recordPurchase('tx_guest', 5, 'USD');
      const list = await auth.getGuestPurchases(p.guestToken);
      expect(list).toHaveLength(1);
      const row = auth.db
        .prepare('SELECT guest_token_hash FROM purchases WHERE transaction_id = ?')
        .get('tx_guest');
      expect(row.guest_token_hash).not.toBe(p.guestToken);
      expect(row.guest_token_hash).toBe(sha256(p.guestToken));
    });

    test('retrieves user purchases', async () => {
      const user = await auth.createUser('testuser', 'password123');
      await auth.recordPurchase('tx_1', 10, 'USD', user.id);
      await auth.recordPurchase('tx_2', 20, 'USD', user.id);
      expect(await auth.getUserPurchases(user.id)).toHaveLength(2);
    });

    test('prevents duplicate transactions', async () => {
      await auth.recordPurchase('tx_dupe', 99.99);
      await expect(auth.recordPurchase('tx_dupe', 99.99)).rejects.toThrow(
        'Transaction already recorded'
      );
    });

    test('rejects non-positive amounts', async () => {
      await expect(auth.recordPurchase('tx_neg', -5, 'USD')).rejects.toThrow(/positive/);
      await expect(auth.recordPurchase('tx_zero', 0, 'USD')).rejects.toThrow(/positive/);
    });

    test('rejects malformed currency codes', async () => {
      await expect(auth.recordPurchase('tx_cur', 5, 'usd')).rejects.toThrow(/ISO 4217/);
      await expect(auth.recordPurchase('tx_cur2', 5, 'DOLLARS')).rejects.toThrow(/ISO 4217/);
    });

    test('cleanupExpiredGuestPurchases removes expired guest rows but keeps user rows', async () => {
      const a = new Whisper({ dbPath: ':memory:', guestTokenExpiry: -1000 });
      const user = await a.createUser('keeper', 'password123');
      await a.recordPurchase('tx_user', 5, 'USD', user.id); // no expiry
      await a.recordPurchase('tx_guest_exp', 5, 'USD'); // already expired
      expect(await a.cleanupExpiredGuestPurchases()).toBe(1);
      expect(await a.getUserPurchases(user.id)).toHaveLength(1);
      await a.close();
    });
  });
});

// Only runs if the optional argon2 dependency is installed.
const argon2Available = (() => {
  try {
    require('argon2');
    return true;
  } catch {
    return false;
  }
})();

(argon2Available ? describe : describe.skip)('Whisper with argon2', () => {
  test('hashes with argon2id and verifies', async () => {
    const a = new Whisper({ dbPath: ':memory:', algorithm: 'argon2' });
    const user = await a.createUser('argonaut', 'password123');
    const row = a.db.prepare('SELECT password_hash FROM users WHERE id = ?').get(user.id);
    expect(row.password_hash.startsWith('$argon2')).toBe(true);
    expect(await a.verifyUser('argonaut', 'password123')).toBeTruthy();
    expect(await a.verifyUser('argonaut', 'wrong-password')).toBeNull();
    await a.close();
  });
});
