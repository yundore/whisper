'use strict';

// Example Express server showing Whisper behind a small JSON API. It is a
// reference, not a turnkey product: read PRIVACY.md and set trust proxy / TLS to
// match your deployment before exposing it.

const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const rl = require('express-rate-limit');
const Whisper = require('../src/index');

const rateLimit = rl.rateLimit || rl;
// ipKeyGenerator normalizes IPv6 (a bare /128 would let an attacker rotate the
// low bits); fall back to identity on older versions.
const ipKeyGenerator = rl.ipKeyGenerator || ((ip) => ip);

const auth = new Whisper({ dbPath: process.env.WHISPER_DB || './whisper.db' });
const app = express();

// Per-process random salt: rate-limit buckets are keyed by a salted hash of the
// client IP, not the raw IP, so no durable client identifier is held in memory.
const IP_SALT = crypto.randomBytes(16).toString('hex');
function privacyKey(req) {
  const normalized = ipKeyGenerator(req.ip);
  return crypto.createHash('sha256').update(IP_SALT + normalized).digest('hex').slice(0, 16);
}

// trust proxy MUST match your deployment. Default trusts nothing (app exposed
// directly). Behind one reverse proxy set TRUST_PROXY=1, etc. Trusting a hop you
// don't actually have lets clients spoof X-Forwarded-For and dodge rate limits.
app.set('trust proxy', Number(process.env.TRUST_PROXY) || false);

app.use(helmet());
app.use(express.json({ limit: '10kb' }));

const jsonLimiter = (windowMs, max, error) =>
  rateLimit({ windowMs, max, keyGenerator: privacyKey, standardHeaders: true, legacyHeaders: false, message: { success: false, error } });

const loginLimiter = jsonLimiter(15 * 60 * 1000, 5, 'Too many attempts, please try again later');
const createLimiter = jsonLimiter(60 * 60 * 1000, 3, 'Too many accounts created, please try again later');
const writeLimiter = jsonLimiter(15 * 60 * 1000, 60, 'Too many requests, please slow down');

const bearer = (req) => (req.headers.authorization || '').replace(/^Bearer /, '');

async function authenticate(req, res, next) {
  const token = bearer(req);
  if (!token) return res.status(401).json({ success: false, error: 'No token provided' });
  try {
    const session = await auth.verifySession(token);
    if (!session) return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    req.user = session;
    next();
  } catch {
    res.status(500).json({ success: false, error: 'Server error' });
  }
}

// === AUTH ===

app.post('/api/register', createLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const user = await auth.createUser(username, password);
    const session = await auth.createSession(user.id);
    res.json({ success: true, token: session.token, expiresAt: session.expiresAt });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const user = await auth.verifyUser(username, password);
    // One generic message for both unknown user and wrong password.
    if (!user) return res.status(401).json({ success: false, error: 'Invalid credentials' });
    const session = await auth.createSession(user.id);
    res.json({ success: true, token: session.token, expiresAt: session.expiresAt });
  } catch {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/logout', authenticate, async (req, res) => {
  try {
    await auth.revokeSession(bearer(req));
    res.json({ success: true, message: 'Logged out successfully' });
  } catch {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/change-password', authenticate, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body || {};
    await auth.changePassword(req.user.userId, oldPassword, newPassword);
    // Existing sessions (including this one) are revoked, so issue a fresh token.
    const session = await auth.createSession(req.user.userId);
    res.json({ success: true, token: session.token, expiresAt: session.expiresAt });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

app.delete('/api/account', authenticate, async (req, res) => {
  try {
    await auth.deleteUser(req.user.userId);
    res.json({ success: true, message: 'Account erased' });
  } catch {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// === PURCHASES ===

app.post('/api/purchase', authenticate, writeLimiter, async (req, res) => {
  try {
    const { transactionId, amount, currency } = req.body || {};
    const purchase = await auth.recordPurchase(transactionId, amount, currency || 'USD', req.user.userId);
    res.json({ success: true, purchase });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

app.post('/api/guest-purchase', writeLimiter, async (req, res) => {
  try {
    const { transactionId, amount, currency } = req.body || {};
    const purchase = await auth.recordPurchase(transactionId, amount, currency || 'USD');
    res.json({ success: true, purchase, guestToken: purchase.guestToken });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

app.get('/api/purchases', authenticate, async (req, res) => {
  try {
    res.json({ success: true, purchases: await auth.getUserPurchases(req.user.userId) });
  } catch {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/guest-purchases/:guestToken', writeLimiter, async (req, res) => {
  try {
    res.json({ success: true, purchases: await auth.getGuestPurchases(req.params.guestToken) });
  } catch {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/health', (_req, res) => res.json({ success: true }));

// Malformed JSON and any other error: respond generically, never echo internals.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ success: false, error: 'Invalid JSON body' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ success: false, error: 'Request body too large' });
  }
  res.status(500).json({ success: false, error: 'Server error' });
});

// Purge expired sessions and guest purchases hourly so data doesn't accumulate.
const cleanup = setInterval(async () => {
  try {
    await auth.cleanupExpiredSessions();
    await auth.cleanupExpiredGuestPurchases();
  } catch (error) {
    console.error('Cleanup error:', error.message);
  }
}, 60 * 60 * 1000);
cleanup.unref();

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Whisper example server listening on port ${PORT}`));
}

module.exports = app;
