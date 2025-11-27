// server.js
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Client } = require('pg');

const app = express();
app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// Allow your Netlify frontend origin to call the backend
const FRONTEND = process.env.FRONTEND_URL || 'http://localhost:3000';
app.use(cors({ origin: FRONTEND, credentials: true }));

// DB client helper (simple pooling via new client per request for this small app)
// For production you can replace with a Pool.
function getClient() {
  return new Client({ connectionString: process.env.DATABASE_URL });
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10
});

const signJwt = (payload) =>
  jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRY || '1d' });

const verifyJwt = (token) => jwt.verify(token, process.env.JWT_SECRET);

// ---- Public health check
app.get('/health', (req, res) => res.json({ ok: true }));

// ---- Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing credentials' });

  const client = getClient();
  await client.connect();
  try {
    const { rows } = await client.query('SELECT * FROM users WHERE email=$1 LIMIT 1', [email]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signJwt({ sub: user.id, role: user.role, email: user.email });

    // send httpOnly cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.json({ ok: true, user: { id: user.id, email: user.email, role: user.role } });
  } catch (err) {
    console.error('Login error', err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    await client.end();
  }
});

// ---- Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

// ---- Middleware to protect routes
async function requireAuth(roleRequired = null) {
  return async (req, res, next) => {
    const token = req.cookies?.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
      const payload = verifyJwt(token);
      if (roleRequired && payload.role !== roleRequired) return res.status(403).json({ error: 'Forbidden' });
      req.user = payload;
      next();
    } catch (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

// ---- Admin-only route example
app.get('/api/admin/dashboard', (req, res, next) => requireAuth('admin')(req, res, next), async (req, res) => {
  // sample data
  res.json({ ok: true, msg: 'Welcome admin', user: req.user });
});

// ---- Registration (disabled in production; optional)
app.post('/api/auth/register', async (req, res) => {
  const { email, password, role } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  const client = getClient();
  await client.connect();
  try {
    const hash = await bcrypt.hash(password, Number(process.env.SALT_ROUNDS || 10));
    await client.query('INSERT INTO users (email, password_hash, role) VALUES ($1,$2,$3)', [email, hash, role || 'user']);
    res.json({ ok: true });
  } catch (err) {
    console.error('Register error', err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    await client.end();
  }
});

const port = Number(process.env.PORT || 5000);
app.listen(port, () => {
  console.log(`Backend listening on ${port}`);
});
