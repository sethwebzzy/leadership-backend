// server.js
require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { Client } = require("pg");

const app = express();
app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// Allow your Netlify frontend origin to call the backend
const FRONTEND = process.env.FRONTEND_URL || "http://localhost:3000";
app.use(
  cors({
    origin: FRONTEND,
    credentials: true,
  })
);

// DB client helper
function getClient() {
  return new Client({ connectionString: process.env.DATABASE_URL });
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
});

const signJwt = (payload) =>
  jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRY || "1d",
  });

const verifyJwt = (token) => jwt.verify(token, process.env.JWT_SECRET);

// --------- Ensure tables exist (users, students, contacts) ----------
async function ensureTables() {
  const client = getClient();
  await client.connect();
  try {
    await client.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

    // Users table (for admin + other users)
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TIMESTAMPTZ DEFAULT now(),
        updated_at TIMESTAMPTZ DEFAULT now(),
        reset_token TEXT,
        reset_expires_at TIMESTAMPTZ
      );
    `);

    // Students table (applications)
    await client.query(`
      CREATE TABLE IF NOT EXISTS students (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        course TEXT NOT NULL,
        additional_info TEXT,
        admission_status TEXT NOT NULL DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT now()
      );
    `);

    // Contacts/messages table
    await client.query(`
      CREATE TABLE IF NOT EXISTS contacts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT,
        subject TEXT,
        message TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT now()
      );
    `);

    console.log("✅ Tables ensured (users, students, contacts)");
  } catch (err) {
    console.error("Error ensuring tables", err);
    throw err;
  } finally {
    await client.end();
  }
}

// ---- Public health check
app.get("/health", (req, res) => res.json({ ok: true }));

// ---- Auth middleware
function requireAuth(roleRequired = null) {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization;
    const bearerToken =
      authHeader && authHeader.startsWith("Bearer ")
        ? authHeader.split(" ")[1]
        : null;

    const token = req.cookies?.token || bearerToken;
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    try {
      const payload = verifyJwt(token);
      if (roleRequired && payload.role !== roleRequired) {
        return res.status(403).json({ error: "Forbidden" });
      }
      req.user = payload;
      next();
    } catch (err) {
      return res.status(401).json({ error: "Invalid token" });
    }
  };
}

// ---- Login
app.post("/api/auth/login", authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Missing credentials" });
  }

  const client = getClient();
  await client.connect();
  try {
    const { rows } = await client.query(
      "SELECT * FROM users WHERE email=$1 LIMIT 1",
      [email]
    );
    const user = rows[0];
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    const token = signJwt({
      sub: user.id,
      role: user.role,
      email: user.email,
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.json({
      ok: true,
      user: { id: user.id, email: user.email, role: user.role },
      token, // frontend also stores this in AuthContext
    });
  } catch (err) {
    console.error("Login error", err);
    res.status(500).json({ error: "Server error" });
  } finally {
    await client.end();
  }
});

// ---- Logout
app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

// ---- Registration (admin seeding / optional)
app.post("/api/auth/register", async (req, res) => {
  const { email, password, role } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const client = getClient();
  await client.connect();
  try {
    const hash = await bcrypt.hash(
      password,
      Number(process.env.SALT_ROUNDS || 10)
    );
    await client.query(
      "INSERT INTO users (email, password_hash, role) VALUES ($1,$2,$3)",
      [email, hash, role || "user"]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("Register error", err);
    res.status(500).json({ error: "Server error" });
  } finally {
    await client.end();
  }
});

// ---- Admin dashboard sample route (not heavily used by frontend)
app.get(
  "/api/admin/dashboard",
  requireAuth("admin"),
  async (req, res) => {
    res.json({ ok: true, msg: "Welcome admin", user: req.user });
  }
);

// ===================== STUDENTS (APPLICATIONS) ===================== //

// Create student (public registration form)
app.post("/api/students", async (req, res) => {
  const { fullName, email, phone, course, additionalInfo } = req.body || {};
  if (!fullName || !email || !phone || !course) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const client = getClient();
  await client.connect();
  try {
    const { rows } = await client.query(
      `
      INSERT INTO students (name, email, phone, course, additional_info)
      VALUES ($1,$2,$3,$4,$5)
      RETURNING id, name, email, phone, course, additional_info, admission_status, created_at;
    `,
      [fullName, email, phone, course, additionalInfo || null]
    );

    const row = rows[0];
    res.status(201).json({
      id: row.id,
      name: row.name,
      email: row.email,
      phone: row.phone,
      course: row.course,
      additionalInfo: row.additional_info,
      admissionStatus: row.admission_status,
      createdAt: row.created_at,
    });
  } catch (err) {
    console.error("Error creating student", err);
    res.status(500).json({ error: "Server error" });
  } finally {
    await client.end();
  }
});

// Get all students (admin pages)
app.get("/api/students", requireAuth("admin"), async (req, res) => {
  const client = getClient();
  await client.connect();
  try {
    const { rows } = await client.query(
      `
      SELECT id, name, email, phone, course, additional_info, admission_status, created_at
      FROM students
      ORDER BY created_at ASC;
    `
    );

    const students = rows.map((row) => ({
      id: row.id,
      name: row.name,
      email: row.email,
      phone: row.phone,
      course: row.course,
      additionalInfo: row.additional_info,
      admissionStatus: row.admission_status,
      createdAt: row.created_at,
    }));

    res.json(students);
  } catch (err) {
    console.error("Error fetching students", err);
    res.status(500).json({ error: "Server error" });
  } finally {
    await client.end();
  }
});

// Update admission status
app.patch(
  "/api/students/:id/admission",
  requireAuth("admin"),
  async (req, res) => {
    const { id } = req.params;
    const { status } = req.body || {};
    if (!status) {
      return res.status(400).json({ error: "Missing status" });
    }

    const client = getClient();
    await client.connect();
    try {
      await client.query(
        `
        UPDATE students
        SET admission_status = $1
        WHERE id = $2;
      `,
        [status, id]
      );
      res.json({ ok: true });
    } catch (err) {
      console.error("Error updating admission status", err);
      res.status(500).json({ error: "Server error" });
    } finally {
      await client.end();
    }
  }
);

// Delete student
app.delete(
  "/api/students/:id",
  requireAuth("admin"),
  async (req, res) => {
    const { id } = req.params;

    const client = getClient();
    await client.connect();
    try {
      await client.query("DELETE FROM students WHERE id=$1", [id]);
      res.json({ ok: true });
    } catch (err) {
      console.error("Error deleting student", err);
      res.status(500).json({ error: "Server error" });
    } finally {
      await client.end();
    }
  }
);

// ===================== CONTACTS (MESSAGES) ===================== //

// Create contact (public contact form)
app.post("/api/contacts", async (req, res) => {
  const { name, email, phone, subject, message } = req.body || {};
  if (!name || !email || !message) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const client = getClient();
  await client.connect();
  try {
    const { rows } = await client.query(
      `
      INSERT INTO contacts (name, email, phone, subject, message)
      VALUES ($1,$2,$3,$4,$5)
      RETURNING id, name, email, phone, subject, message, created_at;
    `,
      [name, email, phone || null, subject || null, message]
    );

    const row = rows[0];
    res.status(201).json({
      id: row.id,
      name: row.name,
      email: row.email,
      phone: row.phone,
      subject: row.subject,
      message: row.message,
      createdAt: row.created_at,
    });
  } catch (err) {
    console.error("Error creating contact", err);
    res.status(500).json({ error: "Server error" });
  } finally {
    await client.end();
  }
});

// Get all contacts (admin messages + dashboard)
app.get("/api/contacts", requireAuth("admin"), async (req, res) => {
  const client = getClient();
  await client.connect();
  try {
    const { rows } = await client.query(
      `
      SELECT id, name, email, phone, subject, message, created_at
      FROM contacts
      ORDER BY created_at DESC;
    `
    );

    const contacts = rows.map((row) => ({
      id: row.id,
      name: row.name,
      email: row.email,
      phone: row.phone,
      subject: row.subject,
      message: row.message,
      createdAt: row.created_at,
    }));

    res.json(contacts);
  } catch (err) {
    console.error("Error fetching contacts", err);
    res.status(500).json({ error: "Server error" });
  } finally {
    await client.end();
  }
});

// Delete contact
app.delete(
  "/api/contacts/:id",
  requireAuth("admin"),
  async (req, res) => {
    const { id } = req.params;
    const client = getClient();
    await client.connect();
    try {
      await client.query("DELETE FROM contacts WHERE id=$1", [id]);
      res.json({ ok: true });
    } catch (err) {
      console.error("Error deleting contact", err);
      res.status(500).json({ error: "Server error" });
    } finally {
      await client.end();
    }
  }
);

// ---- Start server after ensuring tables
const port = Number(process.env.PORT || 5000);

(async () => {
  try {
    await ensureTables();
    app.listen(port, () => {
      console.log(`Backend listening on port ${port}`);
    });
  } catch (err) {
    console.error("Failed to start server", err);
    process.exit(1);
  }
})();
