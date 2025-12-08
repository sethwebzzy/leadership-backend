// routes/authRoutes.js
const express = require("express");
const jwt = require("jsonwebtoken");

const router = express.Router();

/**
 * POST /api/auth/login
 * Body: { email, password }
 */
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;
  const jwtSecret = process.env.JWT_SECRET || "changeme";

  if (!adminEmail || !adminPassword) {
    return res.status(500).json({
      error: "Admin credentials not configured on server",
    });
  }

  if (email !== adminEmail || password !== adminPassword) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const token = jwt.sign({ email }, jwtSecret, { expiresIn: "12h" });

  res.json({
    user: { email },
    token,
  });
});

module.exports = router;
