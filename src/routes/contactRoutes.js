// routes/contactRoutes.js
const express = require("express");
const prisma = require("../utils/prisma");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

/**
 * POST /api/contacts
 * Public: called by ContactForm
 */
router.post("/", async (req, res, next) => {
  try {
    const { name, email, phone, subject, message } = req.body;

    if (!name || !email || !subject || !message) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const contact = await prisma.contact.create({
      data: {
        name,
        email,
        phone: phone || null,
        subject,
        message,
      },
    });

    res.status(201).json({ message: "Message received", contact });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/contacts
 * Protected: admin only
 */
router.get("/", authMiddleware, async (req, res, next) => {
  try {
    const contacts = await prisma.contact.findMany({
      orderBy: { createdAt: "desc" },
    });
    res.json({ contacts });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
