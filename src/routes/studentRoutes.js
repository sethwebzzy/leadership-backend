// routes/studentRoutes.js
const express = require("express");
const prisma = require("../utils/prisma");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

/**
 * POST /api/students
 * Public: called by RegistrationForm
 */
router.post("/", async (req, res, next) => {
  try {
    const { fullName, email, phone, course, additionalInfo } = req.body;

    if (!fullName || !email || !phone || !course) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const student = await prisma.student.create({
      data: {
        fullName,
        email,
        phone,
        course,
        additionalInfo: additionalInfo || null,
      },
    });

    res.status(201).json({ message: "Registration submitted", student });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/students
 * Protected: admin only
 */
router.get("/", authMiddleware, async (req, res, next) => {
  try {
    const students = await prisma.student.findMany({
      orderBy: { createdAt: "desc" },
    });
    res.json({ students });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
