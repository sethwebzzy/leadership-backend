// routes/dashboardRoutes.js
const express = require("express");
const prisma = require("../utils/prisma");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

/**
 * GET /api/dashboard/stats
 * Protected: admin only
 */
router.get("/stats", authMiddleware, async (req, res, next) => {
  try {
    const [studentCount, contactCount] = await Promise.all([
      prisma.student.count(),
      prisma.contact.count(),
    ]);

    res.json({
      studentCount,
      contactCount,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
