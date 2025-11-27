// seed-admin.js
const bcrypt = require('bcryptjs');
const { Client } = require('pg');
require('dotenv').config();

(async () => {
  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();

  const email = process.env.ADMIN_EMAIL || 'admin@leadershipcollege.com';
  const password = process.env.ADMIN_PASSWORD || 'Admin123!';
  const saltRounds = Number(process.env.SALT_ROUNDS || 10);
  const hash = await bcrypt.hash(password, saltRounds);

  try {
    await client.query(`
      INSERT INTO users (email, password_hash, role)
      VALUES ($1, $2, 'admin')
      ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin';
    `, [email, hash]);

    console.log('Admin user seeded:', email);
  } catch (err) {
    console.error('Seeding error:', err);
    process.exit(1);
  } finally {
    await client.end();
  }
})();
