// run-migration.js
const fs = require('fs');
const { Client } = require('pg');
require('dotenv').config();

(async () => {
  const sql = fs.readFileSync(__dirname + '/../migrations/create_users.sql', 'utf8');
  const client = new Client({ connectionString: process.env.DATABASE_URL });
  try {
    await client.connect();
    await client.query(sql);
    console.log('Migration applied successfully.');
  } catch (err) {
    console.error('Migration error:', err);
    process.exit(1);
  } finally {
    await client.end();
  }
})();
