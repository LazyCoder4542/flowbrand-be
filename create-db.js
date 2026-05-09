require('dotenv').config();
const { Client } = require('pg');

async function createDatabase() {
  const client = new Client({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: 'postgres', // Connect to default database first
  });

  try {
    await client.connect();
    console.log('Connected to postgres database');
    
    // Check if database exists
    const res = await client.query(
      `SELECT 1 FROM pg_database WHERE datname = $1`,
      [process.env.DB_DATABASE]
    );
    
    if (res.rows.length === 0) {
      console.log(`Creating database ${process.env.DB_DATABASE}...`);
      await client.query(`CREATE DATABASE "${process.env.DB_DATABASE}"`);
      console.log('✓ Database created');
    } else {
      console.log(`✓ Database ${process.env.DB_DATABASE} already exists`);
    }
    
    await client.end();
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
}

createDatabase();
