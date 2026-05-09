require('dotenv').config();
const { Client } = require('pg');

async function recreateDatabase() {
  const client = new Client({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: 'postgres',
  });

  try {
    await client.connect();
    console.log('Connected to postgres');
    
    // Terminate all connections to the target database
    await client.query(`
      SELECT pg_terminate_backend(pg_stat_activity.pid)
      FROM pg_stat_activity
      WHERE pg_stat_activity.datname = $1
      AND pid <> pg_backend_pid()
    `, [process.env.DB_DATABASE]);
    
    // Drop the database
    await client.query(`DROP DATABASE IF EXISTS "${process.env.DB_DATABASE}"`);
    console.log(`Dropped database ${process.env.DB_DATABASE}`);
    
    // Recreate the database
    await client.query(`CREATE DATABASE "${process.env.DB_DATABASE}"`);
    console.log(`Created database ${process.env.DB_DATABASE}`);
    
    await client.end();
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
}

recreateDatabase();
