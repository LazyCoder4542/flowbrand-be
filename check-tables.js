require('dotenv').config();
const { Client } = require('pg');

async function checkTables() {
  const client = new Client({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
  });

  try {
    await client.connect();
    console.log('Connected to database');
    
    const res = await client.query(
      `SELECT tablename FROM pg_tables WHERE schemaname = 'public'`
    );
    
    console.log('Tables in database:');
    res.rows.forEach(row => console.log(' -', row.tablename));
    
    // Check if users table has updated_at column
    if (res.rows.some(r => r.tablename === 'users')) {
      const colRes = await client.query(
        `SELECT column_name FROM information_schema.columns WHERE table_name = 'users'`
      );
      console.log('\nColumns in users table:');
      colRes.rows.forEach(row => console.log(' -', row.column_name));
    }
    
    await client.end();
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
}

checkTables();
