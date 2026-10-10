'use strict';
const path = require('path');

// Everything lives in its own schema, which Supabase does not expose through its public API.
const SCHEMA_VERSION = '1';
const SCHEMA = `
  CREATE SCHEMA IF NOT EXISTS gateway;
  CREATE TABLE IF NOT EXISTS gateway.users(
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    pass_hash TEXT NOT NULL,
    quota INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL
  );
  CREATE SEQUENCE IF NOT EXISTS gateway.pass_rev;
  CREATE TABLE IF NOT EXISTS gateway.passes(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL,
    persons INTEGER NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    issued_by INTEGER NOT NULL,
    created_at BIGINT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    rev BIGINT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS passes_rev ON gateway.passes(rev);
  CREATE INDEX IF NOT EXISTS passes_issuer ON gateway.passes(issued_by);
  CREATE TABLE IF NOT EXISTS gateway.entries(
    id BIGSERIAL PRIMARY KEY,
    uuid TEXT UNIQUE NOT NULL,
    pass_id TEXT NOT NULL,
    day TEXT NOT NULL,
    scanned_at BIGINT NOT NULL,
    received_at BIGINT NOT NULL,
    scanner_id INTEGER NOT NULL,
    persons INTEGER NOT NULL,
    offline INTEGER NOT NULL DEFAULT 0,
    flag TEXT NOT NULL DEFAULT ''
  );
  -- the database itself guarantees one good entry per pass per day, even with several gate devices
  CREATE UNIQUE INDEX IF NOT EXISTS entries_one_per_day ON gateway.entries(pass_id, day) WHERE flag = '';
  CREATE INDEX IF NOT EXISTS entries_pass_day ON gateway.entries(pass_id, day);
  CREATE INDEX IF NOT EXISTS entries_day ON gateway.entries(day);
  CREATE TABLE IF NOT EXISTS gateway.settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS gateway.secrets(key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS gateway.login_fails(key TEXT PRIMARY KEY, count INTEGER NOT NULL, at BIGINT NOT NULL);
  ALTER TABLE gateway.users ENABLE ROW LEVEL SECURITY;
  ALTER TABLE gateway.passes ENABLE ROW LEVEL SECURITY;
  ALTER TABLE gateway.entries ENABLE ROW LEVEL SECURITY;
  ALTER TABLE gateway.settings ENABLE ROW LEVEL SECURITY;
  ALTER TABLE gateway.secrets ENABLE ROW LEVEL SECURITY;
  ALTER TABLE gateway.login_fails ENABLE ROW LEVEL SECURITY;
  INSERT INTO gateway.settings(key, value) VALUES ('schema_version', '${SCHEMA_VERSION}') ON CONFLICT (key) DO NOTHING;
`;

function connectPostgres(url) {
  const pg = require('pg');
  pg.types.setTypeParser(20, Number); // BIGINT: millisecond timestamps and counts fit in a JS number
  const clean = new URL(url);
  clean.searchParams.delete('sslmode'); // otherwise it overrides the ssl option below
  const local = ['localhost', '127.0.0.1'].includes(clean.hostname);
  const pool = new pg.Pool({
    connectionString: clean.toString(),
    max: 3,
    idleTimeoutMillis: 10000,
    connectionTimeoutMillis: 8000,
    // Supabase signs its certificate with its own CA, which Node does not know. Set DATABASE_CA to
    // that CA certificate (Supabase dashboard > Database > SSL) to verify the server; without it
    // the connection is still encrypted but the server's identity is not checked.
    ssl: local ? false : process.env.DATABASE_CA ? { ca: process.env.DATABASE_CA } : { rejectUnauthorized: false },
  });
  pool.on('error', (err) => console.error('database pool error', err.message));
  return {
    query: (text, params) => pool.query(text, params).then((r) => r.rows),
    exec: (text) => pool.query(text),
    async tx(fn) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const out = await fn((text, params) => client.query(text, params).then((r) => r.rows));
        await client.query('COMMIT');
        return out;
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        client.release();
      }
    },
  };
}

// For trying the system on one computer with no database server.
async function connectLocal(dataDir) {
  const { PGlite } = require(['@electric-sql', 'pglite'].join('/'));
  require('fs').mkdirSync(dataDir, { recursive: true });
  const db = new PGlite(path.join(dataDir, 'pg'));
  await db.waitReady;
  return {
    query: (text, params) => db.query(text, params).then((r) => r.rows),
    exec: (text) => db.exec(text),
    tx: (fn) => db.transaction((t) => fn((text, params) => t.query(text, params).then((r) => r.rows))),
  };
}

async function connect(dataDir) {
  const url = process.env.DATABASE_URL || process.env.POSTGRES_URL;
  if (!url && process.env.VERCEL) {
    throw Object.assign(new Error('DATABASE_URL is not set. Add the Supabase connection string in the Vercel project settings.'), { config: true });
  }
  const db = url ? connectPostgres(url) : await connectLocal(dataDir);
  const version = await db.query(`SELECT value FROM gateway.settings WHERE key = 'schema_version'`).then((r) => r[0]?.value, () => null);
  if (version !== SCHEMA_VERSION) await db.exec(SCHEMA);
  return db;
}

module.exports = { connect };
