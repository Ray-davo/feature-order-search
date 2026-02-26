require('dotenv').config();
const express = require('express');
const session = require('express-session');
const fetch = require('node-fetch');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const postmark = require('postmark');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const BCRYPT_ROUNDS = 10;

// ==================== POSTMARK EMAIL CLIENT ====================
const postmarkClient = process.env.POSTMARK_SERVER_KEY
  ? new postmark.ServerClient(process.env.POSTMARK_SERVER_KEY)
  : null;

// Per-store branding for emails
const storeBranding = {
  '1ink': {
    name: '1ink.com',
    fromName: '1ink.com Support',
    fromEmail: 'support@1inkonline.com',
    replyTo: 'support@1inkonline.com',
    logoUrl: 'https://cdn11.bigcommerce.com/s-9u5u1ss/content/banners/1ink-logo-trademark-invoice.png',
    color: '#007bff',
    address: '21200 Oxnard St. #969, Woodland Hills, CA 91367',
    phone: '1-818-534-2660',
    website: 'https://www.1ink.com'
  },
  'needink': {
    name: 'NeedInk.com',
    fromName: 'NeedInk.com Support',
    fromEmail: 'support@1inkonline.com',
    replyTo: 'support@1inkonline.com',
    logoUrl: 'https://cdn11.bigcommerce.com/s-wyuaqptd/images/stencil/250x68/needink-logo_1571870203__01730.original.png',
    color: '#28a745',
    address: '21200 Oxnard St. #969, Woodland Hills, CA 91367',
    phone: '1-818-534-2660',
    website: 'https://www.needink.com'
  }
};

// Postgres connection (Render)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDb() {
  // ── Core tables ──────────────────────────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS order_lookup (
      order_id BIGINT,
      store TEXT NOT NULL,
      email TEXT,
      first_name TEXT,
      last_name TEXT,
      phone TEXT,
      order_date TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (store, order_id)
    );
    CREATE INDEX IF NOT EXISTS idx_email ON order_lookup (store, email);
    CREATE INDEX IF NOT EXISTS idx_name  ON order_lookup (store, first_name, last_name);
    CREATE INDEX IF NOT EXISTS idx_phone ON order_lookup (store, phone);
    CREATE TABLE IF NOT EXISTS order_notes (
      id SERIAL PRIMARY KEY,
      order_id BIGINT NOT NULL,
      store TEXT NOT NULL,
      username TEXT NOT NULL,
      note_text TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_order_notes ON order_notes (store, order_id);
    CREATE TABLE IF NOT EXISTS login_attempts (
      id SERIAL PRIMARY KEY,
      ip_address TEXT NOT NULL,
      username TEXT,
      success BOOLEAN DEFAULT FALSE,
      attempted_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_login_ip ON login_attempts (ip_address, attempted_at);
    CREATE INDEX IF NOT EXISTS idx_login_user ON login_attempts (username, attempted_at);
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin BOOLEAN DEFAULT FALSE,
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_login TIMESTAMPTZ,
      failed_attempts INT DEFAULT 0,
      locked_until TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS search_audit (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      store TEXT NOT NULL,
      search_type TEXT NOT NULL,
      query TEXT NOT NULL,
      result_count INT DEFAULT 0,
      searched_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_search_audit_user ON search_audit (username, searched_at);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS email_log (
      id SERIAL PRIMARY KEY,
      store TEXT NOT NULL,
      order_id BIGINT NOT NULL,
      email_type TEXT NOT NULL,
      sent_to TEXT NOT NULL,
      sent_by TEXT NOT NULL,
      postmark_message_id TEXT,
      status TEXT DEFAULT 'sent',
      error_message TEXT,
      sent_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_email_log_order ON email_log (store, order_id);
    CREATE INDEX IF NOT EXISTS idx_email_log_sent_at ON email_log (sent_at);
  `);

  // ── Permissions ───────────────────────────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS permissions (
      id         SERIAL PRIMARY KEY,
      code       TEXT UNIQUE NOT NULL,
      name       TEXT NOT NULL,
      description TEXT,
      category   TEXT NOT NULL,
      risk_level INT DEFAULT 1
    );
  `);

  // ── Roles — create if not exists, then migrate schema ────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS roles (
      id          SERIAL PRIMARY KEY,
      name        TEXT NOT NULL,
      description TEXT,
      is_system   BOOLEAN DEFAULT FALSE,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  // Add store_hash if missing (old schema had no store_hash)
  await pool.query(`ALTER TABLE roles ADD COLUMN IF NOT EXISTS store_hash TEXT;`);
  await pool.query(`UPDATE roles SET store_hash = '1ink' WHERE store_hash IS NULL;`);
  await pool.query(`ALTER TABLE roles ALTER COLUMN store_hash SET NOT NULL;`);
  await pool.query(`
    DO $$ BEGIN
      ALTER TABLE roles ADD CONSTRAINT roles_store_hash_name_key UNIQUE (store_hash, name);
    EXCEPTION WHEN duplicate_table OR duplicate_object THEN NULL;
    END $$;
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_roles_store ON roles (store_hash);`);

  // ── role_permissions — check schema, drop+recreate if stale ──────────────
  const rpCheck = await pool.query(`
    SELECT column_name FROM information_schema.columns
    WHERE table_name = 'role_permissions' AND column_name = 'permission_code'
  `);
  if (rpCheck.rows.length === 0) {
    console.log('Migrating role_permissions (stale schema — recreating)...');
    await pool.query(`DROP TABLE IF EXISTS role_permissions CASCADE;`);
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS role_permissions (
      role_id         INT  REFERENCES roles(id) ON DELETE CASCADE,
      permission_code TEXT REFERENCES permissions(code) ON DELETE CASCADE,
      PRIMARY KEY (role_id, permission_code)
    );
  `);

  // ── user_store_roles — check schema, drop+recreate if stale ──────────────
  const usrCheck = await pool.query(`
    SELECT column_name FROM information_schema.columns
    WHERE table_name = 'user_store_roles' AND column_name = 'store_hash'
  `);
  if (usrCheck.rows.length === 0) {
    console.log('Migrating user_store_roles (stale schema — recreating)...');
    await pool.query(`DROP TABLE IF EXISTS user_store_roles CASCADE;`);
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_store_roles (
      user_id    INT  REFERENCES users(id) ON DELETE CASCADE,
      store_hash TEXT NOT NULL,
      role_id    INT  REFERENCES roles(id) ON DELETE RESTRICT,
      is_active  BOOLEAN DEFAULT TRUE,
      PRIMARY KEY (user_id, store_hash)
    );
    CREATE INDEX IF NOT EXISTS idx_usr_user  ON user_store_roles (user_id);
    CREATE INDEX IF NOT EXISTS idx_usr_store ON user_store_roles (store_hash);
  `);

  // ── Seed & housekeeping ───────────────────────────────────────────────────
  await seedPermissions();
  for (const storeKey of Object.keys(stores)) {
    await seedDefaultRoles(storeKey);
  }

  await pool.query(`DELETE FROM login_attempts WHERE attempted_at < NOW() - INTERVAL '24 hours'`);
  await pool.query(`DELETE FROM search_audit   WHERE searched_at  < NOW() - INTERVAL '90 days'`);

  await migrateEnvUsers();
  console.log('Postgres initialized');
}


// Migrate users from env vars to database (runs once)
// Also assigns roles via user_store_roles for each configured store
async function migrateEnvUsers() {
  for (let i = 1; i <= 10; i++) {
    const name = process.env[`USER${i}_NAME`];
    const pass = process.env[`USER${i}_PASS`];
    if (name && pass) {
      const userLower = name.toLowerCase();
      const isAdmin   = i === 1;
      let userId;
      const existing = await pool.query('SELECT id FROM users WHERE username = $1', [userLower]);
      if (existing.rows.length === 0) {
        const hash    = await bcrypt.hash(pass, BCRYPT_ROUNDS);
        const newUser = await pool.query(
          'INSERT INTO users (username, password_hash, is_admin) VALUES ($1, $2, $3) RETURNING id',
          [userLower, hash, isAdmin]
        );
        userId = newUser.rows[0].id;
        console.log(`Migrated user: ${userLower}${isAdmin ? ' (admin)' : ''}`);
      } else {
        userId = existing.rows[0].id;
      }
      const roleName = isAdmin ? 'Admin' : 'Agent';
      for (const storeKey of Object.keys(stores)) {
        const already = await pool.query(
          'SELECT 1 FROM user_store_roles WHERE user_id = $1 AND store_hash = $2',
          [userId, storeKey]
        );
        if (already.rows.length === 0) {
          const roleRes = await pool.query(
            'SELECT id FROM roles WHERE store_hash = $1 AND name = $2',
            [storeKey, roleName]
          );
          if (roleRes.rows.length > 0) {
            await pool.query(
              'INSERT INTO user_store_roles (user_id, store_hash, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
              [userId, storeKey, roleRes.rows[0].id]
            );
            console.log(`Assigned ${roleName} to ${userLower} on ${storeKey}`);
          }
        }
      }
    }
  }
}

// ── 26 system permissions ─────────────────────────────────────────────────
const SYSTEM_PERMISSIONS = [
  { code: 'orders.view',            name: 'View Orders',            description: 'View order details',               category: 'Orders',    risk_level: 1 },
  { code: 'orders.search',          name: 'Search Orders',          description: 'Search for orders',                category: 'Orders',    risk_level: 1 },
  { code: 'orders.notes.add',       name: 'Add Notes',              description: 'Add internal support notes',       category: 'Orders',    risk_level: 1 },
  { code: 'orders.notes.delete',    name: 'Delete Notes',           description: 'Delete internal notes',            category: 'Orders',    risk_level: 2 },
  { code: 'orders.status.update',   name: 'Update Order Status',    description: 'Change order status',              category: 'Orders',    risk_level: 2 },
  { code: 'orders.tracking.add',    name: 'Add Tracking',           description: 'Add tracking numbers',             category: 'Orders',    risk_level: 2 },
  { code: 'orders.ship',            name: 'Create Shipment',        description: 'Mark items as shipped',            category: 'Orders',    risk_level: 2 },
  { code: 'orders.cancel',          name: 'Cancel Order',           description: 'Cancel orders',                    category: 'Orders',    risk_level: 3 },
  { code: 'orders.refund',          name: 'Process Refund',         description: 'Issue full or partial refunds',    category: 'Orders',    risk_level: 3 },
  { code: 'orders.export',          name: 'Export Orders',          description: 'Export order data to CSV',         category: 'Orders',    risk_level: 2 },
  { code: 'customers.view',         name: 'View Customers',         description: 'View customer profiles',           category: 'Customers', risk_level: 1 },
  { code: 'customers.notes',        name: 'Customer Notes',         description: 'Add notes to customer profiles',   category: 'Customers', risk_level: 1 },
  { code: 'customers.merge',        name: 'Merge Duplicates',       description: 'Merge duplicate customer records', category: 'Customers', risk_level: 2 },
  { code: 'customers.export',       name: 'Export Customers',       description: 'Export customer data',             category: 'Customers', risk_level: 2 },
  { code: 'email.view',             name: 'View Emails',            description: 'View email history',               category: 'Email',     risk_level: 1 },
  { code: 'email.reply',            name: 'Reply to Emails',        description: 'Send email replies',               category: 'Email',     risk_level: 2 },
  { code: 'email.templates.use',    name: 'Use Templates',          description: 'Use email templates',              category: 'Email',     risk_level: 1 },
  { code: 'email.templates.manage', name: 'Manage Templates',       description: 'Create and edit email templates',  category: 'Email',     risk_level: 2 },
  { code: 'reports.view',           name: 'View Reports',           description: 'View analytics and reports',       category: 'Reports',   risk_level: 1 },
  { code: 'reports.export',         name: 'Export Reports',         description: 'Export report data',               category: 'Reports',   risk_level: 2 },
  { code: 'admin.users.view',       name: 'View Users',             description: 'View user list',                   category: 'Admin',     risk_level: 1 },
  { code: 'admin.users.manage',     name: 'Manage Users',           description: 'Create, edit, delete users',       category: 'Admin',     risk_level: 3 },
  { code: 'admin.roles.manage',     name: 'Manage Roles',           description: 'Create and edit roles',            category: 'Admin',     risk_level: 3 },
  { code: 'admin.labels.manage',    name: 'Manage Labels',          description: 'Manage support label taxonomy',    category: 'Admin',     risk_level: 2 },
  { code: 'admin.settings',         name: 'App Settings',           description: 'Configure app settings',           category: 'Admin',     risk_level: 3 },
  { code: 'admin.audit.view',       name: 'View Audit Log',         description: 'View search and login audit logs', category: 'Admin',     risk_level: 2 },
];

async function seedPermissions() {
  for (const p of SYSTEM_PERMISSIONS) {
    await pool.query(`
      INSERT INTO permissions (code, name, description, category, risk_level)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (code) DO UPDATE SET
        name = EXCLUDED.name, description = EXCLUDED.description,
        category = EXCLUDED.category, risk_level = EXCLUDED.risk_level
    `, [p.code, p.name, p.description, p.category, p.risk_level]);
  }
  console.log(`Permissions seeded: ${SYSTEM_PERMISSIONS.length} total`);
}

const DEFAULT_ROLES = [
  { name: 'Admin', description: 'Full access to everything', is_system: true,
    permissions: null }, // null = all permissions (filled below)
  { name: 'Senior Manager', description: 'All actions except user/role/settings management', is_system: true,
    permissions: ['orders.view','orders.search','orders.notes.add','orders.notes.delete','orders.status.update','orders.tracking.add','orders.ship','orders.cancel','orders.refund','orders.export','customers.view','customers.notes','customers.merge','customers.export','email.view','email.reply','email.templates.use','email.templates.manage','reports.view','reports.export','admin.users.view','admin.labels.manage','admin.audit.view'] },
  { name: 'Manager', description: 'Orders, tracking, shipments, export', is_system: true,
    permissions: ['orders.view','orders.search','orders.notes.add','orders.status.update','orders.tracking.add','orders.ship','orders.export','customers.view','customers.notes','email.view','email.reply','email.templates.use','reports.view','admin.users.view','admin.audit.view'] },
  { name: 'Supervisor', description: 'View, search, notes, status updates', is_system: true,
    permissions: ['orders.view','orders.search','orders.notes.add','orders.status.update','customers.view','customers.notes','email.view','email.templates.use','admin.users.view'] },
  { name: 'Agent', description: 'View and search orders, add notes only', is_system: true,
    permissions: ['orders.view','orders.search','orders.notes.add','customers.view','email.view','email.templates.use'] },
];

async function seedDefaultRoles(storeHash) {
  for (const role of DEFAULT_ROLES) {
    const perms = role.permissions || SYSTEM_PERMISSIONS.map(p => p.code);
    const result = await pool.query(`
      INSERT INTO roles (store_hash, name, description, is_system)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (store_hash, name) DO UPDATE SET
        description = EXCLUDED.description, is_system = EXCLUDED.is_system
      RETURNING id
    `, [storeHash, role.name, role.description, role.is_system]);
    const roleId = result.rows[0].id;
    await pool.query('DELETE FROM role_permissions WHERE role_id = $1', [roleId]);
    for (const code of perms) {
      await pool.query(
        'INSERT INTO role_permissions (role_id, permission_code) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [roleId, code]
      );
    }
  }
  console.log(`Default roles seeded for: ${storeHash}`);
}

async function hasPermission(userId, storeHash, permissionCode) {
  const result = await pool.query(`
    SELECT 1 FROM user_store_roles usr
    JOIN role_permissions rp ON rp.role_id = usr.role_id
    WHERE usr.user_id = $1 AND usr.store_hash = $2 AND rp.permission_code = $3 AND usr.is_active = true
    LIMIT 1
  `, [userId, storeHash, permissionCode]);
  return result.rows.length > 0;
}

async function getUserPermissions(userId, storeHash) {
  const result = await pool.query(`
    SELECT rp.permission_code FROM user_store_roles usr
    JOIN role_permissions rp ON rp.role_id = usr.role_id
    WHERE usr.user_id = $1 AND usr.store_hash = $2 AND usr.is_active = true
  `, [userId, storeHash]);
  return result.rows.map(r => r.permission_code);
}

// ==================== LOGIN SECURITY ====================

// Security settings
const LOCKOUT_THRESHOLD = 3;        // Failed attempts before lockout
const LOCKOUT_DURATION_MIN = 15;    // Lockout duration in minutes
const RATE_LIMIT_WINDOW_SEC = 60;   // Rate limit window in seconds
const RATE_LIMIT_MAX_ATTEMPTS = 5;  // Max attempts per IP in window

// In-memory cache for faster checks (persisted to DB for audit)
const loginAttempts = {
  byIp: new Map(),      // IP -> { count, firstAttempt, lockedUntil }
  byUser: new Map()     // username -> { count, firstAttempt, lockedUntil }
};

// Get client IP address
function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
         req.headers['x-real-ip'] || 
         req.connection?.remoteAddress || 
         req.ip || 
         'unknown';
}

// Check if IP is rate limited
function isRateLimited(ip) {
  const now = Date.now();
  const record = loginAttempts.byIp.get(ip);
  
  if (!record) return false;
  
  // Reset if window expired
  if (now - record.firstAttempt > RATE_LIMIT_WINDOW_SEC * 1000) {
    loginAttempts.byIp.delete(ip);
    return false;
  }
  
  return record.count >= RATE_LIMIT_MAX_ATTEMPTS;
}

// Check if account is locked
function isAccountLocked(username) {
  const now = Date.now();
  const record = loginAttempts.byUser.get(username);
  
  if (!record) return false;
  
  // Check if still locked
  if (record.lockedUntil && now < record.lockedUntil) {
    const remainingMin = Math.ceil((record.lockedUntil - now) / 60000);
    return { locked: true, remainingMin };
  }
  
  // Lock expired, reset
  if (record.lockedUntil && now >= record.lockedUntil) {
    loginAttempts.byUser.delete(username);
    return false;
  }
  
  return false;
}

// Record failed login attempt
async function recordFailedAttempt(ip, username) {
  const now = Date.now();
  
  // Update IP tracking
  let ipRecord = loginAttempts.byIp.get(ip) || { count: 0, firstAttempt: now };
  
  // Reset if window expired
  if (now - ipRecord.firstAttempt > RATE_LIMIT_WINDOW_SEC * 1000) {
    ipRecord = { count: 0, firstAttempt: now };
  }
  
  ipRecord.count++;
  loginAttempts.byIp.set(ip, ipRecord);
  
  // Update username tracking
  if (username) {
    let userRecord = loginAttempts.byUser.get(username) || { count: 0, firstAttempt: now };
    
    // Reset if lockout expired
    if (userRecord.lockedUntil && now >= userRecord.lockedUntil) {
      userRecord = { count: 0, firstAttempt: now };
    }
    
    userRecord.count++;
    
    // Apply lockout if threshold reached
    if (userRecord.count >= LOCKOUT_THRESHOLD) {
      userRecord.lockedUntil = now + (LOCKOUT_DURATION_MIN * 60 * 1000);
      console.log(`[SECURITY] Account locked: ${username} for ${LOCKOUT_DURATION_MIN} minutes`);
    }
    
    loginAttempts.byUser.set(username, userRecord);
  }
  
  // Log to database for audit
  try {
    await pool.query(
      'INSERT INTO login_attempts (ip_address, username, success) VALUES ($1, $2, $3)',
      [ip, username || 'unknown', false]
    );
  } catch (e) {
    console.error('Failed to log login attempt:', e.message);
  }
}

// Record successful login
async function recordSuccessfulLogin(ip, username) {
  // Clear failed attempts for this user
  loginAttempts.byUser.delete(username);
  
  // Log to database
  try {
    await pool.query(
      'INSERT INTO login_attempts (ip_address, username, success) VALUES ($1, $2, $3)',
      [ip, username, true]
    );
  } catch (e) {
    console.error('Failed to log login attempt:', e.message);
  }
}

// Get lockout info for user
function getLockoutInfo(username) {
  const record = loginAttempts.byUser.get(username);
  if (!record) return null;
  
  const now = Date.now();
  if (record.lockedUntil && now < record.lockedUntil) {
    return {
      locked: true,
      remainingMin: Math.ceil((record.lockedUntil - now) / 60000),
      attemptsLeft: 0
    };
  }
  
  return {
    locked: false,
    attemptsLeft: LOCKOUT_THRESHOLD - (record.count || 0)
  };
}

// ==================== SEARCH RATE LIMITING ====================

const SEARCH_RATE_LIMIT = 30;          // Max searches per hour for non-admins
const SEARCH_RATE_WINDOW_MS = 60 * 60 * 1000; // 1 hour window

const searchRateTracker = new Map();   // username -> { count, windowStart }

function isSearchRateLimited(username) {
  const now = Date.now();
  const record = searchRateTracker.get(username);

  if (!record || (now - record.windowStart) > SEARCH_RATE_WINDOW_MS) {
    // New window
    searchRateTracker.set(username, { count: 1, windowStart: now });
    return false;
  }

  if (record.count >= SEARCH_RATE_LIMIT) {
    const resetMin = Math.ceil((SEARCH_RATE_WINDOW_MS - (now - record.windowStart)) / 60000);
    return { limited: true, resetMin };
  }

  record.count++;
  return false;
}

async function logSearch(username, store, searchType, query, resultCount) {
  try {
    await pool.query(
      'INSERT INTO search_audit (username, store, search_type, query, result_count) VALUES ($1, $2, $3, $4, $5)',
      [username, store, searchType, query, resultCount]
    );
  } catch (e) {
    console.error('Failed to log search:', e.message);
  }
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
const INACTIVITY_TIMEOUT_MIN = 60;    // Logout after 60 min of inactivity
const ABSOLUTE_MAX_SESSION_HR = 8;     // Force logout after 8 hours regardless
const WARNING_BEFORE_LOGOUT_MIN = 2;   // Show warning 2 min before logout

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      maxAge: ABSOLUTE_MAX_SESSION_HR * 60 * 60 * 1000 // 8 hours absolute max
    }
  })
);

// Track last activity on every authenticated request
app.use((req, res, next) => {
  // Skip session check for auth-related routes
  if (req.path === '/api/logout' || req.path === '/api/login' || req.path === '/login') {
    return next();
  }
  
  if (req.session && req.session.user) {
    const now = Date.now();
    
    // Set login time if not set
    if (!req.session.loginTime) {
      req.session.loginTime = now;
    }
    
    // Check absolute max session (8 hours)
    if (now - req.session.loginTime > ABSOLUTE_MAX_SESSION_HR * 60 * 60 * 1000) {
      console.log(`[SESSION] Absolute timeout for ${req.session.user} (8 hours)`);
      req.session.destroy();
      return res.status(401).json({ error: 'Session expired. Please log in again.', reason: 'absolute_timeout' });
    }
    
    // Check inactivity timeout (60 min) - skip for session-check endpoint
    if (req.session.lastActivity && !req.path.includes('/api/session-check')) {
      const inactiveTime = now - req.session.lastActivity;
      if (inactiveTime > INACTIVITY_TIMEOUT_MIN * 60 * 1000) {
        console.log(`[SESSION] Inactivity timeout for ${req.session.user} (${Math.round(inactiveTime/60000)} min)`);
        req.session.destroy();
        return res.status(401).json({ error: 'Session expired due to inactivity.', reason: 'inactivity_timeout' });
      }
    }
    
    // Update last activity (skip for session-check to not reset timer)
    if (!req.path.includes('/api/session-check')) {
      req.session.lastActivity = now;
    }
  }
  next();
});

// Store configurations
const stores = {
  '1ink': {
    name: '1ink.com',
    hash: process.env.BC_1INK_STORE_HASH || process.env.BC_STORE_HASH,
    token: process.env.BC_1INK_ACCESS_TOKEN || process.env.BC_ACCESS_TOKEN,
    baseUrl: 'https://www.1ink.com'
  },
  'needink': {
    name: 'needink.com',
    hash: process.env.BC_NEEDINK_STORE_HASH,
    token: process.env.BC_NEEDINK_ACCESS_TOKEN,
    baseUrl: 'https://www.needink.com'
  }
};

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

// Permission middleware factory
function requirePermission(permCode) {
  return async (req, res, next) => {
    if (!req.session || !req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    const perms = req.session.permissions || [];
    if (perms.includes(permCode)) return next();
    const storeHash = req.session.storeHash || Object.keys(stores)[0];
    const allowed = await hasPermission(req.session.userId, storeHash, permCode);
    if (allowed) return next();
    return res.status(403).json({ error: 'Permission denied', required: permCode });
  };
}

// Backward-compat alias
const requireAdmin = requirePermission('admin.users.manage');

// BigCommerce API helper
async function bcApiRequest(store, endpoint, method = 'GET', body = null) {
  const storeConfig = stores[store];
  if (!storeConfig || !storeConfig.hash || !storeConfig.token) {
    throw new Error('Store not configured');
  }

  const url = `https://api.bigcommerce.com/stores/${storeConfig.hash}/v2/${endpoint}`;

  const fetchOptions = {
    method,
    headers: {
      'X-Auth-Token': storeConfig.token,
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    }
  };

  if (body && (method === 'POST' || method === 'PUT')) {
    fetchOptions.body = JSON.stringify(body);
  }

  const response = await fetch(url, fetchOptions);

  if (!response.ok) {
    if (response.status === 404) {
      const err = new Error('Not found');
      err.notFound = true;
      throw err;
    }
    const errorText = await response.text();
    throw new Error(`BC API Error: ${response.status} - ${errorText}`);
  }

  // DELETE returns 204 No Content
  if (response.status === 204) return { success: true };

  return await response.json();
}

// BC v3 REST API helper (catalog endpoints)
async function bcApiV3Request(store, endpoint) {
  const storeConfig = stores[store];
  if (!storeConfig || !storeConfig.hash || !storeConfig.token) return null;

  const url = `https://api.bigcommerce.com/stores/${storeConfig.hash}/v3/${endpoint}`;

  const response = await fetch(url, {
    method: 'GET',
    headers: {
      'X-Auth-Token': storeConfig.token,
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`v3 API ${response.status}: ${text.slice(0, 200)}`);
  }

  return await response.json();
}

// Normalize phone number to digits only
function normalizePhone(phone) {
  if (!phone) return '';
  return phone.replace(/\D/g, '');
}

// Sync orders from BigCommerce to Postgres index
async function syncOrders(store, fullSync = false) {
  const storeConfig = stores[store];
  if (!storeConfig || !storeConfig.hash) {
    console.log(`Store ${store} not configured, skipping sync`);
    return { synced: 0, error: 'Store not configured' };
  }

  console.log(`Starting ${fullSync ? 'FULL' : 'incremental'} sync for ${store}...`);

  const insertSql = `
    INSERT INTO order_lookup (order_id, store, email, first_name, last_name, phone, order_date)
    VALUES ($1,$2,$3,$4,$5,$6,$7)
    ON CONFLICT (store, order_id)
    DO UPDATE SET
      email=EXCLUDED.email,
      first_name=EXCLUDED.first_name,
      last_name=EXCLUDED.last_name,
      phone=EXCLUDED.phone,
      order_date=EXCLUDED.order_date
  `;

  let page = 1;
  let totalSynced = 0;
  let hasMore = true;

  // Hard cutoff: only index last N years
  const years = parseInt(process.env.ORDER_INDEX_YEARS || '3', 10);
  const cutoff = new Date();
  cutoff.setFullYear(cutoff.getFullYear() - years);

  let minDateFilter = `&min_date_created=${cutoff.toISOString()}`;

  // For incremental sync, tighten it to "since last indexed date - 2 days"
  if (!fullSync) {
    const lastOrderRes = await pool.query(
      'SELECT MAX(order_date) as last_date FROM order_lookup WHERE store = $1',
      [store]
    );

    const lastOrder = lastOrderRes.rows[0];

    if (lastOrder && lastOrder.last_date) {
      const lastDate = new Date(lastOrder.last_date);
      lastDate.setDate(lastDate.getDate() - 2);

      // Use whichever is MORE RECENT: cutoff or last indexed
      const effective = lastDate > cutoff ? lastDate : cutoff;
      minDateFilter = `&min_date_created=${effective.toISOString()}`;

      console.log(`Incremental sync from ${effective.toISOString()}`);
    } else {
      console.log(`Initial incremental sync from cutoff ${cutoff.toISOString()}`);
    }
  } else {
    console.log(`Full sync limited to cutoff ${cutoff.toISOString()}`);
  }

  while (hasMore) {
    try {
      const orders = await bcApiRequest(
        store,
        `orders?limit=250&page=${page}&sort=date_created:desc${minDateFilter}`
      );

      if (!Array.isArray(orders) || orders.length === 0) {
        hasMore = false;
        break;
      }

      for (const order of orders) {
        try {
          const billing = order.billing_address || {};
          const email = (billing.email || '').toLowerCase();
          const firstName = (billing.first_name || '').toLowerCase();
          const lastName = (billing.last_name || '').toLowerCase();
          const phone = normalizePhone(billing.phone);

          if (email || (firstName && lastName) || phone) {
            await pool.query(insertSql, [
              order.id,
              store,
              email,
              firstName,
              lastName,
              phone,
              order.date_created
            ]);
            totalSynced++;
          }
        } catch (e) {
          console.log(`Error processing order ${order.id}: ${e.message}`);
        }
      }

      console.log(`Synced page ${page} (${orders.length} orders), total: ${totalSynced}`);
      page++;

      // If incremental sync and we got less than full page, we're done
      if (!fullSync && orders.length < 250) {
        hasMore = false;
      }

      // Safety limit for incremental sync
      if (!fullSync && page > 20) {
        console.log('Incremental sync safety limit reached (20 pages)');
        hasMore = false;
      }
    } catch (error) {
      console.log(`Sync error on page ${page}: ${error.message}`);
      hasMore = false;
      return { synced: totalSynced, error: error.message };
    }
  }

  console.log(`Sync complete for ${store}: ${totalSynced} records`);
  return { synced: totalSynced };
}

// Search local database for emails by name
// Requires BOTH first and last name - single words are rejected to prevent broad fishing
async function searchByName(store, query) {
  const searchTerm = (query || '').toLowerCase().trim();
  const nameParts = searchTerm.split(/\s+/).filter(Boolean);

  // Require at least two parts (first + last name) to prevent broad single-name searches
  if (nameParts.length < 2) return [];

  // Match from START of name only (not anywhere in middle) to reduce false positives
  const first = `${nameParts[0]}%`;
  const last = `${nameParts[nameParts.length - 1]}%`;

  const { rows } = await pool.query(
    `SELECT DISTINCT email FROM order_lookup
     WHERE store = $1
     AND LOWER(first_name) LIKE $2
     AND LOWER(last_name) LIKE $3
     AND email IS NOT NULL AND email <> ''
     LIMIT 20`,
    [store, first, last]
  );

  return rows.map(r => r.email);
}

// Search local database for emails by phone
async function searchByPhone(store, query) {
  let digits = query.replace(/\D/g, '');

  // Build all variants to search - whatever the customer typed, we find it
  const variants = new Set();
  variants.add(digits); // exactly as stored

  if (digits.length === 11 && digits.startsWith('1')) {
    variants.add(digits.slice(1)); // also try without country code
  } else if (digits.length === 10) {
    variants.add('1' + digits); // also try with country code
  }

  // Must be 10 or 11 digits to be a valid phone
  if (digits.length < 10 || digits.length > 11) return [];

  const variantList = Array.from(variants);
  const { rows } = await pool.query(
    `SELECT DISTINCT email FROM order_lookup
     WHERE store = $1
     AND phone = ANY($2)
     AND email IS NOT NULL AND email <> ''
     LIMIT 20`,
    [store, variantList]
  );

  return rows.map(r => r.email);
}

// Routes

// Login page
app.get('/login', (req, res) => {
  if (req.session && req.session.user) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login API - with rate limiting and account lockout
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const userLower = (username || '').toLowerCase().trim();
  const ip = getClientIp(req);
  
  // Check rate limiting first
  if (isRateLimited(ip)) {
    console.log(`[SECURITY] Rate limited IP: ${ip}`);
    return res.status(429).json({ 
      error: 'Too many login attempts. Please wait a minute and try again.' 
    });
  }
  
  // Check if account is locked (in-memory)
  const lockStatus = isAccountLocked(userLower);
  if (lockStatus && lockStatus.locked) {
    console.log(`[SECURITY] Blocked login for locked account: ${userLower} from ${ip}`);
    await recordFailedAttempt(ip, userLower);
    return res.status(423).json({ 
      error: `Account temporarily locked. Try again in ${lockStatus.remainingMin} minute${lockStatus.remainingMin > 1 ? 's' : ''}.` 
    });
  }
  
  try {
    // Get user from database
    const result = await pool.query(
      'SELECT id, username, password_hash, is_admin, is_active, locked_until FROM users WHERE username = $1',
      [userLower]
    );
    
    const user = result.rows[0];
    
    // Check if user exists and is active
    if (!user || !user.is_active) {
      await recordFailedAttempt(ip, userLower);
      const lockInfo = getLockoutInfo(userLower);
      
      if (lockInfo && lockInfo.attemptsLeft <= 2 && lockInfo.attemptsLeft > 0) {
        return res.status(401).json({ 
          error: `Invalid credentials. ${lockInfo.attemptsLeft} attempt${lockInfo.attemptsLeft > 1 ? 's' : ''} remaining before account lockout.` 
        });
      }
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check if account is locked in database
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const remainingMin = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
      return res.status(423).json({ 
        error: `Account temporarily locked. Try again in ${remainingMin} minute${remainingMin > 1 ? 's' : ''}.` 
      });
    }
    
    // Verify password with bcrypt
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (validPassword) {
      await pool.query(
        'UPDATE users SET last_login = NOW(), failed_attempts = 0, locked_until = NULL WHERE id = $1',
        [user.id]
      );
      const defaultStore  = Object.keys(stores)[0];
      const permissions   = await getUserPermissions(user.id, defaultStore);
      const roleRes       = await pool.query(`
        SELECT r.name FROM user_store_roles usr
        JOIN roles r ON r.id = usr.role_id
        WHERE usr.user_id = $1 AND usr.store_hash = $2 LIMIT 1
      `, [user.id, defaultStore]);
      const roleName = roleRes.rows[0]?.name || 'Agent';
      req.session.user        = userLower;
      req.session.userId      = user.id;
      req.session.storeHash   = defaultStore;
      req.session.permissions = permissions;
      req.session.roleName    = roleName;
      req.session.isAdmin     = permissions.includes('admin.users.manage');
      await recordSuccessfulLogin(ip, userLower);
      console.log(`[${new Date().toISOString()}] Login success: ${userLower} (${roleName}) from ${ip}`);
      return res.json({ success: true, user: userLower, isAdmin: req.session.isAdmin, roleName, permissions });
    }
    
    // Failed login - update database
    await pool.query(
      'UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = $1',
      [user.id]
    );
    
    // Check if should lock in database
    const updatedUser = await pool.query('SELECT failed_attempts FROM users WHERE id = $1', [user.id]);
    if (updatedUser.rows[0].failed_attempts >= LOCKOUT_THRESHOLD) {
      await pool.query(
        'UPDATE users SET locked_until = NOW() + INTERVAL \'15 minutes\' WHERE id = $1',
        [user.id]
      );
    }
    
    await recordFailedAttempt(ip, userLower);
    const lockInfo = getLockoutInfo(userLower);
    
    console.log(`[${new Date().toISOString()}] Login failed: ${username} from ${ip} (${lockInfo?.attemptsLeft || 0} attempts left)`);
    
    if (lockInfo && lockInfo.locked) {
      return res.status(423).json({ 
        error: `Too many failed attempts. Account locked for ${LOCKOUT_DURATION_MIN} minutes.` 
      });
    }
    
    if (lockInfo && lockInfo.attemptsLeft <= 2 && lockInfo.attemptsLeft > 0) {
      return res.status(401).json({ 
        error: `Invalid credentials. ${lockInfo.attemptsLeft} attempt${lockInfo.attemptsLeft > 1 ? 's' : ''} remaining before account lockout.` 
      });
    }
    
    res.status(401).json({ error: 'Invalid credentials' });
    
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  const user = req.session.user;
  req.session.destroy();
  console.log(`[${new Date().toISOString()}] Logout: ${user}`);
  res.json({ success: true });
});

// Check auth status
app.get('/api/auth-check', (req, res) => {
  if (req.session && req.session.user) {
    if (!req.session.lastActivity) req.session.lastActivity = Date.now();
    if (!req.session.loginTime)    req.session.loginTime    = Date.now();
    return res.json({
      authenticated: true,
      user:        req.session.user,
      isAdmin:     req.session.isAdmin     || false,
      roleName:    req.session.roleName    || 'Agent',
      permissions: req.session.permissions || []
    });
  }
  res.json({ authenticated: false });
});

// Session status check (doesn't reset activity timer)
app.get('/api/session-check', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.json({ valid: false });
  }
  
  const now = Date.now();
  const lastActivity = req.session.lastActivity || now;
  const loginTime = req.session.loginTime || now;
  
  // Calculate remaining time (use whichever expires first)
  const inactivityRemaining = (INACTIVITY_TIMEOUT_MIN * 60 * 1000) - (now - lastActivity);
  const absoluteRemaining = (ABSOLUTE_MAX_SESSION_HR * 60 * 60 * 1000) - (now - loginTime);
  const remainingMs = Math.min(inactivityRemaining, absoluteRemaining);
  
  const warningThreshold = WARNING_BEFORE_LOGOUT_MIN * 60 * 1000;
  
  res.json({
    valid: remainingMs > 0,
    remainingMs: Math.max(0, remainingMs),
    remainingSec: Math.max(0, Math.floor(remainingMs / 1000)),
    showWarning: remainingMs > 0 && remainingMs <= warningThreshold,
    reason: absoluteRemaining < inactivityRemaining ? 'absolute' : 'inactivity'
  });
});

// Extend session (user clicked "Stay logged in")
app.post('/api/session-extend', requireAuth, (req, res) => {
  req.session.lastActivity = Date.now();
  console.log(`[SESSION] Extended by ${req.session.user}`);
  res.json({ success: true, message: 'Session extended' });
});

// ==================== ADMIN API ENDPOINTS ====================

app.get('/api/admin/users', requireAuth, requirePermission('admin.users.view'), async (req, res) => {
  const storeHash = req.session.storeHash || Object.keys(stores)[0];
  try {
    const result = await pool.query(`
      SELECT u.id, u.username, u.is_active, u.created_at, u.last_login,
             u.failed_attempts, u.locked_until,
             r.id AS role_id, r.name AS role_name
      FROM users u
      LEFT JOIN user_store_roles usr ON usr.user_id = u.id AND usr.store_hash = $1
      LEFT JOIN roles r ON r.id = usr.role_id
      ORDER BY u.created_at ASC
    `, [storeHash]);
    res.json({ success: true, users: result.rows });
  } catch (err) {
    console.error('Get users error:', err.message);
    res.status(500).json({ error: 'Failed to get users' });
  }
});

app.post('/api/admin/users', requireAuth, requirePermission('admin.users.manage'), async (req, res) => {
  const { username, password, roleId } = req.body;
  const storeHash = req.session.storeHash || Object.keys(stores)[0];
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (password.length < 6)    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (!roleId)                 return res.status(400).json({ error: 'Role is required' });
  const userLower = username.toLowerCase().trim();
  try {
    const existing = await pool.query('SELECT id FROM users WHERE username = $1', [userLower]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Username already exists' });
    const hash    = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const userRes = await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id', [userLower, hash]);
    const newUserId = userRes.rows[0].id;
    await pool.query('INSERT INTO user_store_roles (user_id, store_hash, role_id) VALUES ($1, $2, $3)', [newUserId, storeHash, roleId]);
    const adminPerms = await getUserPermissions(newUserId, storeHash);
    await pool.query('UPDATE users SET is_admin = $1 WHERE id = $2', [adminPerms.includes('admin.users.manage'), newUserId]);
    console.log(`[ADMIN] User created: ${userLower} by ${req.session.user}`);
    res.json({ success: true, userId: newUserId });
  } catch (err) {
    console.error('Create user error:', err.message);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.put('/api/admin/users/:id', requireAuth, requirePermission('admin.users.manage'), async (req, res) => {
  const { id } = req.params;
  const { username, password, roleId, isActive } = req.body;
  const storeHash = req.session.storeHash || Object.keys(stores)[0];
  try {
    const current = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    if (current.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const updates = [], values = [];
    let p = 1;
    if (username !== undefined) {
      const userLower = username.toLowerCase().trim();
      const dup = await pool.query('SELECT id FROM users WHERE username = $1 AND id != $2', [userLower, id]);
      if (dup.rows.length > 0) return res.status(400).json({ error: 'Username already exists' });
      updates.push(`username = $${p++}`); values.push(userLower);
    }
    if (password && password.length > 0) {
      if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
      const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
      updates.push(`password_hash = $${p++}`); values.push(hash);
    }
    if (isActive !== undefined) { updates.push(`is_active = $${p++}`); values.push(isActive); }
    if (updates.length > 0) {
      values.push(id);
      await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${p}`, values);
    }
    if (roleId !== undefined) {
      await pool.query(`
        INSERT INTO user_store_roles (user_id, store_hash, role_id)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, store_hash) DO UPDATE SET role_id = EXCLUDED.role_id
      `, [id, storeHash, roleId]);
      const adminPerms = await getUserPermissions(parseInt(id), storeHash);
      await pool.query('UPDATE users SET is_admin = $1 WHERE id = $2', [adminPerms.includes('admin.users.manage'), id]);
    }
    console.log(`[ADMIN] User updated: id=${id} by ${req.session.user}`);
    res.json({ success: true });
  } catch (err) {
    console.error('Update user error:', err.message);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

app.delete('/api/admin/users/:id', requireAuth, requirePermission('admin.users.manage'), async (req, res) => {
  const { id } = req.params;
  try {
    if (req.session.userId === parseInt(id)) return res.status(400).json({ error: 'Cannot delete your own account' });
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING username', [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    console.log(`[ADMIN] User deleted: ${result.rows[0].username} by ${req.session.user}`);
    res.json({ success: true, message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.post('/api/admin/users/:id/unlock', requireAuth, requirePermission('admin.users.manage'), async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1 RETURNING username', [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    loginAttempts.byUser.delete(result.rows[0].username);
    console.log(`[ADMIN] User unlocked: ${result.rows[0].username} by ${req.session.user}`);
    res.json({ success: true, message: 'User unlocked' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to unlock user' });
  }
});

app.get('/api/admin/permissions', requireAuth, requirePermission('admin.roles.manage'), async (req, res) => {
  try {
    const result = await pool.query('SELECT code, name, description, category, risk_level FROM permissions ORDER BY category, risk_level, name');
    res.json({ success: true, permissions: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get permissions' });
  }
});

app.get('/api/admin/roles', requireAuth, requirePermission('admin.users.view'), async (req, res) => {
  const storeHash = req.session.storeHash || Object.keys(stores)[0];
  try {
    const result = await pool.query(`
      SELECT r.id, r.name, r.description, r.is_system, r.created_at,
             COUNT(rp.permission_code)::int AS permission_count
      FROM roles r
      LEFT JOIN role_permissions rp ON rp.role_id = r.id
      WHERE r.store_hash = $1
      GROUP BY r.id ORDER BY r.is_system DESC, r.name
    `, [storeHash]);
    res.json({ success: true, roles: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get roles' });
  }
});

app.get('/api/admin/roles/:id', requireAuth, requirePermission('admin.roles.manage'), async (req, res) => {
  const storeHash = req.session.storeHash || Object.keys(stores)[0];
  try {
    const roleRes = await pool.query('SELECT id, name, description, is_system FROM roles WHERE id = $1 AND store_hash = $2', [req.params.id, storeHash]);
    if (roleRes.rows.length === 0) return res.status(404).json({ error: 'Role not found' });
    const permRes = await pool.query('SELECT permission_code FROM role_permissions WHERE role_id = $1', [req.params.id]);
    res.json({ success: true, role: roleRes.rows[0], permissions: permRes.rows.map(r => r.permission_code) });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get role' });
  }
});

app.post('/api/admin/roles', requireAuth, requirePermission('admin.roles.manage'), async (req, res) => {
  const { name, description, permissions: perms } = req.body;
  const storeHash = req.session.storeHash || Object.keys(stores)[0];
  if (!name) return res.status(400).json({ error: 'Role name is required' });
  try {
    const roleRes = await pool.query(
      'INSERT INTO roles (store_hash, name, description, is_system) VALUES ($1, $2, $3, false) RETURNING id',
      [storeHash, name.trim(), description || '']
    );
    const roleId = roleRes.rows[0].id;
    if (Array.isArray(perms)) {
      for (const code of perms)
        await pool.query('INSERT INTO role_permissions (role_id, permission_code) VALUES ($1, $2) ON CONFLICT DO NOTHING', [roleId, code]);
    }
    console.log(`[ADMIN] Role created: ${name} by ${req.session.user}`);
    res.json({ success: true, roleId });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'A role with that name already exists' });
    res.status(500).json({ error: 'Failed to create role' });
  }
});

app.put('/api/admin/roles/:id', requireAuth, requirePermission('admin.roles.manage'), async (req, res) => {
  const { name, description, permissions: perms } = req.body;
  const storeHash = req.session.storeHash || Object.keys(stores)[0];
  try {
    const roleRes = await pool.query('SELECT id FROM roles WHERE id = $1 AND store_hash = $2', [req.params.id, storeHash]);
    if (roleRes.rows.length === 0) return res.status(404).json({ error: 'Role not found' });
    await pool.query('UPDATE roles SET name = $1, description = $2 WHERE id = $3', [name.trim(), description || '', req.params.id]);
    await pool.query('DELETE FROM role_permissions WHERE role_id = $1', [req.params.id]);
    if (Array.isArray(perms)) {
      for (const code of perms)
        await pool.query('INSERT INTO role_permissions (role_id, permission_code) VALUES ($1, $2) ON CONFLICT DO NOTHING', [req.params.id, code]);
    }
    console.log(`[ADMIN] Role updated: id=${req.params.id} by ${req.session.user}`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update role' });
  }
});

app.delete('/api/admin/roles/:id', requireAuth, requirePermission('admin.roles.manage'), async (req, res) => {
  const storeHash = req.session.storeHash || Object.keys(stores)[0];
  try {
    const roleRes = await pool.query('SELECT id, name, is_system FROM roles WHERE id = $1 AND store_hash = $2', [req.params.id, storeHash]);
    if (roleRes.rows.length === 0) return res.status(404).json({ error: 'Role not found' });
    if (roleRes.rows[0].is_system)  return res.status(400).json({ error: 'Cannot delete system roles' });
    const inUse = await pool.query('SELECT 1 FROM user_store_roles WHERE role_id = $1 LIMIT 1', [req.params.id]);
    if (inUse.rows.length > 0) return res.status(400).json({ error: 'Cannot delete a role assigned to users' });
    await pool.query('DELETE FROM roles WHERE id = $1', [req.params.id]);
    console.log(`[ADMIN] Role deleted: ${roleRes.rows[0].name} by ${req.session.user}`);
    res.json({ success: true, message: 'Role deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete role' });
  }
});

app.get('/api/admin/login-attempts', requireAuth, requirePermission('admin.audit.view'), async (req, res) => {
  const { limit = 100 } = req.query;
  try {
    const result = await pool.query('SELECT id, ip_address, username, success, attempted_at FROM login_attempts ORDER BY attempted_at DESC LIMIT $1', [Math.min(parseInt(limit), 500)]);
    res.json({ success: true, attempts: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get login attempts' });
  }
});

app.get('/api/admin/search-audit', requireAuth, requirePermission('admin.audit.view'), async (req, res) => {
  const { limit = 200, username } = req.query;
  try {
    let query, params;
    if (username) {
      query  = 'SELECT id, username, store, search_type, query, result_count, searched_at FROM search_audit WHERE username = $1 ORDER BY searched_at DESC LIMIT $2';
      params = [username, Math.min(parseInt(limit), 1000)];
    } else {
      query  = 'SELECT id, username, store, search_type, query, result_count, searched_at FROM search_audit ORDER BY searched_at DESC LIMIT $1';
      params = [Math.min(parseInt(limit), 1000)];
    }
    const result = await pool.query(query, params);
    res.json({ success: true, searches: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get search audit log' });
  }
});

app.get('/admin', requireAuth, requirePermission('admin.users.view'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Database stats
app.get('/api/db-stats', requireAuth, async (req, res) => {
  const stats = {};

  try {
    for (const store of Object.keys(stores)) {
      const countRes = await pool.query(
        'SELECT COUNT(*)::int as count FROM order_lookup WHERE store = $1',
        [store]
      );
      const oldestRes = await pool.query(
        'SELECT MIN(order_date) as date FROM order_lookup WHERE store = $1',
        [store]
      );
      const newestRes = await pool.query(
        'SELECT MAX(order_date) as date FROM order_lookup WHERE store = $1',
        [store]
      );

      stats[store] = {
        count: countRes.rows[0]?.count || 0,
        oldest: oldestRes.rows[0]?.date || null,
        newest: newestRes.rows[0]?.date || null
      };
    }

    res.json(stats);
  } catch (e) {
    console.error('DB stats error:', e.message);
    res.status(500).json({ error: 'Failed to read database stats' });
  }
});

// Manual sync trigger (admin only)
app.post('/api/sync/:store', requireAuth, requireAdmin, async (req, res) => {
  const { store } = req.params;
  const { fullSync } = req.body;

  if (!stores[store]) {
    return res.status(400).json({ error: 'Invalid store' });
  }

  try {
    const result = await syncOrders(store, fullSync === true);
    res.json({ success: true, ...result });
  } catch (error) {
    console.error(`Manual sync error: ${error.message}`);
    res.status(500).json({ error: 'Sync failed.' });
  }
});

// Search orders API
app.post('/api/search', requireAuth, async (req, res) => {
  const { store, searchType, query } = req.body;
  const username  = req.session.user;
  const perms     = req.session.permissions || [];
  const isAdmin   = perms.includes('admin.users.manage');
  const canSearch = perms.includes('orders.search');

  if (!stores[store]) {
    return res.status(400).json({ error: 'Invalid store' });
  }

  if (!query || query.trim().length < 2) {
    return res.status(400).json({ error: 'Search query too short' });
  }

  if (!canSearch) {
    return res.status(403).json({ error: 'You do not have permission to search orders.' });
  }

  // Rate limit non-admin users
  if (!isAdmin) {
    const rateCheck = isSearchRateLimited(username);
    if (rateCheck && rateCheck.limited) {
      console.log(`[SEARCH] Rate limited: ${username} (${SEARCH_RATE_LIMIT} searches/hour exceeded)`);
      return res.status(429).json({
        error: `Search limit reached. You have made ${SEARCH_RATE_LIMIT} searches this hour. Please wait ${rateCheck.resetMin} minute${rateCheck.resetMin !== 1 ? 's' : ''} before searching again.`
      });
    }
  }

  // Results cap: 20 for non-admins, 200 for admins
  const RESULTS_CAP = isAdmin ? 200 : 20;
  const BC_LIMIT = isAdmin ? 50 : 20;

  try {
    let orders = [];

    switch (searchType) {
      case 'order': {
        try {
          const order = await bcApiRequest(store, `orders/${query.trim()}`);
          if (order && order.id) orders = [order];
        } catch (e) {
          if (e.notFound) {
            await logSearch(username, store, searchType, query, 0);
            return res.json({ success: true, orders: [] });
          }
          throw e;
        }
        break;
      }

      case 'email': {
        try {
          const result = await bcApiRequest(store, `orders?email=${encodeURIComponent(query)}&limit=${BC_LIMIT}&sort=date_created:desc`);
          orders = Array.isArray(result) ? result : [];
        } catch (e) {
          if (e.notFound) {
            await logSearch(username, store, searchType, query, 0);
            return res.json({ success: true, orders: [] });
          }
          throw e;
        }
        break;
      }

      case 'name': {
        // Requires both first + last name (enforced in searchByName)
        const nameEmails = await searchByName(store, query);

        if (nameEmails.length === 0 && query.trim().split(/\s+/).filter(Boolean).length < 2) {
          await logSearch(username, store, searchType, query, 0);
          return res.status(400).json({ error: 'Please enter both first and last name to search by name.' });
        }

        console.log(`Name search found ${nameEmails.length} emails:`, nameEmails.slice(0, 5));

        for (const email of nameEmails.slice(0, 10)) {
          try {
            const emailOrders = await bcApiRequest(
              store,
              `orders?email=${encodeURIComponent(email)}&limit=${BC_LIMIT}&sort=date_created:desc`
            );
            if (Array.isArray(emailOrders)) {
              orders = orders.concat(emailOrders);
            }
          } catch (e) { /* Skip */ }
        }

        orders = orders.filter((o, i, arr) => arr.findIndex(x => x.id === o.id) === i);
        break;
      }

      case 'phone': {
        const phoneEmails = await searchByPhone(store, query);
        console.log(`Phone search found ${phoneEmails.length} emails:`, phoneEmails.slice(0, 5));

        for (const email of phoneEmails.slice(0, 10)) {
          try {
            const emailOrders = await bcApiRequest(
              store,
              `orders?email=${encodeURIComponent(email)}&limit=${BC_LIMIT}&sort=date_created:desc`
            );
            if (Array.isArray(emailOrders)) {
              orders = orders.concat(emailOrders);
            }
          } catch (e) { /* Skip */ }
        }

        orders = orders.filter((o, i, arr) => arr.findIndex(x => x.id === o.id) === i);
        break;
      }

      default:
        return res.status(400).json({ error: 'Invalid search type' });
    }

    // Sort by date desc
    if (Array.isArray(orders)) {
      orders.sort((a, b) => new Date(b.date_created) - new Date(a.date_created));
    }

    // Cap results for non-admins
    if (!isAdmin && orders.length > RESULTS_CAP) {
      orders = orders.slice(0, RESULTS_CAP);
    }

    // Log the search for audit
    await logSearch(username, store, searchType, query, orders.length);
    console.log(`[SEARCH] ${username} searched ${store} by ${searchType}: "${query}" -> ${orders.length} results`);

    res.json({ success: true, orders: orders || [] });
  } catch (error) {
    console.error(`Search error: ${error.message}`);
    res.status(500).json({ error: 'Unable to complete search. Please try again.' });
  }
});

// Debug: test v3 product URL lookup (admin only, remove after confirming it works)
app.get('/api/debug/product-url/:store/:productId', requireAuth, requireAdmin, async (req, res) => {
  const { store, productId } = req.params;
  try {
    const data = await bcApiV3Request(store, `catalog/products?id:in=${productId}&limit=1`);
    const product = data?.data?.[0];
    res.json({
      raw_custom_url: product?.custom_url || null,
      built_url: product?.custom_url?.url ? (stores[store].baseUrl + product.custom_url.url) : null,
      product_id: product?.id || null,
      store_baseUrl: stores[store]?.baseUrl || null,
      v3_status: 'ok'
    });
  } catch (e) {
    res.json({ error: e.message, v3_status: 'failed' });
  }
});

// Get full order details
app.get('/api/order/:store/:orderId', requireAuth, async (req, res) => {
  const { store, orderId } = req.params;

  if (!stores[store]) {
    return res.status(400).json({ error: 'Invalid store' });
  }

  try {
    // Get order details
    const order = await bcApiRequest(store, `orders/${orderId}`);

    // Get order products
    const products = await bcApiRequest(store, `orders/${orderId}/products`);

    // Fetch product URLs from v3 catalog API (one batch call)
    let productUrlMap = {};
    try {
      if (Array.isArray(products) && products.length > 0) {
        const productIds = [...new Set(products.map(p => p.product_id).filter(Boolean))].join(',');
        if (productIds) {
          const catalogData = await bcApiV3Request(store, `catalog/products?id:in=${productIds}&limit=50`);
          if (catalogData && Array.isArray(catalogData.data)) {
            const baseUrl = stores[store].baseUrl || '';
            catalogData.data.forEach(cp => {
              if (cp.custom_url && cp.custom_url.url) {
                productUrlMap[String(cp.id)] = baseUrl + cp.custom_url.url;
              }
            });
          }
          console.log(`[PRODUCT-URL] store=${store} ids=${productIds} mapped=${Object.keys(productUrlMap).length}`);
        }
      }
    } catch (e) {
      console.error(`[PRODUCT-URL] Failed:`, e.message);
    }

    // Attach URL to each product
    const productsWithUrls = Array.isArray(products)
      ? products.map(p => ({ ...p, product_url: productUrlMap[String(p.product_id)] || null }))
      : products;

    // Get shipping addresses
    let shippingAddresses = [];
    try {
      shippingAddresses = await bcApiRequest(store, `orders/${orderId}/shipping_addresses`);
    } catch (e) {
      // No shipping addresses
    }

    // Get shipments (for tracking)
    let shipments = [];
    try {
      shipments = await bcApiRequest(store, `orders/${orderId}/shipments`);
    } catch (e) {
      // No shipments
    }

    // Get internal notes from our database
    const notesResult = await pool.query(
      'SELECT id, username, note_text, created_at FROM order_notes WHERE store = $1 AND order_id = $2 ORDER BY created_at DESC',
      [store, orderId]
    );

    res.json({
      success: true,
      order,
      products: productsWithUrls,
      shippingAddresses,
      shipments: Array.isArray(shipments)
        ? shipments.map(s => ({
            id: s.id,
            tracking_number: s.tracking_number,
            tracking_carrier: s.tracking_carrier,
            shipping_method: s.shipping_method,
            date_created: s.date_created,
            items: s.items
          }))
        : [],
      notes: notesResult.rows
    });
  } catch (error) {
    console.error(`Order fetch error: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch order details.' });
  }
});

// Get note counts for multiple orders (used for note badges on search results)
app.post('/api/note-counts', requireAuth, async (req, res) => {
  const { store, orderIds } = req.body;

  if (!stores[store]) return res.status(400).json({ error: 'Invalid store' });
  if (!Array.isArray(orderIds) || orderIds.length === 0) return res.json({ counts: {} });

  try {
    const result = await pool.query(
      `SELECT order_id, COUNT(*)::int as count
       FROM order_notes
       WHERE store = $1 AND order_id = ANY($2::bigint[])
       GROUP BY order_id`,
      [store, orderIds]
    );

    const counts = {};
    result.rows.forEach(row => { counts[row.order_id] = row.count; });
    res.json({ counts });
  } catch (err) {
    console.error('Note counts error:', err.message);
    res.status(500).json({ error: 'Failed to get note counts' });
  }
});

// Add note to order
app.post('/api/order/:store/:orderId/notes', requireAuth, async (req, res) => {
  const { store, orderId } = req.params;
  const { note } = req.body;
  const username = req.session.user;

  if (!stores[store]) {
    return res.status(400).json({ error: 'Invalid store' });
  }

  if (!note || note.trim().length === 0) {
    return res.status(400).json({ error: 'Note cannot be empty' });
  }

  if (note.length > 500) {
    return res.status(400).json({ error: 'Note cannot exceed 500 characters' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO order_notes (order_id, store, username, note_text) VALUES ($1, $2, $3, $4) RETURNING id, username, note_text, created_at',
      [orderId, store, username, note.trim()]
    );

    console.log(`[${new Date().toISOString()}] Note added by ${username} for order ${orderId} (${store})`);

    res.json({
      success: true,
      note: result.rows[0]
    });
  } catch (error) {
    console.error(`Add note error: ${error.message}`);
    res.status(500).json({ error: 'Failed to add note.' });
  }
});

// Delete note from order (own notes only; admins can delete any)
app.delete('/api/order/:store/:orderId/notes/:noteId', requireAuth, async (req, res) => {
  const { store, orderId, noteId } = req.params;
  const username = req.session.user;
  const isAdmin = req.session.isAdmin || false;
  const DELETE_WINDOW_MIN = 15;

  if (!stores[store]) return res.status(400).json({ error: 'Invalid store' });

  try {
    // Fetch the note to check ownership and age
    const existing = await pool.query(
      'SELECT id, username, created_at FROM order_notes WHERE id = $1 AND store = $2 AND order_id = $3',
      [noteId, store, orderId]
    );

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Note not found' });
    }

    const noteOwner = existing.rows[0].username;
    const noteAge = (Date.now() - new Date(existing.rows[0].created_at).getTime()) / 60000; // minutes

    // Agents can only delete their own notes
    if (!isAdmin && noteOwner !== username) {
      return res.status(403).json({ error: 'You can only delete your own notes' });
    }

    // Agents can only delete within 15-minute window; admins bypass this
    if (!isAdmin && noteAge > DELETE_WINDOW_MIN) {
      return res.status(403).json({ error: `Notes can only be deleted within ${DELETE_WINDOW_MIN} minutes of being added` });
    }

    await pool.query('DELETE FROM order_notes WHERE id = $1', [noteId]);

    console.log(`[${new Date().toISOString()}] Note ${noteId} deleted by ${username} for order ${orderId} (${store})`);
    res.json({ success: true });

  } catch (error) {
    console.error(`Delete note error: ${error.message}`);
    res.status(500).json({ error: 'Failed to delete note.' });
  }
});


// ==================== EMAIL HELPERS (POSTMARK) ====================

// Build tracking URL (same logic as frontend)
// Shared carrier detection logic
function identifyCarrier(hint, n) {
  const h = String(hint || '').toLowerCase();
  const isUps  = h.includes('ups')   || /^1Z/i.test(n);  // 1Z prefix = UPS regardless of length
  const isUsps = h.includes('usps')  || /^(94|93|92|95)\d{18,20}$/.test(n) || /^420\d{5,}$/.test(n);
  const isFedex = h.includes('fedex') ||
    (/^\d+$/.test(n) && [12,15,20,22].includes(n.length) &&
     !/^(94|93|92|95)/.test(n) && !/^1Z/i.test(n));  // exclude 1Z from FedEx length match
  const isDhl  = h.includes('dhl')   || /^JD\d+/i.test(n);

  if (isUps)   return 'UPS';
  if (isUsps)  return 'USPS';
  if (isFedex) return 'FedEx';
  if (isDhl)   return 'DHL';
  return null;
}

// Detect clean carrier name from tracking number pattern + hint
function detectCarrierName(carrier, number) {
  const n = String(number || '').trim().replace(/\s+/g, '');
  if (!n) return carrier || '';

  const detected = identifyCarrier(carrier, n);
  if (detected) return detected;

  // Fallback: return original value only if it's a real carrier name, not a generic shipping label
  const genericTerms = ['shipping', 'standard', 'free', 'ground', 'delivery', 'express', 'priority'];
  const hint = String(carrier || '').toLowerCase();
  return genericTerms.some(t => hint.includes(t)) ? '' : (carrier || '');
}

function buildTrackingUrl(carrier, number) {
  if (!number) return null;
  const n = String(number).trim().replace(/\s+/g, '');

  const detected = identifyCarrier(carrier, n);
  if (detected === 'UPS')   return `https://www.ups.com/track?tracknum=${encodeURIComponent(n)}`;
  if (detected === 'USPS')  return `https://tools.usps.com/go/TrackConfirmAction?tLabels=${encodeURIComponent(n)}`;
  if (detected === 'FedEx') return `https://www.fedex.com/fedextrack/?trknbr=${encodeURIComponent(n)}`;
  if (detected === 'DHL')   return `https://www.dhl.com/en/express/tracking.html?AWB=${encodeURIComponent(n)}`;
  return `https://www.fedex.com/fedextrack/?trknbr=${encodeURIComponent(n)}`; // safe fallback
}

// Log sent email to database
async function logEmail(store, orderId, emailType, sentTo, sentBy, postmarkMsgId, status, errorMsg) {
  try {
    await pool.query(
      `INSERT INTO email_log (store, order_id, email_type, sent_to, sent_by, postmark_message_id, status, error_message)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [store, orderId, emailType, sentTo, sentBy, postmarkMsgId || null, status, errorMsg || null]
    );
  } catch (e) {
    console.error('Failed to log email:', e.message);
  }
}

// Build order confirmation HTML email
function buildConfirmationEmailHtml(order, products, shipping, branding) {
  const billing = order.billing_address || {};
  const shippingAddr = shipping || billing;
  const safe = (v) => v == null ? '' : String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const money = (v) => `$${parseFloat(v || 0).toFixed(2)}`;
  const font = "Montserrat,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif";

  const orderDate = order.date_created
    ? new Date(order.date_created).toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' })
    : '';


  // Products - BC style: name bold, SKU small below, qty right, total right
  const itemRows = products.map(p => {
    const qty = parseFloat(p.quantity || 0);
    const unit = parseFloat(p.price_ex_tax ?? p.base_price ?? 0);
    const total = parseFloat(p.total_ex_tax ?? (unit * qty));
    return `
      <tr class="products__item">
        <th class="products__content" style="padding:12px 0; text-align:left; vertical-align:middle; font-weight:400; font-family:${font};">
          <p style="margin:0 0 3px; font-size:14px; color:#333; font-weight:600;">${safe(p.name)}</p>
          ${p.sku ? `<p style="margin:0; font-size:12px; color:#888; line-height:1.5;">${safe(p.sku)}</p>` : ''}

        </th>
        <th class="products__quantity" style="padding:12px 0 12px 16px; vertical-align:middle; width:65px; white-space:nowrap; font-weight:400; font-family:${font};">
          <p style="margin:0; font-size:14px; color:#333;">Qty: ${qty}</p>
        </th>
        <th class="products__total" style="padding:12px 0 12px 16px; vertical-align:middle; width:90px; text-align:right; font-weight:400; font-family:${font};">
          <p style="margin:0; font-size:14px; color:#333; text-align:right;">${money(total)}</p>
        </th>
      </tr>`;
  }).join('');

  const couponDiscount = parseFloat(order.coupon_discount || 0);
  const discountAmount = parseFloat(order.discount_amount || 0);

  // Cart icon delimiter (matches BC's shopping cart divider)
  const delimiter = `
      <table class="container" cellpadding="0" cellspacing="0" style="margin:8px auto;">
        <tr>
          <td style="vertical-align:middle;"><hr style="border:none; border-bottom:1px solid #d0d0d0; width:230px;"></td>
          <td style="padding:0 14px; vertical-align:middle; text-align:center; font-size:22px; color:#aaa;">&#128722;</td>
          <td style="vertical-align:middle;"><hr style="border:none; border-bottom:1px solid #d0d0d0; width:230px;"></td>
        </tr>
      </table>`;

  return `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta name="viewport" content="width=device-width">
  <style type="text/css">
    body, table, tr, td, th, div, h1, h2, p, img { Margin:0; margin:0; padding:0; }
    body { background:#fff; min-width:100%; -ms-text-size-adjust:100%; -webkit-text-size-adjust:100%; }
    table { border-collapse:collapse; border-spacing:0; width:100%; }
    h1, h2, p, a, span { color:#333; font-family:${font}; font-weight:400; word-wrap:break-word; }
    h1 { font-size:28px; font-weight:500; line-height:1.21429; }
    h2 { font-size:21px; font-weight:500; margin:0 0 4px; }
    p { font-size:14px; line-height:1.57143; }
    a { color:#2199e8; text-decoration:none; }
    strong { font-weight:600; }
    hr { border:none; border-bottom:1px solid #d0d0d0; }
    .container { Margin:0 auto; margin:0 auto; width:544px; }
    .products { border-top:1px solid #e5e5e5; width:100%; border-collapse:collapse; }
    .products__item { border-bottom:1px solid #e5e5e5; }
  </style>
</head>
<body>
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center">

      <!-- Logo -->
      <table class="container" cellpadding="0" cellspacing="0" style="margin-top:16px;">
        <tr><td style="padding:24px 0; text-align:center;">
          <a href="https://www.1ink.com" target="_blank">
            <img src="${branding.logoUrl}" alt="${safe(branding.name)}" style="max-width:240px; height:auto; display:block; margin:0 auto;">
          </a>
        </td></tr>
      </table>

      <!-- Cart icon delimiter -->
      ${delimiter}

      <!-- Title + notice box -->
      <table class="container" cellpadding="0" cellspacing="0" style="margin-top:20px;">
        <tr><td>
          <h1 style="margin:0 0 20px; font-size:28px; font-weight:500; color:#333; font-family:${font};">Thank you for your order!</h1>

          <!-- Yellow notice box with Track button -->
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff9e5; border:1px solid #eee; border-radius:0; margin-bottom:32px;">
            <tr><td style="padding:12px 14px; text-align:center; font-family:${font}; font-size:14px; line-height:1.6; font-weight:600; color:#000;">
              <p style="margin:0 0 12px;"><strong>Please Note:</strong> You will receive a separate email with your tracking information once your order has shipped, typically within 24&ndash;48 hrs.</p>
              <!-- Track your order pill button -->
              <table border="0" cellpadding="0" cellspacing="0" align="center" style="width:auto; margin:0 auto;">
                <tr>
                  <td align="center" bgcolor="#1a73e8" style="border-radius:50px; padding:14px 26px;">
                    <a href="https://www.1ink.com/order-tracking/" target="_blank"
                       style="display:block; color:#ffffff; text-decoration:none; font-weight:600; font-size:16px; line-height:14px; white-space:nowrap;">
                      Track your order
                    </a>
                  </td>
                </tr>
              </table>
            </td></tr>
          </table>
        </td></tr>
      </table>

      <!-- Order # + products -->
      <table class="container" cellpadding="0" cellspacing="0" style="margin-bottom:32px;">
        <tr><td>
          <h2 style="margin-bottom:4px; font-family:${font};">Order #${safe(order.id)}</h2>
          <table class="products" cellpadding="0" cellspacing="0">
            ${itemRows}
          </table>
        </td></tr>
      </table>

      <!-- Totals -->
      <table class="container" cellpadding="0" cellspacing="0" style="margin-bottom:32px;">
        <tr><td>
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td align="right">
                <table cellpadding="0" cellspacing="0">
                  <tr>
                    <td style="padding:4px 0; font-size:14px; color:#555; text-align:right; font-family:${font};">Subtotal:</td>
                    <td style="padding:4px 0 4px 15px; font-size:14px; font-weight:600; color:#333; text-align:right; font-family:${font};">${money(order.subtotal_ex_tax)}</td>
                  </tr>
                  ${couponDiscount > 0 ? `<tr>
                    <td style="padding:4px 0; font-size:14px; color:#d32f2f; text-align:right; font-family:${font};">Coupon${order.coupon_code ? ' (' + safe(order.coupon_code) + ')' : ''}:</td>
                    <td style="padding:4px 0 4px 15px; font-size:14px; font-weight:600; color:#d32f2f; text-align:right; font-family:${font};">-${money(couponDiscount)}</td>
                  </tr>` : ''}
                  ${discountAmount > 0 && discountAmount !== couponDiscount ? `<tr>
                    <td style="padding:4px 0; font-size:14px; color:#28a745; text-align:right; font-family:${font};">Discount:</td>
                    <td style="padding:4px 0 4px 15px; font-size:14px; font-weight:600; color:#28a745; text-align:right; font-family:${font};">-${money(discountAmount)}</td>
                  </tr>` : ''}
                  <tr>
                    <td style="padding:4px 0; font-size:14px; color:#555; text-align:right; font-family:${font};">Shipping:</td>
                    <td style="padding:4px 0 4px 15px; font-size:14px; font-weight:600; color:#333; text-align:right; font-family:${font};">${money(order.shipping_cost_ex_tax)}</td>
                  </tr>
                  <tr>
                    <td style="padding:4px 0; font-size:14px; color:#555; text-align:right; font-family:${font};">Tax:</td>
                    <td style="padding:4px 0 4px 15px; font-size:14px; font-weight:600; color:#333; text-align:right; font-family:${font};">${money(order.total_tax)}</td>
                  </tr>
                  <tr>
                    <td colspan="2"><hr style="margin:4px 0;"></td>
                  </tr>
                  <tr>
                    <td style="padding:4px 0; font-size:14px; font-weight:600; color:#333; text-align:right; font-family:${font};">Grand total:</td>
                    <td style="padding:4px 0 4px 15px; font-size:14px; font-weight:700; color:#333; text-align:right; font-family:${font};">${money(order.total_inc_tax)}</td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </td></tr>
      </table>

      <!-- Addresses: Shipping first, then Billing -->
      <table class="container" cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
        <tr><td>
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="width:50%; vertical-align:top; padding-right:15px;">
                <p style="margin:0 0 6px; font-size:14px; font-weight:600; color:#333; font-family:${font};">Shipping address</p>
                <div style="border-top:1px solid #e5e5e5; padding-top:12px; font-size:14px; color:#333; line-height:1.7; font-family:${font};">
                  ${safe(shippingAddr.first_name)} ${safe(shippingAddr.last_name)}<br>
                  <a href="#" style="color:#2199e8;">${safe(shippingAddr.street_1)}${shippingAddr.street_2 ? ', ' + safe(shippingAddr.street_2) : ''}</a><br>
                  ${safe(shippingAddr.city)}, ${safe(shippingAddr.state)} ${safe(shippingAddr.zip)}<br>
                  ${shippingAddr.country && shippingAddr.country.toLowerCase() !== 'united states' ? safe(shippingAddr.country) + '<br>' : 'United States<br>'}
                  ${shippingAddr.phone ? safe(shippingAddr.phone) : ''}
                </div>
              </td>
              <td style="width:50%; vertical-align:top; padding-left:15px;">
                <p style="margin:0 0 6px; font-size:14px; font-weight:600; color:#333; font-family:${font};">Billing Address</p>
                <div style="border-top:1px solid #e5e5e5; padding-top:12px; font-size:14px; color:#333; line-height:1.7; font-family:${font};">
                  ${safe(billing.first_name)} ${safe(billing.last_name)}<br>
                  <a href="#" style="color:#2199e8;">${safe(billing.street_1)}${billing.street_2 ? ', ' + safe(billing.street_2) : ''}</a><br>
                  ${safe(billing.city)}, ${safe(billing.state)} ${safe(billing.zip)}<br>
                  ${billing.country ? safe(billing.country) + '<br>' : ''}
                  ${billing.phone ? safe(billing.phone) : ''}
                </div>
              </td>
            </tr>
          </table>
        </td></tr>
      </table>

      <!-- Footer cart delimiter + store info -->
      ${delimiter}

      <table class="container" cellpadding="0" cellspacing="0" style="margin:16px auto 16px;">
        <tr>
          <td style="width:75%; vertical-align:top; font-family:${font};">
            <p style="margin:0; font-size:14px; font-weight:600; color:#333;">${safe(branding.name)}</p>
            <p style="margin:0;"><a href="https://www.1ink.com" style="color:#777; font-size:12px;">www.1ink.com</a></p>
          </td>
          <td style="width:25%; text-align:right; vertical-align:top;">
            <a href="https://www.1ink.com" style="display:inline-block; border:1px solid #999; border-radius:4px; color:#777; padding:3px 15px; font-size:13px; font-weight:600; text-decoration:none; font-family:${font};">Go shopping</a>
          </td>
        </tr>
      </table>

      <table cellpadding="0" cellspacing="0" style="width:100%; height:16px;"><tr><td>&nbsp;</td></tr></table>

    </td></tr>
  </table>
</body>
</html>`;
}

// Build tracking HTML email (BC-style)
function buildTrackingEmailHtml(order, shipments, shippingAddr, branding) {
  const billing = order.billing_address || {};
  const addr = shippingAddr || billing;
  const recipientName = (addr.first_name || '').trim();
  const safe = (v) => v == null ? '' : String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const font = "Montserrat,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif";

  const orderDate = order.date_created
    ? new Date(order.date_created).toLocaleDateString('en-US', { year:'numeric', month:'short', day:'numeric', year:'numeric' })
    : '';

  const trackingButtons = shipments.map(s => {
    const num = s.tracking_number ? String(s.tracking_number).trim() : '';
    if (!num) return '';
    const url = buildTrackingUrl(s.tracking_carrier, num) || 'https://www.1ink.com/order-tracking/';
    const method = detectCarrierName(s.tracking_carrier || s.shipping_method, num);
    return `
    <tr><td style="padding:6px 0 16px 0;">
      <table border="0" cellpadding="0" cellspacing="0">
        <tr>
          <td align="left" valign="middle">
            <table border="0" cellpadding="0" cellspacing="0" style="border-collapse:separate;">
              <tr>
                <td bgcolor="#1a73e8" style="border-radius:22px; text-align:center;">
                  <a href="${url}" target="_blank"
                     style="display:inline-block; width:160px; background:#1a73e8; color:#ffffff; text-decoration:none; font-weight:600; font-size:16px; line-height:17px; padding:14px 0; border-radius:22px; text-align:center; font-family:${font};">
                    Track your order
                  </a>
                </td>
              </tr>
            </table>
          </td>
          <td style="vertical-align:middle; padding-left:14px; font-family:${font};">
            ${method ? `<span style="font-size:14px; font-weight:600; color:#333;">(${safe(method)})</span>` : ''}
          </td>
        </tr>
      </table>
    </td></tr>`;
  }).filter(Boolean).join('');

  // Products shipped rows
  const productRows = (order._products || []).map(p => {
    const qty = parseFloat(p.quantity || 0);
    return `
      <tr class="products__item">
        <th class="products__content" style="padding:12px 0; text-align:left; vertical-align:middle; font-weight:400; font-family:${font};">
          <p style="margin:0 0 3px; font-size:14px; color:#333; font-weight:600;">${safe(p.name)}</p>
          ${p.sku ? `<p style="margin:0; font-size:12px; color:#888;">${safe(p.sku)}</p>` : ''}
        </th>
        <th class="products__quantity" style="padding:12px 0 12px 16px; vertical-align:middle; width:65px; text-align:right; font-weight:400; font-family:${font};">
          <p style="margin:0; font-size:14px; color:#333; text-align:right;">Qty: ${qty}</p>
        </th>
      </tr>`;
  }).join('');

  // Cart icon delimiter
  const delimiter = `
      <table class="container" cellpadding="0" cellspacing="0" style="margin:8px auto;">
        <tr>
          <td style="vertical-align:middle;"><hr style="border:none; border-bottom:1px solid #d0d0d0; width:230px;"></td>
          <td style="padding:0 14px; vertical-align:middle; text-align:center; font-size:22px; color:#aaa;">&#128722;</td>
          <td style="vertical-align:middle;"><hr style="border:none; border-bottom:1px solid #d0d0d0; width:230px;"></td>
        </tr>
      </table>`;

  return `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta name="viewport" content="width=device-width">
  <style type="text/css">
    body, table, tr, td, th, div, h1, h2, p, img { Margin:0; margin:0; padding:0; }
    body { background:#fff; min-width:100%; -ms-text-size-adjust:100%; -webkit-text-size-adjust:100%; }
    table { border-collapse:collapse; border-spacing:0; width:100%; }
    h1, h2, p, a, span { color:#333; font-family:${font}; font-weight:400; word-wrap:break-word; }
    h1 { font-size:28px; font-weight:500; line-height:1.21429; }
    h2 { font-size:21px; font-weight:500; margin:0 0 4px; }
    p { font-size:14px; line-height:1.57143; }
    a { color:#2199e8; text-decoration:none; }
    strong { font-weight:600; }
    hr { border:none; border-bottom:1px solid #d0d0d0; }
    .container { Margin:0 auto; margin:0 auto; width:544px; }
    .products { border-top:1px solid #e5e5e5; width:100%; border-collapse:collapse; }
    .products__item { border-bottom:1px solid #e5e5e5; }
  </style>
</head>
<body>
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center">

      <!-- Logo -->
      <table class="container" cellpadding="0" cellspacing="0" style="margin-top:16px;">
        <tr><td style="padding:24px 0; text-align:center;">
          <a href="https://www.1ink.com" target="_blank">
            <img src="${branding.logoUrl}" alt="${safe(branding.name)}" style="max-width:240px; height:auto; display:block; margin:0 auto;">
          </a>
        </td></tr>
      </table>

      <!-- Cart icon delimiter -->
      ${delimiter}

      <!-- Title + greeting -->
      <table class="container" cellpadding="0" cellspacing="0" style="margin-top:24px;">
        <tr><td>
          <h1 style="margin:0 0 16px; font-family:${font};">Order Status Update!</h1>
          <p style="margin:0 0 8px; font-family:${font};">Hi ${safe(recipientName)},</p>
          <p style="margin:0 0 18px; font-family:${font};">Good news! Your order <strong>#${safe(order.id)}</strong> has been <strong>Shipped</strong>.</p>

          <!-- Order # badge -->
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
            <tr><td>
              <span style="display:inline-block; background:#e8f0fe; border:1px solid #b6cffb; color:#0b3d91; padding:8px 14px; border-radius:8px; font-size:15px; font-weight:700; font-family:${font};">
                Order #${safe(order.id)}
              </span>
            </td></tr>
          </table>
        </td></tr>
      </table>

      <!-- Order details -->
      <table class="container" cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
        <tr><td>
          <h2 style="margin-bottom:8px; font-family:${font};">Order details</h2>
          <table width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #e5e5e5; margin-top:8px;">
            <tr>
              <th style="padding:8px 0; text-align:left; font-weight:400; font-size:14px; color:#555; width:40%; font-family:${font};">Date placed</th>
              <th style="padding:8px 0; text-align:left; font-weight:600; font-size:14px; color:#333; font-family:${font};">${orderDate}</th>
            </tr>
            <tr>
              <th style="padding:8px 0; text-align:left; font-weight:400; font-size:14px; color:#555; border-top:1px solid #f0f0f0; font-family:${font};">Payment method</th>
              <th style="padding:8px 0; text-align:left; font-weight:600; font-size:14px; color:#333; border-top:1px solid #f0f0f0; font-family:${font};">${safe(order.payment_method || '')}</th>
            </tr>
          </table>
        </td></tr>
      </table>

      <!-- Products shipped -->
      ${productRows ? `
      <table class="container" cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
        <tr><td>
          <h2 style="margin-bottom:8px; font-family:${font};">Products shipped</h2>
          <table class="products" cellpadding="0" cellspacing="0">
            ${productRows}
          </table>
        </td></tr>
      </table>` : ''}

      <!-- Tracking section -->
      <table class="container" cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
        <tr><td>
          <h2 style="margin-bottom:8px; font-family:${font};">Tracking information</h2>
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:16px;">
            ${trackingButtons || '<tr><td style="padding:12px 0; font-size:14px; color:#666; font-family:' + font + '">Tracking information will be available shortly.</td></tr>'}
          </table>

          <!-- Yellow delivery times box -->
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff9e5; border:1px solid #e0c96a; border-radius:4px; margin-top:8px;">
            <tr><td style="padding:14px 18px; font-family:${font}; font-size:14px; line-height:1.6; color:#000; text-align:center;">
              <p style="margin:0 0 8px; font-weight:600;">We ship all orders within 24 hours to ensure prompt delivery. Orders placed on weekends or holidays ship the next business day.</p>
              <p style="margin:0 0 6px; font-weight:600;">TYPICAL DELIVERY TIME</p>
              <p style="margin:0 0 4px; font-weight:600;">West Coast: 1&ndash;3 business days</p>
              <p style="margin:0 0 10px; font-weight:600;">East Coast: 3&ndash;7 business days</p>
              <p style="margin:0; font-weight:600;">We sincerely appreciate your patience and understanding.</p>
            </td></tr>
          </table>
        </td></tr>
      </table>

      <!-- Footer cart delimiter + store info -->
      ${delimiter}

      <table class="container" cellpadding="0" cellspacing="0" style="margin:16px auto 16px;">
        <tr>
          <td style="width:75%; vertical-align:top; font-family:${font};">
            <p style="margin:0; font-size:14px; font-weight:600; color:#333;">${safe(branding.name)}</p>
            <p style="margin:0;"><a href="https://www.1ink.com" style="color:#777; font-size:12px;">www.1ink.com</a></p>
          </td>
          <td style="width:25%; text-align:right; vertical-align:top;">
            <a href="https://www.1ink.com" style="display:inline-block; border:1px solid #999; border-radius:4px; color:#777; padding:3px 15px; font-size:13px; font-weight:600; text-decoration:none; font-family:${font};">Go shopping</a>
          </td>
        </tr>
      </table>

      <table cellpadding="0" cellspacing="0" style="width:100%; height:16px;"><tr><td>&nbsp;</td></tr></table>

    </td></tr>
  </table>
</body>
</html>`;
}



// ==================== EMAIL API ENDPOINTS ====================

// Resend order confirmation via Postmark
app.post('/api/order/:store/:orderId/resend-confirmation', requireAuth, async (req, res) => {
  const { store, orderId } = req.params;
  const sentBy = req.session.user;

  if (!stores[store]) return res.status(400).json({ error: 'Invalid store' });
  if (!postmarkClient) return res.status(500).json({ error: 'Email service not configured. Add POSTMARK_SERVER_KEY to environment variables.' });

  try {
    const branding = storeBranding[store] || storeBranding['1ink'];

    // Fetch all order data needed for the email
    const order = await bcApiRequest(store, `orders/${orderId}`);
    const products = await bcApiRequest(store, `orders/${orderId}/products`);
    let shippingAddresses = [];
    try { shippingAddresses = await bcApiRequest(store, `orders/${orderId}/shipping_addresses`); } catch(e) {}

    const billing = order.billing_address || {};
    const recipientEmail = billing.email;
    if (!recipientEmail) return res.status(400).json({ error: 'No email address on this order' });

    const shippingAddr = shippingAddresses[0] || billing;
    const html = buildConfirmationEmailHtml(order, products, shippingAddr, branding);
    const recipientName = `${billing.first_name || ''} ${billing.last_name || ''}`.trim();

    const result = await postmarkClient.sendEmail({
      From: `${branding.fromName} <${branding.fromEmail}>`,
      To: `${recipientName} <${recipientEmail}>`,
      ReplyTo: branding.replyTo,
      Subject: `Order Confirmation – Order #${orderId} | ${branding.name}`,
      HtmlBody: html,
      TextBody: `Thank you for your order #${orderId} from ${branding.name}. Total: $${parseFloat(order.total_inc_tax || 0).toFixed(2)}. Questions? Email us at ${branding.fromEmail} or call ${branding.phone}.`,
      MessageStream: 'outbound',
      Tag: 'order-confirmation'
    });

    await logEmail(store, orderId, 'confirmation', recipientEmail, sentBy, result.MessageID, 'sent', null);
    console.log(`[EMAIL] Confirmation resent for order ${orderId} (${store}) to ${recipientEmail} by ${sentBy}`);

    res.json({ success: true, sentTo: recipientEmail, messageId: result.MessageID });

  } catch (err) {
    console.error(`Resend confirmation error:`, err.message);
    await logEmail(store, orderId, 'confirmation', 'unknown', sentBy, null, 'failed', err.message);
    res.status(500).json({ error: err.message || 'Failed to send email' });
  }
});

// Resend tracking email via Postmark
app.post('/api/order/:store/:orderId/resend-tracking', requireAuth, async (req, res) => {
  const { store, orderId } = req.params;
  const sentBy = req.session.user;

  if (!stores[store]) return res.status(400).json({ error: 'Invalid store' });
  if (!postmarkClient) return res.status(500).json({ error: 'Email service not configured. Add POSTMARK_SERVER_KEY to environment variables.' });

  try {
    const branding = storeBranding[store] || storeBranding['1ink'];

    // Fetch order, shipping addresses, shipments, and products
    const order = await bcApiRequest(store, `orders/${orderId}`);
    let shippingAddresses = [];
    try { shippingAddresses = await bcApiRequest(store, `orders/${orderId}/shipping_addresses`); } catch(e) {}
    let rawShipments = [];
    try { rawShipments = await bcApiRequest(store, `orders/${orderId}/shipments`); } catch(e) {}
    let products = [];
    try { products = await bcApiRequest(store, `orders/${orderId}/products`); } catch(e) {}
    order._products = Array.isArray(products) ? products : [];

    const billing = order.billing_address || {};
    const recipientEmail = billing.email;
    if (!recipientEmail) return res.status(400).json({ error: 'No email address on this order' });

    if (!Array.isArray(rawShipments) || rawShipments.length === 0) {
      return res.status(400).json({ error: 'This order has no shipments with tracking information yet' });
    }

    const shipments = rawShipments.map(s => ({
      tracking_number: s.tracking_number,
      tracking_carrier: s.tracking_carrier,
      shipping_method: s.shipping_method
    }));

    const shippingAddr = shippingAddresses[0] || billing;
    const html = buildTrackingEmailHtml(order, shipments, shippingAddr, branding);
    const recipientName = `${billing.first_name || ''} ${billing.last_name || ''}`.trim();

    const trackingNumbers = shipments.map(s => s.tracking_number).filter(Boolean).join(', ');

    const result = await postmarkClient.sendEmail({
      From: `${branding.fromName} <${branding.fromEmail}>`,
      To: `${recipientName} <${recipientEmail}>`,
      ReplyTo: branding.replyTo,
      Subject: `Your Order #${orderId} Has Shipped | ${branding.name}`,
      HtmlBody: html,
      TextBody: `Your order #${orderId} from ${branding.name} has shipped. Tracking: ${trackingNumbers}. Questions? Email us at ${branding.fromEmail} or call ${branding.phone}.`,
      MessageStream: 'outbound',
      Tag: 'tracking'
    });

    await logEmail(store, orderId, 'tracking', recipientEmail, sentBy, result.MessageID, 'sent', null);
    console.log(`[EMAIL] Tracking resent for order ${orderId} (${store}) to ${recipientEmail} by ${sentBy} | tracking: ${trackingNumbers}`);

    res.json({ success: true, sentTo: recipientEmail, messageId: result.MessageID });

  } catch (err) {
    console.error(`Resend tracking error:`, err.message);
    await logEmail(store, orderId, 'tracking', 'unknown', sentBy, null, 'failed', err.message);
    res.status(500).json({ error: err.message || 'Failed to send email' });
  }
});

// Get email log for an order (for showing history in the UI)
app.get('/api/order/:store/:orderId/email-log', requireAuth, async (req, res) => {
  const { store, orderId } = req.params;
  if (!stores[store]) return res.status(400).json({ error: 'Invalid store' });
  try {
    const result = await pool.query(
      `SELECT id, email_type, sent_to, sent_by, status, error_message, sent_at
       FROM email_log WHERE store = $1 AND order_id = $2 ORDER BY sent_at DESC LIMIT 20`,
      [store, orderId]
    );
    res.json({ success: true, emails: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch email log' });
  }
});

// Main app - redirect to login if not authenticated
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, async () => {
  await initDb();
  console.log(`BC Order Search app running on port ${PORT}`);
  
  // Get user count from database
  const userCountRes = await pool.query('SELECT COUNT(*)::int as count FROM users');
  console.log(`Users configured: ${userCountRes.rows[0]?.count || 0}`);
  console.log(`Stores configured: ${Object.keys(stores).filter(s => stores[s].hash).join(', ') || 'None'}`);

  // Check database counts
  for (const store of Object.keys(stores)) {
    if (stores[store].hash) {
      const countRes = await pool.query(
        'SELECT COUNT(*)::int as count FROM order_lookup WHERE store = $1',
        [store]
      );
      const count = countRes.rows[0];
      console.log(`Database: ${store} has ${count?.count || 0} orders indexed`);
    }
  }

  // Auto-sync new orders every 30 minutes
  setInterval(async () => {
    console.log('Running auto-sync...');
    for (const store of Object.keys(stores)) {
      if (stores[store].hash) {
        await syncOrders(store, false);
      }
    }
  }, 30 * 60 * 1000);
});

// ==================== ORDER ACTIONS ====================

const BC_STATUS_PERMISSIONS = {
  11: 'orders.status.update', // Awaiting Fulfillment
  9:  'orders.status.update', // Awaiting Shipment
  10: 'orders.status.update', // Completed
  2:  'orders.ship',          // Shipped
  3:  'orders.ship',          // Partially Shipped
  5:  'orders.cancel',        // Cancelled
  4:  'orders.refund',        // Refunded
  14: 'orders.refund',        // Partially Refunded
};
const BC_STATUS_LABELS = {
  11:'Awaiting Fulfillment', 9:'Awaiting Shipment', 10:'Completed',
  2:'Shipped', 3:'Partially Shipped', 5:'Cancelled', 4:'Refunded', 14:'Partially Refunded'
};

// Update order status
app.put('/api/order/:store/:orderId/status', requireAuth, async (req, res) => {
  const { store, orderId } = req.params;
  const { statusId } = req.body;
  if (!stores[store]) return res.status(400).json({ error: 'Invalid store' });

  const requiredPerm = BC_STATUS_PERMISSIONS[parseInt(statusId)];
  if (!requiredPerm) return res.status(400).json({ error: 'Invalid status' });

  const userPerms = req.session.permissions || [];
  if (!userPerms.includes(requiredPerm) && !userPerms.includes('*')) {
    return res.status(403).json({ error: 'Permission denied for this status' });
  }

  try {
    const result = await bcApiRequest(store, `orders/${orderId}`, 'PUT', { status_id: parseInt(statusId) });
    console.log(`[ORDER] Status update: #${orderId} → ${BC_STATUS_LABELS[statusId]} by ${req.session.user}`);
    res.json({ success: true, statusLabel: BC_STATUS_LABELS[statusId] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create shipment with tracking
app.post('/api/order/:store/:orderId/shipment', requireAuth, requirePermission('orders.tracking.add'), async (req, res) => {
  const { store, orderId } = req.params;
  const { trackingNumber, carrier, items } = req.body;
  if (!stores[store]) return res.status(400).json({ error: 'Invalid store' });
  if (!trackingNumber) return res.status(400).json({ error: 'Tracking number is required' });

  const CARRIER_MAP = { ups:'ups', fedex:'fedex', usps:'usps', dhl:'dhl', other:'' };

  try {
    // Fetch order products if no items passed
    let shipItems = items;
    if (!shipItems || shipItems.length === 0) {
      const products = await bcApiRequest(store, `orders/${orderId}/products`);
      shipItems = products.map(p => ({ order_product_id: p.id, quantity: p.quantity }));
    }

    // Get shipping address ID
    const addresses = await bcApiRequest(store, `orders/${orderId}/shipping_addresses`);
    const addressId = addresses && addresses[0] ? addresses[0].id : undefined;

    const payload = {
      tracking_number:   trackingNumber,
      shipping_provider: CARRIER_MAP[carrier] || '',
      items:             shipItems,
    };
    if (addressId) payload.order_address_id = addressId;

    const result = await bcApiRequest(store, `orders/${orderId}/shipments`, 'POST', payload);
    // Also update order status to Shipped
    await bcApiRequest(store, `orders/${orderId}`, 'PUT', { status_id: 2 }).catch(() => {});
    console.log(`[ORDER] Shipment created: #${orderId} tracking ${trackingNumber} by ${req.session.user}`);
    res.json({ success: true, shipmentId: result.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get refund quote — returns available payment methods + calculated total
app.post('/api/order/:store/:orderId/refund-quote', requireAuth, requirePermission('orders.refund'), async (req, res) => {
  const { store, orderId } = req.params;
  // products: [{ order_product_id, quantity }]
  // shipping: { order_address_id, amount }  (optional)
  const { products, shipping, customAmount } = req.body;
  if (!stores[store]) return res.status(400).json({ error: 'Invalid store' });

  try {
    const storeConfig = stores[store];
    const baseUrl = `https://api.bigcommerce.com/stores/${storeConfig.hash}/v3/orders/${orderId}`;
    const headers = { 'X-Auth-Token': storeConfig.token, 'Accept': 'application/json', 'Content-Type': 'application/json' };

    // Build BC quote items array
    const quoteItems = [];

    // Custom order-level amount (from "Apply an order level refund" tab)
    if (customAmount && customAmount > 0) {
      quoteItems.push({ item_type: 'ORDER', item_id: parseInt(orderId), amount: parseFloat(customAmount) });
    } else {
      // Product line items
      if (products && products.length > 0) {
        products.forEach(p => {
          if (p.quantity > 0) {
            quoteItems.push({ item_type: 'PRODUCT', item_id: p.order_product_id, quantity: p.quantity });
          }
        });
      }
      // Shipping line item
      if (shipping && shipping.amount > 0 && shipping.order_address_id) {
        quoteItems.push({ item_type: 'SHIPPING', item_id: shipping.order_address_id, amount: parseFloat(shipping.amount) });
      }
    }

    if (quoteItems.length === 0) {
      return res.status(400).json({ error: 'Select at least one item or shipping to refund' });
    }

    const quoteRes = await fetch(`${baseUrl}/payment_actions/refund_quotes`, {
      method: 'POST', headers, body: JSON.stringify({ items: quoteItems })
    });
    if (!quoteRes.ok) {
      const t = await quoteRes.text();
      throw new Error(`BC API Error: ${quoteRes.status} - ${t.slice(0, 300)}`);
    }
    const quote = await quoteRes.json();

    res.json({
      success:      true,
      total_amount: quote.data?.total_amount,
      total_tax:    quote.data?.total_tax,
      items:        quote.data?.items || [],
      payments:     quote.data?.payments || [],
      quoteItems:   quoteItems,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Execute refund — uses provider selected by agent
app.post('/api/order/:store/:orderId/refund', requireAuth, requirePermission('orders.refund'), async (req, res) => {
  const { store, orderId } = req.params;
  const { quoteItems, selectedPayment, reason } = req.body;
  // selectedPayment: { provider_id, provider_type, amount, offline }
  if (!stores[store]) return res.status(400).json({ error: 'Invalid store' });
  if (!quoteItems || !selectedPayment) return res.status(400).json({ error: 'Missing quote data' });

  try {
    const storeConfig = stores[store];
    const baseUrl = `https://api.bigcommerce.com/stores/${storeConfig.hash}/v3/orders/${orderId}`;
    const headers = { 'X-Auth-Token': storeConfig.token, 'Accept': 'application/json', 'Content-Type': 'application/json' };

    // Add reason to items if provided
    const itemsWithReason = quoteItems.map(item => reason ? { ...item, reason } : item);

    const refundRes = await fetch(`${baseUrl}/payment_actions/refunds`, {
      method: 'POST', headers,
      body: JSON.stringify({
        items:    itemsWithReason,
        payments: [selectedPayment],
      }),
    });
    if (!refundRes.ok) {
      const t = await refundRes.text();
      throw new Error(`BC API Error: ${refundRes.status} - ${t.slice(0, 300)}`);
    }
    const result = await refundRes.json();
    console.log(`[ORDER] Refund processed: #${orderId} $${selectedPayment.amount} via ${selectedPayment.provider_id} by ${req.session.user}`);
    res.json({ success: true, refundId: result.data?.id, amount: selectedPayment.amount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Bulk tracking import
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

function parseTrackingCsv(buffer) {
  const text = buffer.toString('utf8');
  const rows = [];
  let headerSkipped = false;
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    if (!line.trim()) continue;
    const fields = [];
    let cur = '', inQ = false;
    for (const ch of line) {
      if (ch === '"') { inQ = !inQ; continue; }
      if (ch === ',' && !inQ) { fields.push(cur); cur = ''; continue; }
      cur += ch;
    }
    fields.push(cur);
    const orderId  = fields[0] ? fields[0].replace(/[\r\n\s"]+/g, '').trim() : '';
    const tracking = fields[1] ? fields[1].replace(/[\r\n\s"]+/g, '').trim() : '';
    const carrier  = fields[2] ? fields[2].replace(/[\r\n\s"]+/g, '').trim() : '';
    if (!headerSkipped) { headerSkipped = true; if (isNaN(parseInt(orderId))) continue; }
    if (orderId && tracking && !isNaN(parseInt(orderId))) rows.push({ orderId, tracking, carrier });
  }
  return rows;
}

app.post('/api/bulk-tracking', requireAuth, requirePermission('orders.tracking.add'), upload.single('csvFile'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No CSV file uploaded' });
  const store = req.body.store || '1ink';
  if (!stores[store]) return res.status(400).json({ error: 'Invalid store' });

  const rows = parseTrackingCsv(req.file.buffer);
  if (rows.length === 0) return res.status(400).json({ error: 'No valid rows found in CSV' });

  const results = { success: [], failed: [], skipped: [] };
  const CARRIER_MAP = { ups:'ups', fedex:'fedex', usps:'usps', dhl:'dhl' };
  const BATCH = 5;

  for (let i = 0; i < rows.length; i += BATCH) {
    const batch = rows.slice(i, i + BATCH);
    await Promise.all(batch.map(async ({ orderId, tracking, carrier }) => {
      try {
        const existing = await bcApiRequest(store, `orders/${orderId}/shipments`).catch(() => []);
        if (existing && existing.some(s => s.tracking_number === tracking)) {
          results.skipped.push({ orderId, reason: 'Tracking already exists' }); return;
        }
        const products  = await bcApiRequest(store, `orders/${orderId}/products`);
        const addresses = await bcApiRequest(store, `orders/${orderId}/shipping_addresses`);
        const items     = products.map(p => ({ order_product_id: p.id, quantity: p.quantity }));
        const payload   = { tracking_number: tracking, shipping_provider: CARRIER_MAP[carrier.toLowerCase()] || '', items };
        if (addresses && addresses[0]) payload.order_address_id = addresses[0].id;
        await bcApiRequest(store, `orders/${orderId}/shipments`, 'POST', payload);
        await bcApiRequest(store, `orders/${orderId}`, 'PUT', { status_id: 2 }).catch(() => {});
        results.success.push({ orderId, tracking });
      } catch (err) {
        results.failed.push({ orderId, reason: err.message });
      }
    }));
    if (i + BATCH < rows.length) await new Promise(r => setTimeout(r, 300));
  }

  console.log(`[BULK] Tracking import by ${req.session.user}: ${results.success.length} ok, ${results.failed.length} failed, ${results.skipped.length} skipped`);
  res.json({ success: true, results });
});
