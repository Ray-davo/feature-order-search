require('dotenv').config();
const express = require('express');
const session = require('express-session');
const fetch = require('node-fetch');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const BCRYPT_ROUNDS = 10;

// Postgres connection (Render)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDb() {
  // Core tables
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

    -- Permissions table (system-defined)
    CREATE TABLE IF NOT EXISTS permissions (
      id SERIAL PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      category TEXT NOT NULL,
      risk_level INT DEFAULT 1
    );

    -- Roles table (can be customized per merchant in future)
    CREATE TABLE IF NOT EXISTS roles (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      is_system BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    -- Role-Permission mapping
    CREATE TABLE IF NOT EXISTS role_permissions (
      role_id INT REFERENCES roles(id) ON DELETE CASCADE,
      permission_id INT REFERENCES permissions(id) ON DELETE CASCADE,
      PRIMARY KEY (role_id, permission_id)
    );

    -- Users table with role reference
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role_id INT REFERENCES roles(id),
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_login TIMESTAMPTZ,
      failed_attempts INT DEFAULT 0,
      locked_until TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
  `);

  // Clean up old login attempts (older than 24 hours)
  await pool.query(`DELETE FROM login_attempts WHERE attempted_at < NOW() - INTERVAL '24 hours'`);

  // Initialize permissions and roles
  await initPermissionsAndRoles();

  // Migrate users from environment variables to database (one-time)
  await migrateEnvUsers();

  console.log('Postgres initialized');
}

// System-defined permissions
const SYSTEM_PERMISSIONS = [
  // Orders
  { code: 'orders.view', name: 'View Orders', description: 'View order details', category: 'Orders', risk_level: 1 },
  { code: 'orders.search', name: 'Search Orders', description: 'Search for orders', category: 'Orders', risk_level: 1 },
  { code: 'orders.notes.add', name: 'Add Notes', description: 'Add internal notes to orders', category: 'Orders', risk_level: 1 },
  { code: 'orders.notes.delete', name: 'Delete Notes', description: 'Delete internal notes', category: 'Orders', risk_level: 2 },
  { code: 'orders.status.update', name: 'Update Status', description: 'Change order status', category: 'Orders', risk_level: 2 },
  { code: 'orders.tracking.add', name: 'Add Tracking', description: 'Add tracking numbers', category: 'Orders', risk_level: 2 },
  { code: 'orders.ship', name: 'Create Shipments', description: 'Mark items as shipped', category: 'Orders', risk_level: 2 },
  { code: 'orders.cancel', name: 'Cancel Orders', description: 'Cancel orders', category: 'Orders', risk_level: 3 },
  { code: 'orders.refund', name: 'Process Refunds', description: 'Issue refunds', category: 'Orders', risk_level: 3 },
  { code: 'orders.export', name: 'Export Orders', description: 'Export order data', category: 'Orders', risk_level: 2 },
  // Customers
  { code: 'customers.view', name: 'View Customers', description: 'View customer information', category: 'Customers', risk_level: 1 },
  { code: 'customers.notes', name: 'Customer Notes', description: 'Add notes to customers', category: 'Customers', risk_level: 1 },
  { code: 'customers.export', name: 'Export Customers', description: 'Export customer data', category: 'Customers', risk_level: 2 },
  // Admin
  { code: 'admin.users.view', name: 'View Users', description: 'View user list', category: 'Admin', risk_level: 1 },
  { code: 'admin.users.manage', name: 'Manage Users', description: 'Create, edit, delete users', category: 'Admin', risk_level: 3 },
  { code: 'admin.roles.manage', name: 'Manage Roles', description: 'Create and edit roles', category: 'Admin', risk_level: 3 },
  { code: 'admin.settings', name: 'App Settings', description: 'Configure application settings', category: 'Admin', risk_level: 3 },
  { code: 'admin.audit.view', name: 'View Audit Logs', description: 'View login and activity logs', category: 'Admin', risk_level: 2 },
];

// Default role templates with their permissions
const DEFAULT_ROLES = [
  {
    name: 'Admin',
    description: 'Full access to all features',
    is_system: true,
    permissions: 'all'
  },
  {
    name: 'Senior Manager',
    description: 'Can manage orders, refunds, and view users',
    is_system: true,
    permissions: [
      'orders.view', 'orders.search', 'orders.notes.add', 'orders.notes.delete',
      'orders.status.update', 'orders.tracking.add', 'orders.ship',
      'orders.cancel', 'orders.refund', 'orders.export',
      'customers.view', 'customers.notes', 'customers.export',
      'admin.users.view', 'admin.audit.view'
    ]
  },
  {
    name: 'Manager',
    description: 'Can manage orders and shipments',
    is_system: true,
    permissions: [
      'orders.view', 'orders.search', 'orders.notes.add', 'orders.notes.delete',
      'orders.status.update', 'orders.tracking.add', 'orders.ship', 'orders.export',
      'customers.view', 'customers.notes',
      'admin.users.view'
    ]
  },
  {
    name: 'Supervisor',
    description: 'Can update order status and add notes',
    is_system: true,
    permissions: [
      'orders.view', 'orders.search', 'orders.notes.add',
      'orders.status.update',
      'customers.view', 'customers.notes',
      'admin.users.view'
    ]
  },
  {
    name: 'Agent',
    description: 'Can view orders and add notes',
    is_system: true,
    permissions: [
      'orders.view', 'orders.search', 'orders.notes.add',
      'customers.view', 'customers.notes'
    ]
  }
];

// Initialize permissions and roles
async function initPermissionsAndRoles() {
  // Insert permissions (ignore if exists)
  for (const perm of SYSTEM_PERMISSIONS) {
    await pool.query(`
      INSERT INTO permissions (code, name, description, category, risk_level)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (code) DO NOTHING
    `, [perm.code, perm.name, perm.description, perm.category, perm.risk_level]);
  }

  // Insert default roles (if they don't exist)
  for (const role of DEFAULT_ROLES) {
    const existing = await pool.query('SELECT id FROM roles WHERE name = $1', [role.name]);
    
    if (existing.rows.length === 0) {
      const result = await pool.query(
        'INSERT INTO roles (name, description, is_system) VALUES ($1, $2, $3) RETURNING id',
        [role.name, role.description, role.is_system]
      );
      const roleId = result.rows[0].id;

      // Assign permissions to role
      if (role.permissions === 'all') {
        // Admin gets all permissions
        await pool.query(`
          INSERT INTO role_permissions (role_id, permission_id)
          SELECT $1, id FROM permissions
        `, [roleId]);
      } else {
        // Specific permissions
        for (const permCode of role.permissions) {
          await pool.query(`
            INSERT INTO role_permissions (role_id, permission_id)
            SELECT $1, id FROM permissions WHERE code = $2
          `, [roleId, permCode]);
        }
      }
      console.log(`Created role: ${role.name}`);
    }
  }
}

// Migrate users from env vars to database (runs once)
async function migrateEnvUsers() {
  // Get Admin and Agent role IDs
  const adminRole = await pool.query("SELECT id FROM roles WHERE name = 'Admin'");
  const agentRole = await pool.query("SELECT id FROM roles WHERE name = 'Agent'");
  
  const adminRoleId = adminRole.rows[0]?.id;
  const agentRoleId = agentRole.rows[0]?.id;

  for (let i = 1; i <= 10; i++) {
    const name = process.env[`USER${i}_NAME`];
    const pass = process.env[`USER${i}_PASS`];
    
    if (name && pass) {
      const userLower = name.toLowerCase();
      
      // Check if user already exists
      const existing = await pool.query('SELECT id FROM users WHERE username = $1', [userLower]);
      
      if (existing.rows.length === 0) {
        // Hash password and insert
        const hash = await bcrypt.hash(pass, BCRYPT_ROUNDS);
        const roleId = i === 1 ? adminRoleId : agentRoleId; // USER1 is admin, others are agents
        
        await pool.query(
          'INSERT INTO users (username, password_hash, role_id) VALUES ($1, $2, $3)',
          [userLower, hash, roleId]
        );
        console.log(`Migrated user: ${userLower} (${i === 1 ? 'Admin' : 'Agent'})`);
      }
    }
  }
}

// Get user's permissions from their role
async function getUserPermissions(userId) {
  const result = await pool.query(`
    SELECT p.code
    FROM permissions p
    JOIN role_permissions rp ON p.id = rp.permission_id
    JOIN users u ON u.role_id = rp.role_id
    WHERE u.id = $1
  `, [userId]);
  
  return result.rows.map(r => r.code);
}

// Check if user has a specific permission
async function hasPermission(userId, permissionCode) {
  const permissions = await getUserPermissions(userId);
  return permissions.includes(permissionCode);
}

// Permission middleware factory
function requirePermission(permissionCode) {
  return async (req, res, next) => {
    if (!req.session || !req.session.userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const hasPerm = await hasPermission(req.session.userId, permissionCode);
    
    if (!hasPerm) {
      console.log(`[PERMISSION] Denied: ${req.session.user} tried to use ${permissionCode}`);
      return res.status(403).json({ 
        error: 'Permission denied', 
        required: permissionCode 
      });
    }
    
    next();
  };
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
    token: process.env.BC_1INK_ACCESS_TOKEN || process.env.BC_ACCESS_TOKEN
  },
  'needink': {
    name: 'needink.com',
    hash: process.env.BC_NEEDINK_STORE_HASH,
    token: process.env.BC_NEEDINK_ACCESS_TOKEN
  }
};

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

// Admin check middleware - requires admin.users.manage permission
async function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  
  const hasPerm = await hasPermission(req.session.userId, 'admin.users.manage');
  if (hasPerm) {
    return next();
  }
  
  return res.status(403).json({ error: 'Admin access required' });
}

// BigCommerce API helper
async function bcApiRequest(store, endpoint, method = 'GET') {
  const storeConfig = stores[store];
  if (!storeConfig || !storeConfig.hash || !storeConfig.token) {
    throw new Error('Store not configured');
  }

  const url = `https://api.bigcommerce.com/stores/${storeConfig.hash}/v2/${endpoint}`;

  const response = await fetch(url, {
    method,
    headers: {
      'X-Auth-Token': storeConfig.token,
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    if (response.status === 404) {
      const err = new Error('Not found');
      err.notFound = true;
      throw err;
    }
    const errorText = await response.text();
    throw new Error(`BC API Error: ${response.status} - ${errorText}`);
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
async function searchByName(store, query) {
  const searchTerm = (query || '').toLowerCase().trim();
  const nameParts = searchTerm.split(/\s+/).filter(Boolean);

  if (nameParts.length === 0) return [];

  if (nameParts.length === 1) {
    const like = `%${nameParts[0]}%`;
    const { rows } = await pool.query(
      `SELECT DISTINCT email FROM order_lookup
       WHERE store = $1
       AND (LOWER(first_name) LIKE $2 OR LOWER(last_name) LIKE $2)
       AND email IS NOT NULL AND email <> ''
       LIMIT 50`,
      [store, like]
    );
    return rows.map(r => r.email);
  }

  const first = `%${nameParts[0]}%`;
  const last = `%${nameParts[nameParts.length - 1]}%`;

  const { rows } = await pool.query(
    `SELECT DISTINCT email FROM order_lookup
     WHERE store = $1
     AND LOWER(first_name) LIKE $2
     AND LOWER(last_name) LIKE $3
     AND email IS NOT NULL AND email <> ''
     LIMIT 50`,
    [store, first, last]
  );

  return rows.map(r => r.email);
}

// Search local database for emails by phone
async function searchByPhone(store, query) {
  const digits = normalizePhone(query);

  if (digits.length < 7) return []; // Too short, would match too many

  const { rows } = await pool.query(
    `SELECT DISTINCT email FROM order_lookup
     WHERE store = $1
     AND phone LIKE $2
     AND email IS NOT NULL AND email <> ''
     LIMIT 50`,
    [store, `%${digits}%`]
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
    // Get user from database with role info
    const result = await pool.query(`
      SELECT u.id, u.username, u.password_hash, u.role_id, u.is_active, u.locked_until,
             r.name as role_name
      FROM users u
      LEFT JOIN roles r ON u.role_id = r.id
      WHERE u.username = $1
    `, [userLower]);
    
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
      // Update last login
      await pool.query(
        'UPDATE users SET last_login = NOW(), failed_attempts = 0, locked_until = NULL WHERE id = $1',
        [user.id]
      );
      
      // Get user permissions
      const permissions = await getUserPermissions(user.id);
      
      req.session.user = userLower;
      req.session.userId = user.id;
      req.session.roleId = user.role_id;
      req.session.roleName = user.role_name;
      req.session.permissions = permissions;
      
      await recordSuccessfulLogin(ip, userLower);
      console.log(`[${new Date().toISOString()}] Login success: ${userLower} (${user.role_name}) from ${ip}`);
      
      return res.json({ 
        success: true, 
        user: userLower, 
        role: user.role_name,
        permissions: permissions
      });
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
app.get('/api/auth-check', async (req, res) => {
  if (req.session && req.session.user) {
    // Set initial activity time on first check
    if (!req.session.lastActivity) {
      req.session.lastActivity = Date.now();
    }
    if (!req.session.loginTime) {
      req.session.loginTime = Date.now();
    }
    
    // Refresh permissions if not in session
    if (!req.session.permissions && req.session.userId) {
      req.session.permissions = await getUserPermissions(req.session.userId);
    }
    
    return res.json({ 
      authenticated: true, 
      user: req.session.user,
      role: req.session.roleName || 'Unknown',
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

// Get all roles
app.get('/api/admin/roles', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT r.id, r.name, r.description, r.is_system, r.created_at,
             COUNT(rp.permission_id) as permission_count
      FROM roles r
      LEFT JOIN role_permissions rp ON r.id = rp.role_id
      GROUP BY r.id
      ORDER BY r.id ASC
    `);
    res.json({ success: true, roles: result.rows });
  } catch (err) {
    console.error('Get roles error:', err.message);
    res.status(500).json({ error: 'Failed to get roles' });
  }
});

// Get all permissions
app.get('/api/admin/permissions', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, code, name, description, category, risk_level
      FROM permissions
      ORDER BY category, risk_level, name
    `);
    res.json({ success: true, permissions: result.rows });
  } catch (err) {
    console.error('Get permissions error:', err.message);
    res.status(500).json({ error: 'Failed to get permissions' });
  }
});

// Get role details with permissions
app.get('/api/admin/roles/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  
  try {
    const roleResult = await pool.query('SELECT * FROM roles WHERE id = $1', [id]);
    if (roleResult.rows.length === 0) {
      return res.status(404).json({ error: 'Role not found' });
    }
    
    const permissionsResult = await pool.query(`
      SELECT p.code
      FROM permissions p
      JOIN role_permissions rp ON p.id = rp.permission_id
      WHERE rp.role_id = $1
    `, [id]);
    
    res.json({
      success: true,
      role: roleResult.rows[0],
      permissions: permissionsResult.rows.map(r => r.code)
    });
  } catch (err) {
    console.error('Get role error:', err.message);
    res.status(500).json({ error: 'Failed to get role' });
  }
});

// Create new role
app.post('/api/admin/roles', requireAuth, requireAdmin, async (req, res) => {
  const { name, description, permissions } = req.body;
  
  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'Role name is required' });
  }
  
  try {
    // Check if role name exists
    const existing = await pool.query('SELECT id FROM roles WHERE name = $1', [name.trim()]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Role name already exists' });
    }
    
    // Create role
    const result = await pool.query(
      'INSERT INTO roles (name, description, is_system) VALUES ($1, $2, false) RETURNING id',
      [name.trim(), description || '']
    );
    const roleId = result.rows[0].id;
    
    // Assign permissions
    if (permissions && permissions.length > 0) {
      for (const permCode of permissions) {
        await pool.query(`
          INSERT INTO role_permissions (role_id, permission_id)
          SELECT $1, id FROM permissions WHERE code = $2
        `, [roleId, permCode]);
      }
    }
    
    console.log(`[ADMIN] Role created: ${name} by ${req.session.user}`);
    res.json({ success: true, roleId });
    
  } catch (err) {
    console.error('Create role error:', err.message);
    res.status(500).json({ error: 'Failed to create role' });
  }
});

// Update role
app.put('/api/admin/roles/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, description, permissions } = req.body;
  
  try {
    // Check if role exists
    const existing = await pool.query('SELECT * FROM roles WHERE id = $1', [id]);
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Role not found' });
    }
    
    // Don't allow editing system Admin role name
    if (existing.rows[0].is_system && existing.rows[0].name === 'Admin' && name !== 'Admin') {
      return res.status(400).json({ error: 'Cannot rename the Admin role' });
    }
    
    // Update role
    if (name || description !== undefined) {
      await pool.query(
        'UPDATE roles SET name = COALESCE($1, name), description = COALESCE($2, description) WHERE id = $3',
        [name?.trim(), description, id]
      );
    }
    
    // Update permissions if provided
    if (permissions !== undefined) {
      // Clear existing permissions
      await pool.query('DELETE FROM role_permissions WHERE role_id = $1', [id]);
      
      // Add new permissions
      for (const permCode of permissions) {
        await pool.query(`
          INSERT INTO role_permissions (role_id, permission_id)
          SELECT $1, id FROM permissions WHERE code = $2
        `, [id, permCode]);
      }
    }
    
    console.log(`[ADMIN] Role updated: ${name || existing.rows[0].name} by ${req.session.user}`);
    res.json({ success: true });
    
  } catch (err) {
    console.error('Update role error:', err.message);
    res.status(500).json({ error: 'Failed to update role' });
  }
});

// Delete role
app.delete('/api/admin/roles/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  
  try {
    // Check if role exists and is not system role
    const existing = await pool.query('SELECT * FROM roles WHERE id = $1', [id]);
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Role not found' });
    }
    
    if (existing.rows[0].is_system) {
      return res.status(400).json({ error: 'Cannot delete system roles' });
    }
    
    // Check if any users have this role
    const usersWithRole = await pool.query('SELECT COUNT(*) as count FROM users WHERE role_id = $1', [id]);
    if (parseInt(usersWithRole.rows[0].count) > 0) {
      return res.status(400).json({ error: 'Cannot delete role that is assigned to users' });
    }
    
    await pool.query('DELETE FROM roles WHERE id = $1', [id]);
    
    console.log(`[ADMIN] Role deleted: ${existing.rows[0].name} by ${req.session.user}`);
    res.json({ success: true });
    
  } catch (err) {
    console.error('Delete role error:', err.message);
    res.status(500).json({ error: 'Failed to delete role' });
  }
});

// Get all users (admin only)
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.username, u.role_id, r.name as role_name, 
             u.is_active, u.created_at, u.last_login, u.failed_attempts, u.locked_until
      FROM users u
      LEFT JOIN roles r ON u.role_id = r.id
      ORDER BY u.created_at ASC
    `);
    res.json({ success: true, users: result.rows });
  } catch (err) {
    console.error('Get users error:', err.message);
    res.status(500).json({ error: 'Failed to get users' });
  }
});

// Create new user (admin only)
app.post('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const { username, password, roleId } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  
  if (!roleId) {
    return res.status(400).json({ error: 'Role is required' });
  }
  
  const userLower = username.toLowerCase().trim();
  
  try {
    // Check if username exists
    const existing = await pool.query('SELECT id FROM users WHERE username = $1', [userLower]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    // Check if role exists
    const roleExists = await pool.query('SELECT id FROM roles WHERE id = $1', [roleId]);
    if (roleExists.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    
    // Hash password and create user
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const result = await pool.query(`
      INSERT INTO users (username, password_hash, role_id) 
      VALUES ($1, $2, $3) 
      RETURNING id, username, role_id, is_active, created_at
    `, [userLower, hash, roleId]);
    
    console.log(`[ADMIN] User created: ${userLower} by ${req.session.user}`);
    res.json({ success: true, user: result.rows[0] });
    
  } catch (err) {
    console.error('Create user error:', err.message);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// Update user (admin only)
app.put('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { username, password, roleId, isActive } = req.body;
  
  try {
    // Get current user
    const current = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    if (current.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const updates = [];
    const values = [];
    let paramCount = 1;
    
    if (username !== undefined) {
      const userLower = username.toLowerCase().trim();
      // Check if new username exists (for another user)
      const existing = await pool.query('SELECT id FROM users WHERE username = $1 AND id != $2', [userLower, id]);
      if (existing.rows.length > 0) {
        return res.status(400).json({ error: 'Username already exists' });
      }
      updates.push(`username = $${paramCount++}`);
      values.push(userLower);
    }
    
    if (password !== undefined && password.length > 0) {
      if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
      }
      const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
      updates.push(`password_hash = $${paramCount++}`);
      values.push(hash);
    }
    
    if (roleId !== undefined) {
      // Check if role exists
      const roleExists = await pool.query('SELECT id FROM roles WHERE id = $1', [roleId]);
      if (roleExists.rows.length === 0) {
        return res.status(400).json({ error: 'Invalid role' });
      }
      updates.push(`role_id = $${paramCount++}`);
      values.push(roleId);
    }
    
    if (isActive !== undefined) {
      updates.push(`is_active = $${paramCount++}`);
      values.push(isActive);
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: 'No updates provided' });
    }
    
    values.push(id);
    const result = await pool.query(`
      UPDATE users SET ${updates.join(', ')} WHERE id = $${paramCount} 
      RETURNING id, username, role_id, is_active, created_at, last_login, failed_attempts, locked_until
    `, values);
    
    console.log(`[ADMIN] User updated: ${result.rows[0].username} by ${req.session.user}`);
    res.json({ success: true, user: result.rows[0] });
    
  } catch (err) {
    console.error('Update user error:', err.message);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Delete user (admin only)
app.delete('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  
  try {
    // Prevent deleting yourself
    if (req.session.userId === parseInt(id)) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING username', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    console.log(`[ADMIN] User deleted: ${result.rows[0].username} by ${req.session.user}`);
    res.json({ success: true, message: 'User deleted' });
    
  } catch (err) {
    console.error('Delete user error:', err.message);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Unlock user account (admin only)
app.post('/api/admin/users/:id/unlock', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query(
      'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1 RETURNING username',
      [id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Also clear in-memory lockout
    loginAttempts.byUser.delete(result.rows[0].username);
    
    console.log(`[ADMIN] User unlocked: ${result.rows[0].username} by ${req.session.user}`);
    res.json({ success: true, message: 'User unlocked' });
    
  } catch (err) {
    console.error('Unlock user error:', err.message);
    res.status(500).json({ error: 'Failed to unlock user' });
  }
});

// Get login attempts (admin only)
app.get('/api/admin/login-attempts', requireAuth, requireAdmin, async (req, res) => {
  const { limit = 100 } = req.query;
  
  try {
    const result = await pool.query(`
      SELECT id, ip_address, username, success, attempted_at
      FROM login_attempts
      ORDER BY attempted_at DESC
      LIMIT $1
    `, [Math.min(parseInt(limit), 500)]);
    
    res.json({ success: true, attempts: result.rows });
    
  } catch (err) {
    console.error('Get login attempts error:', err.message);
    res.status(500).json({ error: 'Failed to get login attempts' });
  }
});

// Admin page route
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
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

  if (!stores[store]) {
    return res.status(400).json({ error: 'Invalid store' });
  }

  if (!query || query.trim().length < 2) {
    return res.status(400).json({ error: 'Search query too short' });
  }

  try {
    let orders = [];

    switch (searchType) {
      case 'order': {
        // Search by order number - direct
        try {
          const order = await bcApiRequest(store, `orders/${query.trim()}`);
          if (order && order.id) orders = [order];
        } catch (e) {
          if (e.notFound) return res.json({ success: true, orders: [] });
          throw e;
        }
        break;
      }

      case 'email': {
        // Search by email - direct to BigCommerce
        try {
          const result = await bcApiRequest(store, `orders?email=${encodeURIComponent(query)}&limit=50`);
          orders = Array.isArray(result) ? result : [];
        } catch (e) {
          if (e.notFound) return res.json({ success: true, orders: [] });
          throw e;
        }
        break;
      }

      case 'name': {
        // Search local database for emails, then fetch from BigCommerce
        const nameEmails = await searchByName(store, query);
        console.log(`Name search found ${nameEmails.length} emails:`, nameEmails.slice(0, 5));

        for (const email of nameEmails.slice(0, 10)) {
          try {
            const emailOrders = await bcApiRequest(
              store,
              `orders?email=${encodeURIComponent(email)}&limit=50`
            );
            if (Array.isArray(emailOrders)) {
              orders = orders.concat(emailOrders);
            }
          } catch (e) {
            // Skip
          }
        }

        // Deduplicate
        orders = orders.filter((o, i, arr) => arr.findIndex(x => x.id === o.id) === i);
        break;
      }

      case 'phone': {
        // Search local database for emails, then fetch from BigCommerce
        const phoneEmails = await searchByPhone(store, query);
        console.log(`Phone search found ${phoneEmails.length} emails:`, phoneEmails.slice(0, 5));

        for (const email of phoneEmails.slice(0, 10)) {
          try {
            const emailOrders = await bcApiRequest(
              store,
              `orders?email=${encodeURIComponent(email)}&limit=50`
            );
            if (Array.isArray(emailOrders)) {
              orders = orders.concat(emailOrders);
            }
          } catch (e) {
            // Skip
          }
        }

        // Deduplicate
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

    res.json({ success: true, orders: orders || [] });
  } catch (error) {
    console.error(`Search error: ${error.message}`);
    res.status(500).json({ error: 'Unable to complete search. Please try again.' });
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
      products,
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
