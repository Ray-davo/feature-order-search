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

  // Clean up old login attempts (older than 24 hours)
  await pool.query(`DELETE FROM login_attempts WHERE attempted_at < NOW() - INTERVAL '24 hours'`);

  // Migrate users from environment variables to database (one-time)
  await migrateEnvUsers();

  console.log('Postgres initialized');
}

// Migrate users from env vars to database (runs once)
async function migrateEnvUsers() {
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
        const isAdmin = i === 1; // USER1 is admin
        
        await pool.query(
          'INSERT INTO users (username, password_hash, is_admin) VALUES ($1, $2, $3)',
          [userLower, hash, isAdmin]
        );
        console.log(`Migrated user: ${userLower}${isAdmin ? ' (admin)' : ''}`);
      }
    }
  }
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

// Admin check middleware
function requireAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.isAdmin) {
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
      // Update last login
      await pool.query(
        'UPDATE users SET last_login = NOW(), failed_attempts = 0, locked_until = NULL WHERE id = $1',
        [user.id]
      );
      
      req.session.user = userLower;
      req.session.isAdmin = user.is_admin;
      req.session.userId = user.id;
      
      await recordSuccessfulLogin(ip, userLower);
      console.log(`[${new Date().toISOString()}] Login success: ${userLower} from ${ip}`);
      return res.json({ success: true, user: userLower, isAdmin: user.is_admin });
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
    // Set initial activity time on first check
    if (!req.session.lastActivity) {
      req.session.lastActivity = Date.now();
    }
    if (!req.session.loginTime) {
      req.session.loginTime = Date.now();
    }
    
    return res.json({ 
      authenticated: true, 
      user: req.session.user, 
      isAdmin: req.session.isAdmin || false 
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

// Get all users (admin only)
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, username, is_admin, is_active, created_at, last_login, failed_attempts, locked_until
      FROM users
      ORDER BY created_at ASC
    `);
    res.json({ success: true, users: result.rows });
  } catch (err) {
    console.error('Get users error:', err.message);
    res.status(500).json({ error: 'Failed to get users' });
  }
});

// Create new user (admin only)
app.post('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const { username, password, isAdmin } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  
  const userLower = username.toLowerCase().trim();
  
  try {
    // Check if username exists
    const existing = await pool.query('SELECT id FROM users WHERE username = $1', [userLower]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    // Hash password and create user
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const result = await pool.query(
      'INSERT INTO users (username, password_hash, is_admin) VALUES ($1, $2, $3) RETURNING id, username, is_admin, is_active, created_at',
      [userLower, hash, isAdmin || false]
    );
    
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
  const { username, password, isAdmin, isActive } = req.body;
  
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
    
    if (isAdmin !== undefined) {
      updates.push(`is_admin = $${paramCount++}`);
      values.push(isAdmin);
    }
    
    if (isActive !== undefined) {
      updates.push(`is_active = $${paramCount++}`);
      values.push(isActive);
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: 'No updates provided' });
    }
    
    values.push(id);
    const result = await pool.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramCount} 
       RETURNING id, username, is_admin, is_active, created_at, last_login, failed_attempts, locked_until`,
      values
    );
    
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
      case 'order':
        // Search by order number - direct
        const order = await bcApiRequest(store, `orders/${query.trim()}`);
        if (order && order.id) orders = [order];
        break;

      case 'email':
        // Search by email - direct to BigCommerce
        orders = await bcApiRequest(store, `orders?email=${encodeURIComponent(query)}&limit=50`);
        break;

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
    res.status(500).json({ error: 'Search failed.' });
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
  console.log(`Users configured: ${Object.keys(users).length}`);
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
