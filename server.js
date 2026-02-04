require('dotenv').config();
const express = require('express');
const session = require('express-session');
const fetch = require('node-fetch');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

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
  `);

  console.log('Postgres initialized');
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      maxAge: 8 * 60 * 60 * 1000 // 8 hours
    }
  })
);

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

// Users (from environment variables) - supports USER1 through USER10
const users = {};
for (let i = 1; i <= 10; i++) {
  const name = process.env[`USER${i}_NAME`];
  const pass = process.env[`USER${i}_PASS`];
  if (name && pass) {
    users[name.toLowerCase()] = pass;
  }
}

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

// Admin check middleware
function requireAdmin(req, res, next) {
  const adminUser = process.env.USER1_NAME?.toLowerCase();
  if (req.session && req.session.user && req.session.user === adminUser) {
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

// Login API
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const userLower = (username || '').toLowerCase();

  if (users[userLower] && users[userLower] === password) {
    req.session.user = userLower;
    console.log(`[${new Date().toISOString()}] Login success: ${userLower}`);
    return res.json({ success: true, user: userLower });
  }

  console.log(`[${new Date().toISOString()}] Login failed: ${username}`);
  res.status(401).json({ error: 'Invalid credentials' });
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
    const isAdmin = req.session.user === process.env.USER1_NAME?.toLowerCase();
    return res.json({ authenticated: true, user: req.session.user, isAdmin });
  }
  res.json({ authenticated: false });
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
        : []
    });
  } catch (error) {
    console.error(`Order fetch error: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch order details.' });
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
