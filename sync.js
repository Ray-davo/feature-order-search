// sync.js - Run this to populate/update the database
// Usage: 
//   node sync.js              - Incremental sync (new orders only)
//   node sync.js --full       - Full sync (limited by ORDER_INDEX_YEARS)
//   node sync.js 1ink         - Sync just 1ink store
//   node sync.js 1ink --full  - Full sync just 1ink store

require('dotenv').config();
const fetch = require('node-fetch');
const { Pool } = require('pg');

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
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

// Initialize database tables
async function initDatabase() {
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
  
  console.log('Database initialized');
}

// Normalize phone number
function normalizePhone(phone) {
  if (!phone) return '';
  return phone.replace(/\D/g, '');
}

// BigCommerce API helper
async function bcApiRequest(store, endpoint) {
  const storeConfig = stores[store];
  const url = `https://api.bigcommerce.com/stores/${storeConfig.hash}/v2/${endpoint}`;
  
  const response = await fetch(url, {
    headers: {
      'X-Auth-Token': storeConfig.token,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    }
  });
  
  if (!response.ok) {
    throw new Error(`BC API Error: ${response.status}`);
  }
  
  return response.json();
}

// Sync orders
async function syncOrders(store, fullSync = false) {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`SYNCING: ${stores[store].name}`);
  console.log(`Mode: ${fullSync ? 'FULL SYNC' : 'INCREMENTAL'}`);
  console.log('='.repeat(60));
  
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
      
      console.log(`Incremental sync from ${effective.toISOString()}\n`);
    } else {
      console.log(`No existing orders - doing full sync from cutoff ${cutoff.toISOString()}\n`);
    }
  } else {
    console.log(`Full sync limited to cutoff ${cutoff.toISOString()}\n`);
  }
  
  const startTime = Date.now();
  
  while (hasMore) {
    try {
      process.stdout.write(`Page ${page}... `);
      
      const orders = await bcApiRequest(store, `orders?limit=250&page=${page}&sort=date_created:desc${minDateFilter}`);
      
      if (!Array.isArray(orders) || orders.length === 0) {
        console.log('no more orders');
        hasMore = false;
        break;
      }
      
      // Insert orders
      for (const order of orders) {
        try {
          const billing = order.billing_address || {};
          const email = (billing.email || '').toLowerCase();
          const firstName = (billing.first_name || '').toLowerCase();
          const lastName = (billing.last_name || '').toLowerCase();
          const phone = normalizePhone(billing.phone);
          
          // Only insert if we have at least email or name or phone
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
      
      console.log(`${orders.length} orders (total: ${totalSynced})`);
      
      if (orders.length < 250) {
        hasMore = false;
      } else {
        page++;
        await new Promise(resolve => setTimeout(resolve, 250));
      }
      
    } catch (error) {
      console.error(`\nError: ${error.message}`);
      hasMore = false;
    }
  }
  
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  
  console.log(`\nComplete: ${totalSynced} orders in ${elapsed}s`);
  
  // Show final count
  const countResult = await pool.query(`SELECT COUNT(*) FROM order_lookup WHERE store = $1`, [store]);
  console.log(`Total in database for ${store}: ${countResult.rows[0]?.count || 0}`);
  
  return totalSynced;
}

// Main
async function main() {
  const args = process.argv.slice(2);
  const fullSync = args.includes('--full');
  const storeArg = args.find(a => !a.startsWith('--'));
  
  console.log('\n' + '='.repeat(60));
  console.log('BigCommerce Order Search - Database Sync');
  console.log('='.repeat(60));
  
  // Check for DATABASE_URL
  if (!process.env.DATABASE_URL) {
    console.error('\nError: DATABASE_URL not set!');
    console.error('Set DATABASE_URL in your .env file to your PostgreSQL connection string');
    process.exit(1);
  }
  
  // Initialize database
  await initDatabase();
  
  // Check configuration
  const configuredStores = Object.keys(stores).filter(s => stores[s].hash && stores[s].token);
  
  if (configuredStores.length === 0) {
    console.error('\nError: No stores configured!');
    console.error('Please check your .env file has BC_1INK_STORE_HASH and BC_1INK_ACCESS_TOKEN');
    process.exit(1);
  }
  
  console.log(`\nConfigured stores: ${configuredStores.join(', ')}`);
  console.log(`Order index years: ${process.env.ORDER_INDEX_YEARS || '3'}`);
  
  // Show current stats
  console.log('\nCurrent database:');
  for (const store of configuredStores) {
    const countResult = await pool.query(`SELECT COUNT(*) FROM order_lookup WHERE store = $1`, [store]);
    const oldestResult = await pool.query(`SELECT MIN(order_date) FROM order_lookup WHERE store = $1`, [store]);
    const newestResult = await pool.query(`SELECT MAX(order_date) FROM order_lookup WHERE store = $1`, [store]);
    
    const count = countResult.rows[0]?.count || 0;
    const oldest = oldestResult.rows[0]?.min;
    const newest = newestResult.rows[0]?.max;
    
    console.log(`  ${store}: ${count} orders (${oldest || 'empty'} to ${newest || 'empty'})`);
  }
  
  // Determine which stores to sync
  let storesToSync;
  if (storeArg && stores[storeArg]) {
    storesToSync = [storeArg];
  } else if (storeArg) {
    console.error(`\nUnknown store: ${storeArg}`);
    console.error(`Available stores: ${configuredStores.join(', ')}`);
    process.exit(1);
  } else {
    storesToSync = configuredStores;
  }
  
  // Run sync
  for (const store of storesToSync) {
    await syncOrders(store, fullSync);
  }
  
  console.log('\n' + '='.repeat(60));
  console.log('Sync complete!');
  console.log('='.repeat(60) + '\n');
  
  await pool.end();
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
