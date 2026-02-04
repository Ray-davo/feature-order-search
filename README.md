# BigCommerce Order Search (v2 - PostgreSQL)

Staff order lookup tool with fast name/phone search using Render's PostgreSQL database.

## How It Works

**Order # and Email searches** → Direct to BigCommerce API (instant)

**Name and Phone searches** → PostgreSQL lookup to find email → Then BigCommerce API for full details

The database stores only: `order_id, email, name, phone, date` - no sensitive data.

## Setup on Render

### 1. Create PostgreSQL Database on Render
1. Go to Render Dashboard → New → PostgreSQL
2. Name it (e.g., "order-search-db")
3. Choose Free tier
4. Click Create
5. Copy the **Internal Database URL** (starts with `postgresql://`)

### 2. Create Web Service on Render
1. Push this code to GitHub
2. Render Dashboard → New → Web Service
3. Connect your GitHub repo
4. Settings:
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
5. Add Environment Variables:
   - `DATABASE_URL` = (paste Internal Database URL from step 1)
   - `SESSION_SECRET` = (random string)
   - `USER1_NAME` = admin
   - `USER1_PASS` = your-password
   - `BC_1INK_STORE_HASH` = your-hash
   - `BC_1INK_ACCESS_TOKEN` = your-token
   - `ORDER_INDEX_YEARS` = 3 (optional, default is 3)
   - (add more as needed)
6. Deploy

### 3. Initial Sync
After deploying, run the sync from Render Shell:
1. Go to your Web Service → Shell
2. Run: `node sync.js --full`
3. Wait for it to complete

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `SESSION_SECRET` | Yes | Random string for session security |
| `USER1_NAME` | Yes | Admin username |
| `USER1_PASS` | Yes | Admin password |
| `BC_1INK_STORE_HASH` | Yes | 1ink BigCommerce store hash |
| `BC_1INK_ACCESS_TOKEN` | Yes | 1ink BigCommerce API token |
| `BC_NEEDINK_STORE_HASH` | No | needink BigCommerce store hash |
| `BC_NEEDINK_ACCESS_TOKEN` | No | needink BigCommerce API token |
| `ORDER_INDEX_YEARS` | No | How many years of orders to index (default: 3) |

## Keeping Data Fresh

The app auto-syncs new orders every 30 minutes while running.

Manual sync (new orders only):
```bash
npm run sync
```

Full re-sync (respects ORDER_INDEX_YEARS limit):
```bash
npm run sync:full
```

## Security

- Login required
- Read-only (no editing orders)
- Database only has contact info, no payment data
- All searches logged
- No bulk export feature
