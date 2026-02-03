require('dotenv').config();
const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.send('bc-order-search is running');
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});

