const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3001;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

app.use(helmet());
app.use(cors());
app.use(express.json());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5
});

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.userId = decoded.userId;
    next();
  });
};

app.post('/api/auth/register', authLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
  body('username').isLength({ min: 3, max: 50 }).matches(/^[a-zA-Z0-9_]+$/)
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password, username } = req.body;

  try {
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1 OR username = $2',
      [email, username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email or username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const verificationToken = Math.random().toString(36).substring(2, 15);

    const result = await pool.query(
      'INSERT INTO users (email, password_hash, username, verification_token) VALUES ($1, $2, $3, $4) RETURNING id, email, username, balance, created_at',
      [email, hashedPassword, username, verificationToken]
    );

    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        balance: parseFloat(user.balance),
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', authLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  try {
    const result = await pool.query(
      'SELECT id, email, username, password_hash, balance, created_at FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        balance: parseFloat(user.balance),
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/user/profile', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, username, balance, created_at FROM users WHERE id = $1',
      [req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    res.json({
      id: user.id,
      email: user.email,
      username: user.username,
      balance: parseFloat(user.balance),
      createdAt: user.created_at
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.get('/api/crypto/prices', async (req, res) => {
  try {
    const response = await axios.get(
      'https://api.coingecko.com/api/v3/coins/markets',
      {
        params: {
          vs_currency: 'usd',
          order: 'market_cap_desc',
          per_page: 100,
          page: 1,
          sparkline: false
        }
      }
    );

    const prices = response.data.map(coin => ({
      id: coin.id,
      symbol: coin.symbol.toUpperCase(),
      name: coin.name,
      currentPrice: coin.current_price,
      priceChange24h: coin.price_change_percentage_24h,
      marketCap: coin.market_cap,
      image: coin.image
    }));

    res.json(prices);
  } catch (error) {
    console.error('Crypto prices error:', error);
    res.status(500).json({ error: 'Failed to fetch crypto prices' });
  }
});

app.get('/api/crypto/:id/chart', async (req, res) => {
  const { id } = req.params;
  const { days = 7 } = req.query;

  try {
    const response = await axios.get(
      `https://api.coingecko.com/api/v3/coins/${id}/market_chart`,
      {
        params: {
          vs_currency: 'usd',
          days: days
        }
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error('Chart data error:', error);
    res.status(500).json({ error: 'Failed to fetch chart data' });
  }
});

app.post('/api/portfolio/buy', verifyToken, [
  body('cryptoId').notEmpty(),
  body('cryptoSymbol').notEmpty(),
  body('amount').isFloat({ gt: 0 }),
  body('price').isFloat({ gt: 0 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { cryptoId, cryptoSymbol, amount, price } = req.body;
  const totalCost = amount * price;

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const userResult = await client.query(
      'SELECT balance FROM users WHERE id = $1 FOR UPDATE',
      [req.userId]
    );

    if (userResult.rows.length === 0) {
      throw new Error('User not found');
    }

    const currentBalance = parseFloat(userResult.rows[0].balance);

    if (currentBalance < totalCost) {
      throw new Error('Insufficient balance');
    }

    await client.query(
      'UPDATE users SET balance = balance - $1 WHERE id = $2',
      [totalCost, req.userId]
    );

    const portfolioResult = await client.query(
      'SELECT amount, average_buy_price FROM portfolios WHERE user_id = $1 AND crypto_id = $2',
      [req.userId, cryptoId]
    );

    if (portfolioResult.rows.length > 0) {
      const existing = portfolioResult.rows[0];
      const existingAmount = parseFloat(existing.amount);
      const existingAvgPrice = parseFloat(existing.average_buy_price);
      
      const newTotalAmount = existingAmount + amount;
      const newAvgPrice = ((existingAmount * existingAvgPrice) + (amount * price)) / newTotalAmount;

      await client.query(
        'UPDATE portfolios SET amount = $1, average_buy_price = $2 WHERE user_id = $3 AND crypto_id = $4',
        [newTotalAmount, newAvgPrice, req.userId, cryptoId]
      );
    } else {
      await client.query(
        'INSERT INTO portfolios (user_id, crypto_id, crypto_symbol, amount, average_buy_price) VALUES ($1, $2, $3, $4, $5)',
        [req.userId, cryptoId, cryptoSymbol, amount, price]
      );
    }

    await client.query(
      'INSERT INTO transactions (user_id, transaction_type, crypto_id, crypto_symbol, amount, price_at_transaction, total_value) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [req.userId, 'BUY', cryptoId, cryptoSymbol, amount, price, totalCost]
    );

    await client.query('COMMIT');

    const updatedUser = await pool.query(
      'SELECT balance FROM users WHERE id = $1',
      [req.userId]
    );

    res.json({
      success: true,
      newBalance: parseFloat(updatedUser.rows[0].balance)
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Buy error:', error);
    res.status(400).json({ error: error.message || 'Purchase failed' });
  } finally {
    client.release();
  }
});

app.post('/api/portfolio/sell', verifyToken, [
  body('cryptoId').notEmpty(),
  body('cryptoSymbol').notEmpty(),
  body('amount').isFloat({ gt: 0 }),
  body('price').isFloat({ gt: 0 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { cryptoId, cryptoSymbol, amount, price } = req.body;
  const totalValue = amount * price;

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const portfolioResult = await client.query(
      'SELECT amount FROM portfolios WHERE user_id = $1 AND crypto_id = $2 FOR UPDATE',
      [req.userId, cryptoId]
    );

    if (portfolioResult.rows.length === 0) {
      throw new Error('You do not own this cryptocurrency');
    }

    const currentAmount = parseFloat(portfolioResult.rows[0].amount);

    if (currentAmount < amount) {
      throw new Error('Insufficient cryptocurrency balance');
    }

    const newAmount = currentAmount - amount;

    if (newAmount === 0) {
      await client.query(
        'DELETE FROM portfolios WHERE user_id = $1 AND crypto_id = $2',
        [req.userId, cryptoId]
      );
    } else {
      await client.query(
        'UPDATE portfolios SET amount = $1 WHERE user_id = $2 AND crypto_id = $3',
        [newAmount, req.userId, cryptoId]
      );
    }

    await client.query(
      'UPDATE users SET balance = balance + $1 WHERE id = $2',
      [totalValue, req.userId]
    );

    await client.query(
      'INSERT INTO transactions (user_id, transaction_type, crypto_id, crypto_symbol, amount, price_at_transaction, total_value) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [req.userId, 'SELL', cryptoId, cryptoSymbol, amount, price, totalValue]
    );

    await client.query('COMMIT');

    const updatedUser = await pool.query(
      'SELECT balance FROM users WHERE id = $1',
      [req.userId]
    );

    res.json({
      success: true,
      newBalance: parseFloat(updatedUser.rows[0].balance)
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Sell error:', error);
    res.status(400).json({ error: error.message || 'Sale failed' });
  } finally {
    client.release();
  }
});

app.get('/api/portfolio', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT crypto_id, crypto_symbol, amount, average_buy_price FROM portfolios WHERE user_id = $1',
      [req.userId]
    );

    const portfolio = result.rows.map(row => ({
      cryptoId: row.crypto_id,
      cryptoSymbol: row.crypto_symbol,
      amount: parseFloat(row.amount),
      averageBuyPrice: parseFloat(row.average_buy_price)
    }));

    res.json(portfolio);
  } catch (error) {
    console.error('Portfolio fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch portfolio' });
  }
});

app.get('/api/transactions', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT transaction_type, crypto_id, crypto_symbol, amount, price_at_transaction, total_value, created_at FROM transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
      [req.userId]
    );

    const transactions = result.rows.map(row => ({
      type: row.transaction_type,
      cryptoId: row.crypto_id,
      cryptoSymbol: row.crypto_symbol,
      amount: parseFloat(row.amount),
      price: row.price_at_transaction ? parseFloat(row.price_at_transaction) : null,
      totalValue: parseFloat(row.total_value),
      createdAt: row.created_at
    }));

    res.json(transactions);
  } catch (error) {
    console.error('Transactions fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

app.post('/api/transfer/send', verifyToken, [
  body('recipientUsername').notEmpty(),
  body('amount').isFloat({ gt: 0 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { recipientUsername, amount } = req.body;

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const recipientResult = await client.query(
      'SELECT id FROM users WHERE username = $1',
      [recipientUsername]
    );

    if (recipientResult.rows.length === 0) {
      throw new Error('Recipient not found');
    }

    const recipientId = recipientResult.rows[0].id;

    if (recipientId === req.userId) {
      throw new Error('Cannot send money to yourself');
    }

    const senderResult = await client.query(
      'SELECT balance FROM users WHERE id = $1 FOR UPDATE',
      [req.userId]
    );

    const senderBalance = parseFloat(senderResult.rows[0].balance);

    if (senderBalance < amount) {
      throw new Error('Insufficient balance');
    }

    await client.query(
      'UPDATE users SET balance = balance - $1 WHERE id = $2',
      [amount, req.userId]
    );

    await client.query(
      'UPDATE users SET balance = balance + $1 WHERE id = $2',
      [amount, recipientId]
    );

    await client.query(
      'INSERT INTO transfers (sender_id, recipient_id, amount) VALUES ($1, $2, $3)',
      [req.userId, recipientId, amount]
    );

    await client.query(
      'INSERT INTO transactions (user_id, transaction_type, amount, total_value, recipient_id) VALUES ($1, $2, $3, $4, $5)',
      [req.userId, 'SEND', amount, amount, recipientId]
    );

    await client.query(
      'INSERT INTO transactions (user_id, transaction_type, amount, total_value) VALUES ($1, $2, $3, $4)',
      [recipientId, 'RECEIVE', amount, amount]
    );

    await client.query('COMMIT');

    const updatedUser = await pool.query(
      'SELECT balance FROM users WHERE id = $1',
      [req.userId]
    );

    res.json({
      success: true,
      newBalance: parseFloat(updatedUser.rows[0].balance)
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Transfer error:', error);
    res.status(400).json({ error: error.message || 'Transfer failed' });
  } finally {
    client.release();
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});