import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import './App.css';

const API_URL = process.env.REACT_APP_API_URL || '';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      api.get('/api/user/profile')
        .then(response => {
          setUser(response.data);
          setLoading(false);
        })
        .catch(() => {
          localStorage.removeItem('token');
          setLoading(false);
        });
    } else {
      setLoading(false);
    }
  }, []);

  const login = (token, userData) => {
    localStorage.setItem('token', token);
    setUser(userData);
  };

  const logout = () => {
    localStorage.removeItem('token');
    setUser(null);
  };

  if (loading) {
    return <div className="loading">Loading...</div>;
  }

  return (
    <Router>
      <div className="App">
        {user && <Navbar user={user} logout={logout} />}
        <Routes>
          <Route path="/login" element={!user ? <Login login={login} /> : <Navigate to="/dashboard" />} />
          <Route path="/register" element={!user ? <Register login={login} /> : <Navigate to="/dashboard" />} />
          <Route path="/dashboard" element={user ? <Dashboard user={user} setUser={setUser} /> : <Navigate to="/login" />} />
          <Route path="/" element={<Navigate to={user ? "/dashboard" : "/login"} />} />
        </Routes>
      </div>
    </Router>
  );
}

function Navbar({ user, logout }) {
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <nav className="navbar">
      <div className="nav-content">
        <div className="nav-brand">CryptoWallet</div>
        <div className="nav-user">
          <span className="username">{user.username}</span>
          <span className="balance">${user.balance.toFixed(2)}</span>
          <button onClick={handleLogout} className="btn-secondary">Logout</button>
        </div>
      </div>
    </nav>
  );
}

function Login({ login }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await api.post('/api/auth/login', { email, password });
      login(response.data.token, response.data.user);
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-box">
        <h1>Login to CryptoWallet</h1>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              placeholder="Enter your email"
            />
          </div>
          <div className="form-group">
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              placeholder="Enter your password"
            />
          </div>
          {error && <div className="error">{error}</div>}
          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
        <p className="auth-link">
          Don't have an account? <Link to="/register">Register here</Link>
        </p>
      </div>
    </div>
  );
}

function Register({ login }) {
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const validateEmail = (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  };

  const validatePassword = (password) => {
    return password.length >= 8 && /[a-z]/.test(password) && /[A-Z]/.test(password) && /\d/.test(password);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!validateEmail(email)) {
      setError('Please enter a valid email address');
      return;
    }

    if (!validatePassword(password)) {
      setError('Password must be at least 8 characters with uppercase, lowercase, and number');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (username.length < 3 || !/^[a-zA-Z0-9_]+$/.test(username)) {
      setError('Username must be at least 3 characters and contain only letters, numbers, and underscores');
      return;
    }

    setLoading(true);

    try {
      const response = await api.post('/api/auth/register', { email, username, password });
      login(response.data.token, response.data.user);
    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-box">
        <h1>Create Account</h1>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              placeholder="Enter your email"
            />
          </div>
          <div className="form-group">
            <label>Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              placeholder="Choose a username"
            />
          </div>
          <div className="form-group">
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              placeholder="Create a password"
            />
            <small>Must be 8+ characters with uppercase, lowercase, and number</small>
          </div>
          <div className="form-group">
            <label>Confirm Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              placeholder="Confirm your password"
            />
          </div>
          {error && <div className="error">{error}</div>}
          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Creating Account...' : 'Register'}
          </button>
        </form>
        <p className="auth-link">
          Already have an account? <Link to="/login">Login here</Link>
        </p>
      </div>
    </div>
  );
}

function Dashboard({ user, setUser }) {
  const [view, setView] = useState('market');
  const [cryptos, setCryptos] = useState([]);
  const [portfolio, setPortfolio] = useState([]);
  const [transactions, setTransactions] = useState([]);
  const [loading, setLoading] = useState(true);

  const refreshData = async () => {
    try {
      const [cryptoResponse, portfolioResponse, transactionResponse, userResponse] = await Promise.all([
        api.get('/api/crypto/prices'),
        api.get('/api/portfolio'),
        api.get('/api/transactions'),
        api.get('/api/user/profile')
      ]);

      setCryptos(cryptoResponse.data);
      setPortfolio(portfolioResponse.data);
      setTransactions(transactionResponse.data);
      setUser(userResponse.data);
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshData();
    const interval = setInterval(() => {
      api.get('/api/crypto/prices').then(response => setCryptos(response.data));
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <div className="loading">Loading market data...</div>;
  }

  return (
    <div className="dashboard">
      <div className="dashboard-tabs">
        <button 
          className={view === 'market' ? 'tab active' : 'tab'}
          onClick={() => setView('market')}
        >
          Market
        </button>
        <button 
          className={view === 'portfolio' ? 'tab active' : 'tab'}
          onClick={() => setView('portfolio')}
        >
          Portfolio
        </button>
        <button 
          className={view === 'transactions' ? 'tab active' : 'tab'}
          onClick={() => setView('transactions')}
        >
          Transactions
        </button>
        <button 
          className={view === 'transfer' ? 'tab active' : 'tab'}
          onClick={() => setView('transfer')}
        >
          Transfer
        </button>
      </div>

      {view === 'market' && <Market cryptos={cryptos} user={user} refreshData={refreshData} />}
      {view === 'portfolio' && <Portfolio portfolio={portfolio} cryptos={cryptos} user={user} refreshData={refreshData} />}
      {view === 'transactions' && <Transactions transactions={transactions} />}
      {view === 'transfer' && <Transfer user={user} refreshData={refreshData} />}
    </div>
  );
}

function Market({ cryptos, user, refreshData }) {
  const [selectedCrypto, setSelectedCrypto] = useState(null);
  const [showModal, setShowModal] = useState(false);

  const handleBuy = (crypto) => {
    setSelectedCrypto(crypto);
    setShowModal(true);
  };

  return (
    <div className="market-view">
      <h2>Cryptocurrency Market</h2>
      <div className="crypto-grid">
        {cryptos.map((crypto) => (
          <div key={crypto.id} className="crypto-card">
            <div className="crypto-header">
              <img src={crypto.image} alt={crypto.name} />
              <div>
                <h3>{crypto.name}</h3>
                <span className="symbol">{crypto.symbol}</span>
              </div>
            </div>
            <div className="crypto-price">
              <span className="price">${crypto.currentPrice.toLocaleString()}</span>
              <span className={crypto.priceChange24h >= 0 ? 'change positive' : 'change negative'}>
                {crypto.priceChange24h >= 0 ? '+' : ''}{crypto.priceChange24h.toFixed(2)}%
              </span>
            </div>
            <button className="btn-primary" onClick={() => handleBuy(crypto)}>
              Buy
            </button>
          </div>
        ))}
      </div>
      {showModal && (
        <BuySellModal 
          crypto={selectedCrypto} 
          type="buy"
          user={user}
          onClose={() => setShowModal(false)}
          refreshData={refreshData}
        />
      )}
    </div>
  );
}

function Portfolio({ portfolio, cryptos, user, refreshData }) {
  const [selectedCrypto, setSelectedCrypto] = useState(null);
  const [showModal, setShowModal] = useState(false);

  const portfolioWithPrices = portfolio.map(item => {
    const crypto = cryptos.find(c => c.id === item.cryptoId);
    const currentPrice = crypto?.currentPrice || 0;
    const currentValue = item.amount * currentPrice;
    const costBasis = item.amount * item.averageBuyPrice;
    const profitLoss = currentValue - costBasis;
    const profitLossPercent = (profitLoss / costBasis) * 100;

    return {
      ...item,
      crypto,
      currentPrice,
      currentValue,
      profitLoss,
      profitLossPercent
    };
  });

  const totalValue = portfolioWithPrices.reduce((sum, item) => sum + item.currentValue, 0);
  const totalProfitLoss = portfolioWithPrices.reduce((sum, item) => sum + item.profitLoss, 0);

  const handleSell = (item) => {
    setSelectedCrypto(item);
    setShowModal(true);
  };

  return (
    <div className="portfolio-view">
      <div className="portfolio-summary">
        <div className="summary-card">
          <h3>Total Portfolio Value</h3>
          <p className="value">${(totalValue + user.balance).toFixed(2)}</p>
        </div>
        <div className="summary-card">
          <h3>Cash Balance</h3>
          <p className="value">${user.balance.toFixed(2)}</p>
        </div>
        <div className="summary-card">
          <h3>Crypto Holdings</h3>
          <p className="value">${totalValue.toFixed(2)}</p>
        </div>
        <div className="summary-card">
          <h3>Total P&L</h3>
          <p className={totalProfitLoss >= 0 ? 'value positive' : 'value negative'}>
            ${totalProfitLoss.toFixed(2)}
          </p>
        </div>
      </div>

      <h2>Your Holdings</h2>
      {portfolioWithPrices.length === 0 ? (
        <p className="empty-state">You don't own any cryptocurrency yet. Start by buying from the Market tab.</p>
      ) : (
        <div className="portfolio-list">
          {portfolioWithPrices.map((item) => (
            <div key={item.cryptoId} className="portfolio-item">
              <div className="item-info">
                {item.crypto && <img src={item.crypto.image} alt={item.crypto.name} />}
                <div>
                  <h4>{item.crypto?.name || item.cryptoSymbol}</h4>
                  <span className="amount">{item.amount.toFixed(8)} {item.cryptoSymbol}</span>
                </div>
              </div>
              <div className="item-values">
                <div>
                  <small>Current Value</small>
                  <p>${item.currentValue.toFixed(2)}</p>
                </div>
                <div>
                  <small>Avg Buy Price</small>
                  <p>${item.averageBuyPrice.toFixed(2)}</p>
                </div>
                <div>
                  <small>P&L</small>
                  <p className={item.profitLoss >= 0 ? 'positive' : 'negative'}>
                    ${item.profitLoss.toFixed(2)} ({item.profitLossPercent.toFixed(2)}%)
                  </p>
                </div>
              </div>
              <button className="btn-secondary" onClick={() => handleSell(item)}>
                Sell
              </button>
            </div>
          ))}
        </div>
      )}
      {showModal && (
        <BuySellModal 
          crypto={selectedCrypto} 
          type="sell"
          user={user}
          onClose={() => setShowModal(false)}
          refreshData={refreshData}
        />
      )}
    </div>
  );
}

function BuySellModal({ crypto, type, user, onClose, refreshData }) {
  const [amount, setAmount] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [chartData, setChartData] = useState([]);

  useEffect(() => {
    const cryptoId = type === 'buy' ? crypto.id : crypto.cryptoId;
    api.get(`/api/crypto/${cryptoId}/chart?days=7`)
      .then(response => {
        const formatted = response.data.prices.map(([timestamp, price]) => ({
          date: new Date(timestamp).toLocaleDateString(),
          price: price
        }));
        setChartData(formatted);
      })
      .catch(err => console.error('Chart error:', err));
  }, [crypto, type]);

  const currentPrice = type === 'buy' ? crypto.currentPrice : crypto.currentPrice;
  const total = parseFloat(amount || 0) * currentPrice;
  const maxAmount = type === 'buy' 
    ? user.balance / currentPrice 
    : crypto.amount;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    const amountNum = parseFloat(amount);
    if (isNaN(amountNum) || amountNum <= 0) {
      setError('Please enter a valid amount');
      return;
    }

    if (type === 'buy' && total > user.balance) {
      setError('Insufficient balance');
      return;
    }

    if (type === 'sell' && amountNum > crypto.amount) {
      setError('Insufficient cryptocurrency balance');
      return;
    }

    setLoading(true);

    try {
      const endpoint = type === 'buy' ? '/api/portfolio/buy' : '/api/portfolio/sell';
      const payload = {
        cryptoId: type === 'buy' ? crypto.id : crypto.cryptoId,
        cryptoSymbol: type === 'buy' ? crypto.symbol : crypto.cryptoSymbol,
        amount: amountNum,
        price: currentPrice
      };

      await api.post(endpoint, payload);
      await refreshData();
      onClose();
    } catch (err) {
      setError(err.response?.data?.error || `${type} failed`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>{type === 'buy' ? 'Buy' : 'Sell'} {type === 'buy' ? crypto.name : crypto.crypto?.name}</h2>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>
        
        {chartData.length > 0 && (
          <div className="chart-container">
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip />
                <Line type="monotone" dataKey="price" stroke="#4f46e5" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="modal-content">
            <div className="price-info">
              <span>Current Price:</span>
              <span className="price">${currentPrice.toLocaleString()}</span>
            </div>
            
            <div className="form-group">
              <label>Amount ({type === 'buy' ? crypto.symbol : crypto.cryptoSymbol})</label>
              <input
                type="number"
                step="any"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                placeholder="0.00"
                required
              />
              <small>Max: {maxAmount.toFixed(8)}</small>
            </div>

            <div className="total-display">
              <span>Total:</span>
              <span className="total">${total.toFixed(2)}</span>
            </div>

            {type === 'buy' && (
              <div className="balance-display">
                <span>Available Balance:</span>
                <span>${user.balance.toFixed(2)}</span>
              </div>
            )}

            {error && <div className="error">{error}</div>}
          </div>

          <div className="modal-actions">
            <button type="button" className="btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? 'Processing...' : `${type === 'buy' ? 'Buy' : 'Sell'} ${type === 'buy' ? crypto.symbol : crypto.cryptoSymbol}`}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function Transactions({ transactions }) {
  return (
    <div className="transactions-view">
      <h2>Transaction History</h2>
      {transactions.length === 0 ? (
        <p className="empty-state">No transactions yet</p>
      ) : (
        <div className="transactions-list">
          {transactions.map((tx, index) => (
            <div key={index} className="transaction-item">
              <div className="tx-type">
                <span className={`badge ${tx.type.toLowerCase()}`}>{tx.type}</span>
                {tx.cryptoSymbol && <span className="symbol">{tx.cryptoSymbol}</span>}
              </div>
              <div className="tx-details">
                {tx.cryptoSymbol && <span>{tx.amount.toFixed(8)} {tx.cryptoSymbol}</span>}
                {tx.price && <span>@ ${tx.price.toFixed(2)}</span>}
              </div>
              <div className="tx-value">
                <span className={tx.type === 'BUY' || tx.type === 'SEND' ? 'negative' : 'positive'}>
                  {tx.type === 'BUY' || tx.type === 'SEND' ? '-' : '+'}${tx.totalValue.toFixed(2)}
                </span>
              </div>
              <div className="tx-date">
                {new Date(tx.createdAt).toLocaleString()}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Transfer({ user, refreshData }) {
  const [recipientUsername, setRecipientUsername] = useState('');
  const [amount, setAmount] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    const amountNum = parseFloat(amount);
    if (isNaN(amountNum) || amountNum <= 0) {
      setError('Please enter a valid amount');
      return;
    }

    if (amountNum > user.balance) {
      setError('Insufficient balance');
      return;
    }

    setLoading(true);

    try {
      await api.post('/api/transfer/send', {
        recipientUsername,
        amount: amountNum
      });
      
      setSuccess(`Successfully sent $${amountNum.toFixed(2)} to ${recipientUsername}`);
      setRecipientUsername('');
      setAmount('');
      await refreshData();
    } catch (err) {
      setError(err.response?.data?.error || 'Transfer failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="transfer-view">
      <h2>Send Money</h2>
      <div className="transfer-container">
        <form onSubmit={handleSubmit} className="transfer-form">
          <div className="form-group">
            <label>Recipient Username</label>
            <input
              type="text"
              value={recipientUsername}
              onChange={(e) => setRecipientUsername(e.target.value)}
              placeholder="Enter username"
              required
            />
          </div>

          <div className="form-group">
            <label>Amount (USD)</label>
            <input
              type="number"
              step="0.01"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              placeholder="0.00"
              required
            />
            <small>Available: ${user.balance.toFixed(2)}</small>
          </div>

          {error && <div className="error">{error}</div>}
          {success && <div className="success">{success}</div>}

          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Sending...' : 'Send Money'}
          </button>
        </form>
      </div>
    </div>
  );
}

export default App;