# CryptoWallet - Paper Trading Platform


A full-stack cryptocurrency paper trading platform that lets users practice trading with fake money. Features real-time crypto prices, portfolio tracking, and peer-to-peer transfers.

## Features:

- User authentication with email/password validation
- $10,000 starting balance per user
- Real-time cryptocurrency prices via CoinGecko API
- Buy/sell any of the top 100 cryptocurrencies
- Interactive price charts
- Portfolio tracking with profit/loss calculations
- Peer-to-peer money transfers between users
- Complete transaction history
- Persistent user accounts stored in PostgreSQL
- Production-ready backend with JWT authentication

## Tech Stack
### Backend:
- Node.js + Express
- PostgreSQL database
- JWT authentication
- bcrypt password hashing
- Rate limiting and security headers

### Frontend:
- React 18
- React Router for navigation
- Recharts for price visualization
- Axios for API calls

### Infrastructure:
- Docker + Docker Compose
- Nginx reverse proxy
- Multi-stage builds for optimization
