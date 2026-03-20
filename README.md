# USDT Monitor Bot

A Telegram bot that monitors Ethereum addresses for incoming USDT (Tether) and USDC transactions, providing real-time notifications with advanced spam detection to protect users from address poisoning attacks and dust attacks.

> **AI-Assisted Development**: This project was developed using an AI code assistant through several iterations, with minimal human intervention. The AI assistant helped with code generation, architecture design, testing, and documentation, while human developers provided high-level guidance and reviewed the final implementation.

## Features

### Core Functionality
- **Multi-Address Monitoring** - Monitor multiple Ethereum addresses for USDT and USDC transactions
- **Real-Time Notifications** - Instant Telegram notifications when transactions are detected
- **Multi-User Support** - Multiple users can track the same or different addresses
- **Persistent Storage** - SQLite database for user preferences and transaction history

### Security & Protection
- **🛡️ Spam Detection** - Advanced protection against address poisoning and dust attacks
  - 7 distinct detection filters
  - Real-time risk scoring (0-100)
  - Historical transaction pattern analysis
  - Enhanced notifications with risk warnings
  - [View Documentation →](./docs/features/spam-detection/)

### Developer Experience
- **Simple Command Interface** - Easy-to-use Telegram commands
- **Configurable Settings** - Extensive environment variable configuration
- **Verbose Logging** - Optional debug logging via `VERBOSE` environment variable
- **Dockerized Deployment** - Easy containerized deployment
- **Comprehensive Testing** - Full test coverage with async support
- **Automatic Database Migration** - Seamless schema updates

📚 **[View All Features Documentation →](./docs/features/)**

## Commands

- `/start` - Start interaction with the bot
- `/help` - Show available commands
- `/add <eth_address>` - Add an Ethereum address to monitor for incoming USDT
- `/list` - List all addresses you're currently monitoring
- `/remove <eth_address>` - Stop monitoring a specific address

## How It Works

The bot periodically checks for new USDT/USDC transactions to the monitored addresses. Etherscan is the primary data source; if it is unavailable, the bot automatically fails over to Blockscout and then Moralis (if configured), so monitoring continues during API outages or quota exhaustion. Each transaction is analyzed by the spam detection system to identify suspicious patterns. When a new transaction is detected:

1. **Transaction Analysis** - The spam detection engine evaluates the transaction for risk factors
2. **Risk Scoring** - A risk score (0-100) is calculated based on multiple detection filters
3. **Notification** - Users receive notifications with transaction details and risk warnings (if suspicious)
4. **History Tracking** - Transactions are stored for pattern analysis and future detection improvements

## Project Structure

```
usdt_monitor_bot/
├── main.py                 # Main application entry point
├── config.py               # Configuration settings
├── database.py             # Database operations
├── blockchain_provider.py  # Provider protocol, circuit breaker, fallback chain
├── etherscan.py            # Etherscan API client (primary)
├── blockscout.py           # Blockscout API client (fallback 1)
├── moralis.py              # Moralis API client (fallback 2)
├── handlers.py             # Telegram bot command handlers
├── notifier.py             # Notification system
├── checker.py              # Transaction checking logic
├── spam_detector.py        # Spam detection and risk analysis
├── token_config.py         # Token configuration and registry
└── __init__.py
```

📚 **Documentation:**
- `docs/` - Complete documentation index
- `docs/features/` - Feature documentation
- `docs/guides/` - User guides and deployment
- `docs/debug/` - Spam detector debugging and quick reference
- `docs/examples/` - Code examples and usage scenarios

## Requirements

- Python 3.11+
- Docker and Docker Compose (for containerized deployment)
- Telegram Bot Token (from [@BotFather](https://t.me/BotFather))
- Etherscan API Key (from [Etherscan](https://etherscan.io/apis))
- Blockscout API Key (optional, from [Blockscout](https://blockscout.com)) — enables higher rate limits on the Blockscout fallback
- Moralis API Key (optional, from [Moralis](https://moralis.io)) — enables Moralis as a second fallback provider

## Dependencies

- aiogram >= 3.0.0
- aiohttp >= 3.8.0
- apscheduler >= 3.9.0
- python-dotenv >= 0.20.0

## Environment Variables

### Required

- `TELEGRAM_BOT_TOKEN` - Your Telegram bot token (from [@BotFather](https://t.me/BotFather))
- `ETHERSCAN_API_KEY` - Your Etherscan API key (from [Etherscan](https://etherscan.io/apis))

### Optional

- `VERBOSE` - Enable verbose/debug logging (`true`, `1`, `yes`, or `on`). Default: `false` (INFO level)
- `DB_PATH` - Custom database file path. Default: `data/usdt_monitor.db`
- `CHECK_INTERVAL_SECONDS` - Transaction check interval in seconds. Default: `60`
- `MAX_TRANSACTION_AGE_DAYS` - Maximum age of transactions to report. Default: `7`
- `MAX_TRANSACTIONS_PER_CHECK` - Maximum transactions to report per check cycle. Default: `10`
- `ETHERSCAN_REQUEST_DELAY` - Delay between Etherscan API requests (seconds). Default: `0.2`
- `ETHERSCAN_BASE_URL` - Custom Etherscan API base URL. Default: `https://api.etherscan.io/v2/api`

### Fallback Providers

- `BLOCKSCOUT_ENABLED` - Enable/disable Blockscout fallback. Default: `true`
- `BLOCKSCOUT_BASE_URL` - Custom Blockscout API base URL. Default: `https://eth.blockscout.com/api`
- `BLOCKSCOUT_API_KEY` - Blockscout API key for higher rate limits. Default: _(none)_
- `MORALIS_API_KEY` - Moralis API key; set to enable Moralis as a second fallback. Default: _(none)_
- `FALLBACK_FAILURE_THRESHOLD` - Consecutive provider failures before circuit opens. Default: `3`
- `FALLBACK_COOLDOWN_SECONDS` - Seconds before a tripped circuit is re-attempted. Default: `300`

## Local Development

1. Clone the repository
2. Create a `.env` file with your environment variables
3. Install dependencies:

   ```bash
   uv pip install .
   ```

4. Run the bot:

   ```bash
   python -m usdt_monitor_bot.main
   ```

## Docker Deployment

See [Deployment Guide](./docs/guides/DEPLOY.md) for detailed deployment instructions using Docker.

## License

This project is licensed under the terms of the license included in the repository.

## Acknowledgements

- [Etherscan API](https://etherscan.io/apis) for blockchain data (primary)
- [Blockscout API](https://blockscout.com) for blockchain data (fallback)
- [Moralis API](https://moralis.io) for blockchain data (fallback)
- [Aiogram](https://docs.aiogram.dev/) for the Telegram bot framework
- [APScheduler](https://apscheduler.readthedocs.io/) for scheduling tasks
