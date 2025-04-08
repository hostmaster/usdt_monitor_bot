# USDT Monitor Bot

A Telegram bot that monitors Ethereum addresses for incoming USDT (Tether) transactions and notifies users when they receive USDT.

> **AI-Assisted Development**: This project was developed using an AI code assistant through several iterations, with minimal human intervention. The AI assistant helped with code generation, architecture design, testing, and documentation, while human developers provided high-level guidance and reviewed the final implementation.

## Features

- Monitor multiple Ethereum addresses for incoming and outgoing USDT transactions
- Real-time notifications when USDT is received or sent
- Simple command interface via Telegram
- Persistent storage of user preferences and wallet addresses
- Dockerized deployment for easy setup
- Configurable notification settings
- Support for multiple users and addresses
- Robust transaction age filtering with boundary case handling
- Comprehensive test coverage with async support
- Detailed logging for debugging and monitoring

## Commands

- `/start` - Start interaction with the bot
- `/help` - Show available commands
- `/add <eth_address>` - Add an Ethereum address to monitor for incoming USDT
- `/list` - List all addresses you're currently monitoring
- `/remove <eth_address>` - Stop monitoring a specific address

## How It Works

The bot periodically checks the Etherscan API for new USDT transactions to the monitored addresses. When a new incoming transaction is detected, it sends a notification to all users tracking that address.

## Project Structure

```
usdt_monitor_bot/
├── main.py          # Main application entry point
├── config.py        # Configuration settings
├── database.py      # Database operations
├── etherscan.py     # Etherscan API integration
├── handlers.py      # Telegram bot command handlers
├── notifier.py      # Notification system
├── checker.py       # Transaction checking logic
└── __init__.py
```

## Requirements

- Python 3.11+
- Docker and Docker Compose (for containerized deployment)
- Telegram Bot Token (from [@BotFather](https://t.me/BotFather))
- Etherscan API Key (from [Etherscan](https://etherscan.io/apis))

## Dependencies

- aiogram >= 3.0.0
- aiohttp >= 3.8.0
- apscheduler >= 3.9.0
- python-dotenv >= 0.20.0

## Environment Variables

- `BOT_TOKEN` - Your Telegram bot token
- `ETHERSCAN_API_KEY` - Your Etherscan API key

## Local Development

1. Clone the repository
2. Create a `.env` file with your environment variables
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the bot:

   ```bash
   python -m usdt_monitor_bot.main
   ```

## Docker Deployment

See [DEPLOY.md](DEPLOY.md) for detailed deployment instructions using Docker.

## License

This project is licensed under the terms of the license included in the repository.

## Acknowledgements

- [Etherscan API](https://etherscan.io/apis) for blockchain data
- [Aiogram](https://docs.aiogram.dev/) for the Telegram bot framework
- [APScheduler](https://apscheduler.readthedocs.io/) for scheduling tasks
