# USDT Monitor Bot

A Telegram bot that monitors Ethereum addresses for incoming USDT (Tether) transactions and notifies users when they receive USDT.

## Features

- Monitor multiple Ethereum addresses for incoming USDT transactions
- Real-time notifications when USDT is received
- Simple command interface via Telegram
- Persistent storage of user preferences and wallet addresses
- Dockerized deployment for easy setup

## Commands

- `/start` - Start interaction with the bot
- `/help` - Show available commands
- `/add_wallet <eth_address>` - Add an Ethereum address to monitor for incoming USDT
- `/list_wallets` - List all addresses you're currently monitoring
- `/remove_wallet <eth_address>` - Stop monitoring a specific address

## How It Works

The bot periodically checks the Etherscan API for new USDT transactions to the monitored addresses. When a new incoming transaction is detected, it sends a notification to all users tracking that address.

## Requirements

- Python 3.11+
- Docker and Docker Compose (for containerized deployment)
- Telegram Bot Token (from [@BotFather](https://t.me/BotFather))
- Etherscan API Key (from [Etherscan](https://etherscan.io/apis))

## Environment Variables

- `BOT_TOKEN` - Your Telegram bot token
- `ETHERSCAN_API_KEY` - Your Etherscan API key

## Local Development

1. Clone the repository
2. Create a `.env` file with your environment variables
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Run the bot:
   ```
   python usdt_monitor_bot.py
   ```

## Docker Deployment

See [DEPLOY.md](DEPLOY.md) for detailed deployment instructions using Docker.

## License

This project is licensed under the terms of the license included in the repository.

## Acknowledgements

- [Etherscan API](https://etherscan.io/apis) for blockchain data
- [Aiogram](https://docs.aiogram.dev/) for the Telegram bot framework
- [APScheduler](https://apscheduler.readthedocs.io/) for scheduling tasks