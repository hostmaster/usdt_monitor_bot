# Deployment Guide

This guide provides detailed instructions for deploying the USDT Monitor Bot using Docker.

## Prerequisites

- Docker and Docker Compose installed on your system
- A Telegram Bot Token (from [@BotFather](https://t.me/BotFather))
- An Etherscan API Key (from [Etherscan](https://etherscan.io/apis))

## Environment Setup

1. Create a `.env` file in the project root with the following content:

```sh
# .env
# Replace with your actual tokens
BOT_TOKEN=your_telegram_bot_token_here
ETHERSCAN_API_KEY=your_etherscan_api_key_here
```

Replace the placeholder values with your actual API keys.

## Docker Deployment

### Option 1: Using Docker Compose (Recommended)

1. Build and start the container:

```bash
docker compose up -d
```

This will:

- Build the Docker image using the Dockerfile
- Create a container named `usdt_monitor_bot`
- Start the bot in the background
- Mount the data volume to persist the database

2. Check the logs to ensure the bot is running correctly:

```bash
docker compose logs -f
```

3. To stop the bot:

```bash
docker compose down
```

### Option 2: Manual Docker Deployment

1. Build the Docker image:

```bash
docker build -t usdt-monitor-bot .
```

2. Run the container:

```bash
docker run -d \
  --name usdt_monitor_bot \
  --restart unless-stopped \
  --env-file .env \
  -v usdt_monitor_bot_data:/app/data \
  usdt-monitor-bot
```

3. Check the logs:

```bash
docker logs -f usdt_monitor_bot
```

4. To stop the container:

```bash
docker stop usdt_monitor_bot
docker rm usdt_monitor_bot
```

## Updating the Bot

To update the bot to a new version:

1. Pull the latest code changes
2. Rebuild the Docker image:

```bash
docker compose build
```

3. Restart the container:

```bash
docker compose down
docker compose up -d
```

## Troubleshooting

### Database Issues

If you encounter database-related issues, you can reset the database by removing the volume:

```bash
docker compose down -v
```

Then restart the container. A new database will be created automatically.

### API Rate Limits

The Etherscan API has rate limits. If you're monitoring many addresses, you might hit these limits. The bot includes a delay between API calls to avoid this, but you may need to adjust the `ETHERSCAN_REQUEST_DELAY` variable in the code if you're still experiencing issues.

### Container Logs

To view the container logs:

```bash
docker compose logs -f
```

This will show you any errors or issues that might be occurring.

## Security Considerations

- The bot runs as a non-root user (`appuser`) inside the container for security
- API keys are stored in environment variables and not hardcoded
- The database is stored in a Docker volume that persists between container restarts
- Consider using Docker secrets or a secure environment variable management solution for production deployments

## Production Deployment

For production deployments, consider:

1. Setting up monitoring and alerting for the bot's health and performance
2. Implementing backup strategies for the database
3. Using a container orchestration system like Kubernetes for high availability
4. Configuring proper logging and log rotation
5. Setting up proper error monitoring and alerting
