# config.py
import logging
import os
import sys
from dataclasses import dataclass
from decimal import Decimal

from dotenv import load_dotenv

# Define a data directory inside the container's working directory
DATA_DIR = "data"
# Ensure the data directory exists
os.makedirs(DATA_DIR, exist_ok=True)


@dataclass(frozen=True)
class BotConfig:
    bot_token: str
    etherscan_api_key: str
    database_file: str = os.path.join(DATA_DIR, "users_usdt_monitor.db")
    etherscan_api_url: str = "https://api.etherscan.io/api"
    usdt_contract_address: str = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    usdt_decimals: int = 6
    check_interval_seconds: int = 30
    etherscan_request_delay: float = 1.1  # Delay between Etherscan API calls
    etherscan_timeout_seconds: int = 30

    # Derived constants
    USDT_DECIMAL_PLACES: Decimal = Decimal(10) ** usdt_decimals


def load_config() -> BotConfig:
    """Loads configuration from environment variables."""
    load_dotenv()  # Load .env file if present

    try:
        bot_token = os.environ["BOT_TOKEN"]
        etherscan_api_key = os.environ["ETHERSCAN_API_KEY"]
    except KeyError as e:
        logging.error(f"!!! Environment variable {e} not found!")
        sys.exit(f"Environment variable {e} not configured. Exiting.")

    # Optional overrides from environment
    check_interval = int(
        os.environ.get("CHECK_INTERVAL_SECONDS", BotConfig.check_interval_seconds)
    )
    request_delay = float(
        os.environ.get("ETHERSCAN_REQUEST_DELAY", BotConfig.etherscan_request_delay)
    )

    return BotConfig(
        bot_token=bot_token,
        etherscan_api_key=etherscan_api_key,
        check_interval_seconds=check_interval,
        etherscan_request_delay=request_delay,
        # Other fields use defaults from the dataclass definition
    )
