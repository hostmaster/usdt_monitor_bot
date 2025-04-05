# config.py
import logging
import os
import sys
from typing import Optional

from dotenv import load_dotenv

from usdt_monitor_bot.token_config import TokenConfig, TokenRegistry

# Define a data directory inside the container's working directory
DATA_DIR = "data"
# Ensure the data directory exists
os.makedirs(DATA_DIR, exist_ok=True)


class BotConfig:
    """Configuration for the USDT Monitor Bot."""

    def __init__(self):
        # Telegram Bot Token
        self.telegram_bot_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
        if not self.telegram_bot_token:
            raise ValueError("TELEGRAM_BOT_TOKEN environment variable is required")

        # Etherscan API Key
        self.etherscan_api_key: str = os.getenv("ETHERSCAN_API_KEY", "")
        if not self.etherscan_api_key:
            raise ValueError("ETHERSCAN_API_KEY environment variable is required")

        # Database Configuration
        self.db_path: str = os.getenv("DB_PATH", "usdt_monitor.db")

        # Etherscan API Settings
        self.etherscan_base_url: str = os.getenv(
            "ETHERSCAN_BASE_URL", "https://api.etherscan.io/api"
        )
        self.etherscan_request_delay: float = float(
            os.getenv("ETHERSCAN_REQUEST_DELAY", "0.2")
        )  # Delay between requests in seconds

        # Initialize token registry
        self.token_registry = TokenRegistry()

        # Register supported tokens
        self._register_tokens()

    def _register_tokens(self) -> None:
        """Register all supported tokens."""
        # USDT Configuration
        usdt_config = TokenConfig(
            name="Tether USD",
            contract_address=os.getenv(
                "USDT_CONTRACT_ADDRESS",
                "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            ),
            decimals=6,
            symbol="USDT",
            display_name="USDT",
            explorer_url="https://etherscan.io/token/0xdAC17F958D2ee523a2206206994597C13D831ec7",
        )
        self.token_registry.register_token(usdt_config)

        # USDC Configuration
        usdc_config = TokenConfig(
            name="USD Coin",
            contract_address=os.getenv(
                "USDC_CONTRACT_ADDRESS",
                "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            ),
            decimals=6,
            symbol="USDC",
            display_name="USDC",
            explorer_url="https://etherscan.io/token/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        )
        self.token_registry.register_token(usdc_config)

    def get_token_config(self, symbol: str) -> Optional[TokenConfig]:
        """Get token configuration by symbol."""
        return self.token_registry.get_token(symbol)

    def get_token_by_address(self, address: str) -> Optional[TokenConfig]:
        """Get token configuration by contract address."""
        return self.token_registry.get_token_by_address(address)

    def is_supported_token(self, address: str) -> bool:
        """Check if a token address is supported."""
        return self.token_registry.is_supported_token(address)


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
