# config.py
import logging
import os
import sys
from typing import Optional

from dotenv import load_dotenv

from usdt_monitor_bot.token_config import TokenConfig, TokenRegistry

# Define a data directory inside the container's working directory
DATA_DIR = "/app/data" if os.path.exists("/app") else "data"
# Ensure the data directory exists
try:
    os.makedirs(DATA_DIR, exist_ok=True)
except OSError:
    # If we can't create the directory (e.g., in tests), use a temporary directory
    import tempfile

    DATA_DIR = tempfile.mkdtemp()


class BotConfig:
    """Configuration for the USDT Monitor Bot."""

    def __init__(
        self,
        telegram_bot_token: str,
        etherscan_api_key: str,
        db_path: str = os.path.join(DATA_DIR, "usdt_monitor.db"),
        etherscan_base_url: str = "https://api.etherscan.io/api",
        etherscan_request_delay: float = 0.2,
        check_interval_seconds: int = 60,
    ):
        # Telegram Bot Token
        self.telegram_bot_token = telegram_bot_token
        if not self.telegram_bot_token:
            raise ValueError("Telegram bot token is required")

        # Etherscan API Key
        self.etherscan_api_key = etherscan_api_key
        if not self.etherscan_api_key:
            raise ValueError("Etherscan API key is required")

        # Database Configuration
        self.db_path = db_path

        # Etherscan API Settings
        self.etherscan_base_url = etherscan_base_url
        self.etherscan_request_delay = etherscan_request_delay

        # Check interval settings
        self.check_interval_seconds = check_interval_seconds

        # Initialize token registry
        self.token_registry = TokenRegistry()

        # Register supported tokens
        self._register_tokens()

    def _register_tokens(self) -> None:
        """Register all supported tokens."""
        # USDT Configuration
        usdt_config = TokenConfig(
            name="Tether USD",
            contract_address="0xdAC17F958D2ee523a2206206994597C13D831ec7",
            decimals=6,  # Default USDT decimals
            symbol="USDT",
            display_name="USDT",
            explorer_url="https://etherscan.io/token/0xdAC17F958D2ee523a2206206994597C13D831ec7",
        )
        self.token_registry.register_token(usdt_config)

        # USDC Configuration
        usdc_config = TokenConfig(
            name="USD Coin",
            contract_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            decimals=6,  # Default USDC decimals
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

    # Required environment variables
    try:
        telegram_bot_token = os.environ["TELEGRAM_BOT_TOKEN"]
        etherscan_api_key = os.environ["ETHERSCAN_API_KEY"]
    except KeyError as e:
        logging.error(f"!!! Environment variable {e} not found!")
        sys.exit(f"Environment variable {e} not configured. Exiting.")

    # Optional environment variables with defaults
    db_path = os.getenv("DB_PATH", os.path.join(DATA_DIR, "usdt_monitor.db"))
    etherscan_base_url = os.getenv("ETHERSCAN_BASE_URL", "https://api.etherscan.io/api")
    etherscan_request_delay = float(os.getenv("ETHERSCAN_REQUEST_DELAY", "0.2"))
    check_interval_seconds = int(os.getenv("CHECK_INTERVAL_SECONDS", "60"))

    # Create and return config instance
    config = BotConfig(
        telegram_bot_token=telegram_bot_token,
        etherscan_api_key=etherscan_api_key,
        db_path=db_path,
        etherscan_base_url=etherscan_base_url,
        etherscan_request_delay=etherscan_request_delay,
        check_interval_seconds=check_interval_seconds,
    )

    # Override token configurations if specified in environment
    usdt_contract_address = os.getenv("USDT_CONTRACT_ADDRESS")
    usdt_decimals = os.getenv("USDT_DECIMALS")
    if usdt_contract_address or usdt_decimals:
        usdt_config = TokenConfig(
            name="Tether USD",
            contract_address=usdt_contract_address
            or "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            decimals=int(usdt_decimals) if usdt_decimals else 6,
            symbol="USDT",
            display_name="USDT",
            explorer_url=f"https://etherscan.io/token/{usdt_contract_address or '0xdAC17F958D2ee523a2206206994597C13D831ec7'}",
        )
        config.token_registry.register_token(usdt_config)

    usdc_contract_address = os.getenv("USDC_CONTRACT_ADDRESS")
    usdc_decimals = os.getenv("USDC_DECIMALS")
    if usdc_contract_address or usdc_decimals:
        usdc_config = TokenConfig(
            name="USD Coin",
            contract_address=usdc_contract_address
            or "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            decimals=int(usdc_decimals) if usdc_decimals else 6,
            symbol="USDC",
            display_name="USDC",
            explorer_url=f"https://etherscan.io/token/{usdc_contract_address or '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'}",
        )
        config.token_registry.register_token(usdc_config)

    return config
