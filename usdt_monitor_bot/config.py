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
        etherscan_base_url: str = "https://api.etherscan.io/v2/api",
        etherscan_request_delay: float = 0.2,
        check_interval_seconds: int = 60,
        max_transaction_age_days: int = 7,  # Only report transactions from last 7 days
        max_transactions_per_check: int = 10,  # Only report last 10 transactions per check
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

        # Transaction window settings
        self.max_transaction_age_days = max_transaction_age_days
        self.max_transactions_per_check = max_transactions_per_check

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
    logging.info("--- Loading Configuration ---")

    # Required environment variables
    try:
        telegram_bot_token_env = os.environ["TELEGRAM_BOT_TOKEN"]
        logging.info("TELEGRAM_BOT_TOKEN: Loaded from environment.")
        telegram_bot_token = telegram_bot_token_env

        etherscan_api_key_env = os.environ["ETHERSCAN_API_KEY"]
        logging.info("ETHERSCAN_API_KEY: Loaded from environment.")
        etherscan_api_key = etherscan_api_key_env
    except KeyError as e:
        logging.error(f"!!! Environment variable {e} not found!")
        sys.exit(f"Environment variable {e} not configured. Exiting.")

    # Optional environment variables with defaults
    default_db_path = os.path.join(DATA_DIR, "usdt_monitor.db")
    db_path_env = os.getenv("DB_PATH")
    if db_path_env:
        db_path = db_path_env
        logging.info(f"DB_PATH: Loaded from environment variable ('{db_path}').")
    else:
        db_path = default_db_path
        logging.info(f"DB_PATH: Using default value ('{db_path}').")

    default_etherscan_base_url = "https://api.etherscan.io/v2/api"
    etherscan_base_url_env = os.getenv("ETHERSCAN_BASE_URL")
    if etherscan_base_url_env:
        etherscan_base_url = etherscan_base_url_env
        logging.info(f"ETHERSCAN_BASE_URL: Loaded from environment ('{etherscan_base_url}').")
    else:
        etherscan_base_url = default_etherscan_base_url
        logging.info(f"ETHERSCAN_BASE_URL: Using default value ('{etherscan_base_url}').")

    default_etherscan_request_delay = 0.2
    etherscan_request_delay_env = os.getenv("ETHERSCAN_REQUEST_DELAY")
    if etherscan_request_delay_env:
        try:
            etherscan_request_delay = float(etherscan_request_delay_env)
            logging.info(f"ETHERSCAN_REQUEST_DELAY: Loaded from environment (value: {etherscan_request_delay}).")
        except ValueError:
            etherscan_request_delay = default_etherscan_request_delay
            logging.warning(f"ETHERSCAN_REQUEST_DELAY: Invalid value '{etherscan_request_delay_env}' from environment. Using default value ({etherscan_request_delay}).")
    else:
        etherscan_request_delay = default_etherscan_request_delay
        logging.info(f"ETHERSCAN_REQUEST_DELAY: Using default value ({etherscan_request_delay}).")

    default_check_interval_seconds = 60
    check_interval_seconds_env = os.getenv("CHECK_INTERVAL_SECONDS")
    if check_interval_seconds_env:
        try:
            check_interval_seconds = int(check_interval_seconds_env)
            logging.info(f"CHECK_INTERVAL_SECONDS: Loaded from environment (value: {check_interval_seconds}).")
        except ValueError:
            check_interval_seconds = default_check_interval_seconds
            logging.warning(f"CHECK_INTERVAL_SECONDS: Invalid value '{check_interval_seconds_env}' from environment. Using default value ({check_interval_seconds}).")
    else:
        check_interval_seconds = default_check_interval_seconds
        logging.info(f"CHECK_INTERVAL_SECONDS: Using default value ({check_interval_seconds}).")

    default_max_transaction_age_days = 7
    max_transaction_age_days_env = os.getenv("MAX_TRANSACTION_AGE_DAYS")
    if max_transaction_age_days_env:
        try:
            max_transaction_age_days = int(max_transaction_age_days_env)
            logging.info(f"MAX_TRANSACTION_AGE_DAYS: Loaded from environment (value: {max_transaction_age_days}).")
        except ValueError:
            max_transaction_age_days = default_max_transaction_age_days
            logging.warning(f"MAX_TRANSACTION_AGE_DAYS: Invalid value '{max_transaction_age_days_env}' from environment. Using default value ({max_transaction_age_days}).")
    else:
        max_transaction_age_days = default_max_transaction_age_days
        logging.info(f"MAX_TRANSACTION_AGE_DAYS: Using default value ({max_transaction_age_days}).")

    default_max_transactions_per_check = 10
    max_transactions_per_check_env = os.getenv("MAX_TRANSACTIONS_PER_CHECK")
    if max_transactions_per_check_env:
        try:
            max_transactions_per_check = int(max_transactions_per_check_env)
            logging.info(f"MAX_TRANSACTIONS_PER_CHECK: Loaded from environment (value: {max_transactions_per_check}).")
        except ValueError:
            max_transactions_per_check = default_max_transactions_per_check
            logging.warning(f"MAX_TRANSACTIONS_PER_CHECK: Invalid value '{max_transactions_per_check_env}' from environment. Using default value ({max_transactions_per_check}).")
    else:
        max_transactions_per_check = default_max_transactions_per_check
        logging.info(f"MAX_TRANSACTIONS_PER_CHECK: Using default value ({max_transactions_per_check}).")

    logging.info("--- Token Configuration Overrides ---")
    # Create and return config instance
    config = BotConfig(
        telegram_bot_token=telegram_bot_token,
        etherscan_api_key=etherscan_api_key,
        db_path=db_path,
        etherscan_base_url=etherscan_base_url,
        etherscan_request_delay=etherscan_request_delay,
        check_interval_seconds=check_interval_seconds,
        max_transaction_age_days=max_transaction_age_days,
        max_transactions_per_check=max_transactions_per_check,
    )

    # Override token configurations if specified in environment
    usdt_contract_address_env = os.getenv("USDT_CONTRACT_ADDRESS")
    usdt_decimals_env = os.getenv("USDT_DECIMALS")
    default_usdt_contract = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    default_usdt_decimals = 6

    final_usdt_contract = default_usdt_contract
    source_usdt_contract = "default"
    if usdt_contract_address_env:
        final_usdt_contract = usdt_contract_address_env
        source_usdt_contract = "environment"
    logging.info(f"USDT_CONTRACT_ADDRESS: Using {source_usdt_contract} value ('{final_usdt_contract}').")

    final_usdt_decimals = default_usdt_decimals
    source_usdt_decimals = "default"
    if usdt_decimals_env:
        try:
            final_usdt_decimals = int(usdt_decimals_env)
            source_usdt_decimals = "environment"
        except ValueError:
            logging.warning(f"USDT_DECIMALS: Invalid value '{usdt_decimals_env}' from environment. Using default value ({final_usdt_decimals}).")
    logging.info(f"USDT_DECIMALS: Using {source_usdt_decimals} value ({final_usdt_decimals}).")

    if usdt_contract_address_env or usdt_decimals_env: # Only re-register if an override was attempted
        usdt_config = TokenConfig(
            name="Tether USD",
            contract_address=final_usdt_contract,
            decimals=final_usdt_decimals,
            symbol="USDT",
            display_name="USDT",
            explorer_url=f"https://etherscan.io/token/{final_usdt_contract}",
        )
        config.token_registry.register_token(usdt_config) # Overwrites the default one

    usdc_contract_address_env = os.getenv("USDC_CONTRACT_ADDRESS")
    usdc_decimals_env = os.getenv("USDC_DECIMALS")
    default_usdc_contract = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    default_usdc_decimals = 6

    final_usdc_contract = default_usdc_contract
    source_usdc_contract = "default"
    if usdc_contract_address_env:
        final_usdc_contract = usdc_contract_address_env
        source_usdc_contract = "environment"
    logging.info(f"USDC_CONTRACT_ADDRESS: Using {source_usdc_contract} value ('{final_usdc_contract}').")

    final_usdc_decimals = default_usdc_decimals
    source_usdc_decimals = "default"
    if usdc_decimals_env:
        try:
            final_usdc_decimals = int(usdc_decimals_env)
            source_usdc_decimals = "environment"
        except ValueError:
            logging.warning(f"USDC_DECIMALS: Invalid value '{usdc_decimals_env}' from environment. Using default value ({final_usdc_decimals}).")
    logging.info(f"USDC_DECIMALS: Using {source_usdc_decimals} value ({final_usdc_decimals}).")

    if usdc_contract_address_env or usdc_decimals_env: # Only re-register if an override was attempted
        usdc_config = TokenConfig(
            name="USD Coin",
            contract_address=final_usdc_contract,
            decimals=final_usdc_decimals,
            symbol="USDC",
            display_name="USDC",
            explorer_url=f"https://etherscan.io/token/{final_usdc_contract}",
        )
        config.token_registry.register_token(usdc_config) # Overwrites the default one

    logging.info("--- Configuration Loading Complete ---")
    return config
