"""
Configuration module.

Handles loading and managing bot configuration from environment variables
and provides default values.
"""

# Standard library
import logging
import os
import sys
from typing import Optional

# Third-party
from dotenv import load_dotenv

# Local
from usdt_monitor_bot.token_config import TokenConfig, TokenRegistry

# Required environment variables
REQUIRED_ENV_VARS = ("TELEGRAM_BOT_TOKEN", "ETHERSCAN_API_KEY")

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
        etherscan_request_delay: float = 0.5,  # Increased default to stay under 3 req/sec limit
        rate_limiter_min_delay: float = 0.4,  # Minimum delay to stay under 3 req/sec limit
        rate_limiter_max_delay: float = 10.0,  # Maximum delay for aggressive backoff
        rate_limiter_backoff_factor: float = 2.5,  # Multiplier when rate limit is hit
        rate_limiter_recovery_factor: float = 0.95,  # Multiplier when request succeeds
        rate_limiter_success_threshold: int = 20,  # Consecutive successes before reducing delay
        rate_limiter_recovery_cooldown: float = 30.0,  # Seconds to wait after rate limit before reducing
        check_interval_seconds: int = 60,
        max_transaction_age_days: int = 7,  # Only report transactions from last 7 days
        max_transactions_per_check: int = 10,  # Only report last 10 transactions per check
        verbose_logging: bool = False,  # Enable DEBUG level logging
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

        # Rate limiter settings
        self.rate_limiter_min_delay = rate_limiter_min_delay
        self.rate_limiter_max_delay = rate_limiter_max_delay
        self.rate_limiter_backoff_factor = rate_limiter_backoff_factor
        self.rate_limiter_recovery_factor = rate_limiter_recovery_factor
        self.rate_limiter_success_threshold = rate_limiter_success_threshold
        self.rate_limiter_recovery_cooldown = rate_limiter_recovery_cooldown

        # Check interval settings
        self.check_interval_seconds = check_interval_seconds

        # Transaction window settings
        self.max_transaction_age_days = max_transaction_age_days
        self.max_transactions_per_check = max_transactions_per_check

        # Logging settings
        self.verbose_logging = verbose_logging

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


def _get_env_float(name: str, default: float) -> float:
    """Get float from environment with validation."""
    value = os.getenv(name)
    if not value:
        return default
    try:
        result = float(value)
        logging.debug(f"{name}={result} (env)")
        return result
    except ValueError:
        logging.warning(f"Invalid {name}='{value}', using default={default}")
        return default


def _get_env_int(name: str, default: int) -> int:
    """Get int from environment with validation."""
    value = os.getenv(name)
    if not value:
        return default
    try:
        result = int(value)
        logging.debug(f"{name}={result} (env)")
        return result
    except ValueError:
        logging.warning(f"Invalid {name}='{value}', using default={default}")
        return default


def check_required_env_vars() -> bool:
    """Check if all required environment variables are set."""
    return all(os.getenv(var) for var in REQUIRED_ENV_VARS)


def load_config() -> BotConfig:
    """Loads configuration from environment variables."""
    load_dotenv()  # Load .env file if present

    # Required environment variables
    try:
        telegram_bot_token = os.environ["TELEGRAM_BOT_TOKEN"]
        etherscan_api_key = os.environ["ETHERSCAN_API_KEY"]
    except KeyError as e:
        logging.error(f"Missing required env var: {e}")
        sys.exit(f"Environment variable {e} not configured. Exiting.")

    # Optional environment variables with defaults
    db_path = os.getenv("DB_PATH", os.path.join(DATA_DIR, "usdt_monitor.db"))
    etherscan_base_url = os.getenv(
        "ETHERSCAN_BASE_URL", "https://api.etherscan.io/v2/api"
    )
    etherscan_request_delay = _get_env_float("ETHERSCAN_REQUEST_DELAY", 0.5)

    # Rate limiter configuration
    rate_limiter_min_delay = _get_env_float("RATE_LIMITER_MIN_DELAY", 0.4)
    rate_limiter_max_delay = _get_env_float("RATE_LIMITER_MAX_DELAY", 10.0)
    rate_limiter_backoff_factor = _get_env_float("RATE_LIMITER_BACKOFF_FACTOR", 2.5)
    rate_limiter_recovery_factor = _get_env_float("RATE_LIMITER_RECOVERY_FACTOR", 0.95)
    rate_limiter_success_threshold = _get_env_int("RATE_LIMITER_SUCCESS_THRESHOLD", 20)
    rate_limiter_recovery_cooldown = _get_env_float(
        "RATE_LIMITER_RECOVERY_COOLDOWN", 30.0
    )

    # Check interval and transaction settings
    check_interval_seconds = _get_env_int("CHECK_INTERVAL_SECONDS", 60)
    max_transaction_age_days = _get_env_int("MAX_TRANSACTION_AGE_DAYS", 7)
    max_transactions_per_check = _get_env_int("MAX_TRANSACTIONS_PER_CHECK", 10)

    # Verbose logging option
    verbose_env = os.getenv("VERBOSE", "").lower()
    verbose_logging = verbose_env in ("true", "1", "yes", "on")

    # Log all config details at DEBUG level
    logging.debug(
        f"Config: db={db_path}, api_url={etherscan_base_url}, "
        f"delay={etherscan_request_delay}s, interval={check_interval_seconds}s, "
        f"max_age={max_transaction_age_days}d, max_tx={max_transactions_per_check}"
    )
    logging.debug(
        f"Rate limiter: min={rate_limiter_min_delay}s, max={rate_limiter_max_delay}s, "
        f"backoff={rate_limiter_backoff_factor}x, recovery={rate_limiter_recovery_factor}, "
        f"threshold={rate_limiter_success_threshold}, cooldown={rate_limiter_recovery_cooldown}s"
    )

    # Create config instance
    config = BotConfig(
        telegram_bot_token=telegram_bot_token,
        etherscan_api_key=etherscan_api_key,
        db_path=db_path,
        etherscan_base_url=etherscan_base_url,
        etherscan_request_delay=etherscan_request_delay,
        rate_limiter_min_delay=rate_limiter_min_delay,
        rate_limiter_max_delay=rate_limiter_max_delay,
        rate_limiter_backoff_factor=rate_limiter_backoff_factor,
        rate_limiter_recovery_factor=rate_limiter_recovery_factor,
        rate_limiter_success_threshold=rate_limiter_success_threshold,
        rate_limiter_recovery_cooldown=rate_limiter_recovery_cooldown,
        check_interval_seconds=check_interval_seconds,
        max_transaction_age_days=max_transaction_age_days,
        max_transactions_per_check=max_transactions_per_check,
        verbose_logging=verbose_logging,
    )

    # Token configuration overrides
    env_overrides = []

    # USDT overrides
    usdt_contract = os.getenv("USDT_CONTRACT_ADDRESS")
    usdt_decimals_env = os.getenv("USDT_DECIMALS")
    if usdt_contract or usdt_decimals_env:
        final_contract = usdt_contract or "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        final_decimals = _get_env_int("USDT_DECIMALS", 6)
        usdt_config = TokenConfig(
            name="Tether USD",
            contract_address=final_contract,
            decimals=final_decimals,
            symbol="USDT",
            display_name="USDT",
            explorer_url=f"https://etherscan.io/token/{final_contract}",
        )
        config.token_registry.register_token(usdt_config)
        env_overrides.append("USDT")

    # USDC overrides
    usdc_contract = os.getenv("USDC_CONTRACT_ADDRESS")
    usdc_decimals_env = os.getenv("USDC_DECIMALS")
    if usdc_contract or usdc_decimals_env:
        final_contract = usdc_contract or "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        final_decimals = _get_env_int("USDC_DECIMALS", 6)
        usdc_config = TokenConfig(
            name="USD Coin",
            contract_address=final_contract,
            decimals=final_decimals,
            symbol="USDC",
            display_name="USDC",
            explorer_url=f"https://etherscan.io/token/{final_contract}",
        )
        config.token_registry.register_token(usdc_config)
        env_overrides.append("USDC")

    # Single INFO log for config summary
    tokens = list(config.token_registry.get_all_tokens().keys())
    override_info = f", overrides: {env_overrides}" if env_overrides else ""
    logging.info(
        f"Config loaded: interval={check_interval_seconds}s, "
        f"tokens={tokens}{override_info}, verbose={verbose_logging}"
    )

    return config
