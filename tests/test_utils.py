# tests/test_utils.py
# tests/test_utils.py
from unittest.mock import MagicMock  # Import MagicMock if needed by fixture

import pytest

from usdt_monitor_bot.config import BotConfig, TokenConfig

# Adjust the import path based on your project structure
# If is_valid_ethereum_address remains in handlers.py:
from usdt_monitor_bot.handlers import is_valid_ethereum_address
from usdt_monitor_bot.notifier import NotificationService  # Import the service

# If moved here:
# ETH_ADDRESS_REGEX = re.compile(r"^0x[a-fA-F0-9]{40}$")
# def is_valid_ethereum_address(address: Optional[str]) -> bool: # Allow None input
#     if not isinstance(address, str): # Check type first
#         return False
#     return bool(ETH_ADDRESS_REGEX.fullmatch(address))

# --- Constants ---
SAMPLE_TX = {
    "hash": "0xabcdef123456",
    "from": "0xsender",
    "to": "0x1234567890123456789012345678901234567890",
    "value": "1000000",  # 1.00 USDT (6 decimals)
    "timeStamp": "1620000000",
}
MONITORED_ADDRESS = "0x1234567890123456789012345678901234567890"

VALID_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678"
INVALID_ADDRESS = "0xinvalid"
VALID_ADDRESS_UPPER = "0x1234567890ABCDEF1234567890ABCDEF12345678"

# This file does NOT have pytestmark = pytest.mark.asyncio


@pytest.fixture
def mock_config():
    """Create a mock config object."""
    config = MagicMock(spec=BotConfig)
    config.token_registry = MagicMock()
    config.token_registry.get_token.return_value = TokenConfig(
        name="Tether USD",
        contract_address="0xdAC17F958D2ee523a2206206994597C13D831ec7",
        decimals=6,
        symbol="USDT",
        display_name="USDT",
        explorer_url="https://etherscan.io/token/0xdAC17F958D2ee523a2206206994597C13D831ec7",
    )
    return config


@pytest.fixture
def notifier_formatter(mock_config):
    """Create a NotificationService instance with mocked dependencies."""
    return NotificationService(MagicMock(), mock_config)


def test_address_validation():
    """Test Ethereum address validation."""
    valid_addresses = [
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    ]
    invalid_addresses = [
        "not_an_address",
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44",  # Too short
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44ef",  # Too long
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44g",  # Invalid character
    ]

    for addr in valid_addresses:
        assert is_valid_ethereum_address(addr), f"Should accept valid address {addr}"

    for addr in invalid_addresses:
        assert not is_valid_ethereum_address(addr), (
            f"Should reject invalid address {addr}"
        )


def test_format_usdt_message_success(notifier_formatter):
    """Test successful message formatting."""
    formatted_message = notifier_formatter._format_token_message(
        SAMPLE_TX,
        notifier_formatter._config.token_registry.get_token("USDT"),
    )
    assert "New Incoming USDT Transfer!" in formatted_message
    assert "1.00 USDT" in formatted_message
    assert "0xsender" in formatted_message  # Check sender address
    assert "View on Etherscan" in formatted_message
    assert "2021-05-03" in formatted_message  # Check date


def test_format_usdt_message_missing_key(notifier_formatter):
    """Test message formatting with missing data."""
    incomplete_tx = {
        "hash": "0xabcdef123456",
        "value": "invalid",  # This will cause a value formatting error
    }
    formatted_message = notifier_formatter._format_token_message(
        incomplete_tx,
        notifier_formatter._config.token_registry.get_token("USDT"),
    )
    assert formatted_message is None  # Error cases now return None
