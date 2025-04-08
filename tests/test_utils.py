# tests/test_utils.py
# tests/test_utils.py

from unittest.mock import MagicMock

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
    "hash": "0x123",
    "from": "0xsender",
    "to": "0xrecipient",
    "value": "1000000",  # 1 USDT (6 decimals)
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
    return NotificationService(None, mock_config)


def test_format_usdt_message_success(notifier_formatter):
    """Test successful message formatting."""
    formatted_message = notifier_formatter._format_token_message(
        tx_hash="0x123",
        address="0xsender",
        value=1000000.0,  # 1 USDT
        token_config=notifier_formatter._config.token_registry.get_token("USDT"),
        is_incoming=True,
        timestamp=1620000000,
    )
    assert "🔔 New USDT Transfer!" in formatted_message
    assert "From: <code>0xsender</code>" in formatted_message
    assert "Amount: <b>1.00 USDT</b>" in formatted_message
    assert "View on Etherscan" in formatted_message
    assert "2021-05-03" in formatted_message  # Check date


def test_format_usdt_message_missing_key(notifier_formatter):
    """Test message formatting with missing data."""
    formatted_message = notifier_formatter._format_token_message(
        tx_hash="0xabcdef123456",
        address="0xsender",
        value="invalid",  # This will cause a value formatting error
        token_config=notifier_formatter._config.token_registry.get_token("USDT"),
        is_incoming=True,
        timestamp=1620000000,
    )
    assert formatted_message is None  # Error cases now return None


def test_address_validation():
    """Test Ethereum address validation."""
    # Valid addresses
    assert is_valid_ethereum_address("0x1234567890123456789012345678901234567890")
    assert is_valid_ethereum_address("0xabcdef0123456789abcdef0123456789abcdef01")
    assert is_valid_ethereum_address("0xABCDEF0123456789ABCDEF0123456789ABCDEF01")

    # Invalid addresses
    assert not is_valid_ethereum_address("not_an_address")
    assert not is_valid_ethereum_address("0x123")  # Too short
    assert not is_valid_ethereum_address(
        "1234567890123456789012345678901234567890"
    )  # No 0x prefix
    assert not is_valid_ethereum_address(
        "0xghijklmnopqrstuvwxyz1234567890123456"
    )  # Invalid chars
