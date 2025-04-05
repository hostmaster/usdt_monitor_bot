# tests/test_utils.py
# tests/test_utils.py
from unittest.mock import MagicMock  # Import MagicMock if needed by fixture

import pytest

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
    "blockNumber": "15000000",
    "timeStamp": "1775000014",  # 2025-04-05 22:53:34 UTC
    "hash": "0xabcdef123456",
    "from": "0xsenderaddress",
    "to": "0xrecipientaddress",
    "value": "123456789",
    "contractAddress": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    "tokenDecimal": "6",
}
MONITORED_ADDRESS = "0xrecipientaddress"

VALID_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678"
INVALID_ADDRESS = "0xinvalid"
VALID_ADDRESS_UPPER = "0x1234567890ABCDEF1234567890ABCDEF12345678"

# This file does NOT have pytestmark = pytest.mark.asyncio


@pytest.fixture
def mock_config():
    """Provides a mocked config with token decimals."""
    config = MagicMock()
    config.usdt_decimals = 6
    config.usdc_decimals = 6
    return config


@pytest.fixture
def notifier_formatter(mock_config):
    """Provides a NotificationService with mocked dependencies."""
    return NotificationService(config=mock_config, bot=MagicMock())


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
        MONITORED_ADDRESS, SAMPLE_TX, "USDT"
    )
    assert "New Incoming USDT Transfer!" in formatted_message
    assert MONITORED_ADDRESS in formatted_message
    assert SAMPLE_TX["hash"] in formatted_message
    assert SAMPLE_TX["from"] in formatted_message
    assert (
        "123.456789 USDT" in formatted_message
    )  # Value should be formatted with all decimals


def test_format_usdt_message_missing_key(notifier_formatter):
    """Test message formatting with missing data."""
    incomplete_tx = {
        "hash": "0xabcdef123456",
        # Missing other required fields
    }
    formatted_message = notifier_formatter._format_token_message(
        MONITORED_ADDRESS, incomplete_tx, "USDT"
    )
    assert formatted_message.startswith("⚠️")
    assert "Error formatting transaction" in formatted_message
