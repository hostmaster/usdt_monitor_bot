# tests/test_utils.py
# tests/test_utils.py
from datetime import datetime
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
    "hash": "0xabcdef123456",
    "from": "0xsenderaddress",
    "to": "0xrecipientaddress",
    "contractAddress": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    "value": "123456789",
    "tokenDecimal": "6",
    "timeStamp": str(int(datetime.now().timestamp())),
    "blockNumber": "15000000",
}
MONITORED_ADDRESS = "0xrecipientaddress"

VALID_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678"
INVALID_ADDRESS = "0xinvalid"
VALID_ADDRESS_UPPER = "0x1234567890ABCDEF1234567890ABCDEF12345678"

# This file does NOT have pytestmark = pytest.mark.asyncio


@pytest.fixture
def notifier_formatter(mock_config):  # Use existing mock_config fixture
    # No need for mock_bot if only testing _format_usdt_message
    return NotificationService(bot=MagicMock(), config=mock_config)


def test_address_validation():
    assert is_valid_ethereum_address(VALID_ADDRESS) is True
    assert is_valid_ethereum_address(VALID_ADDRESS_UPPER) is True
    assert is_valid_ethereum_address(INVALID_ADDRESS) is False
    assert is_valid_ethereum_address("0x12345") is False  # Too short
    assert is_valid_ethereum_address(VALID_ADDRESS + "0") is False  # Too long
    assert (
        is_valid_ethereum_address(VALID_ADDRESS.replace("a", "g")) is False
    )  # Invalid chars
    assert is_valid_ethereum_address(None) is False  # Test None input
    assert is_valid_ethereum_address("") is False  # Test empty string
    assert is_valid_ethereum_address(123) is False  # Test non-string


def test_format_usdt_message_success(
    notifier_formatter: NotificationService,
):
    formatted_message = notifier_formatter._format_usdt_message(
        MONITORED_ADDRESS, SAMPLE_TX
    )
    assert "New Incoming USDT Transfer!" in formatted_message
    assert f"To Address: <code>{MONITORED_ADDRESS}</code>" in formatted_message
    assert "Amount: <b>123.456789 USDT</b>" in formatted_message
    assert f"From: <code>{SAMPLE_TX['from']}</code>" in formatted_message
    assert "Time:" in formatted_message
    assert (
        f'<a href="https://etherscan.io/tx/{SAMPLE_TX["hash"]}">View on Etherscan</a>'
        in formatted_message
    )


def test_format_usdt_message_missing_key(
    notifier_formatter: NotificationService,
):  # <<< USE CORRECT FIXTURE NAME
    invalid_tx = SAMPLE_TX.copy()
    tx_hash = invalid_tx["hash"]
    del invalid_tx["value"]
    formatted_message = notifier_formatter._format_usdt_message(
        MONITORED_ADDRESS, invalid_tx
    )
    assert formatted_message.startswith("⚠️ Error formatting transaction")
    assert f"⚠️ Error formatting transaction {tx_hash}" in formatted_message
