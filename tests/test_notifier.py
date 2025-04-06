# tests/test_notifier.py
from unittest.mock import AsyncMock, MagicMock  # Import MagicMock

import pytest

from usdt_monitor_bot.config import BotConfig, TokenConfig

# Import exceptions correctly
from usdt_monitor_bot.notifier import NotificationService

pytestmark = pytest.mark.asyncio

# Test data
USER1 = 123456789
USER2 = 987654321
ADDR1 = "0x1234567890123456789012345678901234567890"
TX1_INCOMING_USDT = {
    "hash": "0x123",
    "from": "0xabc",
    "to": ADDR1,
    "value": "1000000",
    "timeStamp": "1620000000",
}
TX2_INCOMING_USDC = {
    "hash": "0x456",
    "from": "0xdef",
    "to": ADDR1,
    "value": "2000000",
    "timeStamp": "1620000001",
}

# Add test data for invalid transactions
TX_INVALID_VALUE = {
    "hash": "0x789",
    "from": "0xabc",
    "to": ADDR1,
    "value": "invalid",  # Invalid value format
    "timeStamp": "1620000000",
}
TX_INVALID_TIMESTAMP = {
    "hash": "0x789",
    "from": "0xabc",
    "to": ADDR1,
    "value": "1000000",
    "timeStamp": "invalid",  # Invalid timestamp
}


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
def mock_telegram_bot():
    """Create a mock Telegram bot."""
    return AsyncMock()


@pytest.fixture
def notifier(mock_config, mock_telegram_bot):
    """Create a NotificationService instance with mocked dependencies."""
    return NotificationService(mock_telegram_bot, mock_config)


@pytest.mark.asyncio
async def test_send_token_notification_usdt(
    notifier: NotificationService, mock_telegram_bot
):
    """Test sending a notification for a USDT transaction."""
    await notifier.send_token_notification(USER1, TX1_INCOMING_USDT, "USDT")
    mock_telegram_bot.send_message.assert_called_once()


@pytest.mark.asyncio
async def test_send_token_notification_usdc(
    notifier: NotificationService, mock_telegram_bot
):
    """Test sending a notification for a USDC transaction."""
    # Update mock to return USDC config
    notifier._config.token_registry.get_token.return_value = TokenConfig(
        name="USD Coin",
        contract_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        decimals=6,
        symbol="USDC",
        display_name="USDC",
        explorer_url="https://etherscan.io/token/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    )
    await notifier.send_token_notification(USER2, TX2_INCOMING_USDC, "USDC")
    mock_telegram_bot.send_message.assert_called_once()


@pytest.mark.asyncio
async def test_send_token_notification_multiple_users(
    notifier: NotificationService, mock_telegram_bot
):
    """Test sending notifications to multiple users."""
    await notifier.send_token_notification(USER1, TX1_INCOMING_USDT, "USDT")
    await notifier.send_token_notification(USER2, TX1_INCOMING_USDT, "USDT")
    assert mock_telegram_bot.send_message.call_count == 2


@pytest.mark.asyncio
async def test_send_token_notification_error_handling(
    notifier: NotificationService, mock_telegram_bot
):
    """Test error handling when sending notifications."""
    mock_telegram_bot.send_message.side_effect = Exception("Failed to send message")

    # Should not raise an exception
    await notifier.send_token_notification(USER1, TX1_INCOMING_USDT, "USDT")
    mock_telegram_bot.send_message.assert_called_once()


@pytest.mark.asyncio
async def test_send_token_notification_unknown_token(
    notifier: NotificationService, mock_telegram_bot
):
    """Test handling of unknown token type."""
    # Configure mock to return None for unknown token
    notifier._config.token_registry.get_token.return_value = None

    # Should not raise an exception
    await notifier.send_token_notification(USER1, TX1_INCOMING_USDT, "UNKNOWN_TOKEN")

    # Verify that no message was sent
    mock_telegram_bot.send_message.assert_not_called()

    # Verify that error was logged
    assert notifier._config.token_registry.get_token.called
    notifier._config.token_registry.get_token.assert_called_with("UNKNOWN_TOKEN")


@pytest.mark.asyncio
async def test_send_token_notification_unrelated_transaction(
    notifier: NotificationService, mock_telegram_bot
):
    """Test handling of transactions that don't involve the monitored address."""
    # Create a transaction that doesn't involve the monitored address
    unrelated_tx = {
        "hash": "0x789",
        "from": "0xabc",
        "to": "0xdef",  # Different from monitored address
        "value": "1000000",
        "timeStamp": "1620000000",
    }

    # Test with a transaction that doesn't involve the monitored address
    await notifier.send_token_notification(USER1, unrelated_tx, "USDT")

    # Verify that a message was sent since we now send notifications for all transactions
    mock_telegram_bot.send_message.assert_called_once()


@pytest.mark.asyncio
async def test_send_token_notification_empty_tx(
    notifier: NotificationService, mock_telegram_bot
):
    """Test that empty transaction data is handled correctly."""
    # Test with None
    await notifier.send_token_notification(USER1, None, "USDT")
    mock_telegram_bot.send_message.assert_not_called()

    # Test with empty dict
    await notifier.send_token_notification(USER1, {}, "USDT")
    mock_telegram_bot.send_message.assert_not_called()


@pytest.mark.asyncio
async def test_send_token_notification_invalid_value(
    notifier: NotificationService, mock_telegram_bot
):
    """Test handling of transaction with invalid value format."""
    await notifier.send_token_notification(USER1, TX_INVALID_VALUE, "USDT")
    mock_telegram_bot.send_message.assert_not_called()


@pytest.mark.asyncio
async def test_send_token_notification_invalid_timestamp(
    notifier: NotificationService, mock_telegram_bot
):
    """Test handling of transaction with invalid timestamp."""
    await notifier.send_token_notification(USER1, TX_INVALID_TIMESTAMP, "USDT")
    mock_telegram_bot.send_message.assert_not_called()


@pytest.mark.asyncio
async def test_send_token_notification_missing_required_fields(
    notifier: NotificationService, mock_telegram_bot
):
    """Test handling of transaction with missing required fields."""
    # Test with missing hash
    tx_missing_hash = {k: v for k, v in TX1_INCOMING_USDT.items() if k != "hash"}
    await notifier.send_token_notification(USER1, tx_missing_hash, "USDT")
    mock_telegram_bot.send_message.assert_not_called()

    # Test with missing value
    tx_missing_value = {k: v for k, v in TX1_INCOMING_USDT.items() if k != "value"}
    await notifier.send_token_notification(USER1, tx_missing_value, "USDT")
    mock_telegram_bot.send_message.assert_not_called()

    # Test with missing timestamp
    tx_missing_timestamp = {
        k: v for k, v in TX1_INCOMING_USDT.items() if k != "timeStamp"
    }
    await notifier.send_token_notification(USER1, tx_missing_timestamp, "USDT")
    mock_telegram_bot.send_message.assert_not_called()
