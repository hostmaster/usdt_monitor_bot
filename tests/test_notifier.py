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
    "value": "1000000",  # 1 USDT (6 decimals)
    "timeStamp": "1620000000",
    "monitored_address": ADDR1,
}
TX2_INCOMING_USDC = {
    "hash": "0x456",
    "from": "0xdef",
    "to": ADDR1,
    "value": "2000000",  # 2 USDC (6 decimals)
    "timeStamp": "1620000001",
    "monitored_address": ADDR1,
}

# Add test data for invalid transactions
TX_INVALID_VALUE = {
    "hash": "0x789",
    "from": "0xabc",
    "to": ADDR1,
    "value": "invalid",  # Invalid value format
    "timeStamp": "1620000000",
    "monitored_address": ADDR1,
}
TX_INVALID_TIMESTAMP = {
    "hash": "0x789",
    "from": "0xabc",
    "to": ADDR1,
    "value": "1000000",
    "timeStamp": "invalid",  # Invalid timestamp
    "monitored_address": ADDR1,
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
    bot = AsyncMock()
    bot.send_message = AsyncMock()
    return bot


@pytest.fixture
def notifier(mock_telegram_bot, mock_config):
    """Create a NotificationService instance with mocked dependencies."""
    return NotificationService(mock_telegram_bot, mock_config)


@pytest.mark.asyncio
async def test_send_token_notification_usdt(
    notifier: NotificationService, mock_telegram_bot
):
    """Test sending a notification for a USDT transaction."""
    await notifier.send_token_notification(USER1, TX1_INCOMING_USDT, "USDT")
    mock_telegram_bot.send_message.assert_called_once()
    message = mock_telegram_bot.send_message.call_args[1]["text"]
    assert "🔔 New USDT Transfer!" in message
    assert "Amount: <b>1.00 USDT</b>" in message
    assert "From: <code>0xabc</code>" in message
    assert "View on Etherscan" in message


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
    message = mock_telegram_bot.send_message.call_args[1]["text"]
    assert "🔔 New USDC Transfer!" in message
    assert "Amount: <b>2.00 USDC</b>" in message
    assert "From: <code>0xdef</code>" in message
    assert "View on Etherscan" in message


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
async def test_send_token_notification_outgoing_tx(
    notifier: NotificationService, mock_telegram_bot, mock_config
):
    """Test notification formatting for outgoing transactions."""
    # Create an outgoing transaction
    outgoing_tx = {
        "hash": "0x789",
        "from": "0x123",  # Monitored address
        "to": "0xdef",
        "value": "1000000",
        "timeStamp": "1620000000",
        "monitored_address": "0x123",  # Add monitored address
    }

    # Test with an outgoing transaction
    await notifier.send_token_notification(USER1, outgoing_tx, "USDT")

    # Verify that the message was formatted correctly
    mock_telegram_bot.send_message.assert_called_once()
    message = mock_telegram_bot.send_message.call_args[1]["text"]
    assert "🔔 New USDT Transfer!" in message
    assert "To: <code>0xdef</code>" in message  # Should show the recipient address
    assert "Amount: <b>1.00 USDT</b>" in message


@pytest.mark.asyncio
async def test_send_token_notification_mixed_tx(
    notifier: NotificationService, mock_telegram_bot, mock_config
):
    """Test notification formatting for mixed incoming and outgoing transactions."""
    # Create both incoming and outgoing transactions
    incoming_tx = {
        "hash": "0xabc",
        "from": "0xsender",
        "to": "0x123",  # Monitored address
        "value": "1000000",
        "timeStamp": "1620000000",
        "monitored_address": "0x123",  # Add monitored address
    }
    outgoing_tx = {
        "hash": "0xdef",
        "from": "0x123",  # Monitored address
        "to": "0xrecipient",
        "value": "2000000",
        "timeStamp": "1620000001",
        "monitored_address": "0x123",  # Add monitored address
    }

    # Test with both transaction types
    await notifier.send_token_notification(USER1, incoming_tx, "USDT")
    await notifier.send_token_notification(USER1, outgoing_tx, "USDT")

    # Verify that both messages were formatted correctly
    assert mock_telegram_bot.send_message.call_count == 2

    # Check incoming transaction message
    incoming_message = mock_telegram_bot.send_message.call_args_list[0][1]["text"]
    assert "🔔 New USDT Transfer!" in incoming_message
    assert "From: <code>0xsender</code>" in incoming_message
    assert "Amount: <b>1.00 USDT</b>" in incoming_message

    # Check outgoing transaction message
    outgoing_message = mock_telegram_bot.send_message.call_args_list[1][1]["text"]
    assert "🔔 New USDT Transfer!" in outgoing_message
    assert "To: <code>0xrecipient</code>" in outgoing_message
    assert "Amount: <b>2.00 USDT</b>" in outgoing_message


@pytest.mark.asyncio
async def test_send_token_notification_self_transfer(
    notifier: NotificationService, mock_telegram_bot, mock_config
):
    """Test notification formatting for self-transfers (same address as sender and receiver)."""
    self_tx = {
        "hash": "0x789",
        "from": "0x123",
        "to": "0x123",  # Same as from address
        "value": "1000000",
        "timeStamp": "1620000000",
        "monitored_address": "0x123",
    }

    await notifier.send_token_notification(USER1, self_tx, "USDT")
    mock_telegram_bot.send_message.assert_called_once()
    message = mock_telegram_bot.send_message.call_args[1]["text"]
    assert "🔔 New USDT Transfer!" in message
    assert "To: <code>0x123</code>" in message
    assert "Amount: <b>1.00 USDT</b>" in message


@pytest.mark.asyncio
async def test_send_token_notification_zero_value(
    notifier: NotificationService, mock_telegram_bot, mock_config
):
    """Test notification formatting for zero-value transfers."""
    zero_tx = {
        "hash": "0x789",
        "from": "0xsender",
        "to": "0x123",
        "value": "0",
        "timeStamp": "1620000000",
        "monitored_address": "0x123",
    }

    await notifier.send_token_notification(USER1, zero_tx, "USDT")
    mock_telegram_bot.send_message.assert_called_once()
    message = mock_telegram_bot.send_message.call_args[1]["text"]
    assert "🔔 New USDT Transfer!" in message
    assert "From: <code>0xsender</code>" in message
    assert "Amount: <b>0.00 USDT</b>" in message


@pytest.mark.asyncio
async def test_send_token_notification_large_value(
    notifier: NotificationService, mock_telegram_bot, mock_config
):
    """Test notification formatting for large value transfers."""
    large_tx = {
        "hash": "0x789",
        "from": "0xsender",
        "to": "0x123",
        "value": "1000000000000",  # 1 million USDT
        "timeStamp": "1620000000",
        "monitored_address": "0x123",
    }

    await notifier.send_token_notification(USER1, large_tx, "USDT")
    mock_telegram_bot.send_message.assert_called_once()
    message = mock_telegram_bot.send_message.call_args[1]["text"]
    assert "🔔 New USDT Transfer!" in message
    assert "From: <code>0xsender</code>" in message
    assert "Amount: <b>1000000.00 USDT</b>" in message
