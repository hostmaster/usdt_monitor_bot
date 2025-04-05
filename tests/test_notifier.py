# tests/test_notifier.py
from unittest.mock import AsyncMock, MagicMock  # Import MagicMock

import pytest

# Import exceptions correctly
from usdt_monitor_bot.notifier import NotificationService

pytestmark = pytest.mark.asyncio

# Test data
ADDR1 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
USER1 = 101
USER2 = 202

TX1_INCOMING_USDT = {
    "blockNumber": "1001",
    "contractAddress": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    "from": "0xsender1",
    "to": ADDR1,
    "hash": "0xtx1",
    "value": "1000000",
    "timeStamp": "1678886400",
    "tokenDecimal": "6",
}

TX2_INCOMING_USDC = {
    "blockNumber": "1002",
    "contractAddress": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "from": "0xsender2",
    "to": ADDR1,
    "hash": "0xtx2",
    "value": "2000000",
    "timeStamp": "1678886402",
    "tokenDecimal": "6",
}


@pytest.fixture
def mock_telegram_bot():
    """Provides a mocked telegram bot."""
    bot = AsyncMock()
    bot.send_message = AsyncMock()
    return bot


@pytest.fixture
def mock_config():
    """Provides a mocked config with token decimals."""
    config = MagicMock()
    config.usdt_decimals = 6
    config.usdc_decimals = 6
    config.usdt_contract = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    config.usdc_contract = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    return config


@pytest.fixture
def notifier(mock_config, mock_telegram_bot):
    """Provides a NotificationService with mocked dependencies."""
    return NotificationService(bot=mock_telegram_bot, config=mock_config)


async def test_send_token_notification_usdt(
    notifier: NotificationService, mock_telegram_bot
):
    """Test sending a notification for a USDT transaction."""
    await notifier.send_token_notification(USER1, ADDR1, TX1_INCOMING_USDT, "USDT")

    mock_telegram_bot.send_message.assert_awaited_once()
    message = mock_telegram_bot.send_message.await_args[0][1]
    assert "USDT" in message
    assert ADDR1 in message
    assert TX1_INCOMING_USDT["hash"] in message
    assert TX1_INCOMING_USDT["from"] in message
    assert "1.000000 USDT" in message  # Value should be formatted with all decimals


async def test_send_token_notification_usdc(
    notifier: NotificationService, mock_telegram_bot
):
    """Test sending a notification for a USDC transaction."""
    await notifier.send_token_notification(USER2, ADDR1, TX2_INCOMING_USDC, "USDC")

    mock_telegram_bot.send_message.assert_awaited_once()
    message = mock_telegram_bot.send_message.await_args[0][1]
    assert "USDC" in message
    assert ADDR1 in message
    assert TX2_INCOMING_USDC["hash"] in message
    assert TX2_INCOMING_USDC["from"] in message
    assert "2.000000 USDC" in message  # Value should be formatted with all decimals


async def test_send_token_notification_multiple_users(
    notifier: NotificationService, mock_telegram_bot
):
    """Test sending notifications to multiple users."""
    await notifier.send_token_notification(USER1, ADDR1, TX1_INCOMING_USDT, "USDT")
    await notifier.send_token_notification(USER2, ADDR1, TX1_INCOMING_USDT, "USDT")

    assert mock_telegram_bot.send_message.await_count == 2
    # Check that both users received the same message
    messages = [call[0][1] for call in mock_telegram_bot.send_message.await_args_list]
    assert all("USDT" in msg for msg in messages)
    assert all(ADDR1 in msg for msg in messages)
    assert all(TX1_INCOMING_USDT["hash"] in msg for msg in messages)
    assert all(TX1_INCOMING_USDT["from"] in msg for msg in messages)
    assert all(
        "1.000000 USDT" in msg for msg in messages
    )  # Value should be formatted with all decimals


async def test_send_token_notification_error_handling(
    notifier: NotificationService, mock_telegram_bot
):
    """Test error handling when sending notifications."""
    mock_telegram_bot.send_message.side_effect = Exception("Failed to send message")

    # Should not raise an exception
    await notifier.send_token_notification(USER1, ADDR1, TX1_INCOMING_USDT, "USDT")

    mock_telegram_bot.send_message.assert_awaited_once()
