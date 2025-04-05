# tests/test_notifier.py
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch  # Import MagicMock

import pytest

# Import exceptions correctly
from aiogram.enums import ParseMode
from aiogram.exceptions import (
    TelegramBadRequest,
    TelegramForbiddenError,
    TelegramRetryAfter,
)

from usdt_monitor_bot.notifier import NotificationService

pytestmark = pytest.mark.asyncio

# Sample valid transaction data
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
USER_ID = 12345


@pytest.fixture
def notifier_service(mock_bot, mock_config):
    return NotificationService(bot=mock_bot, config=mock_config)


# --- Test Cases ---




async def test_send_usdt_notification_success(
    notifier_service: NotificationService, mock_bot
):
    await notifier_service.send_usdt_notification(USER_ID, MONITORED_ADDRESS, SAMPLE_TX)
    mock_bot.send_message.assert_awaited_once()
    call_args = mock_bot.send_message.call_args
    assert call_args[0][0] == USER_ID
    assert "New Incoming USDT Transfer!" in call_args[0][1]
    assert call_args[1]["parse_mode"] == ParseMode.HTML
    assert call_args[1]["disable_web_page_preview"] is True


@patch("asyncio.sleep", new_callable=AsyncMock)
async def test_send_usdt_notification_retry_after(
    mock_sleep, notifier_service: NotificationService, mock_bot
):
    retry_after_duration = 5
    # Provide required dummy args for TelegramRetryAfter
    mock_method = MagicMock(name="MockBotMethod")
    error_message = "Flood control exceeded"
    mock_bot.send_message.side_effect = [
        TelegramRetryAfter(
            method=mock_method, message=error_message, retry_after=retry_after_duration
        ),
        AsyncMock(),  # Simulate success on retry
    ]

    await notifier_service.send_usdt_notification(USER_ID, MONITORED_ADDRESS, SAMPLE_TX)

    assert mock_bot.send_message.await_count == 2
    mock_sleep.assert_awaited_once_with(retry_after_duration)


async def test_send_usdt_notification_forbidden(
    notifier_service: NotificationService, mock_bot
):
    # Provide required dummy args for TelegramForbiddenError
    mock_method = MagicMock(name="MockBotMethod")
    error_message = "Forbidden: bot was blocked by the user"
    mock_bot.send_message.side_effect = TelegramForbiddenError(
        method=mock_method, message=error_message
    )

    await notifier_service.send_usdt_notification(USER_ID, MONITORED_ADDRESS, SAMPLE_TX)
    mock_bot.send_message.assert_awaited_once()  # Error caught, only tried once


async def test_send_usdt_notification_bad_request(
    notifier_service: NotificationService, mock_bot
):
    # Provide required dummy args for TelegramBadRequest
    mock_method = MagicMock(name="MockBotMethod")
    error_message = "Bad Request: chat not found"
    mock_bot.send_message.side_effect = TelegramBadRequest(
        method=mock_method, message=error_message
    )

    await notifier_service.send_usdt_notification(USER_ID, MONITORED_ADDRESS, SAMPLE_TX)
    mock_bot.send_message.assert_awaited_once()  # Error caught, only tried once


async def test_send_usdt_notification_skips_formatting_error(
    notifier_service: NotificationService, mock_bot
):
    invalid_tx = SAMPLE_TX.copy()
    del invalid_tx["value"]
    await notifier_service.send_usdt_notification(
        USER_ID, MONITORED_ADDRESS, invalid_tx
    )
    mock_bot.send_message.assert_not_awaited()
