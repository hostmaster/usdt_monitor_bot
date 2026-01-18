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
    monitored_address = TX1_INCOMING_USDT["to"]  # Monitored address is the recipient
    await notifier.send_token_notification(
        USER1, TX1_INCOMING_USDT, "USDT", monitored_address
    )
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
    monitored_address = TX2_INCOMING_USDC["to"]  # Monitored address is the recipient
    # Update mock to return USDC config
    notifier._config.token_registry.get_token.return_value = TokenConfig(
        name="USD Coin",
        contract_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        decimals=6,
        symbol="USDC",
        display_name="USDC",
        explorer_url="https://etherscan.io/token/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    )
    await notifier.send_token_notification(
        USER2, TX2_INCOMING_USDC, "USDC", monitored_address
    )
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
    monitored_address = TX1_INCOMING_USDT["to"]

    # Should not raise an exception
    await notifier.send_token_notification(
        USER1, TX1_INCOMING_USDT, "UNKNOWN_TOKEN", monitored_address
    )

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
    monitored_address = TX_INVALID_VALUE["to"]
    await notifier.send_token_notification(
        USER1, TX_INVALID_VALUE, "USDT", monitored_address
    )
    mock_telegram_bot.send_message.assert_not_called()


@pytest.mark.asyncio
async def test_send_token_notification_invalid_timestamp(
    notifier: NotificationService, mock_telegram_bot
):
    """Test handling of transaction with invalid timestamp."""
    monitored_address = TX_INVALID_TIMESTAMP["to"]
    await notifier.send_token_notification(
        USER1, TX_INVALID_TIMESTAMP, "USDT", monitored_address
    )
    mock_telegram_bot.send_message.assert_not_called()


@pytest.mark.asyncio
async def test_send_token_notification_outgoing_tx(
    notifier: NotificationService,
    mock_telegram_bot,
    mock_config,  # mock_config might be needed if token settings are tweaked
):
    """Test notification formatting for outgoing transactions."""
    monitored_address_val = "0x123"  # This is the address we are monitoring
    # Create an outgoing transaction
    outgoing_tx = {
        "hash": "0x789",
        "from": monitored_address_val,  # Monitored address is the sender
        "to": "0xdef",  # Recipient
        "value": "1000000",
        "timeStamp": "1620000000",
        # "monitored_address": monitored_address_val, # This key in tx is just for test data convenience
    }

    # Test with an outgoing transaction
    await notifier.send_token_notification(
        USER1, outgoing_tx, "USDT", monitored_address_val
    )

    # Verify that the message was formatted correctly
    mock_telegram_bot.send_message.assert_called_once()
    message = mock_telegram_bot.send_message.call_args[1]["text"]
    assert "🔔 New USDT Transfer!" in message
    assert "To: <code>0xdef</code>" in message  # Should show the recipient address
    assert "Amount: <b>1.00 USDT</b>" in message


@pytest.mark.asyncio
async def test_send_token_notification_mixed_tx(
    notifier: NotificationService,
    mock_telegram_bot,
    mock_config,  # mock_config might be needed if token settings are tweaked
):
    """Test notification formatting for mixed incoming and outgoing transactions."""
    monitored_address_val = "0x123"

    # Create both incoming and outgoing transactions
    incoming_tx = {
        "hash": "0xabc",
        "from": "0xsender",
        "to": monitored_address_val,  # Monitored address is recipient
        "value": "1000000",
        "timeStamp": "1620000000",
    }
    outgoing_tx = {
        "hash": "0xdef",
        "from": monitored_address_val,  # Monitored address is sender
        "to": "0xrecipient",
        "value": "2000000",
        "timeStamp": "1620000001",
    }

    # Test with both transaction types
    await notifier.send_token_notification(
        USER1, incoming_tx, "USDT", monitored_address_val
    )
    await notifier.send_token_notification(
        USER1, outgoing_tx, "USDT", monitored_address_val
    )

    # Verify that both messages were formatted correctly
    assert mock_telegram_bot.send_message.call_count == 2

    # Check incoming transaction message
    incoming_message = mock_telegram_bot.send_message.call_args_list[0][1]["text"]
    assert "🔔 New USDT Transfer!" in incoming_message
    assert "From: <code>0xsender</code>" in incoming_message  # Incoming, so show 'from'
    assert "Amount: <b>1.00 USDT</b>" in incoming_message

    # Check outgoing transaction message
    outgoing_message = mock_telegram_bot.send_message.call_args_list[1][1]["text"]
    assert "🔔 New USDT Transfer!" in outgoing_message
    assert "To: <code>0xrecipient</code>" in outgoing_message  # Outgoing, so show 'to'
    assert "Amount: <b>2.00 USDT</b>" in outgoing_message


@pytest.mark.asyncio
async def test_send_token_notification_self_transfer(
    notifier: NotificationService,
    mock_telegram_bot,
    mock_config,  # mock_config might be needed if token settings are tweaked
):
    """Test notification formatting for self-transfers (same address as sender and receiver)."""
    monitored_address_val = "0x123"
    self_tx = {
        "hash": "0x789",
        "from": monitored_address_val,
        "to": monitored_address_val,  # Same as from address
        "value": "1000000",
        "timeStamp": "1620000000",
    }

    await notifier.send_token_notification(
        USER1, self_tx, "USDT", monitored_address_val
    )
    mock_telegram_bot.send_message.assert_called_once()
    message = mock_telegram_bot.send_message.call_args[1]["text"]
    assert "🔔 New USDT Transfer!" in message
    # Self-transfers are treated as outgoing, so "To:" should be displayed
    assert "To: <code>0x123</code>" in message
    assert "Amount: <b>1.00 USDT</b>" in message


@pytest.mark.asyncio
async def test_send_token_notification_zero_value(
    notifier: NotificationService,
    mock_telegram_bot,
    mock_config,  # mock_config might be needed if token settings are tweaked
):
    """Test notification formatting for zero-value transfers."""
    monitored_address_val = "0x123"  # Monitored address is recipient
    zero_tx = {
        "hash": "0x789",
        "from": "0xsender",
        "to": monitored_address_val,
        "value": "0",
        "timeStamp": "1620000000",
    }

    await notifier.send_token_notification(
        USER1, zero_tx, "USDT", monitored_address_val
    )
    mock_telegram_bot.send_message.assert_called_once()
    message = mock_telegram_bot.send_message.call_args[1]["text"]
    assert "🔔 New USDT Transfer!" in message
    assert "From: <code>0xsender</code>" in message  # Incoming
    assert "Amount: <b>0.00 USDT</b>" in message


@pytest.mark.asyncio
async def test_send_token_notification_large_value(
    notifier: NotificationService,
    mock_telegram_bot,
    mock_config,  # mock_config might be needed if token settings are tweaked
):
    """Test notification formatting for large value transfers."""
    monitored_address_val = "0x123"  # Monitored address is recipient
    large_tx = {
        "hash": "0x789",
        "from": "0xsender",
        "to": monitored_address_val,
        "value": "1000000000000",  # 1 million USDT
        "timeStamp": "1620000000",
    }

    await notifier.send_token_notification(
        USER1, large_tx, "USDT", monitored_address_val
    )
    mock_telegram_bot.send_message.assert_called_once()
    message = mock_telegram_bot.send_message.call_args[1]["text"]
    assert "🔔 New USDT Transfer!" in message
    assert "From: <code>0xsender</code>" in message  # Incoming
    assert "Amount: <b>1000000.00 USDT</b>" in message


@pytest.mark.asyncio
async def test_send_token_notification_spam_short_notice(
    notifier: NotificationService, mock_telegram_bot
):
    """Test that spam transactions send a short notice instead of full details."""
    from usdt_monitor_bot.spam_detector import RiskAnalysis, RiskFlag

    monitored_address_val = TX1_INCOMING_USDT["to"]
    spam_tx = TX1_INCOMING_USDT.copy()

    # Create a suspicious risk analysis
    risk_analysis = RiskAnalysis(
        score=75,
        flags=[RiskFlag.DUST_AMOUNT, RiskFlag.NEW_SENDER_ADDRESS],
        is_suspicious=True,
        similarity_score=0,
        recommendation="⚠️ HIGH RISK - Suspicious address detected.",
        details={},
    )

    await notifier.send_token_notification(
        USER1, spam_tx, "USDT", monitored_address_val, risk_analysis=risk_analysis
    )
    mock_telegram_bot.send_message.assert_called_once()
    message = mock_telegram_bot.send_message.call_args[1]["text"]

    # Should be a short spam notice, not full transaction details
    assert "⚠️ <b>Spam Detected</b>" in message
    assert "From:" in message
    assert "Amount:" in message
    assert "Risk:" in message
    # Should NOT contain full transaction details
    assert "🔔 New USDT Transfer!" not in message
    assert "Time:" not in message
    assert "View on Etherscan" not in message  # Should be just "View"
    assert "View" in message  # Short link text


# --- Tests for Edge Cases and Error Handling ---


@pytest.mark.asyncio
async def test_send_token_notification_empty_tx(
    notifier: NotificationService, mock_telegram_bot, caplog
):
    """Test that empty transaction data is handled gracefully."""
    import logging

    with caplog.at_level(logging.WARNING):
        await notifier.send_token_notification(
            USER1, {}, "USDT", ADDR1
        )

    mock_telegram_bot.send_message.assert_not_called()
    assert "empty transaction data" in caplog.text


@pytest.mark.asyncio
async def test_send_token_notification_none_tx(
    notifier: NotificationService, mock_telegram_bot, caplog
):
    """Test that None transaction is handled gracefully."""
    import logging

    with caplog.at_level(logging.WARNING):
        await notifier.send_token_notification(
            USER1, None, "USDT", ADDR1
        )

    mock_telegram_bot.send_message.assert_not_called()


@pytest.mark.asyncio
async def test_send_token_notification_invalid_user_id(
    notifier: NotificationService, mock_telegram_bot, caplog
):
    """Test that invalid user_id is handled gracefully."""
    import logging

    with caplog.at_level(logging.WARNING):
        # Zero user_id
        await notifier.send_token_notification(
            0, TX1_INCOMING_USDT, "USDT", ADDR1
        )
        mock_telegram_bot.send_message.assert_not_called()

        # Negative user_id
        await notifier.send_token_notification(
            -1, TX1_INCOMING_USDT, "USDT", ADDR1
        )
        mock_telegram_bot.send_message.assert_not_called()

    assert "Invalid user_id" in caplog.text


@pytest.mark.asyncio
async def test_send_token_notification_telegram_api_error(
    notifier: NotificationService, mock_telegram_bot, caplog
):
    """Test handling of Telegram API errors during message sending."""
    import logging
    from aiogram.exceptions import TelegramAPIError

    mock_telegram_bot.send_message.side_effect = TelegramAPIError(
        method="sendMessage", message="Chat not found"
    )

    with caplog.at_level(logging.ERROR):
        await notifier.send_token_notification(
            USER1, TX1_INCOMING_USDT, "USDT", ADDR1
        )

    assert "Failed to send message" in caplog.text


@pytest.mark.asyncio
async def test_format_token_message_missing_tx_hash(notifier: NotificationService):
    """Test that missing tx_hash returns None."""
    result = notifier._format_token_message(
        tx_hash=None,
        address="0xsender",
        value=1.0,
        token_config=notifier._config.token_registry.get_token("USDT"),
        is_incoming=True,
        timestamp=1620000000,
    )
    assert result is None


@pytest.mark.asyncio
async def test_format_token_message_invalid_tx_hash_format(
    notifier: NotificationService,
):
    """Test that tx_hash without 0x prefix returns None."""
    result = notifier._format_token_message(
        tx_hash="abc123",  # No 0x prefix
        address="0xsender",
        value=1.0,
        token_config=notifier._config.token_registry.get_token("USDT"),
        is_incoming=True,
        timestamp=1620000000,
    )
    assert result is None


@pytest.mark.asyncio
async def test_format_token_message_invalid_address_format(
    notifier: NotificationService,
):
    """Test that address without 0x prefix returns None."""
    result = notifier._format_token_message(
        tx_hash="0x123",
        address="sender123",  # No 0x prefix
        value=1.0,
        token_config=notifier._config.token_registry.get_token("USDT"),
        is_incoming=True,
        timestamp=1620000000,
    )
    assert result is None


@pytest.mark.asyncio
async def test_format_token_message_negative_value(notifier: NotificationService):
    """Test that negative value returns None."""
    result = notifier._format_token_message(
        tx_hash="0x123",
        address="0xsender",
        value=-100.0,  # Negative value
        token_config=notifier._config.token_registry.get_token("USDT"),
        is_incoming=True,
        timestamp=1620000000,
    )
    assert result is None


@pytest.mark.asyncio
async def test_format_token_message_future_timestamp(notifier: NotificationService):
    """Test that far future timestamp returns None."""
    from datetime import datetime, timezone

    # Timestamp 2 hours in the future (beyond allowed tolerance)
    future_ts = int(datetime.now(timezone.utc).timestamp()) + 7200

    result = notifier._format_token_message(
        tx_hash="0x123",
        address="0xsender",
        value=1.0,
        token_config=notifier._config.token_registry.get_token("USDT"),
        is_incoming=True,
        timestamp=future_ts,
    )
    assert result is None


@pytest.mark.asyncio
async def test_format_token_message_negative_timestamp(notifier: NotificationService):
    """Test that negative timestamp returns None."""
    result = notifier._format_token_message(
        tx_hash="0x123",
        address="0xsender",
        value=1.0,
        token_config=notifier._config.token_registry.get_token("USDT"),
        is_incoming=True,
        timestamp=-1,
    )
    assert result is None


@pytest.mark.asyncio
async def test_format_token_message_non_integer_timestamp(
    notifier: NotificationService,
):
    """Test that non-integer timestamp returns None."""
    result = notifier._format_token_message(
        tx_hash="0x123",
        address="0xsender",
        value=1.0,
        token_config=notifier._config.token_registry.get_token("USDT"),
        is_incoming=True,
        timestamp="not-a-timestamp",
    )
    assert result is None


@pytest.mark.asyncio
async def test_send_notification_case_insensitive_address_comparison(
    notifier: NotificationService, mock_telegram_bot
):
    """Test that address comparisons are case-insensitive."""
    # Use uppercase in monitored address, lowercase in tx
    monitored_upper = "0x1234567890123456789012345678901234567890".upper()
    tx = {
        "hash": "0x123",
        "from": "0xsender",
        "to": monitored_upper.lower(),  # lowercase in tx
        "value": "1000000",
        "timeStamp": "1620000000",
    }

    await notifier.send_token_notification(
        USER1, tx, "USDT", monitored_upper  # uppercase
    )

    mock_telegram_bot.send_message.assert_called_once()
    message = mock_telegram_bot.send_message.call_args[1]["text"]
    # Should be detected as incoming (to monitored address)
    assert "From:" in message
