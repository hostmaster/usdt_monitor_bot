# tests/test_checker.py
from unittest.mock import AsyncMock, MagicMock

import pytest

from usdt_monitor_bot.checker import TransactionChecker
from usdt_monitor_bot.etherscan import (
    EtherscanRateLimitError,
)

pytestmark = pytest.mark.asyncio

# Sample data
ADDR1 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ADDR2 = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
USER1 = 101
USER2 = 202
BLOCK_ADDR1_START = 1000
BLOCK_ADDR2_START = 2000
USDT_CONTRACT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
USDC_CONTRACT = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"

TX1_INCOMING_ADDR1_USDT = {
    "blockNumber": "1001",
    "timeStamp": "1678886400",
    "hash": "0xtx1",
    "from": "0xsender1",
    "to": ADDR1,
    "value": "1000000",
    "contractAddress": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
}
TX2_OUTGOING_ADDR1_USDT = {
    "blockNumber": "1002",
    "timeStamp": "1678886401",
    "hash": "0xtx2",
    "from": ADDR1,
    "to": "0xrecipient2",
    "value": "2000000",
    "contractAddress": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
}
TX3_INCOMING_ADDR2_USDC = {
    "blockNumber": "2001",
    "timeStamp": "1678886402",
    "hash": "0xtx3",
    "from": "0xsender3",
    "to": ADDR2,
    "value": "3000000",
    "contractAddress": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
}


@pytest.fixture
def mock_config():
    """Provides a mocked config."""
    config = MagicMock()
    config.etherscan_request_delay = 0  # No delay in tests
    config.usdt_contract = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    config.usdc_contract = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

    # Mock token registry
    token_registry = MagicMock()
    usdt_token = MagicMock()
    usdt_token.contract_address = config.usdt_contract
    usdt_token.symbol = "USDT"
    usdc_token = MagicMock()
    usdc_token.contract_address = config.usdc_contract
    usdc_token.symbol = "USDC"

    token_registry.get_all_tokens.return_value = {
        "USDT": usdt_token,
        "USDC": usdc_token,
    }
    config.token_registry = token_registry
    config.get_token_by_address = lambda addr: next(
        (
            token
            for token in token_registry.get_all_tokens().values()
            if token.contract_address == addr
        ),
        None,
    )
    return config


@pytest.fixture
def mock_db_manager():
    """Provides a mocked database manager."""
    return AsyncMock()


@pytest.fixture
def mock_etherscan_client():
    """Provides a mocked Etherscan client."""
    return AsyncMock()


@pytest.fixture
def mock_notifier():
    """Provides a mocked notifier."""
    return AsyncMock()


@pytest.fixture
def checker(mock_config, mock_db_manager, mock_etherscan_client, mock_notifier):
    """Provides a TransactionChecker with mocked dependencies."""
    return TransactionChecker(
        config=mock_config,
        db_manager=mock_db_manager,
        etherscan_client=mock_etherscan_client,
        notifier=mock_notifier,
    )


# --- Test Cases ---


async def test_check_no_addresses(checker, mock_db_manager):
    """Test that no notifications are sent when there are no addresses to check."""
    mock_db_manager.get_distinct_addresses.return_value = []

    await checker.check_all_addresses()

    mock_db_manager.get_distinct_addresses.assert_awaited_once()
    mock_db_manager.get_last_checked_block.assert_not_awaited()


async def test_check_address_no_new_tx(
    checker, mock_db_manager, mock_etherscan_client, mock_notifier
):
    """Test that no notifications are sent when there are no new transactions."""
    mock_db_manager.get_distinct_addresses.return_value = [ADDR1]
    mock_db_manager.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan_client.get_token_transactions.return_value = []

    await checker.check_all_addresses()

    mock_db_manager.get_distinct_addresses.assert_awaited_once()
    mock_db_manager.get_last_checked_block.assert_awaited_once_with(ADDR1.lower())
    mock_etherscan_client.get_token_transactions.assert_awaited()
    mock_notifier.send_token_notification.assert_not_awaited()


async def test_check_address_new_incoming_tx(
    checker, mock_db_manager, mock_etherscan_client, mock_notifier
):
    """Test that notifications are sent for new incoming transactions."""
    mock_db_manager.get_distinct_addresses.return_value = [ADDR1]
    mock_db_manager.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan_client.get_token_transactions.side_effect = [
        [TX1_INCOMING_ADDR1_USDT],  # USDT transactions
        [],  # USDC transactions
    ]
    mock_db_manager.get_users_for_address.return_value = [USER1]

    await checker.check_all_addresses()

    mock_db_manager.get_distinct_addresses.assert_awaited_once()
    mock_db_manager.get_last_checked_block.assert_awaited_once_with(ADDR1.lower())
    assert mock_etherscan_client.get_token_transactions.await_count == 2
    mock_notifier.send_token_notification.assert_awaited_once_with(
        USER1, ADDR1.lower(), TX1_INCOMING_ADDR1_USDT, "USDT"
    )


async def test_check_address_outgoing_tx_only(
    checker, mock_db_manager, mock_etherscan_client, mock_notifier
):
    """Test that no notifications are sent for outgoing transactions."""
    mock_db_manager.get_distinct_addresses.return_value = [ADDR1]
    mock_db_manager.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan_client.get_token_transactions.side_effect = [
        [TX2_OUTGOING_ADDR1_USDT],  # USDT transactions
        [],  # USDC transactions
    ]
    mock_db_manager.get_users_for_address.return_value = [USER1]

    await checker.check_all_addresses()

    mock_db_manager.get_distinct_addresses.assert_awaited_once()
    mock_db_manager.get_last_checked_block.assert_awaited_once_with(ADDR1.lower())
    assert mock_etherscan_client.get_token_transactions.await_count == 2
    mock_notifier.send_token_notification.assert_not_awaited()


async def test_check_mixed_incoming_outgoing(
    checker, mock_db_manager, mock_etherscan_client, mock_notifier
):
    """Test that only incoming transactions trigger notifications."""
    mock_db_manager.get_distinct_addresses.return_value = [ADDR1]
    mock_db_manager.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan_client.get_token_transactions.side_effect = [
        [TX1_INCOMING_ADDR1_USDT, TX2_OUTGOING_ADDR1_USDT],  # USDT transactions
        [],  # USDC transactions
    ]
    mock_db_manager.get_users_for_address.return_value = [USER1]

    await checker.check_all_addresses()

    mock_db_manager.get_distinct_addresses.assert_awaited_once()
    mock_db_manager.get_last_checked_block.assert_awaited_once_with(ADDR1.lower())
    assert mock_etherscan_client.get_token_transactions.await_count == 2
    mock_notifier.send_token_notification.assert_awaited_once_with(
        USER1, ADDR1.lower(), TX1_INCOMING_ADDR1_USDT, "USDT"
    )


async def test_check_multiple_addresses(
    checker, mock_db_manager, mock_etherscan_client, mock_notifier
):
    """Test that multiple addresses are processed correctly."""
    mock_db_manager.get_distinct_addresses.return_value = [ADDR1, ADDR2]
    mock_db_manager.get_last_checked_block.side_effect = [
        BLOCK_ADDR1_START,
        BLOCK_ADDR2_START,
    ]
    mock_etherscan_client.get_token_transactions.side_effect = [
        [TX1_INCOMING_ADDR1_USDT],  # ADDR1 USDT transactions
        [],  # ADDR1 USDC transactions
        [],  # ADDR2 USDT transactions
        [TX3_INCOMING_ADDR2_USDC],  # ADDR2 USDC transactions
    ]
    mock_db_manager.get_users_for_address.side_effect = [[USER1], [USER2]]

    await checker.check_all_addresses()

    assert mock_db_manager.get_distinct_addresses.await_count == 1
    assert mock_db_manager.get_last_checked_block.await_count == 2
    assert mock_etherscan_client.get_token_transactions.await_count == 4
    assert mock_notifier.send_token_notification.await_count == 2
    mock_notifier.send_token_notification.assert_any_await(
        USER1, ADDR1.lower(), TX1_INCOMING_ADDR1_USDT, "USDT"
    )
    mock_notifier.send_token_notification.assert_any_await(
        USER2, ADDR2.lower(), TX3_INCOMING_ADDR2_USDC, "USDC"
    )


async def test_check_etherscan_rate_limit(
    checker, mock_db_manager, mock_etherscan_client, mock_notifier
):
    """Test that rate limiting is handled correctly."""
    mock_db_manager.get_distinct_addresses.return_value = [ADDR1]
    mock_db_manager.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan_client.get_token_transactions.side_effect = EtherscanRateLimitError(
        "Rate Limited"
    )

    await checker.check_all_addresses()

    mock_db_manager.get_distinct_addresses.assert_awaited_once()
    mock_db_manager.get_last_checked_block.assert_awaited_once_with(ADDR1.lower())
    mock_etherscan_client.get_token_transactions.assert_awaited()
    mock_notifier.send_token_notification.assert_not_awaited()
