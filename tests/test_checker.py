# tests/test_checker.py
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from usdt_monitor_bot.checker import TransactionChecker
from usdt_monitor_bot.config import BotConfig
from usdt_monitor_bot.database import DatabaseManager
from usdt_monitor_bot.etherscan import (
    EtherscanClient,
    EtherscanRateLimitError,
)
from usdt_monitor_bot.notifier import NotificationService

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
    "blockNumber": str(BLOCK_ADDR1_START + 1),
    "timeStamp": str(int(datetime.now(timezone.utc).timestamp())),
    "hash": "0x000003e9",
    "from": "0xsender",
    "to": ADDR1,
    "value": "1000000",
    "contractAddress": USDT_CONTRACT,
}
TX2_OUTGOING_ADDR1_USDT = {
    "blockNumber": str(BLOCK_ADDR1_START + 2),
    "timeStamp": str(int(datetime.now(timezone.utc).timestamp())),
    "hash": "0x000003ea",
    "from": ADDR1,
    "to": "0xrecipient",
    "value": "1000000",
    "contractAddress": USDT_CONTRACT,
}
TX3_INCOMING_ADDR2_USDC = {
    "blockNumber": str(BLOCK_ADDR2_START + 1),
    "timeStamp": str(int(datetime.now(timezone.utc).timestamp())),
    "hash": "0x000003eb",
    "from": "0xsender",
    "to": ADDR2,
    "value": "1000000",
    "contractAddress": USDC_CONTRACT,
}


@pytest.fixture
def mock_config():
    """Create a mock config object."""
    config = MagicMock(spec=BotConfig)
    config.etherscan_request_delay = 0.2
    config.max_transaction_age_days = 7
    config.max_transactions_per_check = 10

    # Create token objects
    usdt_token = MagicMock()
    usdt_token.contract_address = USDT_CONTRACT
    usdt_token.symbol = "USDT"
    usdt_token.decimals = 6
    usdt_token.explorer_url = "https://etherscan.io"

    usdc_token = MagicMock()
    usdc_token.contract_address = USDC_CONTRACT
    usdc_token.symbol = "USDC"
    usdc_token.decimals = 6
    usdc_token.explorer_url = "https://etherscan.io"

    # Create token registry
    token_registry = MagicMock()
    token_registry.get_all_tokens.return_value = {
        "USDT": usdt_token,
        "USDC": usdc_token,
    }

    def get_token_by_address(address):
        address = address.lower()
        if address == USDT_CONTRACT.lower():
            return usdt_token
        elif address == USDC_CONTRACT.lower():
            return usdc_token
        return None

    def get_token(symbol):
        if symbol == "USDT":
            return usdt_token
        elif symbol == "USDC":
            return usdc_token
        return None

    token_registry.get_token_by_address.side_effect = get_token_by_address
    token_registry.get_token.side_effect = get_token
    config.token_registry = token_registry
    return config


@pytest.fixture
def mock_db():
    """Create a mock database object."""
    db = AsyncMock(spec=DatabaseManager)
    db.get_distinct_addresses.return_value = [ADDR1]
    db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    db.get_users_for_address.return_value = [USER1]
    db.update_last_checked_block.return_value = True
    return db


@pytest.fixture
def mock_etherscan():
    """Create a mock Etherscan client."""
    client = AsyncMock(spec=EtherscanClient)
    return client


@pytest.fixture
def mock_notifier(mock_config):
    """Create a mock notification service."""
    notifier = AsyncMock(spec=NotificationService)
    notifier._bot = AsyncMock()
    notifier._bot.send_message = AsyncMock(return_value=None)
    notifier._config = mock_config
    notifier._format_token_message = MagicMock(return_value="Test message")
    notifier.send_token_notification = AsyncMock()
    notifier.send_token_notification.return_value = None
    notifier.send_token_notification.side_effect = None
    notifier.send_token_notification.assert_awaited_once_with = AsyncMock()
    notifier.send_token_notification.await_count = 0
    return notifier


@pytest.fixture
def checker(mock_config, mock_db, mock_etherscan, mock_notifier):
    """Create a TransactionChecker instance with mocked dependencies."""
    return TransactionChecker(mock_config, mock_db, mock_etherscan, mock_notifier)


# --- Test Cases ---


async def test_check_no_addresses(checker, mock_db):
    """Test that no notifications are sent when there are no addresses to check."""
    mock_db.get_distinct_addresses.return_value = []

    await checker.check_all_addresses()

    mock_db.get_distinct_addresses.assert_awaited_once()
    mock_db.get_last_checked_block.assert_not_awaited()


async def test_check_address_no_new_tx(checker, mock_db, mock_etherscan, mock_notifier):
    """Test that no notifications are sent when there are no new transactions."""
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan.get_token_transactions.return_value = []

    await checker.check_all_addresses()

    mock_db.get_distinct_addresses.assert_awaited_once()
    mock_db.get_last_checked_block.assert_awaited_once_with(ADDR1.lower())
    mock_etherscan.get_token_transactions.assert_awaited()
    mock_notifier.send_token_notification.assert_not_awaited()


async def test_check_address_new_incoming_tx(
    checker, mock_db, mock_etherscan, mock_notifier, mock_config
):
    """Test that notifications are sent for new incoming transactions."""
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan.get_token_transactions.side_effect = [
        [TX1_INCOMING_ADDR1_USDT],  # USDT transactions
        [],  # USDC transactions
    ]
    mock_db.get_users_for_address.return_value = [USER1]

    await checker.check_all_addresses()

    mock_db.get_distinct_addresses.assert_awaited_once()
    mock_db.get_last_checked_block.assert_awaited_once_with(ADDR1.lower())
    mock_etherscan.get_token_transactions.assert_awaited()
    await mock_notifier.send_token_notification.assert_awaited_once_with(
        USER1, TX1_INCOMING_ADDR1_USDT, "USDT"
    )


async def test_check_address_outgoing_tx_only(
    checker, mock_db, mock_etherscan, mock_notifier
):
    """Test that no notifications are sent for outgoing transactions."""
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan.get_token_transactions.side_effect = [
        [TX2_OUTGOING_ADDR1_USDT],  # USDT transactions
        [],  # USDC transactions
    ]
    mock_db.get_users_for_address.return_value = [USER1]

    await checker.check_all_addresses()

    mock_db.get_distinct_addresses.assert_awaited_once()
    mock_db.get_last_checked_block.assert_awaited_once_with(ADDR1.lower())
    assert mock_etherscan.get_token_transactions.await_count == 2
    mock_notifier.send_token_notification.assert_not_awaited()


async def test_check_mixed_incoming_outgoing(
    checker, mock_db, mock_etherscan, mock_notifier, mock_config
):
    """Test that only incoming transactions trigger notifications."""
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan.get_token_transactions.side_effect = [
        [TX1_INCOMING_ADDR1_USDT, TX2_OUTGOING_ADDR1_USDT],  # USDT transactions
        [],  # USDC transactions
    ]
    mock_db.get_users_for_address.return_value = [USER1]

    await checker.check_all_addresses()

    mock_db.get_distinct_addresses.assert_awaited_once()
    mock_db.get_last_checked_block.assert_awaited_once_with(ADDR1.lower())
    mock_etherscan.get_token_transactions.assert_awaited()
    await mock_notifier.send_token_notification.assert_awaited_once_with(
        USER1, TX1_INCOMING_ADDR1_USDT, "USDT"
    )


async def test_check_multiple_addresses(
    checker, mock_db, mock_etherscan, mock_notifier, mock_config
):
    """Test that multiple addresses are processed correctly."""
    mock_db.get_distinct_addresses.return_value = [ADDR1, ADDR2]
    mock_db.get_last_checked_block.side_effect = [
        BLOCK_ADDR1_START,
        BLOCK_ADDR2_START,
    ]
    mock_etherscan.get_token_transactions.side_effect = [
        [TX1_INCOMING_ADDR1_USDT],  # ADDR1 USDT transactions
        [],  # ADDR1 USDC transactions
        [],  # ADDR2 USDT transactions
        [TX3_INCOMING_ADDR2_USDC],  # ADDR2 USDC transactions
    ]
    mock_db.get_users_for_address.side_effect = [[USER1], [USER2]]

    await checker.check_all_addresses()

    mock_db.get_distinct_addresses.assert_awaited_once()
    assert mock_db.get_last_checked_block.await_count == 2
    mock_etherscan.get_token_transactions.assert_awaited()
    assert mock_notifier.send_token_notification.await_count == 2
    mock_notifier.send_token_notification.assert_any_await(
        USER1, TX1_INCOMING_ADDR1_USDT, "USDT"
    )
    mock_notifier.send_token_notification.assert_any_await(
        USER2, TX3_INCOMING_ADDR2_USDC, "USDC"
    )


async def test_check_etherscan_rate_limit(
    checker, mock_db, mock_etherscan, mock_notifier
):
    """Test that rate limiting is handled correctly."""
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan.get_token_transactions.side_effect = EtherscanRateLimitError(
        "Rate Limited"
    )

    await checker.check_all_addresses()

    mock_db.get_distinct_addresses.assert_awaited_once()
    mock_db.get_last_checked_block.assert_awaited_once_with(ADDR1.lower())
    mock_etherscan.get_token_transactions.assert_awaited()
    mock_notifier.send_token_notification.assert_not_awaited()


def create_mock_transaction(
    timestamp: int, block_number: int, hash: str = None
) -> dict:
    """Helper function to create mock transaction data."""
    if hash is None:
        hash = f"0x{block_number:08x}"
    return {
        "blockNumber": str(block_number),
        "timeStamp": str(timestamp),
        "hash": hash,
        "from": "0xsender",
        "to": ADDR1,
        "value": "1000000",
        "contractAddress": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    }


async def test_transaction_age_filtering(
    checker, mock_db, mock_etherscan, mock_notifier, mock_config
):
    """Test that transactions are filtered by age."""
    # Create transactions with different timestamps
    now = datetime.now(timezone.utc)
    recent_tx = {
        "blockNumber": str(BLOCK_ADDR1_START + 1),
        "timeStamp": str(int((now - timedelta(days=1)).timestamp())),
        "hash": "0x000003e9",
        "from": "0xsender",
        "to": ADDR1,
        "value": "1000000",
        "contractAddress": USDT_CONTRACT,
    }
    old_tx = {
        "blockNumber": str(BLOCK_ADDR1_START + 2),
        "timeStamp": str(int((now - timedelta(days=10)).timestamp())),
        "hash": "0x000003ea",
        "from": "0xsender",
        "to": ADDR1,
        "value": "1000000",
        "contractAddress": USDT_CONTRACT,
    }

    # Setup mock to return both transactions
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan.get_token_transactions.side_effect = [
        [recent_tx, old_tx],  # USDT transactions
        [],  # USDC transactions
    ]
    mock_db.get_users_for_address.return_value = [USER1]

    # Run the checker
    await checker.check_all_addresses()

    # Verify that only the recent transaction was processed
    await mock_notifier.send_token_notification.assert_awaited_once_with(
        USER1, recent_tx, "USDT"
    )


async def test_transaction_count_limiting(
    checker, mock_db, mock_etherscan, mock_notifier
):
    """Test that the number of transactions is limited."""
    # Create more transactions than the limit
    now = datetime.now(timezone.utc)
    transactions = []
    for i in range(15):  # More than max_transactions_per_check (10)
        tx = {
            "blockNumber": str(BLOCK_ADDR1_START + i + 1),
            "timeStamp": str(int((now - timedelta(hours=i)).timestamp())),
            "hash": f"0x{i:08x}",
            "from": "0xsender",
            "to": ADDR1,
            "value": "1000000",
            "contractAddress": USDT_CONTRACT,
        }
        transactions.append(tx)

    # Sort transactions by block number in ascending order
    transactions.sort(key=lambda x: int(x["blockNumber"]))

    # Setup mock to return all transactions
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan.get_token_transactions.side_effect = [
        transactions,  # USDT transactions
        [],  # USDC transactions
    ]
    mock_db.get_users_for_address.return_value = [USER1]

    # Run the checker
    await checker.check_all_addresses()

    # Verify that only the most recent transactions were processed (up to the limit)
    assert mock_notifier.send_token_notification.await_count == 10
    # Verify that transactions were processed in order from newest to oldest
    calls = mock_notifier.send_token_notification.await_args_list
    for i, call in enumerate(calls):
        assert call.args[1]["hash"] == f"0x{(14 - i):08x}"


async def test_invalid_timestamp_handling(
    checker, mock_db, mock_etherscan, mock_notifier, mock_config
):
    """Test handling of transactions with invalid timestamps."""
    # Create a valid transaction and one with invalid timestamp
    now = datetime.now(timezone.utc)
    valid_tx = {
        "blockNumber": str(BLOCK_ADDR1_START + 1),
        "timeStamp": str(int((now - timedelta(days=1)).timestamp())),
        "hash": "0x000003e9",
        "from": "0xsender",
        "to": ADDR1,
        "value": "1000000",
        "contractAddress": USDT_CONTRACT,
    }
    invalid_tx = {
        "blockNumber": str(BLOCK_ADDR1_START + 2),
        "timeStamp": "invalid_timestamp",  # Invalid timestamp
        "hash": "0x000003ea",
        "from": "0xsender",
        "to": ADDR1,
        "value": "1000000",
        "contractAddress": USDT_CONTRACT,
    }

    # Setup mock to return both transactions
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan.get_token_transactions.side_effect = [
        [valid_tx, invalid_tx],  # USDT transactions
        [],  # USDC transactions
    ]
    mock_db.get_users_for_address.return_value = [USER1]

    # Run the checker
    await checker.check_all_addresses()

    # Verify that only the valid transaction was processed
    await mock_notifier.send_token_notification.assert_awaited_once_with(
        USER1, valid_tx, "USDT"
    )


async def test_no_transactions_after_filtering(
    checker, mock_db, mock_etherscan, mock_notifier
):
    """Test that no notifications are sent when all transactions are filtered out."""
    # Create only old transactions
    now = datetime.now(timezone.utc)
    old_tx = {
        "blockNumber": str(BLOCK_ADDR1_START + 1),
        "timeStamp": str(int((now - timedelta(days=10)).timestamp())),
        "hash": "0x000003e9",
        "from": "0xsender",
        "to": ADDR1,
        "value": "1000000",
        "contractAddress": USDT_CONTRACT,
    }

    # Setup mock to return old transactions
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan.get_token_transactions.side_effect = [
        [old_tx],  # USDT transactions
        [],  # USDC transactions
    ]
    mock_db.get_users_for_address.return_value = [USER1]

    # Run the checker
    await checker.check_all_addresses()

    # Verify that no notifications were sent
    mock_notifier.send_token_notification.assert_not_awaited()
    # Verify that the last checked block was updated
    mock_etherscan.get_token_transactions.assert_called()
    mock_db.update_last_checked_block.assert_called()
