# tests/test_checker.py
import unittest.mock
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from usdt_monitor_bot.checker import TransactionChecker
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
    config = MagicMock()
    config.etherscan_base_url = "https://api.etherscan.io/api"
    config.etherscan_api_key = "test_api_key"
    config.telegram_bot_token = "test_bot_token"
    config.db_path = "test.db"
    config.etherscan_request_delay = 0.2
    config.check_interval_seconds = 60
    config.max_transaction_age_days = 7
    config.max_transactions_per_check = 10

    # Create token registry mock
    token_registry = MagicMock()
    usdt_token = MagicMock()
    usdt_token.contract_address = USDT_CONTRACT
    usdt_token.symbol = "USDT"
    usdc_token = MagicMock()
    usdc_token.contract_address = USDC_CONTRACT
    usdc_token.symbol = "USDC"

    # Setup token registry methods
    token_registry.get_all_tokens.return_value = {
        "USDT": usdt_token,
        "USDC": usdc_token,
    }
    token_registry.get_token_by_address.side_effect = lambda addr: next(
        (
            token
            for token in token_registry.get_all_tokens().values()
            if token.contract_address.lower() == addr.lower()
        ),
        None,
    )
    token_registry.get_token.side_effect = lambda symbol: {
        "USDT": usdt_token,
        "USDC": usdc_token,
    }.get(symbol)

    config.token_registry = token_registry
    return config


@pytest.fixture
def mock_db():
    """Create a mock database object."""
    db = AsyncMock(spec=DatabaseManager)
    db.get_distinct_addresses = AsyncMock(return_value=[])
    db.get_last_checked_block = AsyncMock(return_value=0)
    db.get_users_for_address = AsyncMock(return_value=[])
    db.update_last_checked_block = AsyncMock(return_value=True)
    return db


@pytest.fixture
def mock_etherscan():
    """Create a mock Etherscan client."""
    client = AsyncMock(spec=EtherscanClient)
    client.get_token_transactions = AsyncMock(return_value=[])
    return client


@pytest.fixture
def mock_notifier():
    """Create a mock notification service."""
    notifier = AsyncMock(spec=NotificationService)
    notifier._bot = AsyncMock()
    notifier._bot.send_message = AsyncMock(return_value=None)
    notifier._config = MagicMock()
    notifier._format_token_message = MagicMock(return_value="Test message")
    notifier.send_token_notification = AsyncMock(return_value=None)
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
    # Setup test data
    test_address = "0x123"
    test_user = 12345
    test_block = 1000
    test_tx = {
        "hash": "0xabc",
        "blockNumber": str(test_block + 1),
        "timeStamp": str(int(datetime.now(timezone.utc).timestamp())),
        "from": "0xsender",
        "to": test_address,
        "value": "1000000",
        "contractAddress": mock_config.token_registry.get_all_tokens()[
            "USDT"
        ].contract_address,
    }

    # Setup mocks
    mock_db.get_distinct_addresses.return_value = [test_address]
    mock_db.get_last_checked_block.return_value = test_block
    mock_etherscan.get_token_transactions.side_effect = [
        [test_tx],  # USDT transactions
        [],  # USDC transactions
    ]
    mock_db.get_users_for_address.return_value = [test_user]

    # Run the checker
    await checker.check_all_addresses()

    # Verify behavior
    mock_db.get_distinct_addresses.assert_awaited_once()
    mock_db.get_last_checked_block.assert_awaited_once_with(test_address.lower())
    mock_etherscan.get_token_transactions.assert_awaited()
    mock_notifier.send_token_notification.assert_awaited_once_with(
        test_user, test_tx, "USDT"
    )


async def test_check_address_outgoing_tx_only(
    checker, mock_db, mock_etherscan, mock_notifier, mock_config
):
    """Test that notifications are sent for outgoing transactions."""
    # Setup test data
    test_address = "0x123"
    test_user = 12345
    test_block = 1000
    test_tx = {
        "hash": "0xabc",
        "blockNumber": str(test_block + 1),
        "timeStamp": str(int(datetime.now(timezone.utc).timestamp())),
        "from": test_address,
        "to": "0xrecipient",
        "value": "1000000",
        "contractAddress": mock_config.token_registry.get_all_tokens()[
            "USDT"
        ].contract_address,
    }

    # Setup mocks
    mock_db.get_distinct_addresses.return_value = [test_address]
    mock_db.get_last_checked_block.return_value = test_block
    mock_etherscan.get_token_transactions.side_effect = [
        [test_tx],  # USDT transactions
        [],  # USDC transactions
    ]
    mock_db.get_users_for_address.return_value = [test_user]

    # Run the checker
    await checker.check_all_addresses()

    # Verify behavior
    mock_db.get_distinct_addresses.assert_awaited_once()
    mock_db.get_last_checked_block.assert_awaited_once_with(test_address.lower())
    assert mock_etherscan.get_token_transactions.await_count == 2
    mock_notifier.send_token_notification.assert_awaited_once_with(
        test_user, test_tx, "USDT"
    )


async def test_check_mixed_incoming_outgoing(
    checker, mock_db, mock_etherscan, mock_notifier, mock_config
):
    """Test that both incoming and outgoing transactions trigger notifications."""
    # Setup test data
    test_address = "0x123"
    test_user = 12345
    test_block = 1000
    incoming_tx = {
        "hash": "0xabc",
        "blockNumber": str(test_block + 1),
        "timeStamp": str(int(datetime.now(timezone.utc).timestamp())),
        "from": "0xsender",
        "to": test_address,
        "value": "1000000",
        "contractAddress": mock_config.token_registry.get_all_tokens()[
            "USDT"
        ].contract_address,
    }
    outgoing_tx = {
        "hash": "0xdef",
        "blockNumber": str(test_block + 2),
        "timeStamp": str(int(datetime.now(timezone.utc).timestamp())),
        "from": test_address,
        "to": "0xrecipient",
        "value": "1000000",
        "contractAddress": mock_config.token_registry.get_all_tokens()[
            "USDT"
        ].contract_address,
    }

    # Setup mocks
    mock_db.get_distinct_addresses.return_value = [test_address]
    mock_db.get_last_checked_block.return_value = test_block
    mock_etherscan.get_token_transactions.side_effect = [
        [incoming_tx, outgoing_tx],  # USDT transactions
        [],  # USDC transactions
    ]
    mock_db.get_users_for_address.return_value = [test_user]

    # Run the checker
    await checker.check_all_addresses()

    # Verify behavior
    mock_db.get_distinct_addresses.assert_awaited_once()
    mock_db.get_last_checked_block.assert_awaited_once_with(test_address.lower())
    mock_etherscan.get_token_transactions.assert_awaited()
    assert mock_notifier.send_token_notification.await_count == 2
    mock_notifier.send_token_notification.assert_any_await(
        test_user, incoming_tx, "USDT"
    )
    mock_notifier.send_token_notification.assert_any_await(
        test_user, outgoing_tx, "USDT"
    )


async def test_check_multiple_addresses(
    checker, mock_db, mock_etherscan, mock_notifier, mock_config
):
    """Test that multiple addresses are processed correctly."""
    # Setup test data
    test_address1 = "0x123"
    test_address2 = "0x456"
    test_user1 = 12345
    test_user2 = 67890
    test_block1 = 1000
    test_block2 = 2000
    tx1 = {
        "hash": "0xabc",
        "blockNumber": str(test_block1 + 1),
        "timeStamp": str(int(datetime.now(timezone.utc).timestamp())),
        "from": "0xsender",
        "to": test_address1,
        "value": "1000000",
        "contractAddress": mock_config.token_registry.get_all_tokens()[
            "USDT"
        ].contract_address,
    }
    tx2 = {
        "hash": "0xdef",
        "blockNumber": str(test_block2 + 1),
        "timeStamp": str(int(datetime.now(timezone.utc).timestamp())),
        "from": "0xsender",
        "to": test_address2,
        "value": "1000000",
        "contractAddress": mock_config.token_registry.get_all_tokens()[
            "USDC"
        ].contract_address,
    }

    # Setup mocks
    mock_db.get_distinct_addresses.return_value = [test_address1, test_address2]
    mock_db.get_last_checked_block.side_effect = [test_block1, test_block2]
    mock_etherscan.get_token_transactions.side_effect = [
        [tx1],  # ADDR1 USDT transactions
        [],  # ADDR1 USDC transactions
        [],  # ADDR2 USDT transactions
        [tx2],  # ADDR2 USDC transactions
    ]
    mock_db.get_users_for_address.side_effect = [[test_user1], [test_user2]]

    # Run the checker
    await checker.check_all_addresses()

    # Verify behavior
    mock_db.get_distinct_addresses.assert_awaited_once()
    assert mock_db.get_last_checked_block.await_count == 2
    mock_etherscan.get_token_transactions.assert_awaited()
    assert mock_notifier.send_token_notification.await_count == 2
    mock_notifier.send_token_notification.assert_any_await(test_user1, tx1, "USDT")
    mock_notifier.send_token_notification.assert_any_await(test_user2, tx2, "USDC")


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
    mock_notifier.send_token_notification.assert_awaited_once_with(
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
    mock_notifier.send_token_notification.assert_awaited_once_with(
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


async def test_transaction_age_boundary_handling(
    checker, mock_db, mock_etherscan, mock_notifier, mock_config
):
    """Test that transactions exactly at the age boundary are included."""
    # Create transactions with timestamps exactly at the boundary
    now = datetime.now(timezone.utc)
    now_ts = int(now.timestamp())  # Convert to integer timestamp
    # Mock the current time in the checker to match our test time
    with unittest.mock.patch("usdt_monitor_bot.checker.datetime") as mock_datetime:
        mock_datetime.now.return_value = datetime.fromtimestamp(now_ts, tz=timezone.utc)
        mock_datetime.fromtimestamp = datetime.fromtimestamp
        boundary_age = timedelta(days=mock_config.max_transaction_age_days)
        boundary_age_seconds = int(boundary_age.total_seconds())
        boundary_tx = {
            "blockNumber": str(BLOCK_ADDR1_START + 1),
            "timeStamp": str(now_ts - boundary_age_seconds),
            "hash": "0x000003e9",
            "from": "0xsender",
            "to": ADDR1,
            "value": "1000000",
            "contractAddress": USDT_CONTRACT,
        }
        just_old_tx = {
            "blockNumber": str(BLOCK_ADDR1_START + 2),
            "timeStamp": str(now_ts - boundary_age_seconds - 1),
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
            [boundary_tx, just_old_tx],  # USDT transactions
            [],  # USDC transactions
        ]
        mock_db.get_users_for_address.return_value = [USER1]

        # Run the checker
        await checker.check_all_addresses()

        # Verify that only the boundary transaction was processed
        mock_notifier.send_token_notification.assert_awaited_once_with(
            USER1, boundary_tx, "USDT"
        )


async def test_transaction_count_boundary_handling(
    checker, mock_db, mock_etherscan, mock_notifier, mock_config
):
    """Test that exactly max_transactions_per_check transactions are processed."""
    # Create exactly max_transactions_per_check + 1 transactions
    now = datetime.now(timezone.utc)
    transactions = []
    for i in range(mock_config.max_transactions_per_check + 1):
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

    # Verify that exactly max_transactions_per_check transactions were processed
    assert (
        mock_notifier.send_token_notification.await_count
        == mock_config.max_transactions_per_check
    )

    # Verify that transactions were processed in order from newest to oldest
    calls = mock_notifier.send_token_notification.await_args_list
    for i, call in enumerate(calls):
        # The newest transaction has the highest index
        expected_index = mock_config.max_transactions_per_check - i
        assert call.args[1]["hash"] == f"0x{expected_index:08x}"


async def test_transaction_filtering_combined_boundaries(
    checker, mock_db, mock_etherscan, mock_notifier, mock_config
):
    """Test that both age and count boundaries work together correctly."""
    # Create a mix of old and recent transactions
    now = datetime.now(timezone.utc)
    boundary_age = timedelta(days=mock_config.max_transaction_age_days)
    transactions = []

    # Add some old transactions
    for i in range(3):
        tx = {
            "blockNumber": str(BLOCK_ADDR1_START + i + 1),
            "timeStamp": str(
                int((now - boundary_age - timedelta(days=i + 1)).timestamp())
            ),
            "hash": f"0xold{i:08x}",
            "from": "0xsender",
            "to": ADDR1,
            "value": "1000000",
            "contractAddress": USDT_CONTRACT,
        }
        transactions.append(tx)

    # Add more recent transactions than max_transactions_per_check
    for i in range(mock_config.max_transactions_per_check + 2):
        tx = {
            "blockNumber": str(BLOCK_ADDR1_START + i + 4),
            "timeStamp": str(int((now - timedelta(hours=i)).timestamp())),
            "hash": f"0xnew{i:08x}",
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

    # Verify that exactly max_transactions_per_check recent transactions were processed
    assert (
        mock_notifier.send_token_notification.await_count
        == mock_config.max_transactions_per_check
    )

    # Verify that only recent transactions were processed (none of the old ones)
    calls = mock_notifier.send_token_notification.await_args_list
    for i, call in enumerate(calls):
        # The newest transaction has the highest index
        expected_index = mock_config.max_transactions_per_check + 1 - i
        assert call.args[1]["hash"] == f"0xnew{expected_index:08x}"
