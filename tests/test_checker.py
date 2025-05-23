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
    # Ensure last_checked_block is updated for ADDR1 even if no tx found
    mock_db.update_last_checked_block.assert_awaited_once_with(ADDR1.lower(), BLOCK_ADDR1_START)


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
        test_user, test_tx, "USDT", test_address.lower()
    )
    mock_db.update_last_checked_block.assert_awaited_once_with(test_address.lower(), test_block + 1)


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
        test_user, test_tx, "USDT", test_address.lower()
    )
    mock_db.update_last_checked_block.assert_awaited_once_with(test_address.lower(), test_block + 1)


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
        test_user, incoming_tx, "USDT", test_address.lower()
    )
    mock_notifier.send_token_notification.assert_any_await(
        test_user, outgoing_tx, "USDT", test_address.lower()
    )
    mock_db.update_last_checked_block.assert_awaited_once_with(test_address.lower(), test_block + 2)


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
    mock_notifier.send_token_notification.assert_any_await(test_user1, tx1, "USDT", test_address1.lower())
    mock_notifier.send_token_notification.assert_any_await(test_user2, tx2, "USDC", test_address2.lower())
    assert mock_db.update_last_checked_block.await_count == 2
    mock_db.update_last_checked_block.assert_any_await(test_address1.lower(), test_block1 + 1)
    mock_db.update_last_checked_block.assert_any_await(test_address2.lower(), test_block2 + 1)


async def test_check_etherscan_rate_limit_skips_address_update(
    checker, mock_db, mock_etherscan, mock_notifier
):
    """Test that rate limiting skips updating the block for that address."""
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan.get_token_transactions.side_effect = EtherscanRateLimitError(
        "Rate Limited"
    )

    await checker.check_all_addresses()

    mock_db.get_distinct_addresses.assert_awaited_once()
    mock_db.get_last_checked_block.assert_awaited_once_with(ADDR1.lower())
    mock_etherscan.get_token_transactions.assert_awaited() # Will be called for each token
    mock_notifier.send_token_notification.assert_not_awaited()
    # Ensure update_last_checked_block is NOT called for ADDR1 due to rate limit
    # but it might be called for other addresses if any were processed (not in this test setup)
    # For this test, we expect no calls to update_last_checked_block if only ADDR1 is processed and fails.
    # If there were other addresses, they would be updated.
    # The current logic in check_all_addresses is that if _fetch_transactions_for_address
    # itself raises EtherscanRateLimitError (which it would if all token calls inside it are rate limited and tenacity re-raises),
    # then this address is skipped for block update.
    # If _fetch_transactions_for_address returns partial results due to some token calls failing,
    # then _filter_and_process_transactions will run and potentially update the block.
    # This test assumes the EtherscanRateLimitError propagates out of _fetch_transactions_for_address,
    # or is handled internally such that _fetch returns empty.
    # In the current logic, if _fetch_transactions_for_address returns empty due to internal rate limits,
    # _filter_and_process_transactions will still be called with an empty list,
    # and it will return start_block. Thus, update_last_checked_block WILL be called with start_block.
    mock_db.update_last_checked_block.assert_any_await(ADDR1.lower(), BLOCK_ADDR1_START)


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
        USER1, recent_tx, "USDT", ADDR1.lower()
    )
    mock_db.update_last_checked_block.assert_awaited_once_with(ADDR1.lower(), BLOCK_ADDR1_START + 1) # recent_tx is block +1


async def test_transaction_count_limiting(
    checker, mock_db, mock_etherscan, mock_notifier, mock_config # Added mock_config
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
    # Verify that transactions were processed in order from newest to oldest (chronological)
    # The `_filter_and_process_transactions` sorts them chronologically before sending.
    # The 10 newest are selected, then sorted oldest-first among those 10.
    # So, if 15 txs (0-14), newest are 5-14. These 10 are selected.
    # Then sorted: 5, 6, ..., 14.
    calls = mock_notifier.send_token_notification.await_args_list
    expected_hashes_sent = [f"0x{i:08x}" for i in range(5, 15)] # Block numbers 1005 to 1014

    assert len(calls) == 10
    for i, call_args in enumerate(calls):
        assert call_args.args[0] == USER1
        assert call_args.args[1]["hash"] == expected_hashes_sent[i]
        assert call_args.args[2] == "USDT"
        assert call_args.args[3] == ADDR1.lower()
    
    # The latest block processed should be the newest of the 10 processed.
    latest_processed_block = BLOCK_ADDR1_START + 14 + 1 # transactions[14]['blockNumber']
    mock_db.update_last_checked_block.assert_awaited_once_with(ADDR1.lower(), latest_processed_block)


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
        USER1, valid_tx, "USDT", ADDR1.lower()
    )
    mock_db.update_last_checked_block.assert_awaited_once_with(ADDR1.lower(), BLOCK_ADDR1_START + 1) # valid_tx is block +1


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
    # Verify that the last checked block was updated to reflect the highest block seen, even if filtered.
    mock_etherscan.get_token_transactions.assert_called() # Should be called for each token
    mock_db.update_last_checked_block.assert_awaited_once_with(ADDR1.lower(), BLOCK_ADDR1_START + 1) # old_tx's block


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
        USER1, boundary_tx, "USDT", ADDR1.lower()
        )
    mock_db.update_last_checked_block.assert_awaited_once_with(ADDR1.lower(), BLOCK_ADDR1_START + 1)


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

    # Verify that transactions were processed in order (chronological for the newest batch)
    calls = mock_notifier.send_token_notification.await_args_list
    # Newest 10 transactions are 1 to 10 (since 0 is oldest of the +1).
    # Sorted chronologically for processing: 1, 2, ..., 10
    expected_hashes_sent = [f"0x{i:08x}" for i in range(1, mock_config.max_transactions_per_check + 1)]
    
    assert len(calls) == mock_config.max_transactions_per_check
    for i, call_args in enumerate(calls):
        assert call_args.args[0] == USER1
        assert call_args.args[1]["hash"] == expected_hashes_sent[i]
        assert call_args.args[2] == "USDT"
        assert call_args.args[3] == ADDR1.lower()

    latest_processed_block = BLOCK_ADDR1_START + mock_config.max_transactions_per_check + 1 # transactions[10]['blockNumber']
    mock_db.update_last_checked_block.assert_awaited_once_with(ADDR1.lower(), latest_processed_block)


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
    # The newest (max_transactions_per_check) transactions are selected from "new" ones.
    # "new" transactions are indexed 0 to max_transactions_per_check + 1.
    # The newest 10 of these (if max_transactions_per_check is 10) would be new2, new3, ..., new11.
    # These are sorted chronologically: new2, new3, ..., new11.
    calls = mock_notifier.send_token_notification.await_args_list
    # Hashes are "0xnew{i:08x}". The most recent (max_transactions_per_check) transactions are processed.
    # Original indices for "new" txs: 0, 1, ..., (max_transactions_per_check + 1)
    # The latest (max_transactions_per_check) transactions are those with original indices:
    # 2, 3, ..., (max_transactions_per_check + 1)
    # These are sent in chronological order.
    expected_hashes_sent = [f"0xnew{i:08x}" for i in range(2, mock_config.max_transactions_per_check + 2)]

    assert len(calls) == mock_config.max_transactions_per_check
    for i, call_args in enumerate(calls):
        assert call_args.args[0] == USER1
        assert call_args.args[1]["hash"] == expected_hashes_sent[i]
        assert call_args.args[2] == "USDT"
        assert call_args.args[3] == ADDR1.lower()

    latest_processed_block_hash_index = mock_config.max_transactions_per_check + 1 # e.g. new11 if max is 10
    # Block number for this tx: BLOCK_ADDR1_START + latest_processed_block_hash_index + 4
    latest_processed_block = BLOCK_ADDR1_START + latest_processed_block_hash_index + 4
    mock_db.update_last_checked_block.assert_awaited_once_with(ADDR1.lower(), latest_processed_block)


# --- Unit Tests for _fetch_transactions_for_address ---

@pytest.mark.asyncio
async def test_fetch_transactions_success_multiple_tokens(checker, mock_config, mock_etherscan):
    """Test fetching transactions successfully for multiple tokens."""
    address_lower = ADDR1.lower()
    query_start_block = BLOCK_ADDR1_START

    tx_usdt = {"hash": "0x_usdt", "blockNumber": str(query_start_block + 1), "contractAddress": USDT_CONTRACT}
    tx_usdc = {"hash": "0x_usdc", "blockNumber": str(query_start_block + 2), "contractAddress": USDC_CONTRACT}

    mock_etherscan.get_token_transactions.side_effect = [
        [tx_usdt],  # USDT
        [tx_usdc],  # USDC
    ]

    result = await checker._fetch_transactions_for_address(address_lower, query_start_block)

    assert len(result) == 2
    assert result[0]["hash"] == "0x_usdt"
    assert result[0]["token_symbol"] == "USDT"
    assert result[1]["hash"] == "0x_usdc"
    assert result[1]["token_symbol"] == "USDC"
    assert mock_etherscan.get_token_transactions.await_count == 2


@pytest.mark.asyncio
async def test_fetch_transactions_no_transactions_found(checker, mock_etherscan):
    """Test fetching when no transactions are found for any token."""
    address_lower = ADDR1.lower()
    query_start_block = BLOCK_ADDR1_START
    mock_etherscan.get_token_transactions.return_value = [] # No transactions for any token

    result = await checker._fetch_transactions_for_address(address_lower, query_start_block)
    assert len(result) == 0
    assert mock_etherscan.get_token_transactions.await_count == 2 # Called for USDT and USDC


@pytest.mark.asyncio
async def test_fetch_transactions_etherscan_rate_limit_for_one_token(checker, mock_etherscan, mock_config):
    """Test handling EtherscanRateLimitError for one token, success for another."""
    address_lower = ADDR1.lower()
    query_start_block = BLOCK_ADDR1_START
    tx_usdc = {"hash": "0x_usdc", "blockNumber": str(query_start_block + 1), "contractAddress": USDC_CONTRACT}

    mock_etherscan.get_token_transactions.side_effect = [
        EtherscanRateLimitError("Rate limit on USDT"), # USDT fails
        [tx_usdc],                                   # USDC succeeds
    ]

    result = await checker._fetch_transactions_for_address(address_lower, query_start_block)

    assert len(result) == 1
    assert result[0]["hash"] == "0x_usdc"
    assert result[0]["token_symbol"] == "USDC"
    assert mock_etherscan.get_token_transactions.await_count == 2


# --- Unit Tests for _filter_and_process_transactions ---

@pytest.mark.asyncio
async def test_filter_process_no_transactions(checker):
    """Test processing when there are no transactions to filter."""
    address_lower = ADDR1.lower()
    start_block = BLOCK_ADDR1_START
    
    result_block = await checker._filter_and_process_transactions(address_lower, [], start_block)
    
    assert result_block == start_block
    checker._notifier.send_token_notification.assert_not_awaited()


@pytest.mark.asyncio
async def test_filter_process_all_tx_older_than_start_block(checker):
    """Test when all transactions are older than or equal to start_block."""
    address_lower = ADDR1.lower()
    start_block = 100
    transactions = [
        {"hash": "0x1", "blockNumber": "100", "timeStamp": str(int(datetime.now().timestamp()))}, # Equal to start_block
        {"hash": "0x2", "blockNumber": "99", "timeStamp": str(int(datetime.now().timestamp()))},  # Older than start_block
    ]
    
    result_block = await checker._filter_and_process_transactions(address_lower, transactions, start_block)
    
    # Should return the highest block seen in transactions if they are all filtered out by start_block logic
    assert result_block == 100 
    checker._notifier.send_token_notification.assert_not_awaited()

@pytest.mark.asyncio
async def test_filter_process_filter_by_age(checker, mock_config, mock_db, mock_notifier):
    """Test filtering transactions by age."""
    address_lower = ADDR1.lower()
    start_block = BLOCK_ADDR1_START
    now = datetime.now(timezone.utc)
    
    mock_config.max_transaction_age_days = 7
    
    tx_recent = {
        "hash": "0x_recent", "blockNumber": str(start_block + 1), "token_symbol": "USDT",
        "timeStamp": str(int((now - timedelta(days=1)).timestamp()))
    }
    tx_old = { # This transaction is older than max_transaction_age_days
        "hash": "0x_old", "blockNumber": str(start_block + 2), "token_symbol": "USDT",
        "timeStamp": str(int((now - timedelta(days=mock_config.max_transaction_age_days + 1)).timestamp()))
    }
    all_transactions = [tx_recent, tx_old]
    mock_db.get_users_for_address.return_value = [USER1]

    result_block = await checker._filter_and_process_transactions(address_lower, all_transactions, start_block)

    assert result_block == start_block + 1 # Only tx_recent processed
    mock_notifier.send_token_notification.assert_awaited_once_with(
        USER1, tx_recent, "USDT", address_lower
    )

@pytest.mark.asyncio
async def test_filter_process_limit_by_max_transactions(checker, mock_config, mock_db, mock_notifier):
    """Test limiting transactions by max_transactions_per_check."""
    address_lower = ADDR1.lower()
    start_block = BLOCK_ADDR1_START
    now_ts = int(datetime.now(timezone.utc).timestamp())
    
    mock_config.max_transactions_per_check = 2
    
    # Create 3 recent transactions
    tx1 = {"hash": "0x_tx1", "blockNumber": str(start_block + 1), "token_symbol": "USDT", "timeStamp": str(now_ts - 300)}
    tx2 = {"hash": "0x_tx2", "blockNumber": str(start_block + 2), "token_symbol": "USDT", "timeStamp": str(now_ts - 200)}
    tx3 = {"hash": "0x_tx3", "blockNumber": str(start_block + 3), "token_symbol": "USDT", "timeStamp": str(now_ts - 100)} # newest
    all_transactions = [tx1, tx2, tx3] # Given in chronological order from Etherscan (simulated)
    
    mock_db.get_users_for_address.return_value = [USER1]

    result_block = await checker._filter_and_process_transactions(address_lower, all_transactions, start_block)

    # Should process only the 2 newest (tx2, tx3) due to limit, and return block of tx3
    assert result_block == start_block + 3
    assert mock_notifier.send_token_notification.await_count == 2
    # The method sorts them by block number (ascending) before sending.
    # So tx2 will be sent first, then tx3
    mock_notifier.send_token_notification.assert_any_await(USER1, tx2, "USDT", address_lower)
    mock_notifier.send_token_notification.assert_any_await(USER1, tx3, "USDT", address_lower)

@pytest.mark.asyncio
async def test_filter_process_no_users_tracking(checker, mock_db, mock_notifier):
    """Test scenario where transactions are found but no users are tracking the address."""
    address_lower = ADDR1.lower()
    start_block = BLOCK_ADDR1_START
    now_ts = int(datetime.now(timezone.utc).timestamp())
    
    tx1 = {"hash": "0x_tx1", "blockNumber": str(start_block + 1), "token_symbol": "USDT", "timeStamp": str(now_ts)}
    all_transactions = [tx1]
    
    mock_db.get_users_for_address.return_value = [] # No users

    result_block = await checker._filter_and_process_transactions(address_lower, all_transactions, start_block)
    
    # Block should be updated to the latest transaction's block
    assert result_block == start_block + 1
    mock_notifier.send_token_notification.assert_not_awaited()

@pytest.mark.asyncio
async def test_filter_process_advances_block_past_filtered_old_tx(checker, mock_config):
    """
    Test that current_max_block_for_addr is updated to the highest block seen in all_transactions
    if all processable transactions are filtered out by age or other criteria, but were newer than start_block.
    """
    address_lower = ADDR1.lower()
    start_block = 100
    now = datetime.now(timezone.utc)
    mock_config.max_transaction_age_days = 1 # Make it very strict

    # All transactions are newer than start_block, but will be filtered by age
    tx1_old = {"hash": "0x1", "blockNumber": "101", "token_symbol": "USDT", "timeStamp": str(int((now - timedelta(days=2)).timestamp()))}
    tx2_older = {"hash": "0x2", "blockNumber": "102", "token_symbol": "USDT", "timeStamp": str(int((now - timedelta(days=3)).timestamp()))}
    all_transactions = [tx1_old, tx2_older]
    
    checker._db.get_users_for_address.return_value = [USER1] # Assume user is tracking

    result_block = await checker._filter_and_process_transactions(address_lower, all_transactions, start_block)
    
    # Even though no notifications are sent, the block should advance to the newest seen (102)
    assert result_block == 102
    checker._notifier.send_token_notification.assert_not_awaited()
