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

# --- Constants ---
ADDR1 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ADDR2 = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
USER1 = 101
USER2 = 202
BLOCK_ADDR1_START = 1000
USDT_CONTRACT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
USDC_CONTRACT = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
NOW_TS = int(datetime.now(timezone.utc).timestamp())


# --- Helper Functions ---
def create_mock_tx(
    block_number: int,
    from_addr: str,
    to_addr: str,
    contract_address: str,
    timestamp: int = NOW_TS,
    tx_hash: str = None,
) -> dict:
    """Creates a mock transaction dictionary."""
    if tx_hash is None:
        tx_hash = f"0x{block_number:08x}"
    return {
        "blockNumber": str(block_number),
        "timeStamp": str(timestamp),
        "hash": tx_hash,
        "from": from_addr,
        "to": to_addr,
        "value": "1000000",
        "contractAddress": contract_address,
    }


# --- Fixtures ---
@pytest.fixture
def mock_config():
    """Creates a mock config object with a token registry."""
    config = MagicMock()
    config.etherscan_request_delay = 0
    config.max_transaction_age_days = 7
    config.max_transactions_per_check = 10

    token_registry = MagicMock()
    usdt_token = MagicMock(contract_address=USDT_CONTRACT, symbol="USDT")
    usdc_token = MagicMock(contract_address=USDC_CONTRACT, symbol="USDC")

    token_registry.get_all_tokens.return_value = {
        "USDT": usdt_token,
        "USDC": usdc_token,
    }
    token_map = {
        USDT_CONTRACT: usdt_token,
        USDC_CONTRACT: usdc_token,
    }
    token_registry.get_token_by_address.side_effect = lambda addr: token_map.get(
        addr.lower()
    )
    config.token_registry = token_registry
    return config


@pytest.fixture
def mock_db():
    """Creates a mock DatabaseManager."""
    return AsyncMock(spec=DatabaseManager)


@pytest.fixture
def mock_etherscan():
    """Creates a mock EtherscanClient."""
    return AsyncMock(spec=EtherscanClient)


@pytest.fixture
def mock_notifier():
    """Creates a mock NotificationService."""
    return AsyncMock(spec=NotificationService)


@pytest.fixture
def checker(mock_config, mock_db, mock_etherscan, mock_notifier):
    """Creates a TransactionChecker with mocked dependencies."""
    return TransactionChecker(mock_config, mock_db, mock_etherscan, mock_notifier)


# --- High-Level `check_all_addresses` Tests ---


async def test_check_no_addresses(checker: TransactionChecker, mock_db: AsyncMock):
    """Test that the checker handles having no addresses to check."""
    mock_db.get_distinct_addresses.return_value = []

    await checker.check_all_addresses()

    mock_db.get_distinct_addresses.assert_awaited_once()
    mock_db.get_last_checked_block.assert_not_awaited()


async def test_check_address_no_new_tx(
    checker: TransactionChecker,
    mock_db: AsyncMock,
    mock_etherscan: AsyncMock,
    mock_notifier: AsyncMock,
):
    """Test checking an address with no new transactions."""
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan.get_token_transactions.return_value = []

    await checker.check_all_addresses()

    mock_db.get_last_checked_block.assert_awaited_once_with(ADDR1.lower())
    # Etherscan client is called for each token (USDT, USDC)
    assert mock_etherscan.get_token_transactions.await_count == 2
    mock_notifier.send_token_notification.assert_not_awaited()
    # The block should not be updated if it hasn't changed.
    mock_db.update_last_checked_block.assert_not_awaited()


@pytest.mark.parametrize(
    "test_id, transactions, expected_notifications, final_block",
    [
        (
            "incoming_only",
            [create_mock_tx(BLOCK_ADDR1_START + 1, "0xsender", ADDR1, USDT_CONTRACT)],
            1,
            BLOCK_ADDR1_START + 1,
        ),
        (
            "outgoing_only",
            [create_mock_tx(BLOCK_ADDR1_START + 1, ADDR1, "0xrecipient", USDT_CONTRACT)],
            1,
            BLOCK_ADDR1_START + 1,
        ),
        (
            "mixed_incoming_outgoing",
            [
                create_mock_tx(BLOCK_ADDR1_START + 1, "0xsender", ADDR1, USDT_CONTRACT),
                create_mock_tx(BLOCK_ADDR1_START + 2, ADDR1, "0xrecipient", USDT_CONTRACT),
            ],
            2,
            BLOCK_ADDR1_START + 2,
        ),
    ],
)
async def test_check_single_address_with_tx(
    test_id: str,
    transactions: list[dict],
    expected_notifications: int,
    final_block: int,
    checker: TransactionChecker,
    mock_db: AsyncMock,
    mock_etherscan: AsyncMock,
    mock_notifier: AsyncMock,
):
    """Test processing new transactions (incoming, outgoing, mixed) for a single address."""
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_db.get_users_for_address.return_value = [USER1]
    # Assume all test transactions are for USDT
    mock_etherscan.get_token_transactions.side_effect = [transactions, []]

    await checker.check_all_addresses()

    assert mock_notifier.send_token_notification.await_count == expected_notifications
    mock_db.update_last_checked_block.assert_awaited_once_with(ADDR1.lower(), final_block)
    # Verify the last sent notification is for the last transaction
    if expected_notifications > 0:
        last_tx = transactions[-1]
        mock_notifier.send_token_notification.assert_any_await(
            USER1, last_tx, "USDT", ADDR1.lower()
        )


async def test_check_multiple_addresses(
    checker: TransactionChecker,
    mock_db: AsyncMock,
    mock_etherscan: AsyncMock,
    mock_notifier: AsyncMock,
):
    """Test that multiple addresses with different tokens are processed correctly."""
    tx1 = create_mock_tx(BLOCK_ADDR1_START + 1, "0xsender", ADDR1, USDT_CONTRACT)
    tx2 = create_mock_tx(BLOCK_ADDR1_START + 10, "0xsender", ADDR2, USDC_CONTRACT)

    mock_db.get_distinct_addresses.return_value = [ADDR1, ADDR2]
    mock_db.get_last_checked_block.side_effect = [BLOCK_ADDR1_START, BLOCK_ADDR1_START + 9]
    mock_db.get_users_for_address.side_effect = [[USER1], [USER2]]
    mock_etherscan.get_token_transactions.side_effect = [
        [tx1], [],  # ADDR1: USDT tx, no USDC tx
        [], [tx2],  # ADDR2: no USDT tx, USDC tx
    ]

    await checker.check_all_addresses()

    assert mock_notifier.send_token_notification.await_count == 2
    mock_notifier.send_token_notification.assert_any_await(USER1, tx1, "USDT", ADDR1.lower())
    mock_notifier.send_token_notification.assert_any_await(USER2, tx2, "USDC", ADDR2.lower())

    assert mock_db.update_last_checked_block.await_count == 2
    mock_db.update_last_checked_block.assert_any_await(ADDR1.lower(), int(tx1["blockNumber"]))
    mock_db.update_last_checked_block.assert_any_await(ADDR2.lower(), int(tx2["blockNumber"]))


async def test_check_etherscan_rate_limit_skips_block_update(
    checker: TransactionChecker, mock_db: AsyncMock, mock_etherscan: AsyncMock
):
    """Test that a rate-limited address is skipped and its block is not updated."""
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    # Simulate rate limit error for all token fetches for the address
    checker._fetch_transactions_for_address = AsyncMock(side_effect=EtherscanRateLimitError("Rate Limited"))

    await checker.check_all_addresses()

    # The block should not be updated for the rate-limited address.
    mock_db.update_last_checked_block.assert_not_awaited()


async def test_transaction_age_filtering(
    checker: TransactionChecker, mock_db: AsyncMock, mock_etherscan: AsyncMock, mock_notifier: AsyncMock
):
    """Test that transactions older than `max_transaction_age_days` are ignored."""
    recent_ts = int(NOW_TS - timedelta(days=1).total_seconds())
    old_ts = int(NOW_TS - timedelta(days=8).total_seconds())

    recent_tx = create_mock_tx(BLOCK_ADDR1_START + 1, "0xsender", ADDR1, USDT_CONTRACT, timestamp=recent_ts)
    old_tx = create_mock_tx(BLOCK_ADDR1_START + 2, "0xsender", ADDR1, USDT_CONTRACT, timestamp=old_ts)

    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_db.get_users_for_address.return_value = [USER1]
    mock_etherscan.get_token_transactions.side_effect = [[recent_tx, old_tx], []]

    await checker.check_all_addresses()

    # Only the recent transaction should be processed
    mock_notifier.send_token_notification.assert_awaited_once_with(USER1, recent_tx, "USDT", ADDR1.lower())
    # The block number should be updated to the highest *seen*, even if filtered
    mock_db.update_last_checked_block.assert_awaited_once_with(ADDR1.lower(), BLOCK_ADDR1_START + 2)


async def test_transaction_count_limiting(
    checker: TransactionChecker, mock_db: AsyncMock, mock_etherscan: AsyncMock, mock_notifier: AsyncMock, mock_config: MagicMock
):
    """Test that only `max_transactions_per_check` are processed."""
    # Create more transactions than the limit
    tx_count = mock_config.max_transactions_per_check + 5
    transactions = [
        create_mock_tx(BLOCK_ADDR1_START + i + 1, "0xsender", ADDR1, USDT_CONTRACT)
        for i in range(tx_count)
    ]

    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_db.get_users_for_address.return_value = [USER1]
    mock_etherscan.get_token_transactions.side_effect = [transactions, []]

    await checker.check_all_addresses()

    # Verify that only the configured number of newest transactions were processed
    assert mock_notifier.send_token_notification.await_count == mock_config.max_transactions_per_check
    
    # The latest block processed should be the newest of all transactions
    latest_block = BLOCK_ADDR1_START + tx_count
    mock_db.update_last_checked_block.assert_awaited_once_with(ADDR1.lower(), latest_block)


async def test_invalid_timestamp_is_skipped(
    checker: TransactionChecker, mock_db: AsyncMock, mock_etherscan: AsyncMock, mock_notifier: AsyncMock
):
    """Test that a transaction with an invalid timestamp is skipped."""
    valid_tx = create_mock_tx(BLOCK_ADDR1_START + 1, "0xsender", ADDR1, USDT_CONTRACT)
    invalid_tx = create_mock_tx(BLOCK_ADDR1_START + 2, "0xsender", ADDR1, USDT_CONTRACT)
    invalid_tx["timeStamp"] = "not-a-timestamp"

    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_db.get_users_for_address.return_value = [USER1]
    mock_etherscan.get_token_transactions.side_effect = [[valid_tx, invalid_tx], []]

    await checker.check_all_addresses()

    # Only the valid transaction should be processed
    mock_notifier.send_token_notification.assert_awaited_once_with(USER1, valid_tx, "USDT", ADDR1.lower())
    # Block should be updated to the highest block seen, even if it has invalid data and wasn't processed.
    mock_db.update_last_checked_block.assert_awaited_once_with(ADDR1.lower(), BLOCK_ADDR1_START + 2)


# --- Unit Tests for Internal Methods ---


@pytest.mark.asyncio
async def test_fetch_transactions_success(checker: TransactionChecker, mock_etherscan: AsyncMock):
    """Test `_fetch_transactions_for_address` success case."""
    tx_usdt = create_mock_tx(1, "s", "r", USDT_CONTRACT)
    tx_usdc = create_mock_tx(2, "s", "r", USDC_CONTRACT)
    mock_etherscan.get_token_transactions.side_effect = [[tx_usdt], [tx_usdc]]

    result = await checker._fetch_transactions_for_address(ADDR1.lower(), 0)

    assert len(result) == 2
    assert result[0]["token_symbol"] == "USDT"
    assert result[1]["token_symbol"] == "USDC"
    assert mock_etherscan.get_token_transactions.await_count == 2


@pytest.mark.asyncio
async def test_fetch_transactions_partial_failure(checker: TransactionChecker, mock_etherscan: AsyncMock):
    """Test `_fetch_transactions_for_address` with one token failing."""
    tx_usdc = create_mock_tx(2, "s", "r", USDC_CONTRACT)
    mock_etherscan.get_token_transactions.side_effect = [
        EtherscanRateLimitError("Rate limit on USDT"),
        [tx_usdc],
    ]

    result = await checker._fetch_transactions_for_address(ADDR1.lower(), 0)

    assert len(result) == 1
    assert result[0]["token_symbol"] == "USDC"
