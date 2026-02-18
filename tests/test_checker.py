# tests/test_checker.py
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from unittest.mock import ANY, AsyncMock, MagicMock

import pytest

from usdt_monitor_bot.checker import TransactionChecker
from usdt_monitor_bot.database import DatabaseManager
from usdt_monitor_bot.etherscan import (
    EtherscanClient,
    EtherscanError,
    EtherscanRateLimitError,
)
from usdt_monitor_bot.notifier import NotificationService
from usdt_monitor_bot.spam_detector import SpamDetector

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
    tx_hash: Optional[str] = None,
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
    config.notification_dedup_cache_size = 10_000

    token_registry = MagicMock()
    usdt_token = MagicMock(contract_address=USDT_CONTRACT, symbol="USDT")
    usdc_token = MagicMock(contract_address=USDC_CONTRACT, symbol="USDC")

    usdt_token.decimals = 6
    usdc_token.decimals = 6
    token_registry.get_all_tokens.return_value = {
        "USDT": usdt_token,
        "USDC": usdc_token,
    }
    token_registry.get_token.side_effect = lambda s: (
        usdt_token if s == "USDT" else (usdc_token if s == "USDC" else None)
    )
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
    # When no transactions found, we try to get latest block to advance progress
    mock_etherscan.get_latest_block_number.return_value = BLOCK_ADDR1_START + 100

    await checker.check_all_addresses()

    mock_db.get_last_checked_block.assert_awaited_once_with(ADDR1.lower())
    # Etherscan client is called for each token (USDT, USDC)
    assert mock_etherscan.get_token_transactions.await_count == 2
    # When no transactions found, we try to get latest block number
    mock_etherscan.get_latest_block_number.assert_awaited()
    mock_notifier.send_token_notification.assert_not_awaited()
    # The block should be updated to latest block when no transactions found
    # This prevents the bot from getting stuck checking the same block repeatedly
    mock_db.update_last_checked_block.assert_awaited_once_with(
        ADDR1.lower(), BLOCK_ADDR1_START + 100
    )


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
            [
                create_mock_tx(
                    BLOCK_ADDR1_START + 1, ADDR1, "0xrecipient", USDT_CONTRACT
                )
            ],
            1,
            BLOCK_ADDR1_START + 1,
        ),
        (
            "mixed_incoming_outgoing",
            [
                create_mock_tx(BLOCK_ADDR1_START + 1, "0xsender", ADDR1, USDT_CONTRACT),
                create_mock_tx(
                    BLOCK_ADDR1_START + 2, ADDR1, "0xrecipient", USDT_CONTRACT
                ),
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
    checker._spam_detection_enabled = False
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_db.get_users_for_address.return_value = [USER1]
    # Assume all test transactions are for USDT
    mock_etherscan.get_token_transactions.side_effect = [transactions, []]
    # Mock latest block to be >= final_block to avoid reset logic
    mock_etherscan.get_latest_block_number.return_value = final_block + 100

    await checker.check_all_addresses()

    assert mock_notifier.send_token_notification.await_count == expected_notifications
    mock_db.update_last_checked_block.assert_awaited_once_with(
        ADDR1.lower(), final_block
    )
    # Verify the last sent notification is for the last transaction
    if expected_notifications > 0:
        last_tx = transactions[-1]
        mock_notifier.send_token_notification.assert_any_await(
            USER1, last_tx, "USDT", ADDR1.lower(), ANY
        )


async def test_check_multiple_addresses(
    checker: TransactionChecker,
    mock_db: AsyncMock,
    mock_etherscan: AsyncMock,
    mock_notifier: AsyncMock,
):
    """Test that multiple addresses with different tokens are processed correctly."""
    checker._spam_detection_enabled = False
    tx1 = create_mock_tx(BLOCK_ADDR1_START + 1, "0xsender", ADDR1, USDT_CONTRACT)
    tx2 = create_mock_tx(BLOCK_ADDR1_START + 10, "0xsender", ADDR2, USDC_CONTRACT)

    mock_db.get_distinct_addresses.return_value = [ADDR1, ADDR2]
    mock_db.get_last_checked_block.side_effect = [
        BLOCK_ADDR1_START,
        BLOCK_ADDR1_START + 9,
    ]
    mock_db.get_users_for_address.side_effect = [[USER1], [USER2]]
    mock_etherscan.get_token_transactions.side_effect = [
        [tx1],
        [],  # ADDR1: USDT tx, no USDC tx
        [],
        [tx2],  # ADDR2: no USDT tx, USDC tx
    ]
    # Mock latest block to be >= highest block to avoid reset logic
    mock_etherscan.get_latest_block_number.return_value = BLOCK_ADDR1_START + 100

    await checker.check_all_addresses()

    assert mock_notifier.send_token_notification.await_count == 2
    mock_notifier.send_token_notification.assert_any_await(
        USER1, tx1, "USDT", ADDR1.lower(), ANY
    )
    mock_notifier.send_token_notification.assert_any_await(
        USER2, tx2, "USDC", ADDR2.lower(), ANY
    )

    assert mock_db.update_last_checked_block.await_count == 2
    mock_db.update_last_checked_block.assert_any_await(
        ADDR1.lower(), int(tx1["blockNumber"])
    )
    mock_db.update_last_checked_block.assert_any_await(
        ADDR2.lower(), int(tx2["blockNumber"])
    )


async def test_check_etherscan_rate_limit_skips_block_update(
    checker: TransactionChecker, mock_db: AsyncMock, mock_etherscan: AsyncMock
):
    """Test that a rate-limited address is skipped and its block is not updated."""
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    # Simulate rate limit error for all token fetches for the address
    checker._fetch_transactions_for_address = AsyncMock(  # type: ignore[assignment]
        side_effect=EtherscanRateLimitError("Rate Limited")
    )

    await checker.check_all_addresses()

    # The block should not be updated for the rate-limited address.
    mock_db.update_last_checked_block.assert_not_awaited()


async def test_transaction_age_filtering(
    checker: TransactionChecker,
    mock_db: AsyncMock,
    mock_etherscan: AsyncMock,
    mock_notifier: AsyncMock,
):
    """Test that transactions older than `max_transaction_age_days` are ignored."""
    checker._spam_detection_enabled = False
    recent_ts = int(NOW_TS - timedelta(days=1).total_seconds())
    old_ts = int(NOW_TS - timedelta(days=8).total_seconds())

    recent_tx = create_mock_tx(
        BLOCK_ADDR1_START + 1, "0xsender", ADDR1, USDT_CONTRACT, timestamp=recent_ts
    )
    old_tx = create_mock_tx(
        BLOCK_ADDR1_START + 2, "0xsender", ADDR1, USDT_CONTRACT, timestamp=old_ts
    )

    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_db.get_users_for_address.return_value = [USER1]
    mock_etherscan.get_token_transactions.side_effect = [[recent_tx, old_tx], []]
    # Mock latest block to be >= highest block to avoid reset logic
    mock_etherscan.get_latest_block_number.return_value = BLOCK_ADDR1_START + 100

    await checker.check_all_addresses()

    # Only the recent transaction should be processed
    mock_notifier.send_token_notification.assert_awaited_once_with(
        USER1, recent_tx, "USDT", ADDR1.lower(), ANY
    )
    # The block number should be updated to the highest *seen*, even if filtered
    mock_db.update_last_checked_block.assert_awaited_once_with(
        ADDR1.lower(), BLOCK_ADDR1_START + 2
    )


async def test_transaction_count_limiting(
    checker: TransactionChecker,
    mock_db: AsyncMock,
    mock_etherscan: AsyncMock,
    mock_notifier: AsyncMock,
    mock_config: MagicMock,
):
    """Test that only `max_transactions_per_check` are processed."""
    checker._spam_detection_enabled = False
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
    # Mock latest block to be >= highest block to avoid reset logic
    latest_block = BLOCK_ADDR1_START + tx_count
    mock_etherscan.get_latest_block_number.return_value = latest_block + 100

    await checker.check_all_addresses()

    # Verify that only the configured number of newest transactions were processed
    assert (
        mock_notifier.send_token_notification.await_count
        == mock_config.max_transactions_per_check
    )

    # The latest block processed should be the newest of all transactions
    mock_db.update_last_checked_block.assert_awaited_once_with(
        ADDR1.lower(), latest_block
    )


async def test_invalid_timestamp_is_skipped(
    checker: TransactionChecker,
    mock_db: AsyncMock,
    mock_etherscan: AsyncMock,
    mock_notifier: AsyncMock,
):
    """Test that a transaction with an invalid timestamp is skipped."""
    checker._spam_detection_enabled = False
    valid_tx = create_mock_tx(BLOCK_ADDR1_START + 1, "0xsender", ADDR1, USDT_CONTRACT)
    invalid_tx = create_mock_tx(BLOCK_ADDR1_START + 2, "0xsender", ADDR1, USDT_CONTRACT)
    invalid_tx["timeStamp"] = "not-a-timestamp"

    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_db.get_users_for_address.return_value = [USER1]
    mock_etherscan.get_token_transactions.side_effect = [[valid_tx, invalid_tx], []]
    # Mock latest block to be >= highest block to avoid reset logic
    mock_etherscan.get_latest_block_number.return_value = BLOCK_ADDR1_START + 100

    await checker.check_all_addresses()

    # Only the valid transaction should be processed
    mock_notifier.send_token_notification.assert_awaited_once_with(
        USER1, valid_tx, "USDT", ADDR1.lower(), ANY
    )
    # Block should be updated to the highest block seen, even if it has invalid data and wasn't processed.
    mock_db.update_last_checked_block.assert_awaited_once_with(
        ADDR1.lower(), BLOCK_ADDR1_START + 2
    )


# --- Unit Tests for Internal Methods ---


@pytest.mark.asyncio
async def test_fetch_transactions_success(
    checker: TransactionChecker, mock_etherscan: AsyncMock
):
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
async def test_fetch_transactions_partial_failure(
    checker: TransactionChecker, mock_etherscan: AsyncMock
):
    """Test `_fetch_transactions_for_address` with one token failing."""
    tx_usdc = create_mock_tx(2, "s", "r", USDC_CONTRACT)
    mock_etherscan.get_token_transactions.side_effect = [
        EtherscanRateLimitError("Rate limit on USDT"),
        [tx_usdc],
    ]

    result = await checker._fetch_transactions_for_address(ADDR1.lower(), 0)

    assert len(result) == 1
    assert result[0]["token_symbol"] == "USDC"


# --- Unit Tests for `_determine_next_block` ---


@pytest.mark.asyncio
async def test_determine_next_block_database_ahead_of_blockchain(
    checker: TransactionChecker, mock_etherscan: AsyncMock
):
    """Test that database block ahead of blockchain is reset to latest_block."""
    start_block = 1000
    new_last_block = 1005
    latest_block = 995  # Blockchain is behind database
    address_lower = ADDR1.lower()

    mock_etherscan.get_latest_block_number.return_value = latest_block

    result = await checker._determine_next_block(
        start_block, new_last_block, [], address_lower
    )

    assert result.final_block_number == latest_block
    assert result.resetting_to_latest is True
    mock_etherscan.get_latest_block_number.assert_awaited_once()


@pytest.mark.asyncio
async def test_determine_next_block_transaction_ahead_of_blockchain(
    checker: TransactionChecker, mock_etherscan: AsyncMock
):
    """Test that transaction block ahead of blockchain is capped to latest_block."""
    start_block = 1000
    new_last_block = 1010  # From transaction, ahead of blockchain
    latest_block = 1005  # Actual blockchain is behind transaction
    address_lower = ADDR1.lower()
    transactions = [create_mock_tx(1010, "0xsender", ADDR1, USDT_CONTRACT)]

    mock_etherscan.get_latest_block_number.return_value = latest_block

    result = await checker._determine_next_block(
        start_block, new_last_block, transactions, address_lower
    )

    assert result.final_block_number == latest_block
    assert result.resetting_to_latest is True
    mock_etherscan.get_latest_block_number.assert_awaited_once()


@pytest.mark.asyncio
async def test_determine_next_block_both_ahead_of_blockchain(
    checker: TransactionChecker, mock_etherscan: AsyncMock
):
    """Test when both start_block and new_last_block are ahead of blockchain.

    The start_block check should take precedence and reset to latest_block.
    """
    start_block = 1010  # Database ahead
    new_last_block = 1015  # Transaction also ahead
    latest_block = 1000  # Blockchain is behind both
    address_lower = ADDR1.lower()
    transactions = [create_mock_tx(1015, "0xsender", ADDR1, USDT_CONTRACT)]

    mock_etherscan.get_latest_block_number.return_value = latest_block

    result = await checker._determine_next_block(
        start_block, new_last_block, transactions, address_lower
    )

    # Should reset to latest_block due to start_block check (first condition)
    assert result.final_block_number == latest_block
    assert result.resetting_to_latest is True
    mock_etherscan.get_latest_block_number.assert_awaited_once()


@pytest.mark.asyncio
async def test_determine_next_block_normal_case_no_reset(
    checker: TransactionChecker, mock_etherscan: AsyncMock
):
    """Test normal case where no reset is needed."""
    start_block = 1000
    new_last_block = 1005  # From transaction
    latest_block = 1010  # Blockchain is ahead, everything is normal
    address_lower = ADDR1.lower()
    transactions = [create_mock_tx(1005, "0xsender", ADDR1, USDT_CONTRACT)]

    mock_etherscan.get_latest_block_number.return_value = latest_block

    result = await checker._determine_next_block(
        start_block, new_last_block, transactions, address_lower
    )

    # Should keep new_last_block as it's valid
    assert result.final_block_number == new_last_block
    assert result.resetting_to_latest is False
    mock_etherscan.get_latest_block_number.assert_awaited_once()


@pytest.mark.asyncio
async def test_determine_next_block_no_transactions_advances_to_latest(
    checker: TransactionChecker, mock_etherscan: AsyncMock
):
    """Test that when no transactions found, block advances to latest_block."""
    start_block = 1000
    new_last_block = 1000  # No transactions, stayed at start_block
    latest_block = 1005  # Blockchain has advanced
    address_lower = ADDR1.lower()

    mock_etherscan.get_latest_block_number.return_value = latest_block

    result = await checker._determine_next_block(
        start_block, new_last_block, [], address_lower
    )

    # Should advance to latest_block to prevent getting stuck
    assert result.final_block_number == latest_block
    assert result.resetting_to_latest is False
    mock_etherscan.get_latest_block_number.assert_awaited_once()


@pytest.mark.asyncio
async def test_determine_next_block_latest_block_none_guard_clause(
    checker: TransactionChecker, mock_etherscan: AsyncMock
):
    """Test guard clause when latest_block cannot be fetched (returns None)."""
    start_block = 1000
    new_last_block = 1000  # No transactions
    address_lower = ADDR1.lower()

    mock_etherscan.get_latest_block_number.return_value = None

    result = await checker._determine_next_block(
        start_block, new_last_block, [], address_lower
    )

    # Should advance to query_start_block to prevent getting stuck
    assert result.final_block_number == start_block + 1
    assert result.resetting_to_latest is False
    mock_etherscan.get_latest_block_number.assert_awaited_once()


@pytest.mark.asyncio
async def test_determine_next_block_latest_block_none_with_transactions(
    checker: TransactionChecker, mock_etherscan: AsyncMock
):
    """Test guard clause when latest_block is None but transactions were found."""
    start_block = 1000
    new_last_block = 1005  # From transaction
    address_lower = ADDR1.lower()
    transactions = [create_mock_tx(1005, "0xsender", ADDR1, USDT_CONTRACT)]

    mock_etherscan.get_latest_block_number.return_value = None

    result = await checker._determine_next_block(
        start_block, new_last_block, transactions, address_lower
    )

    # Should keep new_last_block since transactions were found
    assert result.final_block_number == new_last_block
    assert result.resetting_to_latest is False
    mock_etherscan.get_latest_block_number.assert_awaited_once()


# --- Tests for Spam Detection Disabled ---


async def test_spam_detection_disabled(
    mock_config: MagicMock,
    mock_db: AsyncMock,
    mock_etherscan: AsyncMock,
    mock_notifier: AsyncMock,
):
    """Test that spam detection can be disabled."""
    checker = TransactionChecker(mock_config, mock_db, mock_etherscan, mock_notifier)
    checker._spam_detection_enabled = False

    tx = create_mock_tx(BLOCK_ADDR1_START + 1, "0xsender", ADDR1, USDT_CONTRACT)
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_db.get_users_for_address.return_value = [USER1]
    mock_etherscan.get_token_transactions.side_effect = [[tx], []]
    mock_etherscan.get_latest_block_number.return_value = BLOCK_ADDR1_START + 100

    await checker.check_all_addresses()

    # Notification should be sent without risk_analysis
    mock_notifier.send_token_notification.assert_awaited_once()
    # When spam detection is disabled, risk_analysis should be None
    call_args = mock_notifier.send_token_notification.call_args
    assert call_args[0][4] is None  # risk_analysis argument


async def test_spam_detection_with_custom_detector(
    mock_config: MagicMock,
    mock_db: AsyncMock,
    mock_etherscan: AsyncMock,
    mock_notifier: AsyncMock,
):
    """Test that custom spam detector can be injected."""
    custom_detector = SpamDetector(config={"suspicious_score_threshold": 100})
    checker = TransactionChecker(
        mock_config, mock_db, mock_etherscan, mock_notifier, spam_detector=custom_detector
    )

    assert checker._spam_detector is custom_detector


# --- Tests for Error Handling ---


async def test_handle_etherscan_error_no_transactions_found(
    checker: TransactionChecker, caplog
):
    """Test that 'No transactions found' errors are silently ignored."""
    error = EtherscanError("No transactions found")
    checker._handle_etherscan_error(error, "USDT", ADDR1)

    # Should not log anything for "No transactions found"
    assert "No transactions found" not in caplog.text


async def test_handle_etherscan_error_notok(checker: TransactionChecker, caplog):
    """Test that NOTOK errors are logged as warnings."""
    with caplog.at_level(logging.WARNING):
        error = EtherscanError("API error: NOTOK - query timeout")
        checker._handle_etherscan_error(error, "USDT", ADDR1)

    assert "NOTOK" in caplog.text or "query timeout" in caplog.text


async def test_handle_etherscan_error_unexpected(checker: TransactionChecker, caplog):
    """Test that unexpected errors are logged with full traceback."""
    with caplog.at_level(logging.ERROR):
        error = RuntimeError("Something unexpected happened")
        checker._handle_etherscan_error(error, "USDT", ADDR1)

    assert "Fetch error" in caplog.text


# --- Tests for Transaction Metadata Conversion ---


async def test_convert_to_transaction_metadata_missing_fields(
    checker: TransactionChecker, caplog
):
    """Test that transactions with missing required fields return None."""
    with caplog.at_level(logging.WARNING):
        # Missing hash
        tx_no_hash = {"from": "0xsender", "to": "0xrecipient", "value": "1000000"}
        result = checker._convert_to_transaction_metadata(tx_no_hash, 6)
        assert result is None

        # Missing from address
        tx_no_from = {"hash": "0x123", "to": "0xrecipient", "value": "1000000"}
        result = checker._convert_to_transaction_metadata(tx_no_from, 6)
        assert result is None

        # Missing to address
        tx_no_to = {"hash": "0x123", "from": "0xsender", "value": "1000000"}
        result = checker._convert_to_transaction_metadata(tx_no_to, 6)
        assert result is None


async def test_convert_to_transaction_metadata_invalid_timestamp(
    checker: TransactionChecker, caplog
):
    """Test that transactions with invalid timestamps return None."""
    with caplog.at_level(logging.DEBUG):
        tx = {
            "hash": "0x123",
            "from": "0xsender",
            "to": "0xrecipient",
            "value": "1000000",
            "timeStamp": "not-a-timestamp",
            "blockNumber": "1000",
        }
        result = checker._convert_to_transaction_metadata(tx, 6)
        assert result is None
        assert "Invalid timestamp" in caplog.text


async def test_convert_to_transaction_metadata_invalid_value(
    checker: TransactionChecker, caplog
):
    """Test that transactions with invalid values return None."""
    with caplog.at_level(logging.DEBUG):
        tx = {
            "hash": "0x123",
            "from": "0xsender",
            "to": "0xrecipient",
            "value": "not-a-number",
            "timeStamp": str(NOW_TS),
            "blockNumber": "1000",
        }
        result = checker._convert_to_transaction_metadata(tx, 6)
        assert result is None
        # The error is caught by the outer exception handler
        assert "Invalid value" in caplog.text or "Metadata conversion error" in caplog.text


# --- Tests for Timestamp Parsing ---


async def test_parse_timestamp_iso_format(checker: TransactionChecker):
    """Test parsing ISO format timestamps."""
    result = checker._parse_timestamp("2025-01-27T12:00:00+00:00")
    assert result is not None
    assert result.year == 2025
    assert result.month == 1
    assert result.day == 27


async def test_parse_timestamp_unix_format(checker: TransactionChecker):
    """Test parsing Unix timestamp strings."""
    result = checker._parse_timestamp("1620000000")
    assert result is not None
    # May 3, 2021
    assert result.year == 2021


async def test_parse_timestamp_invalid_format(checker: TransactionChecker, caplog):
    """Test that invalid timestamp formats return None."""
    with caplog.at_level(logging.DEBUG):
        result = checker._parse_timestamp("invalid-timestamp")
        assert result is None
        assert "Invalid DB timestamp" in caplog.text


# --- Tests for Filter Transactions ---


async def test_filter_transactions_sorts_by_block_chronologically(
    checker: TransactionChecker,
):
    """Test that filtered transactions are sorted chronologically (oldest first)."""
    transactions = [
        create_mock_tx(1003, "s", "r", USDT_CONTRACT),
        create_mock_tx(1001, "s", "r", USDT_CONTRACT),
        create_mock_tx(1002, "s", "r", USDT_CONTRACT),
    ]

    result = checker._filter_transactions(transactions, 1000)

    assert len(result) == 3
    # Should be sorted chronologically (oldest first for processing)
    assert int(result[0]["blockNumber"]) == 1001
    assert int(result[1]["blockNumber"]) == 1002
    assert int(result[2]["blockNumber"]) == 1003


async def test_filter_transactions_excludes_at_or_below_start_block(
    checker: TransactionChecker,
):
    """Test that transactions at or below start_block are excluded."""
    transactions = [
        create_mock_tx(999, "s", "r", USDT_CONTRACT),  # Below
        create_mock_tx(1000, "s", "r", USDT_CONTRACT),  # Equal
        create_mock_tx(1001, "s", "r", USDT_CONTRACT),  # Above
    ]

    result = checker._filter_transactions(transactions, 1000)

    assert len(result) == 1
    assert int(result[0]["blockNumber"]) == 1001


# --- Tests for No Users Tracking Address ---


async def test_transactions_found_but_no_users_tracking(
    checker: TransactionChecker,
    mock_db: AsyncMock,
    mock_etherscan: AsyncMock,
    mock_notifier: AsyncMock,
    caplog,
):
    """Test behavior when transactions are found but no users track the address."""
    tx = create_mock_tx(BLOCK_ADDR1_START + 1, "0xsender", ADDR1, USDT_CONTRACT)
    mock_db.get_distinct_addresses.return_value = [ADDR1]
    mock_db.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_db.get_users_for_address.return_value = []  # No users tracking
    mock_etherscan.get_token_transactions.side_effect = [[tx], []]
    mock_etherscan.get_latest_block_number.return_value = BLOCK_ADDR1_START + 100

    with caplog.at_level(logging.DEBUG):
        await checker.check_all_addresses()

    # No notifications should be sent
    mock_notifier.send_token_notification.assert_not_awaited()
    # Debug log indicates no users tracking
    assert "No users tracking" in caplog.text


# --- Tests for Process Single Transaction Errors ---


async def test_process_transaction_missing_hash_or_symbol(
    checker: TransactionChecker,
    mock_db: AsyncMock,
    mock_notifier: AsyncMock,
    caplog,
):
    """Test that transactions missing hash or symbol are skipped."""
    mock_db.get_recent_transactions.return_value = []

    with caplog.at_level(logging.WARNING):
        # Missing hash
        tx_no_hash = {"token_symbol": "USDT", "from": "s", "to": "r"}
        result = await checker._process_single_transaction(
            tx_no_hash, [USER1], ADDR1.lower(), []
        )
        assert result == 0

        # Missing token_symbol
        tx_no_symbol = {"hash": "0x123", "from": "s", "to": "r"}
        result = await checker._process_single_transaction(
            tx_no_symbol, [USER1], ADDR1.lower(), []
        )
        assert result == 0


# --- Tests for Notification Deduplication ---


async def test_in_batch_dedup_same_tx_hash_one_notification_per_user(
    checker: TransactionChecker,
    mock_db: AsyncMock,
    mock_notifier: AsyncMock,
):
    """Same tx_hash appearing twice in batch (e.g. USDT + USDC) yields one notification per user."""
    checker._spam_detection_enabled = False
    mock_db.get_recent_transactions.return_value = []
    mock_db.get_users_for_address.return_value = [USER1]

    same_hash = "0xabcd1234"
    tx_usdt = create_mock_tx(
        BLOCK_ADDR1_START + 1, "0xsender", ADDR1, USDT_CONTRACT, tx_hash=same_hash
    )
    tx_usdt["token_symbol"] = "USDT"
    tx_usdc = create_mock_tx(
        BLOCK_ADDR1_START + 1, "0xsender", ADDR1, USDC_CONTRACT, tx_hash=same_hash
    )
    tx_usdc["token_symbol"] = "USDC"
    batch_same_tx_twice = [tx_usdt, tx_usdc]

    await checker._process_address_transactions(
        ADDR1.lower(),
        batch_same_tx_twice,
        BLOCK_ADDR1_START,
        latest_block=BLOCK_ADDR1_START + 100,
    )

    # Deduped to one tx, so one notification per user
    mock_notifier.send_token_notification.assert_awaited_once()
    call_args = mock_notifier.send_token_notification.call_args[0]
    assert call_args[0] == USER1
    assert call_args[1].get("hash") == same_hash


async def test_notification_cache_skips_duplicate_send(
    checker: TransactionChecker,
    mock_db: AsyncMock,
    mock_notifier: AsyncMock,
):
    """Same (user_id, tx_hash) sent again in same checker instance is skipped (cache hit)."""
    checker._spam_detection_enabled = False
    mock_db.get_recent_transactions.return_value = []

    tx = create_mock_tx(
        BLOCK_ADDR1_START + 1, "0xsender", ADDR1, USDT_CONTRACT, tx_hash="0xunique99"
    )
    tx["token_symbol"] = "USDT"

    result1 = await checker._process_single_transaction(
        tx, [USER1], ADDR1.lower(), []
    )
    assert result1 == 1
    mock_notifier.send_token_notification.assert_awaited_once()

    result2 = await checker._process_single_transaction(
        tx, [USER1], ADDR1.lower(), []
    )
    assert result2 == 0
    # Still only one call total (second send skipped by cache)
    mock_notifier.send_token_notification.assert_awaited_once()


async def test_notification_cache_disabled_when_size_zero(
    mock_config: MagicMock,
    mock_db: AsyncMock,
    mock_etherscan: AsyncMock,
    mock_notifier: AsyncMock,
):
    """When notification_dedup_cache_size is 0, cache is disabled; duplicate sends are not suppressed."""
    mock_config.notification_dedup_cache_size = 0
    checker = TransactionChecker(mock_config, mock_db, mock_etherscan, mock_notifier)
    checker._spam_detection_enabled = False
    mock_db.get_recent_transactions.return_value = []

    tx = create_mock_tx(
        BLOCK_ADDR1_START + 1, "0xsender", ADDR1, USDT_CONTRACT, tx_hash="0xdup"
    )
    tx["token_symbol"] = "USDT"

    result1 = await checker._process_single_transaction(
        tx, [USER1], ADDR1.lower(), []
    )
    result2 = await checker._process_single_transaction(
        tx, [USER1], ADDR1.lower(), []
    )
    assert result1 == 1
    assert result2 == 1
    assert mock_notifier.send_token_notification.await_count == 2


# --- Tests for Contract Age Caching ---


async def test_contract_age_blocks_caching(
    checker: TransactionChecker,
    mock_etherscan: AsyncMock,
):
    """Test that contract creation blocks are cached."""
    contract_address = "0xcontract123"
    current_block = 1000
    creation_block = 500

    mock_etherscan.get_contract_creation_block.return_value = creation_block

    # First call - should fetch from Etherscan
    age1 = await checker._get_contract_age_blocks(contract_address, current_block)
    assert age1 == 500  # 1000 - 500

    # Second call - should use cache
    age2 = await checker._get_contract_age_blocks(contract_address, current_block + 100)
    assert age2 == 600  # 1100 - 500

    # Etherscan should only be called once
    mock_etherscan.get_contract_creation_block.assert_awaited_once()


async def test_contract_age_blocks_error_cached_as_none(
    checker: TransactionChecker,
    mock_etherscan: AsyncMock,
):
    """Test that errors are cached to avoid repeated failed calls."""
    contract_address = "0xcontract456"

    mock_etherscan.get_contract_creation_block.side_effect = Exception("API Error")

    # First call - should attempt fetch and fail
    age1 = await checker._get_contract_age_blocks(contract_address, 1000)
    assert age1 == 0  # Default on error

    # Second call - should use cached None
    age2 = await checker._get_contract_age_blocks(contract_address, 1000)
    assert age2 == 0

    # Etherscan should only be called once
    mock_etherscan.get_contract_creation_block.assert_awaited_once()
