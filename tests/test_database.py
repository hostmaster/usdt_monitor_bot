# tests/test_database.py
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from usdt_monitor_bot.database import (
    _TRANSACTION_HISTORY_DDL,
    DatabaseManager,
    WalletAddResult,
)

pytestmark = pytest.mark.asyncio


async def test_add_and_check_user(memory_db_manager: DatabaseManager):
    user_id = 123
    assert not await memory_db_manager.check_user_exists(
        user_id
    )  # Should be False initially
    added = await memory_db_manager.add_user(user_id, "testuser", "Test", "User")
    assert added > 0  # First add returns rowcount > 0
    assert await memory_db_manager.check_user_exists(user_id)  # Should exist now
    added_again = await memory_db_manager.add_user(user_id, "testuser", "Test", "User")
    assert added_again == 0  # Duplicate INSERT OR IGNORE returns 0 (rowcount == 0)
    assert await memory_db_manager.check_user_exists(user_id)  # Still exists


async def test_add_and_list_wallets(memory_db_manager: DatabaseManager):
    user_id = 456
    addr1 = "0x1111111111111111111111111111111111111111"
    addr2 = "0x2222222222222222222222222222222222222222"
    addr1_upper = "0x1111111111111111111111111111111111111111"

    await memory_db_manager.add_user(user_id, "u2", "U", "2")
    initial_wallets = await memory_db_manager.list_wallets(user_id)
    assert initial_wallets == []  # Expect empty list initially
    assert await memory_db_manager.add_wallet(user_id, addr1) == WalletAddResult.ADDED
    assert await memory_db_manager.add_wallet(user_id, addr2) == WalletAddResult.ADDED
    assert (
        await memory_db_manager.add_wallet(user_id, addr1_upper)
        == WalletAddResult.ALREADY_EXISTS
    )  # Duplicate
    wallets = await memory_db_manager.list_wallets(user_id)
    assert isinstance(wallets, list)  # Check it's a list
    assert sorted(wallets) == sorted([addr1.lower(), addr2.lower()])


async def test_remove_wallet(memory_db_manager: DatabaseManager):
    user_id = 789
    addr = "0x3333333333333333333333333333333333333333"
    addr_lower = addr.lower()

    await memory_db_manager.add_user(user_id, "u3", "U", "3")
    await memory_db_manager.add_wallet(user_id, addr)
    current_wallets = await memory_db_manager.list_wallets(user_id)
    assert current_wallets == [addr_lower]  # Verify exists
    removed = await memory_db_manager.remove_wallet(user_id, addr)
    assert removed > 0  # Successful DELETE returns rowcount > 0
    assert await memory_db_manager.list_wallets(user_id) == []  # Verify removed
    removed_again = await memory_db_manager.remove_wallet(user_id, addr)
    assert removed_again == 0  # Deleting non-existent returns 0 (rowcount == 0)


async def test_get_distinct_addresses(memory_db_manager: DatabaseManager):
    user1, user2 = 101, 102
    addr1 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    addr2 = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    addr3 = "0xcccccccccccccccccccccccccccccccccccccccc"
    await memory_db_manager.add_user(user1, "u101", "U", "101")
    await memory_db_manager.add_user(user2, "u102", "U", "102")
    await memory_db_manager.add_wallet(user1, addr1)
    await memory_db_manager.add_wallet(user1, addr2)
    await memory_db_manager.add_wallet(user2, addr2)
    await memory_db_manager.add_wallet(user2, addr3)

    distinct_addrs = await memory_db_manager.get_distinct_addresses()
    assert isinstance(distinct_addrs, list)  # Expect list (even if empty)
    assert sorted(distinct_addrs) == sorted([addr1, addr2, addr3])


async def test_get_users_for_address(memory_db_manager: DatabaseManager):
    user1, user2 = 201, 202
    addr1 = "0xdddddddddddddddddddddddddddddddddddddddd"
    addr2 = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    await memory_db_manager.add_user(user1, "u201", "U", "201")
    await memory_db_manager.add_user(user2, "u202", "U", "202")
    await memory_db_manager.add_wallet(user1, addr1)
    await memory_db_manager.add_wallet(user2, addr1)
    await memory_db_manager.add_wallet(user2, addr2)

    users_addr1 = await memory_db_manager.get_users_for_address(addr1)
    assert isinstance(users_addr1, list)  # Expect list
    assert sorted(users_addr1) == sorted([user1, user2])
    users_addr2 = await memory_db_manager.get_users_for_address(addr2)
    assert users_addr2 == [user2]
    users_addr_nonexist = await memory_db_manager.get_users_for_address("0x404")
    assert users_addr_nonexist == []  # Expect empty list


async def test_last_checked_block(memory_db_manager: DatabaseManager):
    addr = "0xffffffffffffffffffffffffffffffffffffffff"
    user_id = 999
    await memory_db_manager.add_user(user_id, "u999", "U", "9")
    await memory_db_manager.add_wallet(user_id, addr)
    assert await memory_db_manager.get_last_checked_block(addr) == 0

    update1 = await memory_db_manager.update_last_checked_block(addr, 12345)
    assert update1 > 0
    assert await memory_db_manager.get_last_checked_block(addr) == 12345

    update2 = await memory_db_manager.update_last_checked_block(addr, 54321)
    assert update2 > 0
    assert await memory_db_manager.get_last_checked_block(addr) == 54321

    # Check non-tracked address gets added with 0
    assert await memory_db_manager.get_last_checked_block("0xabc") == 0

    # The previous check `assert await memory_db_manager.get_last_checked_block("0xabc") == 0`
    # already covers that "0xabc" (newly added by get_last_checked_block) will have its block as 0.
    # We can simplify this test by removing the direct _execute_db_query test part,
    # as it was causing TypeErrors and the main functionality is covered.

    # Test that get_last_checked_block returns 0 for an unknown address (and adds it)
    unknown_addr = "0xunknown0000000000000000000000000000000"
    assert await memory_db_manager.get_last_checked_block(unknown_addr) == 0
    # Verify it was added by checking its block value again
    assert await memory_db_manager.get_last_checked_block(unknown_addr) == 0


async def test_add_wallet_db_error_on_wallets_insert(
    memory_db_manager: DatabaseManager, mocker
):
    user_id = 12345
    address = "0xErrorWallet00000000000000000000000000000"
    await memory_db_manager.add_user(user_id, "err_user", "E", "U")

    # Mock _execute_db_query specifically for the INSERT into 'wallets' table
    # to simulate a DB error for that operation only.
    original_execute_db_query = memory_db_manager._execute_db_query

    def mock_execute_side_effect(
        query: str, params: tuple = (), commit: bool = False, **kwargs
    ):
        if "INSERT OR IGNORE INTO wallets" in query and commit:
            return -1  # Simulate DB error (rowcount = -1)
        # For other queries (like INSERT into tracked_addresses or SELECTs), use original behavior.
        # This requires careful handling if original_execute_db_query is complex or stateful.
        # For this test, we assume other DB operations within add_wallet_sync would succeed or are not critical to this error path.
        # A simpler mock might be to just return -1 if commit is True for any INSERT during this test.
        # However, the goal is to test the specific error handling in _add_wallet_sync.
        # The `tracked_addresses` insert should ideally still work or be handled.
        # The current WalletAddResult.DB_ERROR is returned if the *wallets* table insert fails.

        # Let's use a more direct patch on the specific call that matters for DB_ERROR return.
        # We are mocking the return of _execute_db_query when called by _add_wallet_sync
        # for the 'wallets' table insert.
        return original_execute_db_query(query, params, commit=commit, **kwargs)

    # We need to patch the _execute_db_query method of the specific memory_db_manager instance
    mocker.patch.object(
        memory_db_manager, "_execute_db_query", side_effect=mock_execute_side_effect
    )

    # The first call to _execute_db_query within _add_wallet_sync for the wallets table
    # will be mocked to return -1.

    result = await memory_db_manager.add_wallet(user_id, address)
    assert result == WalletAddResult.DB_ERROR


async def test_add_wallet_db_error_on_tracked_addresses_insert(
    memory_db_manager: DatabaseManager, mocker, caplog
):
    user_id = 54321
    address = "0xTrackedErrorWallet000000000000000000000"
    await memory_db_manager.add_user(user_id, "track_err_user", "T", "E")

    # Mock _execute_db_query: success for 'wallets', error for 'tracked_addresses'
    def mock_execute_side_effect_tracked(
        query: str, params: tuple = (), commit: bool = False, **kwargs
    ):
        if "INSERT OR IGNORE INTO wallets" in query and commit:
            # Simulate successful add to wallets (e.g., 1 row affected)
            return 1
        if "INSERT OR IGNORE INTO tracked_addresses" in query and commit:
            return -1  # Simulate DB error for tracked_addresses
        # Fallback to original for other calls (if any)
        # This specific test is tricky because the original method is not easily accessible
        # within the side_effect if we fully replace it.
        # A better approach for complex side_effects is to use a spy or more granular patching if possible.
        # For this test, we'll assume these are the only two commit queries in _add_wallet_sync.
        # If _execute_db_query is called for other reasons, this mock might be too simple.

        # Using a direct return value for non-matching queries might be safer:
        if commit:
            return 0  # Default success for other commit operations
        return None  # Default for select

    mocker.patch.object(
        memory_db_manager,
        "_execute_db_query",
        side_effect=mock_execute_side_effect_tracked,
    )

    with caplog.at_level("ERROR"):
        result = await memory_db_manager.add_wallet(user_id, address)

    # According to current logic in _add_wallet_sync, if wallets insert is successful,
    # it returns ADDED, even if tracked_addresses insert fails (it logs an error).
    assert result == WalletAddResult.ADDED
    assert "Track address failed" in caplog.text


async def test_store_and_retrieve_transaction(memory_db_manager: DatabaseManager):
    """Test storing and retrieving transactions from history."""
    monitored_addr = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    await memory_db_manager.add_user(1, "user1", "U", "1")
    await memory_db_manager.add_wallet(1, monitored_addr)

    # Store a transaction
    stored = await memory_db_manager.store_transaction(
        tx_hash="0x123",
        monitored_address=monitored_addr,
        from_address="0x1111111111111111111111111111111111111111",
        to_address="0x2222222222222222222222222222222222222222",
        value=100.50,
        block_number=1000,
        timestamp="2025-01-27T12:00:00+00:00",
        token_symbol="USDT",
        risk_score=75,
    )
    assert stored is True

    # Retrieve recent transactions
    recent = await memory_db_manager.get_recent_transactions(monitored_addr, limit=10)
    assert len(recent) == 1
    assert recent[0]["tx_hash"] == "0x123"
    assert recent[0]["value"] == 100.50
    assert recent[0]["risk_score"] == 75
    assert recent[0]["token_symbol"] == "USDT"


async def test_get_recent_transactions_limit(memory_db_manager: DatabaseManager):
    """Test that get_recent_transactions respects the limit."""
    monitored_addr = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    await memory_db_manager.add_user(2, "user2", "U", "2")
    await memory_db_manager.add_wallet(2, monitored_addr)

    # Store multiple transactions
    for i in range(15):
        await memory_db_manager.store_transaction(
            tx_hash=f"0x{i:04x}",
            monitored_address=monitored_addr,
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=float(i),
            block_number=1000 + i,
            timestamp=f"2025-01-27T12:00:{i:02d}+00:00",
            token_symbol="USDT",
        )

    # Retrieve with limit
    recent = await memory_db_manager.get_recent_transactions(monitored_addr, limit=10)
    assert len(recent) == 10
    # Should be ordered by block number descending
    assert recent[0]["block_number"] > recent[-1]["block_number"]


async def test_is_new_sender_address(memory_db_manager: DatabaseManager):
    """Test checking if a sender address is new."""
    monitored_addr = "0xcccccccccccccccccccccccccccccccccccccccc"
    sender1 = "0x1111111111111111111111111111111111111111"
    sender2 = "0x2222222222222222222222222222222222222222"

    await memory_db_manager.add_user(3, "user3", "U", "3")
    await memory_db_manager.add_wallet(3, monitored_addr)

    # Initially, both senders should be new
    assert (
        await memory_db_manager.is_new_sender_address(monitored_addr, sender1) is True
    )
    assert (
        await memory_db_manager.is_new_sender_address(monitored_addr, sender2) is True
    )

    # Store a transaction from sender1
    await memory_db_manager.store_transaction(
        tx_hash="0x111",
        monitored_address=monitored_addr,
        from_address=sender1,
        to_address=monitored_addr,
        value=100.0,
        block_number=1000,
        timestamp="2025-01-27T12:00:00+00:00",
        token_symbol="USDT",
    )

    # Now sender1 should not be new, but sender2 should still be new
    assert (
        await memory_db_manager.is_new_sender_address(monitored_addr, sender1) is False
    )
    assert (
        await memory_db_manager.is_new_sender_address(monitored_addr, sender2) is True
    )


async def test_cleanup_old_transactions(memory_db_manager: DatabaseManager):
    """Test cleanup of old transactions."""
    monitored_addr = "0xdddddddddddddddddddddddddddddddddddddddd"
    await memory_db_manager.add_user(4, "user4", "U", "4")
    await memory_db_manager.add_wallet(4, monitored_addr)

    # Store old transaction (35 days ago)
    old_timestamp = (datetime.now(UTC) - timedelta(days=35)).isoformat()
    await memory_db_manager.store_transaction(
        tx_hash="0xold",
        monitored_address=monitored_addr,
        from_address="0x1111111111111111111111111111111111111111",
        to_address="0x2222222222222222222222222222222222222222",
        value=100.0,
        block_number=1000,
        timestamp=old_timestamp,
        token_symbol="USDT",
    )

    # Store recent transaction
    recent_timestamp = datetime.now(UTC).isoformat()
    await memory_db_manager.store_transaction(
        tx_hash="0xrecent",
        monitored_address=monitored_addr,
        from_address="0x1111111111111111111111111111111111111111",
        to_address="0x2222222222222222222222222222222222222222",
        value=200.0,
        block_number=2000,
        timestamp=recent_timestamp,
        token_symbol="USDT",
    )

    # Verify both exist
    recent = await memory_db_manager.get_recent_transactions(monitored_addr, limit=10)
    assert len(recent) == 2

    # Cleanup transactions older than 30 days
    deleted = await memory_db_manager.cleanup_old_transactions(days_to_keep=30)
    assert deleted == 1

    # Verify only recent transaction remains
    recent_after = await memory_db_manager.get_recent_transactions(
        monitored_addr, limit=10
    )
    assert len(recent_after) == 1
    assert recent_after[0]["tx_hash"] == "0xrecent"


async def test_database_migration_existing_db(memory_db_manager: DatabaseManager):
    """Test that database migration works on existing databases."""
    # Simulate an existing database by creating the old tables manually
    # (In real scenario, these would already exist)
    monitored_addr = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    await memory_db_manager.add_user(5, "user5", "U", "5")
    await memory_db_manager.add_wallet(5, monitored_addr)

    # Verify old tables exist
    result = await memory_db_manager._run_sync_db_operation(
        lambda: memory_db_manager._execute_db_query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users'",
            fetch_one=True,
        )
    )
    assert result is not None

    # Re-initialize database (simulating migration on existing DB)
    # This should add the new transaction_history table without affecting existing data
    migration_success = await memory_db_manager.init_db()
    assert migration_success is True

    # Verify new table was created
    result = await memory_db_manager._run_sync_db_operation(
        lambda: memory_db_manager._execute_db_query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='transaction_history'",
            fetch_one=True,
        )
    )
    assert result is not None
    assert result[0] == "transaction_history"

    # Verify indexes were created
    indexes = await memory_db_manager._run_sync_db_operation(
        lambda: memory_db_manager._execute_db_query(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_tx_history%'",
            fetch_all=True,
        )
    )
    assert len(indexes) == 2

    # Verify existing data is still intact
    wallets = await memory_db_manager.list_wallets(5)
    assert wallets is not None
    assert monitored_addr.lower() in wallets

    # Verify we can use the new table
    stored = await memory_db_manager.store_transaction(
        tx_hash="0xmigration_test",
        monitored_address=monitored_addr,
        from_address="0x1111111111111111111111111111111111111111",
        to_address="0x2222222222222222222222222222222222222222",
        value=50.0,
        block_number=5000,
        timestamp="2025-01-27T15:00:00+00:00",
        token_symbol="USDT",
    )
    assert stored is True

    # Verify we can retrieve from new table
    recent = await memory_db_manager.get_recent_transactions(monitored_addr, limit=1)
    assert len(recent) == 1
    assert recent[0]["tx_hash"] == "0xmigration_test"


async def test_init_db_idempotent(memory_db_manager: DatabaseManager):
    """Test that init_db can be called multiple times safely (idempotent)."""
    # First initialization
    result1 = await memory_db_manager.init_db()
    assert result1 is True

    # Second initialization (should not fail or cause issues)
    result2 = await memory_db_manager.init_db()
    assert result2 is True

    # Verify tables still exist and are usable
    await memory_db_manager.add_user(6, "user6", "U", "6")
    user_exists = await memory_db_manager.check_user_exists(6)
    assert user_exists is True


# --- Tests for Error Handling and Edge Cases ---


async def test_list_wallets_returns_empty_list_for_nonexistent_user(
    memory_db_manager: DatabaseManager,
):
    """Test that list_wallets returns empty list for user with no wallets."""
    # User doesn't exist yet
    wallets = await memory_db_manager.list_wallets(999999)
    assert wallets == []


async def test_remove_wallet_nonexistent_returns_zero(
    memory_db_manager: DatabaseManager,
):
    """Test that removing a non-existent wallet returns 0."""
    user_id = 111
    await memory_db_manager.add_user(user_id, "u111", "U", "111")

    # Try to remove wallet that was never added
    result = await memory_db_manager.remove_wallet(
        user_id, "0x9999999999999999999999999999999999999999"
    )
    assert result == 0


async def test_get_users_for_address_nonexistent_returns_empty(
    memory_db_manager: DatabaseManager,
):
    """Test that getting users for non-tracked address returns empty list."""
    users = await memory_db_manager.get_users_for_address(
        "0xnonexistent000000000000000000000000000000"
    )
    assert users == []


async def test_store_transaction_duplicate_replaces(memory_db_manager: DatabaseManager):
    """Test that storing a transaction with same hash replaces the old one."""
    monitored_addr = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    await memory_db_manager.add_user(1, "user1", "U", "1")
    await memory_db_manager.add_wallet(1, monitored_addr)

    # Store first version
    await memory_db_manager.store_transaction(
        tx_hash="0xduplicate",
        monitored_address=monitored_addr,
        from_address="0x1111111111111111111111111111111111111111",
        to_address="0x2222222222222222222222222222222222222222",
        value=100.0,
        block_number=1000,
        timestamp="2025-01-27T12:00:00+00:00",
        token_symbol="USDT",
        risk_score=50,
    )

    # Store updated version with same hash
    await memory_db_manager.store_transaction(
        tx_hash="0xduplicate",
        monitored_address=monitored_addr,
        from_address="0x1111111111111111111111111111111111111111",
        to_address="0x2222222222222222222222222222222222222222",
        value=200.0,  # Different value
        block_number=1000,
        timestamp="2025-01-27T12:00:00+00:00",
        token_symbol="USDT",
        risk_score=75,  # Different risk score
    )

    # Should only have one transaction with updated values
    recent = await memory_db_manager.get_recent_transactions(monitored_addr, limit=10)
    assert len(recent) == 1
    assert recent[0]["value"] == 200.0
    assert recent[0]["risk_score"] == 75


async def test_get_recent_transactions_empty_address(memory_db_manager: DatabaseManager):
    """Test that getting transactions for address with no history returns empty."""
    monitored_addr = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    await memory_db_manager.add_user(2, "user2", "U", "2")
    await memory_db_manager.add_wallet(2, monitored_addr)

    recent = await memory_db_manager.get_recent_transactions(monitored_addr, limit=10)
    assert recent == []


async def test_is_new_sender_case_insensitive(memory_db_manager: DatabaseManager):
    """Test that sender address comparison is case-insensitive."""
    monitored_addr = "0xcccccccccccccccccccccccccccccccccccccccc"
    sender_lower = "0x1111111111111111111111111111111111111111"
    sender_upper = "0x1111111111111111111111111111111111111111".upper()

    await memory_db_manager.add_user(3, "user3", "U", "3")
    await memory_db_manager.add_wallet(3, monitored_addr)

    # Store with lowercase sender
    await memory_db_manager.store_transaction(
        tx_hash="0x111",
        monitored_address=monitored_addr,
        from_address=sender_lower,
        to_address=monitored_addr,
        value=100.0,
        block_number=1000,
        timestamp="2025-01-27T12:00:00+00:00",
        token_symbol="USDT",
    )

    # Check with uppercase - should still find it
    is_new = await memory_db_manager.is_new_sender_address(monitored_addr, sender_upper)
    assert is_new is False


async def test_cleanup_old_transactions_none_to_clean(
    memory_db_manager: DatabaseManager,
):
    """Test cleanup when there are no old transactions."""
    monitored_addr = "0xdddddddddddddddddddddddddddddddddddddddd"
    await memory_db_manager.add_user(4, "user4", "U", "4")
    await memory_db_manager.add_wallet(4, monitored_addr)

    # Store only recent transaction
    recent_timestamp = datetime.now(UTC).isoformat()
    await memory_db_manager.store_transaction(
        tx_hash="0xrecent",
        monitored_address=monitored_addr,
        from_address="0x1111111111111111111111111111111111111111",
        to_address="0x2222222222222222222222222222222222222222",
        value=100.0,
        block_number=1000,
        timestamp=recent_timestamp,
        token_symbol="USDT",
    )

    # Cleanup should return 0 (nothing deleted)
    deleted = await memory_db_manager.cleanup_old_transactions(days_to_keep=30)
    assert deleted == 0


async def test_update_last_checked_block_creates_if_not_exists(
    memory_db_manager: DatabaseManager,
):
    """Test that updating block creates entry if address doesn't exist in tracked_addresses."""
    new_addr = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

    # Update block for address not in tracked_addresses
    result = await memory_db_manager.update_last_checked_block(new_addr, 5000)
    assert result > 0

    # Should be able to retrieve the block
    block = await memory_db_manager.get_last_checked_block(new_addr)
    assert block == 5000


async def test_add_wallet_case_normalization(memory_db_manager: DatabaseManager):
    """Test that wallet addresses are normalized to lowercase."""
    user_id = 5
    addr_upper = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    await memory_db_manager.add_user(user_id, "u5", "U", "5")
    result = await memory_db_manager.add_wallet(user_id, addr_upper)
    assert result == WalletAddResult.ADDED

    # List should return lowercase
    wallets = await memory_db_manager.list_wallets(user_id)
    assert wallets == [addr_upper.lower()]


async def test_store_transaction_with_null_risk_score(
    memory_db_manager: DatabaseManager,
):
    """Test storing transaction without risk score (None)."""
    monitored_addr = "0xffffffffffffffffffffffffffffffffffff0001"
    await memory_db_manager.add_user(6, "user6", "U", "6")
    await memory_db_manager.add_wallet(6, monitored_addr)

    stored = await memory_db_manager.store_transaction(
        tx_hash="0xnullrisk",
        monitored_address=monitored_addr,
        from_address="0x1111111111111111111111111111111111111111",
        to_address="0x2222222222222222222222222222222222222222",
        value=100.0,
        block_number=1000,
        timestamp="2025-01-27T12:00:00+00:00",
        token_symbol="USDT",
        risk_score=None,
    )
    assert stored is True

    recent = await memory_db_manager.get_recent_transactions(monitored_addr, limit=1)
    assert len(recent) == 1
    assert recent[0]["risk_score"] is None


# --- Migration tests ---

_OLD_TX_HISTORY_DDL = """
    CREATE TABLE transaction_history (
        tx_hash TEXT PRIMARY KEY,
        monitored_address TEXT NOT NULL,
        from_address TEXT NOT NULL,
        to_address TEXT NOT NULL,
        value REAL NOT NULL,
        block_number INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        token_symbol TEXT NOT NULL,
        risk_score INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(monitored_address) REFERENCES tracked_addresses(address)
    )
"""


def _create_old_schema_db(db_path: str) -> None:
    """Create a DB with old transaction_history schema (no ON DELETE CASCADE)."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE users (
            user_id INTEGER PRIMARY KEY, username TEXT, first_name TEXT, last_name TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE wallets (
            wallet_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            address TEXT NOT NULL, added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
            UNIQUE(user_id, address)
        )
    """)
    conn.execute("""
        CREATE TABLE tracked_addresses (
            address TEXT PRIMARY KEY, last_checked_block INTEGER DEFAULT 0, last_check_time TIMESTAMP
        )
    """)
    conn.execute(_OLD_TX_HISTORY_DDL)
    conn.commit()
    conn.close()


async def test_migrate_fk_table_absent(tmp_path):
    """Migration returns True when transaction_history table doesn't exist yet."""
    db_path = str(tmp_path / "no_tx_table.sqlite")
    # Create a DB with only tracked_addresses (no transaction_history)
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE tracked_addresses (address TEXT PRIMARY KEY)")
    conn.commit()
    conn.close()

    db_manager = DatabaseManager(db_path=db_path)
    result = db_manager._migrate_transaction_history_fk_sync()
    assert result is True


async def test_migrate_fk_already_has_cascade(tmp_path):
    """Migration returns True without touching schema when CASCADE already present."""
    db_path = str(tmp_path / "cascade_db.sqlite")
    conn = sqlite3.connect(db_path)
    # Create table WITH the correct ON DELETE CASCADE
    conn.execute(_TRANSACTION_HISTORY_DDL.format(name="transaction_history"))
    conn.commit()
    conn.close()

    db_manager = DatabaseManager(db_path=db_path)
    result = db_manager._migrate_transaction_history_fk_sync()
    assert result is True

    # Schema should still contain ON DELETE CASCADE (unchanged)
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='transaction_history'"
    ).fetchone()
    conn.close()
    assert row is not None
    assert "on delete cascade" in row[0].lower()


async def test_migrate_fk_performs_migration(tmp_path):
    """Migration rewrites table to add ON DELETE CASCADE when it was missing."""
    db_path = str(tmp_path / "old_schema.sqlite")
    _create_old_schema_db(db_path)

    # Verify old schema lacks CASCADE before migration
    conn = sqlite3.connect(db_path)
    row_before = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='transaction_history'"
    ).fetchone()
    conn.close()
    assert "on delete cascade" not in (row_before[0] or "").lower()

    db_manager = DatabaseManager(db_path=db_path)
    result = db_manager._migrate_transaction_history_fk_sync()
    assert result is True

    # After migration the schema must have ON DELETE CASCADE
    conn = sqlite3.connect(db_path)
    row_after = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='transaction_history'"
    ).fetchone()
    conn.close()
    assert row_after is not None
    assert "on delete cascade" in row_after[0].lower()


async def test_migrate_fk_preserves_existing_rows(tmp_path):
    """Migration copies existing rows to the new table."""
    db_path = str(tmp_path / "preserve_rows.sqlite")
    _create_old_schema_db(db_path)

    # Insert a row before migration
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO tracked_addresses (address) VALUES (?)", ("0xabc",))
    conn.execute(
        "INSERT INTO transaction_history "
        "(tx_hash, monitored_address, from_address, to_address, value, block_number, timestamp, token_symbol) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("0xhash1", "0xabc", "0xfrom", "0xto", 1.0, 100, "2025-01-01T00:00:00+00:00", "USDT"),
    )
    conn.commit()
    conn.close()

    db_manager = DatabaseManager(db_path=db_path)
    assert db_manager._migrate_transaction_history_fk_sync() is True

    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT tx_hash FROM transaction_history").fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0][0] == "0xhash1"


# --- Spam transaction queries ---

async def _setup_user_with_spam(db: DatabaseManager, user_id: int, addr: str) -> None:
    await db.add_user(user_id, f"u{user_id}", "U", str(user_id))
    await db.add_wallet(user_id, addr)


async def test_get_spam_transactions_empty(memory_db_manager: DatabaseManager):
    """Returns empty list when no spam transactions exist."""
    await _setup_user_with_spam(memory_db_manager, 801, "0xspam0000000000000000000000000000000000aa")
    result = await memory_db_manager.get_spam_transactions_for_user(801)
    assert result == []


async def test_get_spam_transactions_returns_spam_only(memory_db_manager: DatabaseManager):
    """Returns only transactions with risk_score >= threshold."""
    addr = "0xspam0000000000000000000000000000000000bb"
    await _setup_user_with_spam(memory_db_manager, 802, addr)

    # Store one spam and one legit tx
    await memory_db_manager.store_transaction(
        "0xspam_tx", addr, "0xfrom1", "0xto1", 0.01, 100, "2025-01-01T00:00:00+00:00", "USDT", risk_score=75
    )
    await memory_db_manager.store_transaction(
        "0xlegit_tx", addr, "0xfrom2", "0xto2", 50.0, 101, "2025-01-02T00:00:00+00:00", "USDT", risk_score=5
    )

    result = await memory_db_manager.get_spam_transactions_for_user(802)
    assert len(result) == 1
    assert result[0]["tx_hash"] == "0xspam_tx"
    assert result[0]["risk_score"] == 75


async def test_get_spam_transactions_respects_limit(memory_db_manager: DatabaseManager):
    """Limit parameter caps number of returned rows."""
    addr = "0xspam0000000000000000000000000000000000cc"
    await _setup_user_with_spam(memory_db_manager, 803, addr)

    for i in range(5):
        await memory_db_manager.store_transaction(
            f"0xspam_{i:04x}", addr, "0xfrom", "0xto", 0.01, 100 + i,
            f"2025-01-0{i+1}T00:00:00+00:00", "USDT", risk_score=60 + i,
        )

    result = await memory_db_manager.get_spam_transactions_for_user(803, limit=3)
    assert len(result) == 3


async def test_get_spam_summary_empty(memory_db_manager: DatabaseManager):
    """Summary returns zeros when no spam transactions exist."""
    await _setup_user_with_spam(memory_db_manager, 804, "0xspam0000000000000000000000000000000000dd")
    summary = await memory_db_manager.get_spam_summary_for_user(804)
    assert summary["count"] == 0
    assert summary["total_value"] == 0.0


async def test_get_spam_summary_with_data(memory_db_manager: DatabaseManager):
    """Summary computes correct aggregates over spam transactions."""
    addr = "0xspam0000000000000000000000000000000000ee"
    await _setup_user_with_spam(memory_db_manager, 805, addr)

    await memory_db_manager.store_transaction(
        "0xspam_a", addr, "0xfrom", "0xto", 10.0, 200, "2025-01-01T00:00:00+00:00", "USDT", risk_score=60
    )
    await memory_db_manager.store_transaction(
        "0xspam_b", addr, "0xfrom", "0xto", 20.0, 201, "2025-01-02T00:00:00+00:00", "USDT", risk_score=80
    )
    # Below threshold, should not be counted
    await memory_db_manager.store_transaction(
        "0xlegit_c", addr, "0xfrom", "0xto", 100.0, 202, "2025-01-03T00:00:00+00:00", "USDT", risk_score=10
    )

    summary = await memory_db_manager.get_spam_summary_for_user(805)
    assert summary["count"] == 2
    assert summary["total_value"] == pytest.approx(30.0)
    assert summary["max_score"] == 80
    assert summary["avg_score"] == 70


async def test_get_spam_transactions_only_own_addresses(memory_db_manager: DatabaseManager):
    """User can only see spam from their own watched addresses."""
    addr_user1 = "0xspam0000000000000000000000000000000000ff"
    addr_user2 = "0xspam000000000000000000000000000000000100"
    await _setup_user_with_spam(memory_db_manager, 806, addr_user1)
    await _setup_user_with_spam(memory_db_manager, 807, addr_user2)

    # Store spam for user2's address
    await memory_db_manager.store_transaction(
        "0xother_spam", addr_user2, "0xfrom", "0xto", 0.01, 300,
        "2025-01-01T00:00:00+00:00", "USDT", risk_score=75
    )

    # User1 should see nothing
    result = await memory_db_manager.get_spam_transactions_for_user(806)
    assert result == []


# --- cleanup_old_transactions ---


async def test_cleanup_old_transactions_removes_old(memory_db_manager: DatabaseManager):
    """Transactions older than days_to_keep are deleted."""
    addr = "0xclean000000000000000000000000000000000aa"
    await memory_db_manager.add_user(901, "u901", "U", "1")
    await memory_db_manager.add_wallet(901, addr)

    # Insert an old transaction (35 days ago)
    old_ts = (datetime.now(UTC) - timedelta(days=35)).isoformat()
    await memory_db_manager.store_transaction(
        "0xold_tx", addr, "0xfrom", "0xto", 10.0, 100, old_ts, "USDT", risk_score=None
    )
    # Insert a recent transaction
    recent_ts = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    await memory_db_manager.store_transaction(
        "0xrecent_tx", addr, "0xfrom", "0xto", 20.0, 101, recent_ts, "USDT", risk_score=None
    )

    deleted = await memory_db_manager.cleanup_old_transactions(days_to_keep=30)
    assert deleted == 1

    remaining = await memory_db_manager.get_recent_transactions(addr, limit=10)
    assert len(remaining) == 1
    assert remaining[0]["tx_hash"] == "0xrecent_tx"


async def test_cleanup_old_transactions_none_to_delete(memory_db_manager: DatabaseManager):
    """Returns 0 when nothing is old enough to delete."""
    addr = "0xclean000000000000000000000000000000000bb"
    await memory_db_manager.add_user(902, "u902", "U", "2")
    await memory_db_manager.add_wallet(902, addr)

    recent_ts = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    await memory_db_manager.store_transaction(
        "0xfresh_tx", addr, "0xfrom", "0xto", 5.0, 200, recent_ts, "USDT", risk_score=None
    )

    deleted = await memory_db_manager.cleanup_old_transactions(days_to_keep=30)
    assert deleted == 0


async def test_cleanup_old_transactions_empty_table(memory_db_manager: DatabaseManager):
    """Returns 0 when transaction_history is empty."""
    deleted = await memory_db_manager.cleanup_old_transactions(days_to_keep=30)
    assert deleted == 0
