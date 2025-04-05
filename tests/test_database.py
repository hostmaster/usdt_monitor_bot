# tests/test_database.py
import pytest

from usdt_monitor_bot.database import DatabaseManager

pytestmark = pytest.mark.asyncio


async def test_init_db(memory_db_manager: DatabaseManager):
    # Fixture handles init, test just ensures it runs without error implicitly
    pass


async def test_add_and_check_user(memory_db_manager: DatabaseManager):
    user_id = 123
    assert not await memory_db_manager.check_user_exists(
        user_id
    )  # Should be False initially
    added = await memory_db_manager.add_user(user_id, "testuser", "Test", "User")
    assert added is True  # First add returns True (rowcount > 0)
    assert await memory_db_manager.check_user_exists(user_id)  # Should exist now
    added_again = await memory_db_manager.add_user(user_id, "testuser", "Test", "User")
    assert (
        added_again is False
    )  # Duplicate INSERT OR IGNORE returns False (rowcount == 0)
    assert await memory_db_manager.check_user_exists(user_id)  # Still exists


async def test_add_and_list_wallets(memory_db_manager: DatabaseManager):
    user_id = 456
    addr1 = "0x1111111111111111111111111111111111111111"
    addr2 = "0x2222222222222222222222222222222222222222"
    addr1_upper = "0x1111111111111111111111111111111111111111"

    await memory_db_manager.add_user(user_id, "u2", "U", "2")
    initial_wallets = await memory_db_manager.list_wallets(user_id)
    assert initial_wallets == []  # Expect empty list initially
    assert await memory_db_manager.add_wallet(user_id, addr1) is True
    assert await memory_db_manager.add_wallet(user_id, addr2) is True
    assert (
        await memory_db_manager.add_wallet(user_id, addr1_upper) is False
    )  # Duplicate returns False
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
    assert removed is True  # Successful DELETE returns True (rowcount > 0)
    assert await memory_db_manager.list_wallets(user_id) == []  # Verify removed
    removed_again = await memory_db_manager.remove_wallet(user_id, addr)
    assert removed_again is False  # Deleting non-existent returns False (rowcount == 0)


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
    assert update1 is True
    assert await memory_db_manager.get_last_checked_block(addr) == 12345

    update2 = await memory_db_manager.update_last_checked_block(addr, 54321)
    assert update2 is True
    assert await memory_db_manager.get_last_checked_block(addr) == 54321

    # Check non-tracked address gets added with 0
    assert await memory_db_manager.get_last_checked_block("0xabc") == 0

    # Correctly wrap the call to _execute_db_query
    result = await memory_db_manager._run_sync_db_operation(
        memory_db_manager._execute_db_query,  # Function to run
        # --- Positional arguments for _execute_db_query: ---
        "SELECT last_checked_block FROM tracked_addresses WHERE address=?",  # query
        ("0xabc".lower(),),  # params
        True,  # fetch_one=True
        False,  # fetch_all=False
        False,  # commit=False
        # --- End positional arguments ---
    )
    assert result == (0,)  # Check the value returned by fetchone
