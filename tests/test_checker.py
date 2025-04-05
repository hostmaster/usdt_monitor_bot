# tests/test_checker.py
from dataclasses import replace
from unittest.mock import call  # Import call and ANY

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
    "hash": "0xtx1",
    "blockNumber": str(BLOCK_ADDR1_START + 1),
    "value": "1000000",
    "from": "0xsender1",
    "to": ADDR1,
    "contractAddress": USDT_CONTRACT,
    "timeStamp": "1678886401",
    "tokenDecimal": "6",
}
TX2_OUTGOING_ADDR1_USDT = {
    "hash": "0xtx2",
    "blockNumber": str(BLOCK_ADDR1_START + 2),
    "value": "500000",
    "from": ADDR1,
    "to": "0xreceiver1",
    "contractAddress": USDT_CONTRACT,
    "timeStamp": "1678886402",
    "tokenDecimal": "6",
}
TX3_INCOMING_ADDR2_USDC = {
    "hash": "0xtx3",
    "blockNumber": str(BLOCK_ADDR2_START + 5),
    "value": "2000000",
    "from": "0xsender2",
    "to": ADDR2,
    "contractAddress": USDC_CONTRACT,
    "timeStamp": "1678886405",
    "tokenDecimal": "6",
}


@pytest.fixture
def checker(mock_config, mock_db_manager, mock_etherscan_client, mock_notifier):
    # Ensure the mock config has the correct token addresses for checks
    updated_config = replace(
        mock_config,
        usdt_contract_address=USDT_CONTRACT,
        usdc_contract_address=USDC_CONTRACT,
    )
    return TransactionChecker(
        config=updated_config,
        db_manager=mock_db_manager,
        etherscan_client=mock_etherscan_client,
        notifier=mock_notifier,
    )


# --- Test Cases ---


async def test_check_no_addresses(
    checker: TransactionChecker, mock_db_manager, mock_etherscan_client
):
    mock_db_manager.get_distinct_addresses.return_value = []

    await checker.check_all_addresses()

    mock_db_manager.get_distinct_addresses.assert_awaited_once()
    mock_etherscan_client.get_usdt_token_transactions.assert_not_awaited()
    mock_etherscan_client.get_usdc_token_transactions.assert_not_awaited()
    mock_db_manager.update_last_checked_block.assert_not_awaited()


async def test_check_address_no_new_tx(
    checker: TransactionChecker, mock_db_manager, mock_etherscan_client, mock_notifier
):
    mock_db_manager.get_distinct_addresses.return_value = [ADDR1]
    mock_db_manager.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan_client.get_usdt_token_transactions.return_value = []  # No tx found
    mock_etherscan_client.get_usdc_token_transactions.return_value = []  # No tx found

    await checker.check_all_addresses()

    mock_db_manager.get_distinct_addresses.assert_awaited_once()
    mock_db_manager.get_last_checked_block.assert_awaited_once_with(ADDR1)
    # Query should start from block + 1
    mock_etherscan_client.get_usdt_token_transactions.assert_awaited_once_with(
        ADDR1, start_block=BLOCK_ADDR1_START + 1
    )
    mock_etherscan_client.get_usdc_token_transactions.assert_awaited_once_with(
        ADDR1, start_block=BLOCK_ADDR1_START + 1
    )
    mock_notifier.send_token_notification.assert_not_awaited()
    # Should update with the *original* start block since no new ones were processed
    mock_db_manager.update_last_checked_block.assert_awaited_once_with(
        ADDR1, BLOCK_ADDR1_START
    )


async def test_check_address_new_incoming_tx(
    checker: TransactionChecker, mock_db_manager, mock_etherscan_client, mock_notifier
):
    mock_db_manager.get_distinct_addresses.return_value = [ADDR1]
    mock_db_manager.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan_client.get_usdt_token_transactions.return_value = [
        TX1_INCOMING_ADDR1_USDT
    ]
    mock_etherscan_client.get_usdc_token_transactions.return_value = []
    mock_db_manager.get_users_for_address.return_value = [USER1]

    await checker.check_all_addresses()

    mock_etherscan_client.get_usdt_token_transactions.assert_awaited_once_with(
        ADDR1, start_block=BLOCK_ADDR1_START + 1
    )
    mock_etherscan_client.get_usdc_token_transactions.assert_awaited_once_with(
        ADDR1, start_block=BLOCK_ADDR1_START + 1
    )
    mock_db_manager.get_users_for_address.assert_awaited_once_with(ADDR1)
    mock_notifier.send_token_notification.assert_awaited_once_with(
        USER1, ADDR1, TX1_INCOMING_ADDR1_USDT, "USDT"
    )
    # Update with the block number of the processed transaction
    mock_db_manager.update_last_checked_block.assert_awaited_once_with(
        ADDR1, int(TX1_INCOMING_ADDR1_USDT["blockNumber"])
    )


async def test_check_address_outgoing_tx_only(
    checker: TransactionChecker, mock_db_manager, mock_etherscan_client, mock_notifier
):
    mock_db_manager.get_distinct_addresses.return_value = [ADDR1]
    mock_db_manager.get_last_checked_block.return_value = BLOCK_ADDR1_START
    mock_etherscan_client.get_usdt_token_transactions.return_value = [
        TX2_OUTGOING_ADDR1_USDT
    ]
    mock_etherscan_client.get_usdc_token_transactions.return_value = []
    mock_db_manager.get_users_for_address.return_value = [USER1]  # Doesn't matter here

    await checker.check_all_addresses()

    mock_etherscan_client.get_usdt_token_transactions.assert_awaited_once_with(
        ADDR1, start_block=BLOCK_ADDR1_START + 1
    )
    mock_etherscan_client.get_usdc_token_transactions.assert_awaited_once_with(
        ADDR1, start_block=BLOCK_ADDR1_START + 1
    )
    mock_db_manager.get_users_for_address.assert_awaited_once_with(ADDR1)
    # Notifier should NOT be called for outgoing tx
    mock_notifier.send_token_notification.assert_not_awaited()
    # Block should still be updated as we processed this block
    mock_db_manager.update_last_checked_block.assert_awaited_once_with(
        ADDR1, int(TX2_OUTGOING_ADDR1_USDT["blockNumber"])
    )


async def test_check_mixed_incoming_outgoing(
    checker: TransactionChecker, mock_db_manager, mock_etherscan_client, mock_notifier
):
    mock_db_manager.get_distinct_addresses.return_value = [ADDR1]
    mock_db_manager.get_last_checked_block.return_value = BLOCK_ADDR1_START
    # Return both, checker should filter
    mock_etherscan_client.get_usdt_token_transactions.return_value = [
        TX1_INCOMING_ADDR1_USDT,
        TX2_OUTGOING_ADDR1_USDT,
    ]
    mock_etherscan_client.get_usdc_token_transactions.return_value = []
    mock_db_manager.get_users_for_address.return_value = [
        USER1,
        USER2,
    ]  # Two users tracking

    await checker.check_all_addresses()

    # Check notifications sent only for the incoming one, to both users
    assert mock_notifier.send_token_notification.await_count == 2
    mock_notifier.send_token_notification.assert_has_awaits(
        [
            call(USER1, ADDR1, TX1_INCOMING_ADDR1_USDT, "USDT"),
            call(USER2, ADDR1, TX1_INCOMING_ADDR1_USDT, "USDT"),
        ],
        any_order=True,
    )

    # Block updated to the HIGHEST block seen in the batch
    mock_db_manager.update_last_checked_block.assert_awaited_once_with(
        ADDR1, int(TX2_OUTGOING_ADDR1_USDT["blockNumber"])
    )


async def test_check_multiple_addresses(
    checker: TransactionChecker, mock_db_manager, mock_etherscan_client, mock_notifier
):
    mock_db_manager.get_distinct_addresses.return_value = [ADDR1, ADDR2]
    mock_db_manager.get_last_checked_block.side_effect = [
        BLOCK_ADDR1_START,
        BLOCK_ADDR2_START,
    ]
    mock_etherscan_client.get_usdt_token_transactions.side_effect = [
        [TX1_INCOMING_ADDR1_USDT],  # Txs for ADDR1
        [],  # No USDT txs for ADDR2
    ]
    mock_etherscan_client.get_usdc_token_transactions.side_effect = [
        [],  # No USDC txs for ADDR1
        [TX3_INCOMING_ADDR2_USDC],  # Txs for ADDR2
    ]
    mock_db_manager.get_users_for_address.side_effect = [[USER1], [USER2]]

    await checker.check_all_addresses()

    # Check Etherscan calls
    assert mock_etherscan_client.get_usdt_token_transactions.await_count == 2
    assert mock_etherscan_client.get_usdc_token_transactions.await_count == 2
    mock_etherscan_client.get_usdt_token_transactions.assert_has_awaits(
        [
            call(ADDR1, start_block=BLOCK_ADDR1_START + 1),
            call(ADDR2, start_block=BLOCK_ADDR2_START + 1),
        ],
        any_order=True,
    )
    mock_etherscan_client.get_usdc_token_transactions.assert_has_awaits(
        [
            call(ADDR1, start_block=BLOCK_ADDR1_START + 1),
            call(ADDR2, start_block=BLOCK_ADDR2_START + 1),
        ],
        any_order=True,
    )

    # Check notifications
    assert mock_notifier.send_token_notification.await_count == 2
    mock_notifier.send_token_notification.assert_has_awaits(
        [
            call(USER1, ADDR1, TX1_INCOMING_ADDR1_USDT, "USDT"),
            call(USER2, ADDR2, TX3_INCOMING_ADDR2_USDC, "USDC"),
        ],
        any_order=True,
    )

    # Check block updates
    assert mock_db_manager.update_last_checked_block.await_count == 2
    mock_db_manager.update_last_checked_block.assert_has_awaits(
        [
            call(ADDR1, int(TX1_INCOMING_ADDR1_USDT["blockNumber"])),
            call(ADDR2, int(TX3_INCOMING_ADDR2_USDC["blockNumber"])),
        ],
        any_order=True,
    )


async def test_check_etherscan_rate_limit(
    checker: TransactionChecker, mock_db_manager, mock_etherscan_client, mock_notifier
):
    mock_db_manager.get_distinct_addresses.return_value = [ADDR1, ADDR2]
    mock_db_manager.get_last_checked_block.side_effect = [
        BLOCK_ADDR1_START,
        BLOCK_ADDR2_START,
    ]
    # ADDR1 gets rate limited for USDT, so entire check is skipped
    mock_etherscan_client.get_usdt_token_transactions.side_effect = [
        EtherscanRateLimitError("Rate Limited"),
        [],  # ADDR2 has no USDT transactions
    ]
    # ADDR2 gets rate limited for USDC, so entire check is skipped
    mock_etherscan_client.get_usdc_token_transactions.side_effect = [
        EtherscanRateLimitError("Rate Limited"),  # ADDR1 gets rate limited
        EtherscanRateLimitError("Rate Limited"),  # ADDR2 gets rate limited
    ]
    mock_db_manager.get_users_for_address.return_value = [USER2]  # Should not be called

    await checker.check_all_addresses()

    # Both addresses were rate limited, so no notifications should be sent
    mock_notifier.send_token_notification.assert_not_awaited()
    # No blocks should be updated due to rate limiting
    mock_db_manager.update_last_checked_block.assert_not_awaited()
