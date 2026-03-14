# tests/test_block_tracker.py
"""Tests for BlockTracker block management logic."""
from unittest.mock import AsyncMock

import pytest

from usdt_monitor_bot.block_tracker import BlockDeterminationResult, BlockTracker
from usdt_monitor_bot.etherscan import EtherscanClient

ADDR = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ADDR_SHORT = ADDR[:8]


@pytest.fixture
def mock_etherscan():
    return AsyncMock(spec=EtherscanClient)


@pytest.fixture
def tracker(mock_etherscan):
    return BlockTracker(mock_etherscan)


# --- cap_block_to_latest ---


def test_cap_block_no_cap_needed():
    result = BlockTracker.cap_block_to_latest(500, 1000, ADDR)
    assert result == 500


def test_cap_block_caps_to_latest():
    result = BlockTracker.cap_block_to_latest(1500, 1000, ADDR)
    assert result == 1000


def test_cap_block_latest_none_no_change():
    result = BlockTracker.cap_block_to_latest(1500, None, ADDR)
    assert result == 1500


def test_cap_block_equal_no_cap():
    result = BlockTracker.cap_block_to_latest(1000, 1000, ADDR)
    assert result == 1000


# --- handle_latest_block_unavailable ---


def test_handle_latest_unavailable_with_transactions():
    """When transactions found and latest unavailable, keep new_last_block."""
    tx = {"blockNumber": "999"}
    result = BlockTracker.handle_latest_block_unavailable(900, 999, [tx], ADDR)
    assert result == BlockDeterminationResult(final_block_number=999, resetting_to_latest=False)


def test_handle_latest_unavailable_no_transactions_same_block():
    """When no transactions and block unchanged, advance by 1."""
    result = BlockTracker.handle_latest_block_unavailable(900, 900, [], ADDR)
    assert result == BlockDeterminationResult(final_block_number=901, resetting_to_latest=False)


def test_handle_latest_unavailable_no_transactions_different_block():
    """When no transactions but block advanced, keep new_last_block."""
    result = BlockTracker.handle_latest_block_unavailable(900, 950, [], ADDR)
    assert result == BlockDeterminationResult(final_block_number=950, resetting_to_latest=False)


# --- sync_block_with_blockchain ---


def test_sync_db_ahead_of_chain():
    """When DB block ahead of chain, reset to latest."""
    final, resetting = BlockTracker.sync_block_with_blockchain(1500, 1500, 1000, ADDR)
    assert final == 1000
    assert resetting is True


def test_sync_new_block_ahead_of_chain():
    """When processed block would go beyond chain, cap to latest."""
    final, resetting = BlockTracker.sync_block_with_blockchain(900, 1200, 1000, ADDR)
    assert final == 1000
    assert resetting is True


def test_sync_normal_advance():
    """Normal case: block within chain range."""
    final, resetting = BlockTracker.sync_block_with_blockchain(900, 950, 1000, ADDR)
    assert final == 950
    assert resetting is False


def test_sync_new_block_equals_latest():
    """Block exactly at latest is fine."""
    final, resetting = BlockTracker.sync_block_with_blockchain(900, 1000, 1000, ADDR)
    assert final == 1000
    assert resetting is False


# --- determine_next_block (async) ---


async def test_determine_next_block_uses_provided_latest(tracker, mock_etherscan):
    """When latest_block is provided, should not call API."""
    result = await tracker.determine_next_block(
        start_block=900, new_last_block=950, raw_transactions=[{"blockNumber": "950"}],
        address_lower=ADDR, latest_block=1000,
    )
    mock_etherscan.get_latest_block_number.assert_not_awaited()
    assert result.final_block_number == 950
    assert result.resetting_to_latest is False


async def test_determine_next_block_fetches_latest_when_none(tracker, mock_etherscan):
    """When latest_block is None, should fetch from API."""
    mock_etherscan.get_latest_block_number.return_value = 1000
    result = await tracker.determine_next_block(
        start_block=900, new_last_block=950, raw_transactions=[{"blockNumber": "950"}],
        address_lower=ADDR, latest_block=None,
    )
    mock_etherscan.get_latest_block_number.assert_awaited_once()
    assert result.final_block_number == 950


async def test_determine_next_block_no_txs_advances_to_latest(tracker, mock_etherscan):
    """No transactions: block should advance to latest."""
    mock_etherscan.get_latest_block_number.return_value = 1000
    result = await tracker.determine_next_block(
        start_block=900, new_last_block=900, raw_transactions=[],
        address_lower=ADDR, latest_block=None,
    )
    assert result.final_block_number == 1000


async def test_determine_next_block_latest_api_unavailable(tracker, mock_etherscan):
    """When API returns None, falls back to handle_latest_block_unavailable."""
    mock_etherscan.get_latest_block_number.return_value = None
    result = await tracker.determine_next_block(
        start_block=900, new_last_block=900, raw_transactions=[],
        address_lower=ADDR, latest_block=None,
    )
    # No transactions, same block → advance by 1
    assert result.final_block_number == 901
    assert result.resetting_to_latest is False
