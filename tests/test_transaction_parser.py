# tests/test_transaction_parser.py
"""Tests for transaction_parser utility functions."""
from datetime import UTC, datetime
from decimal import Decimal

from usdt_monitor_bot.etherscan import _MAX_VALID_BLOCK_NUMBER
from usdt_monitor_bot.transaction_parser import (
    convert_db_transaction_to_metadata,
    filter_transactions,
    parse_timestamp,
)

NOW_TS = int(datetime.now(UTC).timestamp())


# --- parse_timestamp ---


def test_parse_timestamp_unix_string():
    result = parse_timestamp(str(NOW_TS))
    assert result is not None
    assert isinstance(result, datetime)
    assert result.tzinfo is not None


def test_parse_timestamp_iso_format():
    result = parse_timestamp("2025-01-15T12:00:00+00:00")
    assert result is not None
    assert result.year == 2025


def test_parse_timestamp_iso_with_z():
    result = parse_timestamp("2025-01-15T12:00:00Z")
    assert result is not None


def test_parse_timestamp_invalid_returns_none():
    assert parse_timestamp("not_a_timestamp") is None
    assert parse_timestamp("") is None


# --- filter_transactions ---


def _make_tx(block: int, age_seconds: int = 0) -> dict:
    ts = NOW_TS - age_seconds
    return {
        "blockNumber": str(block),
        "timeStamp": str(ts),
        "hash": f"0x{block:08x}",
        "from": "0xfrom",
        "to": "0xto",
        "value": "1000",
    }


def test_filter_max_per_check_zero_returns_empty():
    txs = [_make_tx(100)]
    result = filter_transactions(txs, start_block=0, max_age_days=7, max_per_check=0)
    assert result == []


def test_filter_block_below_start_excluded():
    tx_old = _make_tx(50)
    tx_new = _make_tx(200)
    result = filter_transactions([tx_old, tx_new], start_block=100, max_age_days=7, max_per_check=10)
    assert len(result) == 1
    assert result[0]["blockNumber"] == "200"


def test_filter_block_equal_to_start_excluded():
    tx = _make_tx(100)
    result = filter_transactions([tx], start_block=100, max_age_days=7, max_per_check=10)
    assert result == []


def test_filter_too_old_excluded():
    old_tx = _make_tx(200, age_seconds=8 * 24 * 3600)  # 8 days old
    result = filter_transactions([old_tx], start_block=0, max_age_days=7, max_per_check=10)
    assert result == []


def test_filter_recent_included():
    recent_tx = _make_tx(200, age_seconds=3600)  # 1 hour old
    result = filter_transactions([recent_tx], start_block=0, max_age_days=7, max_per_check=10)
    assert len(result) == 1


def test_filter_returns_newest_n_in_order():
    txs = [_make_tx(100 + i) for i in range(10)]
    result = filter_transactions(txs, start_block=0, max_age_days=7, max_per_check=3)
    assert len(result) == 3
    # Should be the 3 newest
    assert [int(tx["blockNumber"]) for tx in result] == [107, 108, 109]


def test_filter_out_of_range_block_skipped():
    valid_tx = _make_tx(500)
    invalid_tx = {
        "blockNumber": str(_MAX_VALID_BLOCK_NUMBER + 1),
        "timeStamp": str(NOW_TS),
        "hash": "0xbadblock",
        "from": "0xfrom",
        "to": "0xto",
        "value": "1000",
    }
    result = filter_transactions([valid_tx, invalid_tx], start_block=0, max_age_days=7, max_per_check=10)
    assert len(result) == 1
    assert result[0]["blockNumber"] == "500"


def test_filter_zero_block_number_skipped():
    """Block number 0 fails the `0 < block_num` bounds check and is excluded."""
    zero_tx = _make_tx(0)
    result = filter_transactions([zero_tx], start_block=0, max_age_days=7, max_per_check=10)
    assert result == []


def test_filter_block_above_start_included():
    tx = _make_tx(1)
    result = filter_transactions([tx], start_block=0, max_age_days=7, max_per_check=10)
    assert len(result) == 1


# --- convert_db_transaction_to_metadata ---


def test_convert_db_tx_success():
    db_tx = {
        "tx_hash": "0xabc123",
        "from_address": "0xfrom",
        "to_address": "0xto",
        "value": "10.5",
        "block_number": 9999,
        "timestamp": "2025-01-15T12:00:00+00:00",
    }
    result = convert_db_transaction_to_metadata(db_tx)
    assert result is not None
    assert result.tx_hash == "0xabc123"
    assert result.value == Decimal("10.5")
    assert result.block_number == 9999


def test_convert_db_tx_invalid_timestamp_returns_none():
    db_tx = {
        "tx_hash": "0xabc123",
        "from_address": "0xfrom",
        "to_address": "0xto",
        "value": "10.0",
        "block_number": 100,
        "timestamp": "NOT_A_DATE",
    }
    result = convert_db_transaction_to_metadata(db_tx)
    assert result is None


def test_convert_db_tx_missing_fields_uses_defaults():
    """Missing optional fields fall back to defaults (empty strings, 0, etc.)."""
    db_tx = {
        "timestamp": "2025-01-15T12:00:00+00:00",
    }
    result = convert_db_transaction_to_metadata(db_tx)
    assert result is not None
    assert result.tx_hash == ""
    assert result.value == Decimal("0")
