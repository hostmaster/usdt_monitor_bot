# tests/test_with_fallback.py
"""Unit tests for WithFallback and ProviderCircuitBreaker."""
import time
from unittest.mock import AsyncMock

import aiohttp
import pytest

from usdt_monitor_bot.blockchain_provider import (
    ProviderCircuitBreaker,
    ProviderError,
    WithFallback,
)
from usdt_monitor_bot.etherscan import EtherscanError

CONTRACT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
ADDRESS = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

SAMPLE_TXS = [{"hash": "0x1", "blockNumber": "100", "timeStamp": "1678886400"}]


def _make_provider(
    txs=None,
    latest_block=19000000,
    creation_block=12345678,
):
    """Create a mock provider that returns the given values."""
    p = AsyncMock()
    p.get_token_transactions = AsyncMock(return_value=txs or [])
    p.get_latest_block_number = AsyncMock(return_value=latest_block)
    p.get_contract_creation_block = AsyncMock(return_value=creation_block)
    p.close = AsyncMock()
    return p


def _make_failing_provider(exc: Exception):
    """Create a mock provider that always raises exc."""
    p = AsyncMock()
    p.get_token_transactions = AsyncMock(side_effect=exc)
    p.get_latest_block_number = AsyncMock(side_effect=exc)
    p.get_contract_creation_block = AsyncMock(side_effect=exc)
    p.close = AsyncMock()
    return p


# --- WithFallback basic routing ---


async def test_primary_success_no_fallback_called():
    primary = _make_provider(txs=SAMPLE_TXS)
    fallback = _make_provider(txs=[])
    client = WithFallback(primary=primary, fallbacks=[fallback])

    result = await client.get_token_transactions(CONTRACT, ADDRESS)

    assert result == SAMPLE_TXS
    primary.get_token_transactions.assert_awaited_once()
    fallback.get_token_transactions.assert_not_awaited()


async def test_primary_fails_fallback_called():
    primary = _make_failing_provider(EtherscanError("quota exceeded"))
    fallback = _make_provider(txs=SAMPLE_TXS)
    client = WithFallback(primary=primary, fallbacks=[fallback], failure_threshold=1)

    result = await client.get_token_transactions(CONTRACT, ADDRESS)

    assert result == SAMPLE_TXS
    primary.get_token_transactions.assert_awaited_once()
    fallback.get_token_transactions.assert_awaited_once()


async def test_aiohttp_error_triggers_fallback():
    primary = _make_failing_provider(aiohttp.ClientConnectionError("network"))
    fallback = _make_provider(txs=SAMPLE_TXS)
    client = WithFallback(primary=primary, fallbacks=[fallback], failure_threshold=1)

    result = await client.get_token_transactions(CONTRACT, ADDRESS)
    assert result == SAMPLE_TXS


async def test_timeout_error_triggers_fallback():
    primary = _make_failing_provider(TimeoutError())
    fallback = _make_provider(txs=SAMPLE_TXS)
    client = WithFallback(primary=primary, fallbacks=[fallback], failure_threshold=1)

    result = await client.get_token_transactions(CONTRACT, ADDRESS)
    assert result == SAMPLE_TXS


async def test_provider_error_triggers_fallback():
    primary = _make_failing_provider(ProviderError("blockscout down"))
    fallback = _make_provider(txs=SAMPLE_TXS)
    client = WithFallback(primary=primary, fallbacks=[fallback], failure_threshold=1)

    result = await client.get_token_transactions(CONTRACT, ADDRESS)
    assert result == SAMPLE_TXS


async def test_all_providers_fail_raises_last_exception():
    err1 = EtherscanError("primary failed")
    err2 = ProviderError("fallback also failed")
    primary = _make_failing_provider(err1)
    fallback = _make_failing_provider(err2)
    client = WithFallback(primary=primary, fallbacks=[fallback], failure_threshold=1)

    with pytest.raises(ProviderError, match="fallback also failed"):
        await client.get_token_transactions(CONTRACT, ADDRESS)


async def test_no_fallbacks_primary_fails_raises():
    primary = _make_failing_provider(EtherscanError("out"))
    client = WithFallback(primary=primary, fallbacks=[], failure_threshold=1)

    with pytest.raises(EtherscanError):
        await client.get_token_transactions(CONTRACT, ADDRESS)


async def test_get_latest_block_number_routes_to_fallback():
    primary = _make_failing_provider(EtherscanError("rate limited"))
    fallback = _make_provider(latest_block=19999999)
    client = WithFallback(primary=primary, fallbacks=[fallback], failure_threshold=1)

    result = await client.get_latest_block_number()
    assert result == 19999999


async def test_get_contract_creation_block_routes_to_fallback():
    primary = _make_failing_provider(EtherscanError("out"))
    fallback = _make_provider(creation_block=4634748)
    client = WithFallback(primary=primary, fallbacks=[fallback], failure_threshold=1)

    result = await client.get_contract_creation_block(CONTRACT)
    assert result == 4634748


async def test_close_calls_all_providers():
    primary = _make_provider()
    f1 = _make_provider()
    f2 = _make_provider()
    client = WithFallback(primary=primary, fallbacks=[f1, f2])

    await client.close()

    primary.close.assert_awaited_once()
    f1.close.assert_awaited_once()
    f2.close.assert_awaited_once()


# --- ProviderCircuitBreaker ---


def test_circuit_breaker_starts_available():
    cb = ProviderCircuitBreaker("TestProvider", failure_threshold=3, cooldown_seconds=60)
    assert cb.is_available()
    assert not cb.is_recovering()


def test_circuit_breaker_opens_after_threshold():
    cb = ProviderCircuitBreaker("TestProvider", failure_threshold=3, cooldown_seconds=60)
    cb.record_failure()
    cb.record_failure()
    assert cb.is_available()  # still closed after 2 failures
    cb.record_failure()
    assert not cb.is_available()  # opened after 3rd failure


def test_circuit_breaker_resets_on_success():
    cb = ProviderCircuitBreaker("TestProvider", failure_threshold=2, cooldown_seconds=60)
    cb.record_failure()
    cb.record_failure()
    assert not cb.is_available()
    cb.record_success()
    assert cb.is_available()


def test_circuit_breaker_recovers_after_cooldown():
    cb = ProviderCircuitBreaker("TestProvider", failure_threshold=2, cooldown_seconds=1)
    cb.record_failure()
    cb.record_failure()
    assert not cb.is_available()

    # Simulate cooldown passing
    cb._opened_at = time.monotonic() - 2.0  # 2s ago > 1s cooldown

    assert cb.is_available()
    assert cb.is_recovering()


def test_circuit_breaker_not_recovering_when_closed():
    cb = ProviderCircuitBreaker("TestProvider", failure_threshold=3, cooldown_seconds=60)
    assert not cb.is_recovering()


def test_circuit_breaker_not_recovering_during_cooldown():
    cb = ProviderCircuitBreaker("TestProvider", failure_threshold=1, cooldown_seconds=300)
    cb.record_failure()
    # cooldown not elapsed yet
    assert not cb.is_recovering()
    assert not cb.is_available()


# --- Circuit breaker integration with WithFallback ---


async def test_circuit_opens_after_threshold_skips_provider():
    """After failure_threshold failures, primary is skipped and fallback used."""
    primary = _make_failing_provider(EtherscanError("out"))
    fallback = _make_provider(txs=SAMPLE_TXS)
    client = WithFallback(
        primary=primary, fallbacks=[fallback], failure_threshold=2, cooldown_seconds=300
    )

    # First call: primary tried and fails, fallback succeeds
    await client.get_token_transactions(CONTRACT, ADDRESS)
    assert primary.get_token_transactions.call_count == 1

    # Second call: primary tried and fails again → threshold hit, circuit opens
    await client.get_token_transactions(CONTRACT, ADDRESS)
    assert primary.get_token_transactions.call_count == 2

    # Third call: primary circuit is open → skipped entirely
    await client.get_token_transactions(CONTRACT, ADDRESS)
    assert primary.get_token_transactions.call_count == 2  # not called again


async def test_circuit_breaker_recovery_after_cooldown():
    """After cooldown, primary is attempted again and recovers."""
    primary = _make_provider(txs=SAMPLE_TXS)  # will succeed after recovery
    fallback = _make_provider(txs=[])
    client = WithFallback(
        primary=primary, fallbacks=[fallback], failure_threshold=1, cooldown_seconds=300
    )

    # Manually open the primary's circuit breaker and backdate it
    primary_breaker = client._breakers[0]
    primary_breaker._consecutive_failures = 1
    primary_breaker._opened_at = time.monotonic() - 301.0  # past cooldown

    assert primary_breaker.is_available()  # cooldown expired
    assert primary_breaker.is_recovering()

    result = await client.get_token_transactions(CONTRACT, ADDRESS)

    # Primary was tried and succeeded → circuit closes
    assert result == SAMPLE_TXS
    primary.get_token_transactions.assert_awaited_once()
    assert primary_breaker._opened_at is None  # circuit closed


# --- get_contract_creation_blocks (bulk) ---


async def test_bulk_primary_success_no_fallback():
    """Primary returns data, fallback not called."""
    primary = _make_provider()
    primary.get_contract_creation_blocks = AsyncMock(
        return_value={"0xa": 100, "0xb": 200}
    )
    fallback = _make_provider()
    fallback.get_contract_creation_blocks = AsyncMock(return_value={})
    client = WithFallback(primary=primary, fallbacks=[fallback])

    result = await client.get_contract_creation_blocks(["0xa", "0xb"])
    assert result == {"0xa": 100, "0xb": 200}
    primary.get_contract_creation_blocks.assert_awaited_once()
    fallback.get_contract_creation_blocks.assert_not_awaited()


async def test_bulk_empty_input_returns_empty():
    """Empty input short-circuits to empty dict without touching providers."""
    primary = _make_provider()
    primary.get_contract_creation_blocks = AsyncMock(return_value={"should": "skip"})
    client = WithFallback(primary=primary, fallbacks=[])

    result = await client.get_contract_creation_blocks([])
    assert result == {}
    primary.get_contract_creation_blocks.assert_not_awaited()


async def test_bulk_primary_raises_falls_over_to_fallback():
    """Transport-level error on primary triggers fallback with full address list."""
    primary = _make_provider()
    primary.get_contract_creation_blocks = AsyncMock(side_effect=aiohttp.ClientError("boom"))
    fallback = _make_provider()
    fallback.get_contract_creation_blocks = AsyncMock(return_value={"0xa": 7})
    client = WithFallback(primary=primary, fallbacks=[fallback])

    result = await client.get_contract_creation_blocks(["0xa"])
    assert result == {"0xa": 7}
    primary.get_contract_creation_blocks.assert_awaited_once()
    fallback.get_contract_creation_blocks.assert_awaited_once_with(["0xa"])


async def test_bulk_partial_none_is_authoritative_no_fallback_requery():
    """
    None entries in the primary's response are treated as authoritative
    (`not a contract`) and are NOT re-queried against fallbacks \u2014 re-querying
    would reintroduce the N+1 this feature eliminates.
    """
    primary = _make_provider()
    primary.get_contract_creation_blocks = AsyncMock(
        return_value={"0xa": 100, "0xb": None}
    )
    fallback = _make_provider()
    fallback.get_contract_creation_blocks = AsyncMock(
        return_value={"0xa": 999, "0xb": 999}
    )
    client = WithFallback(primary=primary, fallbacks=[fallback])

    result = await client.get_contract_creation_blocks(["0xa", "0xb"])
    assert result == {"0xa": 100, "0xb": None}
    fallback.get_contract_creation_blocks.assert_not_awaited()


async def test_bulk_all_providers_fail_reraises():
    """When every provider raises, the last exception is reraised."""
    primary = _make_provider()
    primary.get_contract_creation_blocks = AsyncMock(side_effect=EtherscanError("a"))
    fallback = _make_provider()
    fallback.get_contract_creation_blocks = AsyncMock(side_effect=ProviderError("b"))
    client = WithFallback(primary=primary, fallbacks=[fallback])

    with pytest.raises(ProviderError):
        await client.get_contract_creation_blocks(["0xa"])
    primary.get_contract_creation_blocks.assert_awaited_once()
    fallback.get_contract_creation_blocks.assert_awaited_once()
