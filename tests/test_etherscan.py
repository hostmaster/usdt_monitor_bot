# tests/test_etherscan.py
import asyncio
from unittest.mock import AsyncMock, MagicMock

import aiohttp  # Import aiohttp
import pytest

from usdt_monitor_bot.etherscan import (
    _MAX_VALID_BLOCK_NUMBER,
    AdaptiveRateLimiter,
    EtherscanClient,
    EtherscanError,
    EtherscanRateLimitError,
)

# Test data
ADDR1 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
BLOCK_START = 1000
SAMPLE_TX = {
    "blockNumber": "1001",
    "timeStamp": "1678886400",
    "hash": "0xtx1",
    "from": "0xsender",
    "to": ADDR1,
    "value": "1000000",
    "contractAddress": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
}


@pytest.fixture
def mock_config():
    """Create a mock config object."""
    config = MagicMock()
    config.etherscan_base_url = "https://api.etherscan.io/v2/api"
    config.etherscan_api_key = "test_api_key"
    config.telegram_bot_token = "test_bot_token"
    config.db_path = "test.db"
    config.etherscan_request_delay = 0.2
    config.rate_limiter_min_delay = 0.4
    config.rate_limiter_max_delay = 10.0
    config.rate_limiter_backoff_factor = 2.5
    config.rate_limiter_recovery_factor = 0.95
    config.rate_limiter_success_threshold = 20
    config.rate_limiter_recovery_cooldown = 30.0
    config.check_interval_seconds = 60
    return config


@pytest.fixture
def mock_response():
    """Create a mock response object."""
    response = AsyncMock()
    response.status = 200
    response.json.return_value = {
        "status": "1",
        "message": "OK",
        "result": [
            {
                "blockNumber": "123456",
                "timeStamp": "1620000000",
                "hash": "0x123",
                "from": "0xabc",
                "to": "0xdef",
                "value": "1000000",
                "contractAddress": "0xusdt",
                "tokenName": "Tether USD",
                "tokenSymbol": "USDT",
                "tokenDecimal": "6",
            }
        ],
    }
    return response


# Fixture to use mock_aiohttp_session from conftest.py
@pytest.fixture
async def etherscan_client_with_mocked_session(
    mock_config, mock_aiohttp_session, monkeypatch
):
    """Provides an EtherscanClient instance with a mocked aiohttp.ClientSession."""

    # Instead of monkeypatching aiohttp.ClientSession globally for all tests in this file,
    # we can inject the mock_aiohttp_session specifically into an EtherscanClient instance.
    # One way is to allow EtherscanClient to accept a session in its constructor for testing,
    # or to patch it during its __aenter__ if it creates a session there.
    # For now, let's assume EtherscanClient creates its session internally if not provided.
    # We'll patch 'aiohttp.ClientSession' just before EtherscanClient is created.

    monkeypatch.setattr(
        "aiohttp.ClientSession", lambda *args, **kwargs: mock_aiohttp_session
    )

    async with EtherscanClient(mock_config) as client:
        # The client now uses mock_aiohttp_session internally
        yield client
    # __aexit__ will call mock_aiohttp_session.close()


async def test_get_token_transactions_success(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """Test successful token transaction retrieval."""
    client = etherscan_client_with_mocked_session
    mock_session_get = (
        mock_aiohttp_session.get
    )  # This is the MagicMock returning the context manager

    # Configure the response for the successful call
    # Access the mock_response from the fixture structure
    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={
            "status": "1",
            "message": "OK",
            "result": [{"hash": "0x123", "from": "0xabc", "to": "0xdef"}],
        }
    )

    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    result = await client.get_token_transactions(contract_address, address, start_block)
    assert len(result) == 1
    assert result[0]["hash"] == "0x123"
    assert result[0]["from"] == "0xabc"
    assert result[0]["to"] == "0xdef"
    assert mock_session_get.call_count == 1


async def test_get_token_transactions_empty(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """Test empty token transaction response."""
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get

    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={"status": "1", "message": "OK", "result": []}
    )

    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    result = await client.get_token_transactions(contract_address, address, start_block)
    assert len(result) == 0
    assert mock_session_get.call_count == 1


async def test_get_token_transactions_rate_limit_eventually_fails(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """Test rate limit error handling after retries."""
    client = etherscan_client_with_mocked_session

    # Configure the mock_response that is returned by mock_session_get().__aenter__()
    # to always indicate a rate limit error.
    async def configure_rate_limit_response(mock_get_call):
        response_ctx = await mock_get_call.__aenter__()
        response_ctx.status = 429  # Rate limit HTTP status
        response_ctx.json = AsyncMock(
            side_effect=EtherscanRateLimitError("Simulated rate limit from status")
        )  # if status is checked first
        # To ensure EtherscanRateLimitError is raised if json content is checked first
        # response_ctx.json = AsyncMock(return_value={"status": "0", "message": "Max rate limit reached", "result": []})
        return response_ctx

    # We need to make session.get() itself raise the error, or the response object it yields.
    # The EtherscanClient checks response.status == 429 first.

    # Let's make the __aenter__ of the context manager (returned by get) set up the response status.
    # The mock_aiohttp_session.get returns a context manager (mock_context_manager).
    # This context manager's __aenter__ returns a response (mock_response).

    # Simplified: make the response object (mock_response) always have status 429
    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 429
    # Ensure json() isn't called or if it is, it doesn't contradict the rate limit
    mock_response.json = AsyncMock(
        return_value={"message": "Rate limit hit"}
    )  # This json might not even be called if status 429 is checked first

    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    with pytest.raises(EtherscanRateLimitError):
        await client.get_token_transactions(contract_address, address, start_block)

    assert (
        mock_aiohttp_session.get.call_count == 5
    )  # Tenacity default attempts for the client


async def test_get_token_transactions_api_error_no_retry(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """Test API error handling (non-retriable)."""
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get

    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200  # API error can come with 200 OK but status "0" in json
    mock_response.json = AsyncMock(
        return_value={
            "status": "0",
            "message": "Error! Invalid address format",
            "result": [],
        }
    )

    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    with pytest.raises(EtherscanError, match="Error! Invalid address format"):
        await client.get_token_transactions(contract_address, address, start_block)
    assert mock_session_get.call_count == 1  # Should not retry this


async def test_get_token_transactions_notok_error(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """Test NOTOK error handling with context information."""
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get

    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={"status": "0", "message": "NOTOK", "result": []}
    )

    contract_address = "0xdac17f958d2ee523a2206206994597c13d831ec7"
    address = "0x31390eaf4db4013b3d5d9dbcff494e689589ae83"
    start_block = 1000

    with pytest.raises(EtherscanError) as exc_info:
        await client.get_token_transactions(contract_address, address, start_block)

    # Verify the error message contains the status but not internal addresses/block numbers
    error_msg = str(exc_info.value)
    assert "NOTOK" in error_msg
    assert "query timeout" in error_msg.lower() or "invalid parameters" in error_msg.lower()
    # Internal details must not be leaked into error messages
    assert contract_address[:10] not in error_msg
    assert address[:10] not in error_msg
    assert str(start_block) not in error_msg

    assert mock_session_get.call_count == 1


async def test_get_token_transactions_http_error_retried(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """Test HTTP error handling (retriable aiohttp.ClientError)."""
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get

    # Configure .get() to raise ClientError directly
    mock_session_get.side_effect = [aiohttp.ClientError("Simulated network error")] * 5

    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    with pytest.raises(aiohttp.ClientError, match="Simulated network error"):
        await client.get_token_transactions(contract_address, address, start_block)
    assert mock_session_get.call_count == 5


async def test_get_token_transactions_timeout_retried(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """Test timeout error handling (retriable asyncio.TimeoutError)."""
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get

    # Configure .get() to raise TimeoutError directly
    mock_session_get.side_effect = [TimeoutError("Simulated timeout")] * 5

    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    with pytest.raises(asyncio.TimeoutError, match="Simulated timeout"):
        await client.get_token_transactions(contract_address, address, start_block)
    assert mock_session_get.call_count == 5


async def test_get_token_transactions_unexpected_format_no_retry(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """Test unexpected response format handling (non-retriable)."""
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get

    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    # This JSON {"invalid": "format"} will cause data.get("status") to be None.
    # Then message becomes "Unknown error". So EtherscanError is "API error: Unknown error".
    mock_response.json = AsyncMock(return_value={"invalid": "format"})

    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    with pytest.raises(EtherscanError, match="API error: Unknown error"):
        await client.get_token_transactions(contract_address, address, start_block)
    assert mock_session_get.call_count == 1


async def test_retry_success_on_third_attempt_rate_limit(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    client = etherscan_client_with_mocked_session
    mock_session_get = (
        mock_aiohttp_session.get
    )  # This is the MagicMock for session.get()

    # Mock responses for each call to session.get()
    # Call 1: Rate Limit (status 429)
    response1_ctx_manager = AsyncMock()
    response1 = AsyncMock(status=429)
    response1.json = AsyncMock(return_value={"message": "Rate limit attempt 1"})
    response1_ctx_manager.__aenter__.return_value = response1

    # Call 2: Rate Limit (status 429)
    response2_ctx_manager = AsyncMock()
    response2 = AsyncMock(status=429)
    response2.json = AsyncMock(return_value={"message": "Rate limit attempt 2"})
    response2_ctx_manager.__aenter__.return_value = response2

    # Call 3: Success
    response3_ctx_manager = AsyncMock()
    response3 = AsyncMock(status=200)
    response3.json = AsyncMock(
        return_value={"status": "1", "message": "OK", "result": [{"tx_id": "success"}]}
    )
    response3_ctx_manager.__aenter__.return_value = response3

    mock_session_get.side_effect = [
        response1_ctx_manager,
        response2_ctx_manager,
        response3_ctx_manager,
    ]

    result = await client.get_token_transactions("contract", "address", 0)

    assert mock_session_get.call_count == 3
    assert len(result) == 1
    assert result[0]["tx_id"] == "success"


async def test_retry_success_on_client_error(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get

    # Call 1 & 2: aiohttp.ClientError
    # Call 3: Success
    response_success_ctx_manager = AsyncMock()
    response_success = AsyncMock(status=200)
    response_success.json = AsyncMock(
        return_value={
            "status": "1",
            "message": "OK",
            "result": [{"tx_id": "net_success"}],
        }
    )
    response_success_ctx_manager.__aenter__.return_value = response_success

    mock_session_get.side_effect = [
        aiohttp.ClientError("Network fail 1"),
        aiohttp.ClientError("Network fail 2"),
        response_success_ctx_manager,
    ]

    result = await client.get_token_transactions("contract", "address", 0)

    assert mock_session_get.call_count == 3
    assert len(result) == 1
    assert result[0]["tx_id"] == "net_success"


async def test_get_latest_block_number_rate_limit_in_result(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """Test that rate limit error messages in result field raise EtherscanRateLimitError."""
    client = etherscan_client_with_mocked_session

    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={"result": "Max calls per sec rate limit reached (3/sec)"}
    )

    with pytest.raises(EtherscanRateLimitError) as exc_info:
        await client.get_latest_block_number()

    assert "rate limit" in str(exc_info.value).lower()


async def test_get_latest_block_number_success(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """Test successful latest block number retrieval."""
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get

    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={"result": "0x123456"}  # Hex block number
    )

    result = await client.get_latest_block_number()
    assert result == 0x123456
    assert mock_session_get.call_count == 1


async def test_get_latest_block_number_invalid_hex(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """Test handling of invalid hex format in result."""
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get

    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={"result": "not a hex number"}  # Invalid format
    )

    result = await client.get_latest_block_number()
    assert result is None
    assert mock_session_get.call_count == 1


async def test_client_session_cleanup(mock_config, mock_aiohttp_session, monkeypatch):
    """Test that the client session is properly cleaned up."""
    # Patch aiohttp.ClientSession globally for this test to ensure our mock is used
    monkeypatch.setattr(
        "aiohttp.ClientSession", lambda *args, **kwargs: mock_aiohttp_session
    )

    # Create client without context manager to test explicit close
    client_no_ctx = EtherscanClient(mock_config)
    # At this point, client_no_ctx._session might be None or an actual session depending on EtherscanClient's __init__
    # Let's assume __init__ doesn't create it, but __aenter__ does.

    # Test with context manager
    async with EtherscanClient(mock_config) as client_ctx:
        # mock_aiohttp_session is used due to monkeypatch
        assert client_ctx._session == mock_aiohttp_session
    assert mock_aiohttp_session.close.called  # close called by __aexit__

    # Reset call count for next check
    mock_aiohttp_session.close.reset_mock()

    # Test explicit close()
    # Need to ensure EtherscanClient uses the patched session even outside context manager
    # This part of the test might need EtherscanClient to allow session injection or more complex patching.
    # The current EtherscanClient creates session in __aenter__ or if _session is None.

    # If EtherscanClient creates session on demand:
    await client_no_ctx.get_token_transactions(
        "c", "a", 0
    )  # This would create and use a session
    assert (
        client_no_ctx._session == mock_aiohttp_session
    )  # Check if it used the mocked one
    await client_no_ctx.close()
    assert mock_aiohttp_session.close.called


# --- AdaptiveRateLimiter ---


def test_rate_limiter_on_rate_limit_increases_delay():
    limiter = AdaptiveRateLimiter(initial_delay=1.0, max_delay=10.0, backoff_factor=2.0)
    limiter.on_rate_limit()
    assert limiter.current_delay == 2.0


def test_rate_limiter_on_rate_limit_caps_at_max():
    limiter = AdaptiveRateLimiter(initial_delay=8.0, max_delay=10.0, backoff_factor=2.0)
    limiter.on_rate_limit()
    assert limiter.current_delay == 10.0


def test_rate_limiter_on_rate_limit_resets_consecutive_successes():
    """on_rate_limit always resets the consecutive-success counter to zero."""
    # Use a very long cooldown so on_success never reduces delay (counter won't auto-reset)
    limiter = AdaptiveRateLimiter(
        initial_delay=1.0, success_threshold=5, recovery_cooldown=9999.0
    )
    limiter.on_rate_limit()  # Set _last_rate_limit_time to now
    for _ in range(3):
        limiter.on_success()
    assert limiter._consecutive_successes == 3
    limiter.on_rate_limit()
    assert limiter._consecutive_successes == 0


def test_rate_limiter_on_success_increments_counter():
    limiter = AdaptiveRateLimiter(initial_delay=1.0)
    limiter.on_success()
    assert limiter._consecutive_successes == 1
    limiter.on_success()
    assert limiter._consecutive_successes == 2


def test_rate_limiter_on_success_does_not_reduce_below_threshold():
    """Delay should NOT reduce before success_threshold is reached."""
    limiter = AdaptiveRateLimiter(
        initial_delay=1.0, min_delay=0.1, success_threshold=10, recovery_cooldown=0.0
    )
    initial = limiter.current_delay
    for _ in range(9):  # One less than threshold
        limiter.on_success()
    assert limiter.current_delay == initial


def test_rate_limiter_on_success_reduces_delay_after_threshold_and_cooldown():
    """Delay reduces after threshold successes with no cooldown restriction."""
    limiter = AdaptiveRateLimiter(
        initial_delay=2.0, min_delay=0.1, recovery_factor=0.5,
        success_threshold=3, recovery_cooldown=0.0,
    )
    # Ensure _last_rate_limit_time is in the past (it starts at 0.0)
    for _ in range(3):
        limiter.on_success()
    assert limiter.current_delay < 2.0


def test_rate_limiter_does_not_reduce_during_cooldown():
    """Delay should NOT reduce if still within cooldown window after rate limit."""
    limiter = AdaptiveRateLimiter(
        initial_delay=2.0, min_delay=0.1, recovery_factor=0.5,
        success_threshold=3, recovery_cooldown=9999.0,  # Very long cooldown
    )
    limiter.on_rate_limit()  # Records _last_rate_limit_time = now
    initial_after_backoff = limiter.current_delay
    for _ in range(5):
        limiter.on_success()
    assert limiter.current_delay == initial_after_backoff


def test_rate_limiter_does_not_reduce_below_min_delay():
    """Delay must never drop below min_delay."""
    limiter = AdaptiveRateLimiter(
        initial_delay=0.11, min_delay=0.1, recovery_factor=0.5,
        success_threshold=3, recovery_cooldown=0.0,
    )
    for _ in range(20):
        limiter.on_success()
    assert limiter.current_delay >= 0.1


# --- _MAX_VALID_BLOCK_NUMBER validation ---


async def test_get_latest_block_number_rejects_out_of_range(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """get_latest_block_number returns None when block exceeds _MAX_VALID_BLOCK_NUMBER."""
    client = etherscan_client_with_mocked_session
    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    # Encode a block number > 10^9 as hex
    oversized_block = _MAX_VALID_BLOCK_NUMBER + 1
    hex_block = hex(oversized_block)
    mock_response.json = AsyncMock(
        return_value={"result": hex_block}
    )
    result = await client.get_latest_block_number()
    assert result is None


async def test_get_latest_block_number_accepts_valid_block(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """get_latest_block_number returns block number when within valid range."""
    client = etherscan_client_with_mocked_session
    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    valid_block = 20_000_000
    mock_response.json = AsyncMock(return_value={"result": hex(valid_block)})
    result = await client.get_latest_block_number()
    assert result == valid_block


async def test_get_contract_creation_block_rejects_out_of_range(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """get_contract_creation_block returns None when block exceeds _MAX_VALID_BLOCK_NUMBER."""
    client = etherscan_client_with_mocked_session
    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={
            "status": "1",
            "result": [{"blockNumber": str(_MAX_VALID_BLOCK_NUMBER + 1)}],
        }
    )
    result = await client.get_contract_creation_block("0xcontract")
    assert result is None


async def test_get_contract_creation_block_accepts_valid_block(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """get_contract_creation_block returns block number for valid range."""
    client = etherscan_client_with_mocked_session
    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={
            "status": "1",
            "result": [{"blockNumber": "12345678"}],
        }
    )
    result = await client.get_contract_creation_block("0xcontract")
    assert result == 12345678


# --- Batch contract creation tests ---


async def test_get_contract_creation_blocks_empty_input(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """Empty input returns empty dict without any HTTP calls."""
    client = etherscan_client_with_mocked_session
    mock_aiohttp_session.get.reset_mock()
    result = await client.get_contract_creation_blocks([])
    assert result == {}
    mock_aiohttp_session.get.assert_not_called()


async def test_get_contract_creation_blocks_single_chunk(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """<=5 addresses go in a single batched request; results keyed by lowercased address."""
    client = etherscan_client_with_mocked_session
    addrs = [
        "0xAaa0000000000000000000000000000000000001",
        "0xBbb0000000000000000000000000000000000002",
        "0xCcc0000000000000000000000000000000000003",
    ]
    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={
            "status": "1",
            "result": [
                {"contractAddress": addrs[0].lower(), "blockNumber": "100"},
                {"contractAddress": addrs[1].lower(), "blockNumber": "200"},
                {"contractAddress": addrs[2].lower(), "blockNumber": "300"},
            ],
        }
    )
    mock_aiohttp_session.get.reset_mock()

    result = await client.get_contract_creation_blocks(addrs)

    assert result == {
        addrs[0].lower(): 100,
        addrs[1].lower(): 200,
        addrs[2].lower(): 300,
    }
    assert mock_aiohttp_session.get.call_count == 1
    # Confirm the API received the 3 addresses as a comma-separated list
    call_params = mock_aiohttp_session.get.call_args.kwargs["params"]
    assert call_params["action"] == "getcontractcreation"
    csv = call_params["contractaddresses"]
    assert set(csv.split(",")) == {a.lower() for a in addrs}


async def test_get_contract_creation_blocks_chunks_by_5(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """12 addresses result in ceil(12/5) == 3 HTTP calls."""
    client = etherscan_client_with_mocked_session
    addrs = [f"0x{(0xa0 + i):040x}" for i in range(12)]
    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    # Return the same static payload for each chunk; the fact that addresses
    # are missing from the response is handled (they become None), but here
    # we just want to count HTTP calls, so return an empty result list.
    mock_response.json = AsyncMock(return_value={"status": "1", "result": []})
    mock_aiohttp_session.get.reset_mock()

    result = await client.get_contract_creation_blocks(addrs)

    assert mock_aiohttp_session.get.call_count == 3
    # All 12 addresses should be present in the result, mapped to None.
    assert set(result.keys()) == {a.lower() for a in addrs}
    assert all(v is None for v in result.values())


async def test_get_contract_creation_blocks_deduplicates_input(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """Duplicate / mixed-case addresses are deduplicated before chunking."""
    client = etherscan_client_with_mocked_session
    addr = "0xAAAaaaAAAAAAaaaaaaAAaaAaaaaaAaAaaaaaAaAa"
    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={
            "status": "1",
            "result": [{"contractAddress": addr.lower(), "blockNumber": "42"}],
        }
    )
    mock_aiohttp_session.get.reset_mock()

    result = await client.get_contract_creation_blocks(
        [addr, addr.lower(), addr.upper()]
    )
    assert result == {addr.lower(): 42}
    # One input once -> one HTTP call.
    assert mock_aiohttp_session.get.call_count == 1


async def test_get_contract_creation_blocks_missing_entries_are_none(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """Addresses absent from the API response are mapped to None."""
    client = etherscan_client_with_mocked_session
    addrs = [
        "0x" + "a" * 40,
        "0x" + "b" * 40,
        "0x" + "c" * 40,
    ]
    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    # API only returns data for 2 of the 3 addresses.
    mock_response.json = AsyncMock(
        return_value={
            "status": "1",
            "result": [
                {"contractAddress": addrs[0], "blockNumber": "1"},
                {"contractAddress": addrs[2], "blockNumber": "3"},
            ],
        }
    )
    mock_aiohttp_session.get.reset_mock()

    result = await client.get_contract_creation_blocks(addrs)
    assert result == {addrs[0]: 1, addrs[1]: None, addrs[2]: 3}


async def test_get_contract_creation_blocks_rejects_out_of_range(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """Entries with a block number outside the valid range are mapped to None."""
    client = etherscan_client_with_mocked_session
    addrs = ["0x" + "a" * 40, "0x" + "b" * 40]
    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={
            "status": "1",
            "result": [
                {"contractAddress": addrs[0], "blockNumber": "100"},
                {
                    "contractAddress": addrs[1],
                    "blockNumber": str(_MAX_VALID_BLOCK_NUMBER + 1),
                },
            ],
        }
    )
    mock_aiohttp_session.get.reset_mock()

    result = await client.get_contract_creation_blocks(addrs)
    assert result[addrs[0]] == 100
    assert result[addrs[1]] is None


async def test_get_contract_creation_blocks_api_error_returns_empty(
    etherscan_client_with_mocked_session, mock_aiohttp_session
):
    """status != '1' is treated as empty result and all addresses map to None."""
    client = etherscan_client_with_mocked_session
    addrs = ["0x" + "a" * 40, "0x" + "b" * 40]
    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={"status": "0", "message": "NOTOK", "result": "rate limited"}
    )
    mock_aiohttp_session.get.reset_mock()

    result = await client.get_contract_creation_blocks(addrs)
    assert result == {addrs[0]: None, addrs[1]: None}
