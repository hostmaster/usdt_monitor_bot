# tests/test_etherscan.py
import asyncio
from unittest.mock import AsyncMock, MagicMock
import aiohttp # Import aiohttp
import pytest

from usdt_monitor_bot.etherscan import (
    EtherscanClient,
    EtherscanError,
    EtherscanRateLimitError,
)

pytestmark = pytest.mark.asyncio


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


class MockClientSession:
    """Mock aiohttp.ClientSession for testing."""

    def __init__(self, timeout=None):
        self.timeout = timeout
        self._closed = False
        self._response = None

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._closed = True

    def get(self, *args, **kwargs):
        """Return a context manager that yields the response."""
        return self

    def set_response(self, response):
        """Set the response to be returned by the context manager."""
        self._response = response

    async def close(self):
        """Close the session."""
        self._closed = True

# New fixture to use mock_aiohttp_session from conftest.py
@pytest.fixture
async def etherscan_client_with_mocked_session(mock_config, mock_aiohttp_session, monkeypatch):
    """Provides an EtherscanClient instance with a mocked aiohttp.ClientSession."""

    # Instead of monkeypatching aiohttp.ClientSession globally for all tests in this file,
    # we can inject the mock_aiohttp_session specifically into an EtherscanClient instance.
    # One way is to allow EtherscanClient to accept a session in its constructor for testing,
    # or to patch it during its __aenter__ if it creates a session there.
    # For now, let's assume EtherscanClient creates its session internally if not provided.
    # We'll patch 'aiohttp.ClientSession' just before EtherscanClient is created.

    monkeypatch.setattr("aiohttp.ClientSession", lambda *args, **kwargs: mock_aiohttp_session)

    async with EtherscanClient(mock_config) as client:
        # The client now uses mock_aiohttp_session internally
        yield client
    # __aexit__ will call mock_aiohttp_session.close()


@pytest.mark.asyncio
async def test_get_token_transactions_success(etherscan_client_with_mocked_session, mock_aiohttp_session):
    """Test successful token transaction retrieval."""
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get # This is the MagicMock returning the context manager

    # Configure the response for the successful call
    # Access the mock_response from the fixture structure
    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={
        "status": "1",
        "message": "OK",
        "result": [{"hash": "0x123", "from": "0xabc", "to": "0xdef"}]
    })

    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    result = await client.get_token_transactions(
        contract_address, address, start_block
    )
    assert len(result) == 1
    assert result[0]["hash"] == "0x123"
    assert result[0]["from"] == "0xabc"
    assert result[0]["to"] == "0xdef"
    assert mock_session_get.call_count == 1


@pytest.mark.asyncio
async def test_get_token_transactions_empty(etherscan_client_with_mocked_session, mock_aiohttp_session):
    """Test empty token transaction response."""
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get

    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={
        "status": "1", "message": "OK", "result": []
    })

    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    result = await client.get_token_transactions(
        contract_address, address, start_block
    )
    assert len(result) == 0
    assert mock_session_get.call_count == 1


@pytest.mark.asyncio
async def test_get_token_transactions_rate_limit_eventually_fails(etherscan_client_with_mocked_session, mock_aiohttp_session):
    """Test rate limit error handling after retries."""
    client = etherscan_client_with_mocked_session

    # Configure the mock_response that is returned by mock_session_get().__aenter__()
    # to always indicate a rate limit error.
    async def configure_rate_limit_response(mock_get_call):
        response_ctx = await mock_get_call.__aenter__()
        response_ctx.status = 429 # Rate limit HTTP status
        response_ctx.json = AsyncMock(side_effect=EtherscanRateLimitError("Simulated rate limit from status")) # if status is checked first
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
    mock_response.json = AsyncMock(return_value={"message":"Rate limit hit"}) # This json might not even be called if status 429 is checked first


    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    with pytest.raises(EtherscanRateLimitError):
        await client.get_token_transactions(contract_address, address, start_block)

    assert mock_aiohttp_session.get.call_count == 5 # Tenacity default attempts for the client


@pytest.mark.asyncio
async def test_get_token_transactions_api_error_no_retry(etherscan_client_with_mocked_session, mock_aiohttp_session):
    """Test API error handling (non-retriable)."""
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get

    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200 # API error can come with 200 OK but status "0" in json
    mock_response.json = AsyncMock(return_value={
        "status": "0", "message": "Error! Invalid address format", "result": []
    })

    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    with pytest.raises(EtherscanError, match="Error! Invalid address format"):
        await client.get_token_transactions(contract_address, address, start_block)
    assert mock_session_get.call_count == 1 # Should not retry this


@pytest.mark.asyncio
async def test_get_token_transactions_notok_error(etherscan_client_with_mocked_session, mock_aiohttp_session):
    """Test NOTOK error handling with context information."""
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get

    mock_response = mock_aiohttp_session.get.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={
        "status": "0", "message": "NOTOK", "result": []
    })

    contract_address = "0xdac17f958d2ee523a2206206994597c13d831ec7"
    address = "0x31390eaf4db4013b3d5d9dbcff494e689589ae83"
    start_block = 1000

    with pytest.raises(EtherscanError) as exc_info:
        await client.get_token_transactions(contract_address, address, start_block)

    # Verify the error message includes context
    error_msg = str(exc_info.value)
    assert "NOTOK" in error_msg
    assert "Contract:" in error_msg or "query timeout" in error_msg.lower() or "invalid parameters" in error_msg.lower()
    assert contract_address[:10] in error_msg or address[:10] in error_msg or str(start_block) in error_msg

    assert mock_session_get.call_count == 1


@pytest.mark.asyncio
async def test_get_token_transactions_http_error_retried(etherscan_client_with_mocked_session, mock_aiohttp_session):
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


@pytest.mark.asyncio
async def test_get_token_transactions_timeout_retried(etherscan_client_with_mocked_session, mock_aiohttp_session):
    """Test timeout error handling (retriable asyncio.TimeoutError)."""
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get

    # Configure .get() to raise TimeoutError directly
    mock_session_get.side_effect = [asyncio.TimeoutError("Simulated timeout")] * 5

    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    with pytest.raises(asyncio.TimeoutError, match="Simulated timeout"):
        await client.get_token_transactions(contract_address, address, start_block)
    assert mock_session_get.call_count == 5


@pytest.mark.asyncio
async def test_get_token_transactions_unexpected_format_no_retry(etherscan_client_with_mocked_session, mock_aiohttp_session):
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


@pytest.mark.asyncio
async def test_retry_success_on_third_attempt_rate_limit(etherscan_client_with_mocked_session, mock_aiohttp_session):
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get # This is the MagicMock for session.get()

    # Mock responses for each call to session.get()
    # Call 1: Rate Limit (status 429)
    response1_ctx_manager = AsyncMock()
    response1 = AsyncMock(status=429)
    response1.json = AsyncMock(return_value={"message":"Rate limit attempt 1"})
    response1_ctx_manager.__aenter__.return_value = response1

    # Call 2: Rate Limit (status 429)
    response2_ctx_manager = AsyncMock()
    response2 = AsyncMock(status=429)
    response2.json = AsyncMock(return_value={"message":"Rate limit attempt 2"})
    response2_ctx_manager.__aenter__.return_value = response2

    # Call 3: Success
    response3_ctx_manager = AsyncMock()
    response3 = AsyncMock(status=200)
    response3.json = AsyncMock(return_value={"status": "1", "message": "OK", "result": [{"tx_id": "success"}]})
    response3_ctx_manager.__aenter__.return_value = response3

    mock_session_get.side_effect = [
        response1_ctx_manager,
        response2_ctx_manager,
        response3_ctx_manager
    ]

    result = await client.get_token_transactions("contract", "address", 0)

    assert mock_session_get.call_count == 3
    assert len(result) == 1
    assert result[0]["tx_id"] == "success"


@pytest.mark.asyncio
async def test_retry_success_on_client_error(etherscan_client_with_mocked_session, mock_aiohttp_session):
    client = etherscan_client_with_mocked_session
    mock_session_get = mock_aiohttp_session.get

    # Call 1 & 2: aiohttp.ClientError
    # Call 3: Success
    response_success_ctx_manager = AsyncMock()
    response_success = AsyncMock(status=200)
    response_success.json = AsyncMock(return_value={"status": "1", "message": "OK", "result": [{"tx_id": "net_success"}]})
    response_success_ctx_manager.__aenter__.return_value = response_success

    mock_session_get.side_effect = [
        aiohttp.ClientError("Network fail 1"),
        aiohttp.ClientError("Network fail 2"),
        response_success_ctx_manager
    ]

    result = await client.get_token_transactions("contract", "address", 0)

    assert mock_session_get.call_count == 3
    assert len(result) == 1
    assert result[0]["tx_id"] == "net_success"


@pytest.mark.asyncio
async def test_client_session_cleanup(mock_config, mock_aiohttp_session, monkeypatch):
    """Test that the client session is properly cleaned up."""
    # Patch aiohttp.ClientSession globally for this test to ensure our mock is used
    monkeypatch.setattr("aiohttp.ClientSession", lambda *args, **kwargs: mock_aiohttp_session)

    # Create client without context manager to test explicit close
    client_no_ctx = EtherscanClient(mock_config)
    # At this point, client_no_ctx._session might be None or an actual session depending on EtherscanClient's __init__
    # Let's assume __init__ doesn't create it, but __aenter__ does.

    # Test with context manager
    async with EtherscanClient(mock_config) as client_ctx:
        # mock_aiohttp_session is used due to monkeypatch
        assert client_ctx._session == mock_aiohttp_session
    assert mock_aiohttp_session.close.called # close called by __aexit__

    # Reset call count for next check
    mock_aiohttp_session.close.reset_mock()

    # Test explicit close()
    # Need to ensure EtherscanClient uses the patched session even outside context manager
    # This part of the test might need EtherscanClient to allow session injection or more complex patching.
    # The current EtherscanClient creates session in __aenter__ or if _session is None.

    # If EtherscanClient creates session on demand:
    await client_no_ctx.get_token_transactions("c", "a", 0) # This would create and use a session
    assert client_no_ctx._session == mock_aiohttp_session # Check if it used the mocked one
    await client_no_ctx.close()
    assert mock_aiohttp_session.close.called
