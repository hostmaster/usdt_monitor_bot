# tests/test_etherscan.py
import asyncio
from unittest.mock import AsyncMock, MagicMock

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
    config.etherscan_base_url = "https://api.etherscan.io/api"
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


@pytest.mark.asyncio
async def test_get_token_transactions_success(mock_config, mock_response, monkeypatch):
    """Test successful token transaction retrieval."""
    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    # Create a mock session
    session = MockClientSession()
    session.set_response(mock_response)

    # Patch the ClientSession to return our mock
    monkeypatch.setattr("aiohttp.ClientSession", lambda *args, **kwargs: session)

    async with EtherscanClient(mock_config) as client:
        result = await client.get_token_transactions(
            contract_address, address, start_block
        )
        assert len(result) == 1
        assert result[0]["hash"] == "0x123"
        assert result[0]["from"] == "0xabc"
        assert result[0]["to"] == "0xdef"


@pytest.mark.asyncio
async def test_get_token_transactions_empty(mock_config, mock_response, monkeypatch):
    """Test empty token transaction response."""
    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    # Modify mock response for empty result
    mock_response.json.return_value = {
        "status": "1",
        "message": "OK",
        "result": [],
    }

    # Create a mock session
    session = MockClientSession()
    session.set_response(mock_response)

    # Patch the ClientSession to return our mock
    monkeypatch.setattr("aiohttp.ClientSession", lambda *args, **kwargs: session)

    async with EtherscanClient(mock_config) as client:
        result = await client.get_token_transactions(
            contract_address, address, start_block
        )
        assert len(result) == 0


@pytest.mark.asyncio
async def test_get_token_transactions_rate_limit(
    mock_config, mock_response, monkeypatch
):
    """Test rate limit error handling."""
    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    # Modify mock response for rate limit
    mock_response.status = 429

    # Create a mock session
    session = MockClientSession()
    session.set_response(mock_response)

    # Patch the ClientSession to return our mock
    monkeypatch.setattr("aiohttp.ClientSession", lambda *args, **kwargs: session)

    async with EtherscanClient(mock_config) as client:
        with pytest.raises(EtherscanRateLimitError):
            await client.get_token_transactions(contract_address, address, start_block)


@pytest.mark.asyncio
async def test_get_token_transactions_api_error(
    mock_config, mock_response, monkeypatch
):
    """Test API error handling."""
    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    # Modify mock response for API error
    mock_response.json.return_value = {
        "status": "0",
        "message": "Error! Invalid address format",
        "result": [],
    }

    # Create a mock session
    session = MockClientSession()
    session.set_response(mock_response)

    # Patch the ClientSession to return our mock
    monkeypatch.setattr("aiohttp.ClientSession", lambda *args, **kwargs: session)

    async with EtherscanClient(mock_config) as client:
        with pytest.raises(EtherscanError):
            await client.get_token_transactions(contract_address, address, start_block)


@pytest.mark.asyncio
async def test_get_token_transactions_http_error(
    mock_config, mock_response, monkeypatch
):
    """Test HTTP error handling."""
    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    # Modify mock response for HTTP error
    mock_response.status = 500

    # Create a mock session
    session = MockClientSession()
    session.set_response(mock_response)

    # Patch the ClientSession to return our mock
    monkeypatch.setattr("aiohttp.ClientSession", lambda *args, **kwargs: session)

    async with EtherscanClient(mock_config) as client:
        with pytest.raises(EtherscanError):
            await client.get_token_transactions(contract_address, address, start_block)


@pytest.mark.asyncio
async def test_get_token_transactions_timeout(mock_config, mock_response, monkeypatch):
    """Test timeout error handling."""
    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    # Create a mock session that raises TimeoutError
    session = MockClientSession()
    session.get = MagicMock(side_effect=asyncio.TimeoutError())

    # Patch the ClientSession to return our mock
    monkeypatch.setattr("aiohttp.ClientSession", lambda *args, **kwargs: session)

    async with EtherscanClient(mock_config) as client:
        with pytest.raises(EtherscanError):
            await client.get_token_transactions(contract_address, address, start_block)


@pytest.mark.asyncio
async def test_get_token_transactions_unexpected_format(
    mock_config, mock_response, monkeypatch
):
    """Test unexpected response format handling."""
    contract_address = "0xusdt"
    address = "0xabc"
    start_block = 0

    # Modify mock response for invalid format
    mock_response.json.return_value = {"invalid": "format"}

    # Create a mock session
    session = MockClientSession()
    session.set_response(mock_response)

    # Patch the ClientSession to return our mock
    monkeypatch.setattr("aiohttp.ClientSession", lambda *args, **kwargs: session)

    async with EtherscanClient(mock_config) as client:
        with pytest.raises(EtherscanError):
            await client.get_token_transactions(contract_address, address, start_block)


@pytest.mark.asyncio
async def test_client_session_cleanup(mock_config, monkeypatch):
    """Test that the client session is properly cleaned up."""
    # Create a mock session
    session = MockClientSession()

    # Patch the ClientSession to return our mock
    monkeypatch.setattr("aiohttp.ClientSession", lambda *args, **kwargs: session)

    # Create client without context manager
    client = EtherscanClient(mock_config)
    assert client._session is None

    # Create session
    await client.__aenter__()
    assert client._session is not None

    # Cleanup
    await client.__aexit__(None, None, None)
    assert client._session is None

    # Test explicit close
    await client.__aenter__()
    assert client._session is not None
    await client.close()
    assert client._session is None
