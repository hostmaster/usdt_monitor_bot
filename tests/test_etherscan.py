# tests/test_etherscan.py
import asyncio
from unittest.mock import MagicMock

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
    """Provides a mocked config."""
    config = MagicMock()
    config.etherscan_api_key = "test_api_key"
    config.etherscan_base_url = "https://api.etherscan.io/api"
    return config


@pytest.fixture
def etherscan_client(mock_config):
    """Provides an EtherscanClient with mocked config."""
    return EtherscanClient(config=mock_config)


class MockResponse:
    """Mock response that supports async context manager."""

    def __init__(self, status=200, json_data=None, json_error=None):
        self.status = status
        self._json_data = json_data
        self._json_error = json_error

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    async def json(self):
        if self._json_error:
            raise self._json_error
        return self._json_data


class MockClientSession:
    """Mock client session that supports async context manager."""

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    def get(self, *args, **kwargs):
        """Return a mock response that implements the async context manager protocol."""
        return self._response

    def set_response(self, response):
        """Set up the mock response for the next request."""
        self._response = response


@pytest.fixture
def mock_session(monkeypatch):
    """Provides a mock session that properly handles async context managers."""
    session = MockClientSession()
    monkeypatch.setattr("aiohttp.ClientSession", lambda *args, **kwargs: session)
    return session


async def test_get_token_transactions_success(etherscan_client, mock_session):
    """Test successful token transaction retrieval."""
    contract_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    mock_response = MockResponse(
        status=200,
        json_data={"status": "1", "message": "OK", "result": [SAMPLE_TX]},
    )
    mock_session.set_response(mock_response)

    transactions = await etherscan_client.get_token_transactions(
        contract_address, ADDR1, BLOCK_START
    )

    assert len(transactions) == 1
    assert transactions[0] == SAMPLE_TX


async def test_get_token_transactions_empty(etherscan_client, mock_session):
    """Test empty token transaction response."""
    contract_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    mock_response = MockResponse(
        status=200,
        json_data={"status": "1", "message": "OK", "result": []},
    )
    mock_session.set_response(mock_response)

    transactions = await etherscan_client.get_token_transactions(
        contract_address, ADDR1, BLOCK_START
    )

    assert len(transactions) == 0


async def test_get_token_transactions_rate_limit(etherscan_client, mock_session):
    """Test rate limit error handling."""
    contract_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    mock_response = MockResponse(status=429)
    mock_session.set_response(mock_response)

    with pytest.raises(EtherscanRateLimitError):
        await etherscan_client.get_token_transactions(
            contract_address, ADDR1, BLOCK_START
        )


async def test_get_token_transactions_api_error(etherscan_client, mock_session):
    """Test API error handling."""
    contract_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    mock_response = MockResponse(
        status=200,
        json_data={"status": "0", "message": "Error", "result": None},
    )
    mock_session.set_response(mock_response)

    with pytest.raises(EtherscanError, match="API error: Error"):
        await etherscan_client.get_token_transactions(
            contract_address, ADDR1, BLOCK_START
        )


async def test_get_token_transactions_http_error(etherscan_client, mock_session):
    """Test HTTP error handling."""
    contract_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    mock_response = MockResponse(status=500)
    mock_session.set_response(mock_response)

    with pytest.raises(EtherscanError, match="API request failed with status 500"):
        await etherscan_client.get_token_transactions(
            contract_address, ADDR1, BLOCK_START
        )


async def test_get_token_transactions_timeout(etherscan_client, mock_session):
    """Test timeout error handling."""
    contract_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"

    class TimeoutResponse:
        async def __aenter__(self):
            raise asyncio.TimeoutError()

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    def get(*args, **kwargs):
        return TimeoutResponse()

    mock_session.get = get

    with pytest.raises(EtherscanError, match="Request timeout:"):
        await etherscan_client.get_token_transactions(
            contract_address, ADDR1, BLOCK_START
        )


async def test_get_token_transactions_unexpected_format(etherscan_client, mock_session):
    """Test handling of unexpected response format."""
    contract_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    mock_response = MockResponse(
        status=200,
        json_error=ValueError("Invalid JSON"),
    )
    mock_session.set_response(mock_response)

    with pytest.raises(EtherscanError, match="Invalid JSON response:"):
        await etherscan_client.get_token_transactions(
            contract_address, ADDR1, BLOCK_START
        )
