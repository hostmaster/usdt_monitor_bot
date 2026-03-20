# tests/test_blockscout.py
"""Unit tests for BlockscoutClient."""
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from usdt_monitor_bot.blockscout import BlockscoutClient, BlockscoutError, _normalize_tx

CONTRACT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
ADDRESS = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


@pytest.fixture
def mock_config():
    config = MagicMock()
    config.blockscout_base_url = "https://eth.blockscout.com/api"
    config.blockscout_api_key = None
    return config


def _make_session(json_data: dict, status: int = 200) -> MagicMock:
    """Build a minimal mock aiohttp session returning json_data."""
    mock_response = AsyncMock(spec=aiohttp.ClientResponse)
    mock_response.status = status
    mock_response.json = AsyncMock(return_value=json_data)

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock(spec=aiohttp.ClientSession)
    mock_session.get = MagicMock(return_value=mock_cm)
    mock_session.closed = False
    mock_session.close = AsyncMock()
    return mock_session


# --- _normalize_tx ---


def test_normalize_tx_int_block_number():
    tx = {"blockNumber": 12345, "timeStamp": "1678886400"}
    result = _normalize_tx(tx)
    assert result["blockNumber"] == "12345"


def test_normalize_tx_iso_timestamp():
    tx = {"blockNumber": "12345", "timeStamp": "2023-03-15T12:00:00Z"}
    result = _normalize_tx(tx)
    # Should be a numeric unix timestamp string
    assert result["timeStamp"].isdigit()
    assert int(result["timeStamp"]) > 1_600_000_000


def test_normalize_tx_already_unix_timestamp():
    tx = {"blockNumber": "12345", "timeStamp": "1678886400"}
    result = _normalize_tx(tx)
    assert result["timeStamp"] == "1678886400"


def test_normalize_tx_default_fields():
    tx = {"blockNumber": "12345", "timeStamp": "1678886400"}
    result = _normalize_tx(tx)
    assert result["gas"] == "0"
    assert result["gasPrice"] == "0"
    assert result["tokenDecimal"] == "0"


# --- get_token_transactions ---


async def test_get_token_transactions_success(mock_config, monkeypatch):
    sample_tx = {
        "blockNumber": "19000000",
        "timeStamp": "1678886400",
        "hash": "0xtx1",
        "from": "0xsender",
        "to": ADDRESS,
        "value": "1000000",
        "contractAddress": CONTRACT,
        "tokenSymbol": "USDT",
        "tokenDecimal": "6",
    }
    mock_session = _make_session({"status": "1", "message": "OK", "result": [sample_tx]})
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    result = await client.get_token_transactions(CONTRACT, ADDRESS, start_block=0)

    assert len(result) == 1
    assert result[0]["hash"] == "0xtx1"
    assert result[0]["blockNumber"] == "19000000"


async def test_get_token_transactions_empty(mock_config):
    mock_session = _make_session(
        {"status": "0", "message": "No transactions found", "result": []}
    )
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    result = await client.get_token_transactions(CONTRACT, ADDRESS)
    assert result == []


async def test_get_token_transactions_api_error(mock_config):
    mock_session = _make_session({"status": "0", "message": "Invalid address"})
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    with pytest.raises(BlockscoutError, match="API error"):
        await client.get_token_transactions(CONTRACT, ADDRESS)


async def test_get_token_transactions_http_429(mock_config):
    mock_session = _make_session({}, status=429)
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    with pytest.raises(BlockscoutError, match="Rate limit"):
        await client.get_token_transactions(CONTRACT, ADDRESS)


async def test_get_token_transactions_http_500(mock_config):
    mock_session = _make_session({}, status=500)
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    with pytest.raises(BlockscoutError, match="status 500"):
        await client.get_token_transactions(CONTRACT, ADDRESS)


async def test_get_token_transactions_network_error(mock_config):
    mock_response = AsyncMock(spec=aiohttp.ClientResponse)
    mock_response.status = 200
    mock_response.json = AsyncMock(side_effect=aiohttp.ClientConnectionError("network"))

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock(spec=aiohttp.ClientSession)
    mock_session.get = MagicMock(return_value=mock_cm)
    mock_session.closed = False

    client = BlockscoutClient(mock_config)
    client._session = mock_session

    with pytest.raises(aiohttp.ClientConnectionError):
        await client.get_token_transactions(CONTRACT, ADDRESS)


# --- get_latest_block_number ---


async def test_get_latest_block_number_success(mock_config):
    mock_session = _make_session({"result": "0x1234567"})
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    result = await client.get_latest_block_number()
    assert result == 0x1234567


async def test_get_latest_block_number_returns_none_on_error_status(mock_config):
    mock_session = _make_session({}, status=500)
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    result = await client.get_latest_block_number()
    assert result is None


async def test_get_latest_block_number_returns_none_on_rpc_error(mock_config):
    mock_session = _make_session({"error": {"message": "rate limit"}})
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    result = await client.get_latest_block_number()
    assert result is None


# --- get_contract_creation_block ---


async def test_get_contract_creation_block_success(mock_config):
    mock_session = _make_session({"creation_block_number": 12345678})
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    result = await client.get_contract_creation_block(CONTRACT)
    assert result == 12345678


async def test_get_contract_creation_block_missing_field(mock_config):
    mock_session = _make_session({"some_other_field": "value"})
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    result = await client.get_contract_creation_block(CONTRACT)
    assert result is None


async def test_get_contract_creation_block_non_200(mock_config):
    mock_session = _make_session({}, status=404)
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    result = await client.get_contract_creation_block(CONTRACT)
    assert result is None


# --- API key handling ---


async def test_api_key_included_in_token_tx_params(mock_config):
    mock_config.blockscout_api_key = "mykey123"
    mock_session = _make_session({"status": "1", "message": "OK", "result": []})
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    await client.get_token_transactions(CONTRACT, ADDRESS)

    call_kwargs = mock_session.get.call_args[1]
    assert call_kwargs["params"]["apikey"] == "mykey123"


async def test_api_key_excluded_when_not_set(mock_config):
    mock_config.blockscout_api_key = None
    mock_session = _make_session({"status": "1", "message": "OK", "result": []})
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    await client.get_token_transactions(CONTRACT, ADDRESS)

    call_kwargs = mock_session.get.call_args[1]
    assert "apikey" not in call_kwargs["params"]


async def test_api_key_included_in_latest_block_params(mock_config):
    mock_config.blockscout_api_key = "mykey123"
    mock_session = _make_session({"result": "0x1234567"})
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    await client.get_latest_block_number()

    call_kwargs = mock_session.get.call_args[1]
    assert call_kwargs["params"]["apikey"] == "mykey123"


async def test_api_key_included_in_contract_creation_params(mock_config):
    mock_config.blockscout_api_key = "mykey123"
    mock_session = _make_session({"creation_block_number": 12345678})
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    await client.get_contract_creation_block(CONTRACT)

    call_kwargs = mock_session.get.call_args[1]
    assert call_kwargs["params"]["apikey"] == "mykey123"


# --- close ---


async def test_close_clears_session(mock_config):
    mock_session = MagicMock(spec=aiohttp.ClientSession)
    mock_session.close = AsyncMock()
    client = BlockscoutClient(mock_config)
    client._session = mock_session

    await client.close()

    mock_session.close.assert_awaited_once()
    assert client._session is None
