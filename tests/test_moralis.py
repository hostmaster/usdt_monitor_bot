# tests/test_moralis.py
"""Unit tests for MoralisClient."""
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from usdt_monitor_bot.moralis import MoralisClient, MoralisError, _normalize_tx

CONTRACT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
ADDRESS = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

SAMPLE_MORALIS_TX = {
    "transaction_hash": "0xtxhash1",
    "block_number": "19000000",
    "block_timestamp": "2023-03-15T12:00:00.000Z",
    "from_address": "0xsender",
    "to_address": ADDRESS,
    "value": "1000000",
    "address": CONTRACT,
    "token_name": "Tether USD",
    "token_symbol": "USDT",
    "token_decimals": "6",
}


@pytest.fixture
def mock_config():
    config = MagicMock()
    config.moralis_api_key = "test_moralis_key"
    return config


def _make_session(json_data: dict, status: int = 200) -> MagicMock:
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


def test_normalize_tx_field_mapping():
    result = _normalize_tx(SAMPLE_MORALIS_TX)
    assert result["hash"] == "0xtxhash1"
    assert result["blockNumber"] == "19000000"
    assert result["from"] == "0xsender"
    assert result["to"] == ADDRESS
    assert result["value"] == "1000000"
    assert result["contractAddress"] == CONTRACT
    assert result["tokenName"] == "Tether USD"
    assert result["tokenSymbol"] == "USDT"
    assert result["tokenDecimal"] == "6"


def test_normalize_tx_iso_timestamp_converted():
    result = _normalize_tx(SAMPLE_MORALIS_TX)
    # Should be a unix timestamp string (numeric)
    assert result["timeStamp"].isdigit()
    assert int(result["timeStamp"]) > 1_600_000_000


def test_normalize_tx_default_gas_fields():
    result = _normalize_tx(SAMPLE_MORALIS_TX)
    assert result["gas"] == "0"
    assert result["gasPrice"] == "0"
    assert result["gasUsed"] == "0"
    assert result["nonce"] == "0"
    assert result["confirmations"] == "0"


def test_normalize_tx_missing_fields():
    result = _normalize_tx({})
    assert result["hash"] == ""
    assert result["blockNumber"] == "0"
    assert result["timeStamp"] == "0"
    assert result["value"] == "0"


# --- get_token_transactions ---


async def test_get_token_transactions_success(mock_config):
    mock_session = _make_session({"result": [SAMPLE_MORALIS_TX], "cursor": None})
    client = MoralisClient(mock_config)
    client._session = mock_session

    result = await client.get_token_transactions(CONTRACT, ADDRESS)

    assert len(result) == 1
    assert result[0]["hash"] == "0xtxhash1"
    assert result[0]["contractAddress"] == CONTRACT


async def test_get_token_transactions_empty(mock_config):
    mock_session = _make_session({"result": [], "cursor": None})
    client = MoralisClient(mock_config)
    client._session = mock_session

    result = await client.get_token_transactions(CONTRACT, ADDRESS)
    assert result == []


async def test_get_token_transactions_401_raises(mock_config):
    mock_session = _make_session({"message": "Invalid API key"}, status=401)
    client = MoralisClient(mock_config)
    client._session = mock_session

    with pytest.raises(MoralisError, match="Invalid or missing API key"):
        await client.get_token_transactions(CONTRACT, ADDRESS)


async def test_get_token_transactions_429_raises(mock_config):
    mock_session = _make_session({}, status=429)
    client = MoralisClient(mock_config)
    client._session = mock_session

    with pytest.raises(MoralisError, match="Rate limit"):
        await client.get_token_transactions(CONTRACT, ADDRESS)


async def test_get_token_transactions_500_raises(mock_config):
    mock_session = _make_session({}, status=500)
    client = MoralisClient(mock_config)
    client._session = mock_session

    with pytest.raises(MoralisError, match="status 500"):
        await client.get_token_transactions(CONTRACT, ADDRESS)


async def test_get_token_transactions_with_start_block(mock_config):
    mock_session = _make_session({"result": []})
    client = MoralisClient(mock_config)
    client._session = mock_session

    await client.get_token_transactions(CONTRACT, ADDRESS, start_block=19000000)

    call_args = mock_session.get.call_args
    # params is passed as positional or keyword arg
    params = call_args[1].get("params") or call_args[0][1] if len(call_args[0]) > 1 else call_args[1]["params"]
    param_dict = dict(params)
    assert param_dict.get("from_block") == "19000000"


# --- get_latest_block_number ---


async def test_get_latest_block_number_success(mock_config):
    mock_session = _make_session({"block": 19000000, "timestamp": 1678886400})
    client = MoralisClient(mock_config)
    client._session = mock_session

    result = await client.get_latest_block_number()
    assert result == 19000000


async def test_get_latest_block_number_returns_none_on_non_200(mock_config):
    mock_session = _make_session({}, status=500)
    client = MoralisClient(mock_config)
    client._session = mock_session

    result = await client.get_latest_block_number()
    assert result is None


async def test_get_latest_block_number_returns_none_on_missing_field(mock_config):
    mock_session = _make_session({"date": "2023-03-15"})  # no "block" field
    client = MoralisClient(mock_config)
    client._session = mock_session

    result = await client.get_latest_block_number()
    assert result is None


async def test_get_latest_block_number_returns_none_on_network_error(mock_config):
    mock_response = AsyncMock(spec=aiohttp.ClientResponse)
    mock_response.status = 200
    mock_response.json = AsyncMock(side_effect=aiohttp.ClientConnectionError("network"))

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock(spec=aiohttp.ClientSession)
    mock_session.get = MagicMock(return_value=mock_cm)
    mock_session.closed = False

    client = MoralisClient(mock_config)
    client._session = mock_session

    # get_latest_block_number catches ClientError → returns None
    result = await client.get_latest_block_number()
    assert result is None


# --- get_contract_creation_block ---


async def test_get_contract_creation_block_success(mock_config):
    mock_session = _make_session({"block_number": 4634748, "chain": "eth"})
    client = MoralisClient(mock_config)
    client._session = mock_session

    result = await client.get_contract_creation_block(CONTRACT)
    assert result == 4634748


async def test_get_contract_creation_block_returns_none_on_missing_field(mock_config):
    mock_session = _make_session({"some_field": "value"})
    client = MoralisClient(mock_config)
    client._session = mock_session

    result = await client.get_contract_creation_block(CONTRACT)
    assert result is None


async def test_get_contract_creation_block_returns_none_on_non_200(mock_config):
    mock_session = _make_session({}, status=404)
    client = MoralisClient(mock_config)
    client._session = mock_session

    result = await client.get_contract_creation_block(CONTRACT)
    assert result is None


# --- get_contract_creation_blocks (bulk loops single-address) ---


async def test_moralis_bulk_loops_single_address(mock_config):
    """Moralis's current endpoint has no native batch; bulk method loops."""
    addrs = ["0x" + "a" * 40, "0x" + "b" * 40]
    client = MoralisClient(mock_config)
    client.get_contract_creation_block = AsyncMock(side_effect=[111, 222])

    result = await client.get_contract_creation_blocks(addrs)
    assert result == {addrs[0]: 111, addrs[1]: 222}
    assert client.get_contract_creation_block.await_count == 2


async def test_moralis_bulk_empty_input(mock_config):
    client = MoralisClient(mock_config)
    client.get_contract_creation_block = AsyncMock()
    assert await client.get_contract_creation_blocks([]) == {}
    client.get_contract_creation_block.assert_not_awaited()


# --- close ---


async def test_close_clears_session(mock_config):
    mock_session = MagicMock(spec=aiohttp.ClientSession)
    mock_session.close = AsyncMock()
    client = MoralisClient(mock_config)
    client._session = mock_session

    await client.close()

    mock_session.close.assert_awaited_once()
    assert client._session is None
