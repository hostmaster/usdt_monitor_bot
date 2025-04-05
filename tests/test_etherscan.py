# tests/test_etherscan.py
import asyncio
from unittest.mock import MagicMock

import aiohttp
import pytest

from usdt_monitor_bot.etherscan import (
    EtherscanClient,
    EtherscanError,
    EtherscanRateLimitError,
)

pytestmark = pytest.mark.asyncio


@pytest.fixture
def etherscan_client(mock_aiohttp_session, mock_config):
    """Fixture to create EtherscanClient with mocked session."""
    return EtherscanClient(
        session=mock_aiohttp_session,
        api_key=mock_config.etherscan_api_key,
        api_url=mock_config.etherscan_api_url,
        usdt_contract=mock_config.usdt_contract_address,
        usdc_contract=mock_config.usdc_contract_address,
        timeout=mock_config.etherscan_timeout_seconds,
    )


# --- Test Cases ---


async def test_get_token_transactions_success(
    etherscan_client: EtherscanClient, mock_aiohttp_session
):
    address = "0x123"
    start_block = 100
    mock_tx_list = [
        {"hash": "0xabc", "value": "1000000"},
        {"hash": "0xdef", "value": "2000000"},
    ]

    final_response_mock = mock_aiohttp_session.get.return_value.__aenter__.return_value
    final_response_mock.status = 200
    final_response_mock.json.return_value = {
        "status": "1",
        "message": "OK",
        "result": mock_tx_list,
    }
    final_response_mock.raise_for_status.side_effect = None

    result = await etherscan_client.get_token_transactions(
        address, etherscan_client._usdt_contract, start_block
    )

    assert result == mock_tx_list
    mock_aiohttp_session.get.assert_called_once()
    mock_aiohttp_session.get.return_value.__aenter__.assert_awaited_once()


async def test_get_usdt_token_transactions_success(
    etherscan_client: EtherscanClient, mock_aiohttp_session
):
    address = "0x123"
    start_block = 100
    mock_tx_list = [
        {"hash": "0xabc", "value": "1000000"},
        {"hash": "0xdef", "value": "2000000"},
    ]

    final_response_mock = mock_aiohttp_session.get.return_value.__aenter__.return_value
    final_response_mock.status = 200
    final_response_mock.json.return_value = {
        "status": "1",
        "message": "OK",
        "result": mock_tx_list,
    }
    final_response_mock.raise_for_status.side_effect = None

    result = await etherscan_client.get_usdt_token_transactions(address, start_block)

    assert result == mock_tx_list
    mock_aiohttp_session.get.assert_called_once()
    mock_aiohttp_session.get.return_value.__aenter__.assert_awaited_once()


async def test_get_usdc_token_transactions_success(
    etherscan_client: EtherscanClient, mock_aiohttp_session
):
    address = "0x123"
    start_block = 100
    mock_tx_list = [
        {"hash": "0xabc", "value": "1000000"},
        {"hash": "0xdef", "value": "2000000"},
    ]

    final_response_mock = mock_aiohttp_session.get.return_value.__aenter__.return_value
    final_response_mock.status = 200
    final_response_mock.json.return_value = {
        "status": "1",
        "message": "OK",
        "result": mock_tx_list,
    }
    final_response_mock.raise_for_status.side_effect = None

    result = await etherscan_client.get_usdc_token_transactions(address, start_block)

    assert result == mock_tx_list
    mock_aiohttp_session.get.assert_called_once()
    mock_aiohttp_session.get.return_value.__aenter__.assert_awaited_once()


async def test_get_token_transactions_empty(
    etherscan_client: EtherscanClient, mock_aiohttp_session
):
    final_response_mock = mock_aiohttp_session.get.return_value.__aenter__.return_value
    final_response_mock.status = 200
    final_response_mock.json.return_value = {
        "status": "0",
        "message": "No transactions found",
        "result": None,
    }
    final_response_mock.raise_for_status.side_effect = None

    result = await etherscan_client.get_token_transactions(
        "0x456", etherscan_client._usdt_contract, 200
    )

    assert result == []
    mock_aiohttp_session.get.assert_called_once()


async def test_get_token_transactions_rate_limit(
    etherscan_client: EtherscanClient, mock_aiohttp_session
):
    final_response_mock = mock_aiohttp_session.get.return_value.__aenter__.return_value
    final_response_mock.status = 200
    final_response_mock.json.return_value = {
        "status": "0",
        "message": "Max rate limit reached",
        "result": "Please wait...",
    }
    final_response_mock.raise_for_status.side_effect = None

    with pytest.raises(EtherscanRateLimitError):
        await etherscan_client.get_token_transactions(
            "0x789", etherscan_client._usdt_contract, 300
        )
    mock_aiohttp_session.get.assert_called_once()


async def test_get_token_transactions_api_error(
    etherscan_client: EtherscanClient, mock_aiohttp_session
):
    final_response_mock = mock_aiohttp_session.get.return_value.__aenter__.return_value
    final_response_mock.status = 200
    final_response_mock.json.return_value = {
        "status": "0",
        "message": "Error! Invalid address format",
        "result": None,
    }
    final_response_mock.raise_for_status.side_effect = None

    with pytest.raises(
        EtherscanError, match="API Error: error! invalid address format"
    ):
        await etherscan_client.get_token_transactions(
            "invalid-address", etherscan_client._usdt_contract, 400
        )
    mock_aiohttp_session.get.assert_called_once()


async def test_get_token_transactions_http_error(
    etherscan_client: EtherscanClient, mock_aiohttp_session
):
    final_response_mock = mock_aiohttp_session.get.return_value.__aenter__.return_value
    final_response_mock.status = 503
    final_response_mock.raise_for_status.side_effect = aiohttp.ClientResponseError(
        MagicMock(), (), status=503, message="Service Unavailable"
    )

    with pytest.raises(EtherscanError, match="HTTP Error 503: Service Unavailable"):
        await etherscan_client.get_token_transactions(
            "0xabc", etherscan_client._usdt_contract, 500
        )
    mock_aiohttp_session.get.assert_called_once()


async def test_get_token_transactions_timeout(
    etherscan_client: EtherscanClient, mock_aiohttp_session
):
    mock_aiohttp_session.get.side_effect = asyncio.TimeoutError

    with pytest.raises(asyncio.TimeoutError):
        await etherscan_client.get_token_transactions(
            "0xdef", etherscan_client._usdt_contract, 600
        )
    mock_aiohttp_session.get.assert_called_once()


async def test_get_token_transactions_unexpected_format(
    etherscan_client: EtherscanClient, mock_aiohttp_session
):
    final_response_mock = mock_aiohttp_session.get.return_value.__aenter__.return_value
    final_response_mock.status = 200
    final_response_mock.json.return_value = {
        "status": "1",
        "message": "OK",
        "result": "This should be a list",
    }
    final_response_mock.raise_for_status.side_effect = None

    with pytest.raises(EtherscanError, match="Unexpected result format: <class 'str'>"):
        await etherscan_client.get_token_transactions(
            "0xghi", etherscan_client._usdt_contract, 700
        )
    mock_aiohttp_session.get.assert_called_once()
