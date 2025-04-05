# etherscan.py
import asyncio
import logging
from typing import List

import aiohttp
from aiohttp import ClientTimeout

from usdt_monitor_bot.config import BotConfig


class EtherscanError(Exception):
    """Base class for Etherscan API errors."""

    pass


class EtherscanRateLimitError(EtherscanError):
    """Raised when the Etherscan API rate limit is exceeded."""

    pass


class EtherscanClient:
    """Client for interacting with the Etherscan API."""

    def __init__(self, config: BotConfig):
        self._config = config
        self._base_url = config.etherscan_base_url
        self._api_key = config.etherscan_api_key
        self._timeout = ClientTimeout(total=30)  # 30 seconds timeout
        logging.info("EtherscanClient initialized.")

    async def get_token_transactions(
        self, contract_address: str, address: str, start_block: int = 0
    ) -> List[dict]:
        """
        Get token transactions for an address from a specific block number.

        Args:
            contract_address: The token contract address
            address: The address to check transactions for
            start_block: The block number to start checking from

        Returns:
            List of transaction dictionaries

        Raises:
            EtherscanRateLimitError: If the API rate limit is exceeded
            EtherscanError: For other API errors
        """
        params = {
            "module": "account",
            "action": "tokentx",
            "address": address,
            "contractaddress": contract_address,
            "startblock": start_block,
            "endblock": 99999999,  # Far future block
            "sort": "asc",
            "apikey": self._api_key,
        }

        try:
            async with aiohttp.ClientSession(timeout=self._timeout) as session:
                async with session.get(self._base_url, params=params) as response:
                    if response.status == 429:  # Too Many Requests
                        raise EtherscanRateLimitError("Rate limit exceeded")

                    if response.status != 200:
                        raise EtherscanError(
                            f"API request failed with status {response.status}"
                        )

                    data = await response.json()
                    if data.get("status") != "1":
                        message = data.get("message", "Unknown error")
                        if "rate limit" in message.lower():
                            raise EtherscanRateLimitError(message)
                        raise EtherscanError(f"API error: {message}")

                    return data.get("result", [])

        except aiohttp.ClientError as e:
            raise EtherscanError(f"Network error: {e}") from e
        except asyncio.TimeoutError as e:
            raise EtherscanError(f"Request timeout: {e}") from e
        except ValueError as e:
            raise EtherscanError(f"Invalid JSON response: {e}") from e
