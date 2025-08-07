# etherscan.py
import asyncio
import logging
from typing import List

import aiohttp
from aiohttp import ClientTimeout
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

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
        self._session = None
        logging.info("EtherscanClient initialized.")

    async def __aenter__(self):
        """Create a new session when entering the context."""
        self._session = aiohttp.ClientSession(timeout=self._timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close the session when exiting the context."""
        if self._session:
            await self._session.close()
            self._session = None

    @retry(
        stop=stop_after_attempt(5),  # Attempt 5 times in total (1 initial + 4 retries)
        wait=wait_exponential(
            multiplier=1, min=1, max=10
        ),  # Waits 1s, 2s, 4s, 8s (max is 10 but won't be reached with 4 retries after first failure)
        retry=retry_if_exception_type(
            (EtherscanRateLimitError, aiohttp.ClientError, asyncio.TimeoutError)
        ),
        before_sleep=before_sleep_log(logging.getLogger(__name__), logging.INFO),
        reraise=True,  # Reraise the last exception if all retries fail
    )
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
        if not self._session:
            self._session = aiohttp.ClientSession(timeout=self._timeout)

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

        # The @retry decorator will handle ClientError and TimeoutError.
        # We only need to catch other exceptions like JSON decoding errors.
        try:
            async with self._session.get(self._base_url, params=params) as response:
                if response.status == 429:  # Too Many Requests
                    raise EtherscanRateLimitError("Rate limit exceeded")

                if response.status != 200:
                    # Don't retry on other client/server errors, raise immediately.
                    raise EtherscanError(
                        f"API request failed with status {response.status}"
                    )

                data = await response.json()

                # Etherscan API returns status '0' for errors, '1' for success.
                if data.get("status") != "1":
                    message = data.get("message", "Unknown error")
                    # Explicitly check for rate limit messages in the response body
                    if "rate limit" in message.lower():
                        raise EtherscanRateLimitError(message)
                    # For other API-level errors (e.g., "Invalid API Key"), raise a generic EtherscanError.
                    raise EtherscanError(f"API error: {message}")

                return data.get("result", [])

        except ValueError as e:  # Catches JSON decoding errors
            raise EtherscanError(f"Invalid JSON response: {e}") from e

    async def close(self):
        """Close the session if it exists."""
        if self._session:
            await self._session.close()
            self._session = None
