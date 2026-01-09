"""
Etherscan API client module.

Provides async client for interacting with the Etherscan API,
including transaction fetching and contract information retrieval.
"""

# Standard library
import asyncio
import logging
from typing import List, Optional

# Third-party
import aiohttp
from aiohttp import ClientTimeout
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

# Local
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
        self._closed = False
        logging.debug("EtherscanClient initialized.")

    async def _ensure_session(self):
        """Ensure a session exists, creating one if necessary."""
        if self._session is None or (hasattr(self._session, 'closed') and self._session.closed):
            self._session = aiohttp.ClientSession(timeout=self._timeout)
            self._closed = False

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
        await self._ensure_session()

        params = {
            "chainid": "1",  # Ethereum mainnet - required for V2 API
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
                    result = data.get("result", "")

                    # Explicitly check for rate limit messages in the response body
                    if "rate limit" in message.lower():
                        raise EtherscanRateLimitError(message)

                    # Handle common "NOTOK" cases with more context
                    error_details = f"API error: {message}"
                    if message == "NOTOK":
                        # NOTOK can mean query timeout, invalid params, or other issues
                        # Include additional context from result if available
                        if result and isinstance(result, str):
                            error_details = f"API error: {message} - {result}"
                        else:
                            error_details = (
                                f"API error: {message} (possible query timeout or invalid parameters). "
                                f"Contract: {contract_address[:10]}..., Address: {address[:10]}..., "
                                f"Start block: {start_block}"
                            )

                    # For other API-level errors (e.g., "Invalid API Key"), raise a generic EtherscanError.
                    raise EtherscanError(error_details)

                return data.get("result", [])

        except ValueError as e:  # Catches JSON decoding errors
            raise EtherscanError(f"Invalid JSON response: {e}") from e

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=5),
        retry=retry_if_exception_type(
            (EtherscanRateLimitError, aiohttp.ClientError, asyncio.TimeoutError)
        ),
        before_sleep=before_sleep_log(logging.getLogger(__name__), logging.INFO),
        reraise=True,
    )
    async def get_contract_creation_block(self, contract_address: str) -> Optional[int]:
        """
        Get the block number where a contract was created.

        Args:
            contract_address: The contract address to check

        Returns:
            The block number where the contract was created, or None if not found/error

        Note:
            This uses Etherscan's "getcontractcreation" API which returns the creation
            transaction hash and block number directly.
        """
        await self._ensure_session()

        params = {
            "chainid": "1",
            "module": "contract",
            "action": "getcontractcreation",
            "contractaddresses": contract_address,
            "apikey": self._api_key,
        }

        try:
            async with self._session.get(self._base_url, params=params) as response:
                if response.status == 429:
                    logging.warning(
                        f"Rate limited while fetching contract creation for {contract_address}"
                    )
                    return None

                if response.status != 200:
                    logging.warning(
                        f"Failed to get contract creation: status {response.status}"
                    )
                    return None

                data = await response.json()

                if data.get("status") != "1":
                    # Contract might not exist or API error
                    return None

                result = data.get("result", [])
                if not result or not isinstance(result, list) or len(result) == 0:
                    return None

                # Get the creation block number directly from the result
                creation_info = result[0]
                block_number = creation_info.get("blockNumber")

                if block_number:
                    try:
                        return int(block_number)
                    except (ValueError, TypeError):
                        logging.warning(f"Invalid block number format: {block_number}")
                        return None

                return None

        except (ValueError, aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.warning(
                f"Error fetching contract creation block for {contract_address}: {e}"
            )
            return None

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=5),
        retry=retry_if_exception_type(
            (EtherscanRateLimitError, aiohttp.ClientError, asyncio.TimeoutError)
        ),
        before_sleep=before_sleep_log(logging.getLogger(__name__), logging.INFO),
        reraise=True,
    )
    async def get_latest_block_number(self) -> Optional[int]:
        """
        Get the latest block number from Ethereum mainnet.

        Returns:
            The latest block number, or None if unable to fetch
        """
        await self._ensure_session()

        params = {
            "chainid": "1",
            "module": "proxy",
            "action": "eth_blockNumber",
            "apikey": self._api_key,
        }

        try:
            async with self._session.get(self._base_url, params=params) as response:
                if response.status == 429:
                    logging.warning("Rate limited while fetching latest block number")
                    return None

                if response.status != 200:
                    logging.warning(
                        f"Failed to get latest block number: status {response.status}"
                    )
                    return None

                data = await response.json()

                # Proxy endpoints use JSON-RPC format, not standard Etherscan API format
                # Check for JSON-RPC error first
                if "error" in data:
                    error = data.get("error", {})
                    error_message = error.get("message", "Unknown error")
                    error_code = error.get("code", "unknown")
                    logging.warning(
                        f"Failed to get latest block number: JSON-RPC error {error_code}: {error_message}"
                    )
                    return None

                # Check for result in JSON-RPC format
                result = data.get("result", "")
                if result:
                    try:
                        # Convert hex string to int (e.g., "0x1234" -> 4660)
                        block_number = int(result, 16)
                        logging.debug(f"Latest block number fetched: {block_number}")
                        return block_number
                    except (ValueError, TypeError) as e:
                        logging.warning(
                            f"Invalid block number format: {result}. Error: {e}"
                        )
                        return None

                logging.warning("Latest block number API returned empty result")
                return None

        except (ValueError, aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.warning(f"Error fetching latest block number: {e}")
            return None

    async def close(self):
        """Close the session if it exists."""
        if self._session:
            try:
                # Always attempt to close - aiohttp sessions handle already-closed gracefully
                # For mocks, this ensures close() is called
                await self._session.close()
                # Wait a bit for connections to close gracefully
                await asyncio.sleep(0.1)
            except (aiohttp.ClientError, RuntimeError) as e:
                # If closing fails (e.g., already closed or event loop closed), log and continue
                logging.debug(f"Error closing EtherscanClient session (non-critical): {e}")
            except Exception as e:
                # Catch any other unexpected errors but log them
                logging.warning(f"Unexpected error closing EtherscanClient session: {e}")
        self._session = None
        self._closed = True
