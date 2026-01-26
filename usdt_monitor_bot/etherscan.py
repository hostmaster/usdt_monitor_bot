"""
Etherscan API client module.

Provides async client for interacting with the Etherscan API,
including transaction fetching and contract information retrieval.
"""

# Standard library
import asyncio
import logging
import time
from typing import List, Optional

# Third-party
import aiohttp
from aiohttp import ClientTimeout, TCPConnector
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


class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts delay based on rate limit responses.

    Increases delay when rate limits are hit and gradually decreases it
    when requests succeed, helping to maintain optimal request rate.
    """

    def __init__(
        self,
        initial_delay: float = 0.2,
        min_delay: float = 0.1,
        max_delay: float = 5.0,
        backoff_factor: float = 2.0,
        recovery_factor: float = 0.9,
        success_threshold: int = 10,
        recovery_cooldown: float = 30.0,
    ):
        """
        Args:
            initial_delay: Starting delay in seconds
            min_delay: Minimum delay in seconds
            max_delay: Maximum delay in seconds
            backoff_factor: Multiplier when rate limit is hit (e.g., 2.0 = double the delay)
            recovery_factor: Multiplier when request succeeds (e.g., 0.9 = reduce by 10%)
            success_threshold: Number of consecutive successes before reducing delay
            recovery_cooldown: Seconds to wait after rate limit before reducing delay
        """
        self._current_delay = initial_delay
        self._min_delay = min_delay
        self._max_delay = max_delay
        self._backoff_factor = backoff_factor
        self._recovery_factor = recovery_factor
        self._success_threshold = success_threshold
        self._recovery_cooldown = recovery_cooldown
        self._consecutive_successes = 0
        self._last_rate_limit_time = 0.0

    async def wait(self) -> None:
        """Wait for the current delay period before making a request."""
        await asyncio.sleep(self._current_delay)

    def on_rate_limit(self) -> None:
        """Called when a rate limit error is encountered. Increases delay."""
        self._current_delay = min(
            self._current_delay * self._backoff_factor, self._max_delay
        )
        self._consecutive_successes = 0
        self._last_rate_limit_time = time.time()
        logging.info(f"Rate limit hit, delay={self._current_delay:.2f}s")

    def on_success(self) -> None:
        """Called when a request succeeds. Gradually reduces delay if stable."""
        self._consecutive_successes += 1

        # Only reduce delay after a threshold of consecutive successes
        # and if enough time has passed since last rate limit
        time_since_rate_limit = time.time() - self._last_rate_limit_time
        if (
            self._consecutive_successes >= self._success_threshold
            and time_since_rate_limit > self._recovery_cooldown
        ):
            new_delay = max(
                self._current_delay * self._recovery_factor, self._min_delay
            )
            if new_delay < self._current_delay:
                logging.debug(f"Delay reduced: {self._current_delay:.2f}s->{new_delay:.2f}s")
                self._current_delay = new_delay
                self._consecutive_successes = 0

    @property
    def current_delay(self) -> float:
        """Get the current delay in seconds."""
        return self._current_delay


class EtherscanClient:
    """Client for interacting with the Etherscan API."""

    # TCPConnector configuration constants
    MAX_TOTAL_CONNECTIONS = (
        3  # Maximum total connections (reduced from 10 to prevent FD exhaustion)
    )
    MAX_CONNECTIONS_PER_HOST = (
        2  # Maximum connections per host (reduced from 5 to prevent FD exhaustion)
    )
    DNS_CACHE_TTL_SECONDS = 300  # DNS cache TTL in seconds (5 minutes)

    def __init__(self, config: BotConfig):
        self._config = config
        self._base_url = config.etherscan_base_url
        self._api_key = config.etherscan_api_key
        self._timeout = ClientTimeout(total=30)  # 30 seconds timeout
        self._session = None
        self._connector = None  # Store connector reference for explicit cleanup
        self._session_lock = (
            asyncio.Lock()
        )  # Protect session creation from race conditions
        # Initialize adaptive rate limiter
        # Etherscan free tier: 3 requests/sec = minimum 0.34s between requests
        # Use 0.5s initial delay to stay safely under the limit
        initial_delay = max(config.etherscan_request_delay, 0.5)
        self._rate_limiter = AdaptiveRateLimiter(
            initial_delay=initial_delay,
            min_delay=config.rate_limiter_min_delay,
            max_delay=config.rate_limiter_max_delay,
            backoff_factor=config.rate_limiter_backoff_factor,
            recovery_factor=config.rate_limiter_recovery_factor,
            success_threshold=config.rate_limiter_success_threshold,
            recovery_cooldown=config.rate_limiter_recovery_cooldown,
        )
        logging.debug(f"EtherscanClient: delay={initial_delay}s")

    def _create_connector(self) -> TCPConnector:
        """Create a TCPConnector with configured limits to prevent file descriptor exhaustion.

        Returns:
            A configured TCPConnector instance.
        """
        # Create connector with strict limits to prevent file descriptor exhaustion
        # force_close=True closes connections after each request to prevent FD accumulation
        # Note: enable_cleanup_closed is deprecated in Python 3.14+ (fixed in CPython)
        return TCPConnector(
            limit=self.MAX_TOTAL_CONNECTIONS,
            limit_per_host=self.MAX_CONNECTIONS_PER_HOST,
            ttl_dns_cache=self.DNS_CACHE_TTL_SECONDS,
            force_close=True,
        )

    def _create_session(self) -> aiohttp.ClientSession:
        """Create a ClientSession with configured timeout and connector.

        Returns:
            A configured ClientSession instance.
        """
        connector = self._create_connector()
        self._connector = connector  # Store reference for explicit cleanup
        return aiohttp.ClientSession(timeout=self._timeout, connector=connector)

    async def _ensure_session(self):
        """Ensure a session exists, creating one if necessary.

        Thread-safe: Uses a lock to prevent race conditions when multiple
        coroutines try to create a session concurrently.
        """
        # Check if session exists outside the lock for better performance
        if self._session and not getattr(self._session, "closed", True):
            return

        # Acquire lock to prevent concurrent session creation
        async with self._session_lock:
            # Double-check pattern: another coroutine may have created the session
            # while we were waiting for the lock
            if not self._session or getattr(self._session, "closed", True):
                # Close old session and connector before creating new one
                if self._session:
                    try:
                        await self._session.close()
                    except Exception as e:
                        logging.debug(f"Session close error: {e}")
                # Explicitly close connector to ensure file descriptors are released
                if self._connector:
                    try:
                        await self._connector.close()
                    except Exception as e:
                        logging.debug(f"Connector close error: {e}")
                    self._connector = None
                self._session = self._create_session()

    async def __aenter__(self):
        """Create a new session when entering the context."""
        # _create_session() already stores connector in self._connector
        self._session = self._create_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close the session when exiting the context."""
        if self._session:
            await self._session.close()
            self._session = None
        # Explicitly close connector to ensure file descriptors are released
        if self._connector:
            try:
                await self._connector.close()
            except Exception as e:
                logging.debug(f"Connector close error: {e}")
            self._connector = None

    async def _make_request_with_rate_limiting(self, request_func):
        """Make an API request with adaptive rate limiting.

        Args:
            request_func: Async function that makes the actual request

        Returns:
            The result from request_func

        Raises:
            EtherscanRateLimitError: If rate limit is hit (rate limiter is adapted)
            EtherscanError: For other API errors
        """
        # Wait for rate limiter before making request
        await self._rate_limiter.wait()

        try:
            result = await request_func()
            # Mark success - rate limiter will gradually reduce delay
            self._rate_limiter.on_success()
            return result
        except EtherscanRateLimitError:
            # Adapt rate limiter when rate limit error is encountered
            self._rate_limiter.on_rate_limit()
            raise

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

        async def _make_request():
            """Inner function to make the actual request."""
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

        # The @retry decorator will handle ClientError and TimeoutError.
        # We only need to catch other exceptions like JSON decoding errors.
        try:
            return await self._make_request_with_rate_limiting(_make_request)
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

        async def _make_request():
            """Inner function to make the actual request."""
            async with self._session.get(self._base_url, params=params) as response:
                if response.status == 429:
                    raise EtherscanRateLimitError("Rate limit exceeded")

                if response.status != 200:
                    logging.debug(f"Contract creation API status={response.status}")
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
                        logging.debug(f"Invalid block number: {block_number}")
                        return None

                return None

        try:
            return await self._make_request_with_rate_limiting(_make_request)
        except EtherscanRateLimitError:
            logging.debug(f"Rate limited: contract creation {contract_address[:10]}...")
            return None
        except (ValueError, aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.debug(f"Contract creation error {contract_address[:10]}...: {e}")
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

        async def _make_request():
            """Inner function to make the actual request."""
            async with self._session.get(self._base_url, params=params) as response:
                if response.status == 429:
                    raise EtherscanRateLimitError("Rate limit exceeded")

                if response.status != 200:
                    logging.debug(f"Latest block API status={response.status}")
                    return None

                data = await response.json()

                # Proxy endpoints use JSON-RPC format, not standard Etherscan API format
                # Check for JSON-RPC error first
                if "error" in data:
                    error = data.get("error", {})
                    logging.debug(f"Latest block RPC error: {error.get('message', 'unknown')}")
                    return None

                # Check for result in JSON-RPC format
                result = data.get("result", "")
                if result:
                    # Check if result is an error message (e.g., rate limit)
                    result_str = str(result)
                    result_lower = result_str.lower()
                    if "rate" in result_lower and "limit" in result_lower:
                        raise EtherscanRateLimitError(
                            f"Rate limit error in response: {result_str}"
                        )

                    # Validate that result is a hex string
                    if not isinstance(result, str) or not result.startswith("0x"):
                        logging.debug(f"Invalid block format: {result_str}")
                        return None

                    # Validate hex string contains only valid hex characters
                    hex_part = result[2:]
                    if not hex_part or not all(c in "0123456789abcdefABCDEF" for c in hex_part):
                        logging.debug(f"Invalid hex in block: {result_str}")
                        return None

                    try:
                        block_number = int(result, 16)
                        logging.debug(f"Latest block: {block_number}")
                        return block_number
                    except (ValueError, TypeError) as e:
                        result_str = str(result).lower()
                        if "rate limit" in result_str or ("rate" in result_str and "limit" in result_str):
                            raise EtherscanRateLimitError(f"Rate limit: {result}")
                        logging.debug(f"Block parse error: {e}")
                        return None

                logging.debug("Empty latest block response")
                return None

        try:
            return await self._make_request_with_rate_limiting(_make_request)
        except (ValueError, aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.debug(f"Latest block fetch error: {e}")
            return None
        # EtherscanRateLimitError is handled by @retry decorator
        # If all retries fail, it will be reraised (reraise=True)
        # We don't catch it here to allow retry mechanism to work

    async def close(self):
        """Close the session and connector if they exist.

        Explicitly closes both session and connector to ensure file descriptors
        are released. While session.close() should close the connector automatically,
        explicit connector.close() ensures immediate FD release.
        """
        if self._session:
            try:
                await self._session.close()
                # Brief wait for graceful connection cleanup
                await asyncio.sleep(0.1)
            except (aiohttp.ClientError, RuntimeError) as e:
                logging.debug(f"Session close: {e}")
            except Exception as e:
                logging.warning(f"Unexpected session close error: {e}", exc_info=True)
            self._session = None
        
        # Explicitly close connector to ensure file descriptors are released
        # This is critical because even after session.close(), FDs may not be
        # immediately released without explicit connector cleanup
        if self._connector:
            try:
                await self._connector.close()
                # Additional wait for connector cleanup
                await asyncio.sleep(0.1)
            except Exception as e:
                logging.debug(f"Connector close error: {e}")
            self._connector = None
