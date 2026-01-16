"""
Etherscan API client module.

Provides async client for interacting with the Etherscan API,
including transaction fetching and contract information retrieval.
"""

# Standard library
import asyncio
import logging
import os
import time
from pathlib import Path
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

# Debug log path - works in both local and container environments
_DEBUG_LOG_PATH = None


def _get_debug_log_path() -> str:
    """Get the debug log file path, creating it if necessary.

    Works in both local development and container environments.
    In containers, uses /app/data/.cursor/debug.log (writable data directory).
    In local dev, finds workspace root by looking for .cursor or pyproject.toml.
    """
    global _DEBUG_LOG_PATH
    if _DEBUG_LOG_PATH is None:
        current = Path.cwd()

        # Check if we're in a container (working directory is /app)
        if str(current) == "/app" or (
            len(current.parts) > 0 and current.parts[-1] == "app"
        ):
            # Container environment: use /app/data/.cursor/debug.log (writable data dir)
            _DEBUG_LOG_PATH = "/app/data/.cursor/debug.log"
            try:
                Path(_DEBUG_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
            except (OSError, PermissionError):
                # Fallback to /app/.cursor if data directory fails
                _DEBUG_LOG_PATH = "/app/.cursor/debug.log"
                Path(_DEBUG_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
        else:
            # Local development: try to find workspace root
            for parent in [current] + list(current.parents):
                if (parent / ".cursor").exists() or (
                    parent / "pyproject.toml"
                ).exists():
                    _DEBUG_LOG_PATH = str(parent / ".cursor" / "debug.log")
                    # Ensure .cursor directory exists
                    (parent / ".cursor").mkdir(exist_ok=True)
                    break
            else:
                # Fallback: use current directory
                _DEBUG_LOG_PATH = str(Path.cwd() / ".cursor" / "debug.log")
                Path(_DEBUG_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
    return _DEBUG_LOG_PATH


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
        logging.info(f"Rate limit hit. Increasing delay to {self._current_delay:.2f}s")

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
                logging.info(
                    f"Reducing delay from {self._current_delay:.2f}s to {new_delay:.2f}s "
                    f"({self._consecutive_successes} consecutive successes)"
                )
                self._current_delay = new_delay
                self._consecutive_successes = 0  # Reset counter after reduction

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
        logging.debug("EtherscanClient initialized.")

    def _create_connector(self) -> TCPConnector:
        """Create a TCPConnector with configured limits to prevent file descriptor exhaustion.

        Connection pooling (keep-alive) is enabled by default to improve performance
        by reusing TCP connections and avoiding repeated TLS handshakes.

        Returns:
            A configured TCPConnector instance.
        """
        # #region agent log
        try:
            fd_count = (
                len(os.listdir("/proc/self/fd"))
                if os.path.exists("/proc/self/fd")
                else -1
            )
            with open(_get_debug_log_path(), "a") as f:
                import json

                f.write(
                    json.dumps(
                        {
                            "sessionId": "debug-session",
                            "runId": "run1",
                            "hypothesisId": "B",
                            "location": "etherscan.py:155",
                            "message": "Creating connector",
                            "data": {"fd_count": fd_count},
                            "timestamp": int(time.time() * 1000),
                        }
                    )
                    + "\n"
                )
        except Exception:
            pass
        # #endregion
        # Create connector with strict limits to prevent file descriptor exhaustion
        # Connection pooling is enabled by default (force_close=False) for better performance
        connector = TCPConnector(
            limit=self.MAX_TOTAL_CONNECTIONS,
            limit_per_host=self.MAX_CONNECTIONS_PER_HOST,
            ttl_dns_cache=self.DNS_CACHE_TTL_SECONDS,
        )
        # #region agent log
        try:
            fd_count = (
                len(os.listdir("/proc/self/fd"))
                if os.path.exists("/proc/self/fd")
                else -1
            )
            with open(_get_debug_log_path(), "a") as f:
                import json

                f.write(
                    json.dumps(
                        {
                            "sessionId": "debug-session",
                            "runId": "run1",
                            "hypothesisId": "B",
                            "location": "etherscan.py:172",
                            "message": "Connector created",
                            "data": {"fd_count": fd_count},
                            "timestamp": int(time.time() * 1000),
                        }
                    )
                    + "\n"
                )
        except Exception:
            pass
        # #endregion
        return connector

    def _create_session(self) -> aiohttp.ClientSession:
        """Create a ClientSession with configured timeout and connector.

        Returns:
            A configured ClientSession instance.
        """
        connector = self._create_connector()
        return aiohttp.ClientSession(timeout=self._timeout, connector=connector)

    async def _ensure_session(self):
        """Ensure a session exists, creating one if necessary.

        Thread-safe: Uses a lock to prevent race conditions when multiple
        coroutines try to create a session concurrently.
        """
        # #region agent log
        try:
            fd_count = (
                len(os.listdir("/proc/self/fd"))
                if os.path.exists("/proc/self/fd")
                else -1
            )
            with open(_get_debug_log_path(), "a") as f:
                import json

                f.write(
                    json.dumps(
                        {
                            "sessionId": "debug-session",
                            "runId": "run1",
                            "hypothesisId": "A",
                            "location": "etherscan.py:181",
                            "message": "_ensure_session entry",
                            "data": {
                                "fd_count": fd_count,
                                "has_session": self._session is not None,
                                "session_closed": getattr(self._session, "closed", True)
                                if self._session
                                else None,
                            },
                            "timestamp": int(time.time() * 1000),
                        }
                    )
                    + "\n"
                )
        except Exception:
            pass
        # #endregion
        # Check if session exists outside the lock for better performance
        if self._session and not getattr(self._session, "closed", True):
            return

        # Acquire lock to prevent concurrent session creation
        async with self._session_lock:
            # Double-check pattern: another coroutine may have created the session
            # while we were waiting for the lock
            if not self._session or getattr(self._session, "closed", True):
                # #region agent log
                try:
                    old_session = self._session
                    old_connector = (
                        getattr(old_session, "connector", None) if old_session else None
                    )
                    with open(_get_debug_log_path(), "a") as f:
                        import json

                        f.write(
                            json.dumps(
                                {
                                    "sessionId": "debug-session",
                                    "runId": "run1",
                                    "hypothesisId": "A",
                                    "location": "etherscan.py:196",
                                    "message": "Creating new session",
                                    "data": {
                                        "old_session_exists": old_session is not None,
                                        "old_connector_exists": old_connector
                                        is not None,
                                    },
                                    "timestamp": int(time.time() * 1000),
                                }
                            )
                            + "\n"
                        )
                except Exception:
                    pass
                # #endregion
                # CRITICAL FIX: Close old session and connector before creating new one
                if self._session:
                    try:
                        old_connector = getattr(self._session, "connector", None)
                        if old_connector and hasattr(old_connector, "close"):
                            await old_connector.close()
                        await self._session.close()
                        # #region agent log
                        try:
                            with open(_get_debug_log_path(), "a") as f:
                                import json

                                f.write(
                                    json.dumps(
                                        {
                                            "sessionId": "debug-session",
                                            "runId": "run1",
                                            "hypothesisId": "A",
                                            "location": "etherscan.py:203",
                                            "message": "Closed old session before creating new",
                                            "data": {},
                                            "timestamp": int(time.time() * 1000),
                                        }
                                    )
                                    + "\n"
                                )
                        except Exception:
                            pass
                        # #endregion
                    except Exception as e:
                        # #region agent log
                        try:
                            with open(_get_debug_log_path(), "a") as f:
                                import json

                                f.write(
                                    json.dumps(
                                        {
                                            "sessionId": "debug-session",
                                            "runId": "run1",
                                            "hypothesisId": "A",
                                            "location": "etherscan.py:210",
                                            "message": "Error closing old session",
                                            "data": {"error": str(e)},
                                            "timestamp": int(time.time() * 1000),
                                        }
                                    )
                                    + "\n"
                                )
                        except Exception:
                            pass
                        # #endregion
                        logging.debug(
                            f"Error closing old session before creating new (non-critical): {e}"
                        )
                self._session = self._create_session()
                # #region agent log
                try:
                    fd_count = (
                        len(os.listdir("/proc/self/fd"))
                        if os.path.exists("/proc/self/fd")
                        else -1
                    )
                    with open(_get_debug_log_path(), "a") as f:
                        import json

                        f.write(
                            json.dumps(
                                {
                                    "sessionId": "debug-session",
                                    "runId": "run1",
                                    "hypothesisId": "A",
                                    "location": "etherscan.py:217",
                                    "message": "New session created",
                                    "data": {"fd_count": fd_count},
                                    "timestamp": int(time.time() * 1000),
                                }
                            )
                            + "\n"
                        )
                except Exception:
                    pass
                # #endregion

    async def __aenter__(self):
        """Create a new session when entering the context."""
        self._session = self._create_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close the session when exiting the context."""
        if self._session:
            await self._session.close()
            self._session = None

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
            # #region agent log
            try:
                fd_count = (
                    len(os.listdir("/proc/self/fd"))
                    if os.path.exists("/proc/self/fd")
                    else -1
                )
                with open(_get_debug_log_path(), "a") as f:
                    import json

                    f.write(
                        json.dumps(
                            {
                                "sessionId": "debug-session",
                                "runId": "run1",
                                "hypothesisId": "E",
                                "location": "etherscan.py:280",
                                "message": "Before HTTP request",
                                "data": {"fd_count": fd_count},
                                "timestamp": int(time.time() * 1000),
                            }
                        )
                        + "\n"
                    )
            except Exception:
                pass
            # #endregion
            async with self._session.get(self._base_url, params=params) as response:
                # #region agent log
                try:
                    fd_count = (
                        len(os.listdir("/proc/self/fd"))
                        if os.path.exists("/proc/self/fd")
                        else -1
                    )
                    with open(_get_debug_log_path(), "a") as f:
                        import json

                        f.write(
                            json.dumps(
                                {
                                    "sessionId": "debug-session",
                                    "runId": "run1",
                                    "hypothesisId": "E",
                                    "location": "etherscan.py:282",
                                    "message": "HTTP response context entered",
                                    "data": {
                                        "fd_count": fd_count,
                                        "status": response.status,
                                    },
                                    "timestamp": int(time.time() * 1000),
                                }
                            )
                            + "\n"
                        )
                except Exception:
                    pass
                # #endregion
                if response.status == 429:  # Too Many Requests
                    raise EtherscanRateLimitError("Rate limit exceeded")

                if response.status != 200:
                    # Don't retry on other client/server errors, raise immediately.
                    raise EtherscanError(
                        f"API request failed with status {response.status}"
                    )

                data = await response.json()
                # #region agent log
                try:
                    fd_count = (
                        len(os.listdir("/proc/self/fd"))
                        if os.path.exists("/proc/self/fd")
                        else -1
                    )
                    with open(_get_debug_log_path(), "a") as f:
                        import json

                        f.write(
                            json.dumps(
                                {
                                    "sessionId": "debug-session",
                                    "runId": "run1",
                                    "hypothesisId": "E",
                                    "location": "etherscan.py:295",
                                    "message": "After response.json()",
                                    "data": {"fd_count": fd_count},
                                    "timestamp": int(time.time() * 1000),
                                }
                            )
                            + "\n"
                        )
                except Exception:
                    pass
                # #endregion

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
                # #region agent log
                # Response will be closed when exiting the async with block
                # #endregion

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

        try:
            return await self._make_request_with_rate_limiting(_make_request)
        except EtherscanRateLimitError:
            logging.warning(
                f"Rate limited while fetching contract creation for {contract_address}"
            )
            return None
        except (ValueError, aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.warning(
                f"Error fetching contract creation block for {contract_address}: {e}"
            )
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

        async def _make_request():
            """Inner function to make the actual request."""
            async with self._session.get(self._base_url, params=params) as response:
                if response.status == 429:
                    raise EtherscanRateLimitError("Rate limit exceeded")

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
                    # Check if result is an error message (e.g., rate limit)
                    result_str = str(result)
                    result_lower = result_str.lower()
                    if "rate" in result_lower and "limit" in result_lower:
                        raise EtherscanRateLimitError(
                            f"Rate limit error in response: {result_str}"
                        )

                    # Validate that result is a hex string (starts with "0x" and contains valid hex)
                    if not isinstance(result, str) or not result.startswith("0x"):
                        logging.warning(
                            f"Invalid block number format (not hex): {result_str}"
                        )
                        return None

                    # Validate hex string contains only valid hex characters
                    hex_part = result[2:]  # Remove "0x" prefix
                    if not hex_part or not all(
                        c in "0123456789abcdefABCDEF" for c in hex_part
                    ):
                        logging.warning(
                            f"Invalid block number format (invalid hex): {result_str}"
                        )
                        return None

                    try:
                        # Convert hex string to int (e.g., "0x1234" -> 4660)
                        block_number = int(result, 16)
                        logging.debug(f"Latest block number fetched: {block_number}")
                        return block_number
                    except (ValueError, TypeError) as e:
                        # Check if the error is due to a rate limit message in result field
                        result_str = str(result).lower()
                        if "rate limit" in result_str or (
                            "rate" in result_str and "limit" in result_str
                        ):
                            raise EtherscanRateLimitError(
                                f"Rate limit error in response: {result}"
                            )
                        logging.warning(
                            f"Failed to parse block number: {result_str}. Error: {e}"
                        )
                        return None

                logging.warning("Latest block number API returned empty result")
                return None

        try:
            return await self._make_request_with_rate_limiting(_make_request)
        except (ValueError, aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.warning(f"Error fetching latest block number: {e}")
            return None
        # EtherscanRateLimitError is handled by @retry decorator
        # If all retries fail, it will be reraised (reraise=True)
        # We don't catch it here to allow retry mechanism to work

    async def close(self):
        """Close the session and its connector if they exist."""
        # #region agent log
        try:
            fd_count = (
                len(os.listdir("/proc/self/fd"))
                if os.path.exists("/proc/self/fd")
                else -1
            )
            with open(_get_debug_log_path(), "a") as f:
                import json

                f.write(
                    json.dumps(
                        {
                            "sessionId": "debug-session",
                            "runId": "run1",
                            "hypothesisId": "C",
                            "location": "etherscan.py:524",
                            "message": "close() called",
                            "data": {
                                "fd_count": fd_count,
                                "has_session": self._session is not None,
                            },
                            "timestamp": int(time.time() * 1000),
                        }
                    )
                    + "\n"
                )
        except Exception:
            pass
        # #endregion
        if self._session:
            try:
                # Get connector before closing session
                connector = getattr(self._session, "connector", None)

                # Explicitly close idle connections before closing the session
                # This helps release file descriptors immediately
                if connector and hasattr(connector, "close"):
                    try:
                        # Close idle connections to free up file descriptors
                        await connector.close()
                        # #region agent log
                        try:
                            fd_count = (
                                len(os.listdir("/proc/self/fd"))
                                if os.path.exists("/proc/self/fd")
                                else -1
                            )
                            with open(_get_debug_log_path(), "a") as f:
                                import json

                                f.write(
                                    json.dumps(
                                        {
                                            "sessionId": "debug-session",
                                            "runId": "run1",
                                            "hypothesisId": "C",
                                            "location": "etherscan.py:535",
                                            "message": "Connector closed",
                                            "data": {"fd_count": fd_count},
                                            "timestamp": int(time.time() * 1000),
                                        }
                                    )
                                    + "\n"
                                )
                        except Exception:
                            pass
                        # #endregion
                    except Exception as e:
                        logging.debug(
                            f"Error closing connector connections (non-critical): {e}"
                        )

                # Always attempt to close - aiohttp sessions handle already-closed gracefully
                # For mocks, this ensures close() is called
                await self._session.close()
                # #region agent log
                try:
                    fd_count = (
                        len(os.listdir("/proc/self/fd"))
                        if os.path.exists("/proc/self/fd")
                        else -1
                    )
                    with open(_get_debug_log_path(), "a") as f:
                        import json

                        f.write(
                            json.dumps(
                                {
                                    "sessionId": "debug-session",
                                    "runId": "run1",
                                    "hypothesisId": "C",
                                    "location": "etherscan.py:543",
                                    "message": "Session closed",
                                    "data": {"fd_count": fd_count},
                                    "timestamp": int(time.time() * 1000),
                                }
                            )
                            + "\n"
                        )
                except Exception:
                    pass
                # #endregion

                # Wait 0.2 seconds for connections to close gracefully.
                # This brief delay allows aiohttp's connection pool to properly release
                # file descriptors and close underlying TCP connections before the event
                # loop continues. Without this, connections may not be fully closed when
                # the session.close() coroutine completes, potentially leading to resource leaks.
                await asyncio.sleep(0.2)
                # #region agent log
                try:
                    fd_count = (
                        len(os.listdir("/proc/self/fd"))
                        if os.path.exists("/proc/self/fd")
                        else -1
                    )
                    with open(_get_debug_log_path(), "a") as f:
                        import json

                        f.write(
                            json.dumps(
                                {
                                    "sessionId": "debug-session",
                                    "runId": "run1",
                                    "hypothesisId": "C",
                                    "location": "etherscan.py:550",
                                    "message": "After sleep, close complete",
                                    "data": {"fd_count": fd_count},
                                    "timestamp": int(time.time() * 1000),
                                }
                            )
                            + "\n"
                        )
                except Exception:
                    pass
                # #endregion
            except (aiohttp.ClientError, RuntimeError) as e:
                # If closing fails (e.g., already closed or event loop closed), log and continue
                logging.debug(
                    f"Error closing EtherscanClient session (non-critical): {e}"
                )
            except Exception as e:
                # Catch any other unexpected errors but log them
                logging.warning(
                    f"Unexpected error closing EtherscanClient session: {e}"
                )
        self._session = None
