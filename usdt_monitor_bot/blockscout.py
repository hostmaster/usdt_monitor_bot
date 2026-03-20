"""Blockscout API client — Etherscan-compatible fallback provider."""

import asyncio
import logging
from datetime import datetime
from typing import List, Optional

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

from usdt_monitor_bot.blockchain_provider import ProviderError
from usdt_monitor_bot.config import BotConfig
from usdt_monitor_bot.etherscan import AdaptiveRateLimiter

_MAX_VALID_BLOCK_NUMBER = 10**9


class BlockscoutError(ProviderError):
    """Raised when the Blockscout API returns an error."""

    pass


def _normalize_tx(tx: dict) -> dict:
    """Normalize a Blockscout transaction dict to Etherscan field shape."""
    result = dict(tx)
    # blockNumber may be int → str
    if "blockNumber" in result and not isinstance(result["blockNumber"], str):
        result["blockNumber"] = str(result["blockNumber"])
    # timeStamp may be ISO datetime string → unix timestamp string
    ts = result.get("timeStamp", "")
    if ts and not str(ts).lstrip("-").isdigit():
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            result["timeStamp"] = str(int(dt.timestamp()))
        except (ValueError, AttributeError):
            pass
    # Ensure required fields exist
    for field in ("gas", "gasPrice", "gasUsed", "nonce", "confirmations"):
        result.setdefault(field, "0")
    result.setdefault("tokenName", "")
    result.setdefault("tokenSymbol", "")
    result.setdefault("tokenDecimal", "0")
    return result


class BlockscoutClient:
    """Etherscan-compatible client for the Blockscout API.

    Uses the Etherscan-compatible endpoint (module/action style) for
    get_token_transactions and get_latest_block_number, and the Blockscout
    REST v2 API for get_contract_creation_block.

    No tenacity retries — retries are handled by WithFallback.
    """

    MAX_TOTAL_CONNECTIONS = 3
    MAX_CONNECTIONS_PER_HOST = 2
    DNS_CACHE_TTL_SECONDS = 300

    def __init__(self, config: BotConfig) -> None:
        self._base_url = config.blockscout_base_url
        self._timeout = ClientTimeout(total=30)
        self._session: Optional[aiohttp.ClientSession] = None
        self._connector: Optional[TCPConnector] = None
        self._session_lock = asyncio.Lock()
        self._rate_limiter = AdaptiveRateLimiter(
            initial_delay=0.2,
            min_delay=0.1,
            max_delay=5.0,
        )

    def _create_session(self) -> aiohttp.ClientSession:
        self._connector = TCPConnector(
            limit=self.MAX_TOTAL_CONNECTIONS,
            limit_per_host=self.MAX_CONNECTIONS_PER_HOST,
            ttl_dns_cache=self.DNS_CACHE_TTL_SECONDS,
            force_close=True,
        )
        return aiohttp.ClientSession(timeout=self._timeout, connector=self._connector)

    async def _ensure_session(self) -> None:
        if self._session and not getattr(self._session, "closed", True):
            return
        async with self._session_lock:
            if not self._session or getattr(self._session, "closed", True):
                if self._connector:
                    try:
                        await self._connector.close()
                    except Exception:
                        pass
                    self._connector = None
                self._session = self._create_session()

    async def get_token_transactions(
        self, contract_address: str, address: str, start_block: int = 0
    ) -> List[dict]:
        await self._ensure_session()
        await self._rate_limiter.wait()

        params = {
            "module": "account",
            "action": "tokentx",
            "address": address,
            "contractaddress": contract_address,
            "startblock": start_block,
            "endblock": 99999999,
            "sort": "asc",
        }
        session = self._session
        if session is None:
            raise RuntimeError("HTTP session not initialized")

        try:
            async with session.get(self._base_url, params=params) as response:
                if response.status == 429:
                    raise BlockscoutError("Rate limit exceeded")
                if response.status != 200:
                    raise BlockscoutError(
                        f"API request failed with status {response.status}"
                    )
                data = await response.json(content_type=None)
                if data.get("status") != "1":
                    message = data.get("message", "Unknown error")
                    if "No transactions found" in message:
                        return []
                    raise BlockscoutError(f"API error: {message}")
                self._rate_limiter.on_success()
                return [_normalize_tx(tx) for tx in data.get("result", [])]
        except BlockscoutError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError):
            raise
        except ValueError as e:
            raise BlockscoutError(f"Invalid JSON response: {e}") from e

    async def get_latest_block_number(self) -> Optional[int]:
        await self._ensure_session()
        await self._rate_limiter.wait()

        params = {"module": "proxy", "action": "eth_blockNumber"}
        session = self._session
        if session is None:
            raise RuntimeError("HTTP session not initialized")

        try:
            async with session.get(self._base_url, params=params) as response:
                if response.status != 200:
                    return None
                data = await response.json(content_type=None)
                if "error" in data:
                    return None
                result = data.get("result", "")
                if not isinstance(result, str) or not result.startswith("0x"):
                    return None
                block_number = int(result, 16)
                if not (0 < block_number <= _MAX_VALID_BLOCK_NUMBER):
                    return None
                self._rate_limiter.on_success()
                return block_number
        except (aiohttp.ClientError, asyncio.TimeoutError):
            raise
        except (ValueError, TypeError):
            return None

    async def get_contract_creation_block(
        self, contract_address: str
    ) -> Optional[int]:
        await self._ensure_session()
        await self._rate_limiter.wait()

        # Blockscout REST v2 endpoint: GET /api/v2/addresses/{address}
        url = f"{self._base_url}/v2/addresses/{contract_address}"
        session = self._session
        if session is None:
            raise RuntimeError("HTTP session not initialized")

        try:
            async with session.get(url) as response:
                if response.status != 200:
                    return None
                data = await response.json(content_type=None)
                block_number = data.get("creation_block_number")
                if block_number is None:
                    return None
                parsed = int(block_number)
                if not (0 < parsed <= _MAX_VALID_BLOCK_NUMBER):
                    return None
                self._rate_limiter.on_success()
                return parsed
        except (aiohttp.ClientError, asyncio.TimeoutError):
            raise
        except (ValueError, TypeError, KeyError):
            return None

    async def close(self) -> None:
        if self._session:
            try:
                await self._session.close()
            except Exception as e:
                logging.debug(f"BlockscoutClient session close error: {e}")
            finally:
                self._session = None
        if self._connector:
            try:
                await self._connector.close()
            except Exception as e:
                logging.debug(f"BlockscoutClient connector close error: {e}")
            finally:
                self._connector = None
