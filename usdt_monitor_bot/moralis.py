"""Moralis Web3 Data API client — fallback blockchain provider."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Optional

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

from usdt_monitor_bot.blockchain_provider import ProviderError
from usdt_monitor_bot.config import BotConfig

_MAX_VALID_BLOCK_NUMBER = 10**9
_MORALIS_BASE_URL = "https://deep-index.moralis.io/api/v2.2"


class MoralisError(ProviderError):
    """Raised when the Moralis API returns an error."""

    pass


def _iso_to_unix(iso_str: str) -> str:
    """Convert an ISO 8601 datetime string to a unix timestamp string."""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return str(int(dt.timestamp()))
    except (ValueError, AttributeError):
        return iso_str


def _normalize_tx(tx: dict) -> dict:
    """Map a Moralis ERC20 transfer dict to the Etherscan field shape."""
    ts_raw = tx.get("block_timestamp", "")
    ts = _iso_to_unix(ts_raw) if ts_raw else "0"
    return {
        "hash": tx.get("transaction_hash", ""),
        "blockNumber": str(tx.get("block_number", "0")),
        "timeStamp": ts,
        "from": tx.get("from_address", ""),
        "to": tx.get("to_address", ""),
        "value": tx.get("value", "0"),
        "contractAddress": tx.get("address", ""),
        "tokenName": tx.get("token_name", ""),
        "tokenSymbol": tx.get("token_symbol", ""),
        "tokenDecimal": str(tx.get("token_decimals", "0")),
        "gas": "0",
        "gasPrice": "0",
        "gasUsed": "0",
        "nonce": "0",
        "confirmations": "0",
    }


class MoralisClient:
    """Moralis Web3 Data API client for ERC20 transaction monitoring.

    Requires MORALIS_API_KEY. No tenacity retries — handled by WithFallback.
    get_latest_block_number returns None gracefully on any failure (block_tracker
    already handles a None latest_block).
    """

    MAX_TOTAL_CONNECTIONS = 3
    MAX_CONNECTIONS_PER_HOST = 2
    DNS_CACHE_TTL_SECONDS = 300

    def __init__(self, config: BotConfig) -> None:
        self._api_key = config.moralis_api_key or ""
        self._timeout = ClientTimeout(total=30)
        self._session: Optional[aiohttp.ClientSession] = None
        self._connector: Optional[TCPConnector] = None
        self._session_lock = asyncio.Lock()

    def _create_session(self) -> aiohttp.ClientSession:
        self._connector = TCPConnector(
            limit=self.MAX_TOTAL_CONNECTIONS,
            limit_per_host=self.MAX_CONNECTIONS_PER_HOST,
            ttl_dns_cache=self.DNS_CACHE_TTL_SECONDS,
            force_close=True,
        )
        return aiohttp.ClientSession(
            timeout=self._timeout,
            connector=self._connector,
            headers={"X-API-Key": self._api_key},
        )

    async def _ensure_session(self) -> None:
        if self._session and not getattr(self._session, "closed", True):
            return
        async with self._session_lock:
            if not self._session or getattr(self._session, "closed", True):
                if self._connector:
                    try:
                        await self._connector.close()
                    except Exception as e:
                        logging.debug(f"MoralisClient old connector close error: {e}")
                    self._connector = None
                self._session = self._create_session()

    async def get_token_transactions(
        self, contract_address: str, address: str, start_block: int = 0
    ) -> List[dict]:
        await self._ensure_session()

        url = f"{_MORALIS_BASE_URL}/{address}/erc20/transfers"
        params: list = [
            ("chain", "eth"),
            ("contract_addresses[]", contract_address),
            ("limit", "100"),
        ]
        if start_block > 0:
            params.append(("from_block", str(start_block)))

        session = self._session
        if session is None:
            raise RuntimeError("HTTP session not initialized")

        try:
            async with session.get(url, params=params) as response:
                if response.status == 401:
                    raise MoralisError("Invalid or missing API key")
                if response.status == 429:
                    raise MoralisError("Rate limit exceeded")
                if response.status != 200:
                    raise MoralisError(
                        f"API request failed with status {response.status}"
                    )
                data = await response.json(content_type=None)
                return [_normalize_tx(tx) for tx in data.get("result", [])]
        except ValueError as e:
            raise MoralisError(f"Invalid JSON response: {e}") from e

    async def get_latest_block_number(self) -> Optional[int]:
        """Returns current block number, or None on any failure (graceful degradation)."""
        await self._ensure_session()

        url = f"{_MORALIS_BASE_URL}/dateToBlock"
        now_iso = datetime.now(timezone.utc).isoformat()
        params = {"chain": "eth", "date": now_iso}

        session = self._session
        if session is None:
            raise RuntimeError("HTTP session not initialized")

        try:
            async with session.get(url, params=params) as response:
                if response.status != 200:
                    return None
                data = await response.json(content_type=None)
                block = data.get("block")
                if block is None:
                    return None
                parsed = int(block)
                if not (0 < parsed <= _MAX_VALID_BLOCK_NUMBER):
                    return None
                return parsed
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None
        except (ValueError, TypeError):
            return None

    async def get_contract_creation_block(
        self, contract_address: str
    ) -> Optional[int]:
        await self._ensure_session()

        url = f"{_MORALIS_BASE_URL}/{contract_address}"
        params = {"chain": "eth"}

        session = self._session
        if session is None:
            raise RuntimeError("HTTP session not initialized")

        try:
            async with session.get(url, params=params) as response:
                if response.status != 200:
                    return None
                data = await response.json(content_type=None)
                block_number = data.get("block_number")
                if block_number is None:
                    return None
                parsed = int(block_number)
                if not (0 < parsed <= _MAX_VALID_BLOCK_NUMBER):
                    return None
                return parsed
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None
        except (ValueError, TypeError):
            return None

    async def close(self) -> None:
        if self._session:
            try:
                await self._session.close()
            except Exception as e:
                logging.debug(f"MoralisClient session close error: {e}")
            finally:
                self._session = None
        if self._connector:
            try:
                await self._connector.close()
            except Exception as e:
                logging.debug(f"MoralisClient connector close error: {e}")
            finally:
                self._connector = None
