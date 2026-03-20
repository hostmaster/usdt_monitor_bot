"""Blockchain provider protocol, circuit breaker, and fallback chain."""

import asyncio
import logging
import time
from typing import List, Optional, Protocol, runtime_checkable

import aiohttp

from usdt_monitor_bot.etherscan import EtherscanError


class ProviderError(Exception):
    """Base class for fallback provider errors."""

    pass


@runtime_checkable
class BlockchainProvider(Protocol):
    """Protocol satisfied by EtherscanClient and all fallback clients."""

    async def get_token_transactions(
        self, contract_address: str, address: str, start_block: int = 0
    ) -> List[dict]: ...

    async def get_latest_block_number(self) -> Optional[int]: ...

    async def get_contract_creation_block(
        self, contract_address: str
    ) -> Optional[int]: ...

    async def close(self) -> None: ...


class ProviderCircuitBreaker:
    """Tracks per-provider failure state with cooldown-based recovery."""

    def __init__(
        self, name: str, failure_threshold: int, cooldown_seconds: float
    ) -> None:
        self._name = name
        self._threshold = failure_threshold
        self._cooldown = cooldown_seconds
        self._consecutive_failures = 0
        self._opened_at: Optional[float] = None

    def is_available(self) -> bool:
        """True if the provider should be attempted (healthy or cooldown expired)."""
        if self._opened_at is None:
            return True
        return (time.monotonic() - self._opened_at) >= self._cooldown

    def is_recovering(self) -> bool:
        """True if circuit was opened and cooldown has since elapsed."""
        if self._opened_at is None:
            return False
        return (time.monotonic() - self._opened_at) >= self._cooldown

    def record_success(self) -> None:
        if self._opened_at is not None:
            elapsed = time.monotonic() - self._opened_at
            logging.info(f"Provider {self._name} recovered after {elapsed:.0f}s")
        self._consecutive_failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._threshold:
            if self._opened_at is None:
                logging.warning(
                    f"Provider {self._name} circuit opened after "
                    f"{self._consecutive_failures} consecutive failures"
                )
            self._opened_at = time.monotonic()


class WithFallback:
    """Composes a primary provider with ordered fallbacks and per-provider circuit breakers.

    On each call:
    - Tries providers in order, skipping those whose circuit is open.
    - On EtherscanError / ProviderError / aiohttp.ClientError / asyncio.TimeoutError:
      logs a WARNING, records a failure, tries the next provider.
    - If all providers fail or are unavailable: raises the last exception seen.
    """

    def __init__(
        self,
        primary: BlockchainProvider,
        fallbacks: List[BlockchainProvider],
        failure_threshold: int = 3,
        cooldown_seconds: float = 300.0,
    ) -> None:
        self._providers = [primary] + list(fallbacks)
        self._breakers = [
            ProviderCircuitBreaker(
                name=type(p).__name__,
                failure_threshold=failure_threshold,
                cooldown_seconds=cooldown_seconds,
            )
            for p in self._providers
        ]

    async def _call_with_fallback(self, method_name: str, *args, **kwargs):
        last_exc: Optional[Exception] = None
        for provider, breaker in zip(self._providers, self._breakers):
            if not breaker.is_available():
                continue
            try:
                result = await getattr(provider, method_name)(*args, **kwargs)
                breaker.record_success()
                return result
            except (
                EtherscanError,
                ProviderError,
                aiohttp.ClientError,
                asyncio.TimeoutError,
            ) as e:
                logging.warning(
                    f"Provider {type(provider).__name__} failed [{method_name}]: {e}"
                )
                breaker.record_failure()
                last_exc = e
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("All providers unavailable (all circuit breakers open)")

    async def get_token_transactions(
        self, contract_address: str, address: str, start_block: int = 0
    ) -> List[dict]:
        return await self._call_with_fallback(
            "get_token_transactions", contract_address, address, start_block
        )

    async def get_latest_block_number(self) -> Optional[int]:
        return await self._call_with_fallback("get_latest_block_number")

    async def get_contract_creation_block(
        self, contract_address: str
    ) -> Optional[int]:
        return await self._call_with_fallback(
            "get_contract_creation_block", contract_address
        )

    async def close(self) -> None:
        for provider in self._providers:
            await provider.close()
