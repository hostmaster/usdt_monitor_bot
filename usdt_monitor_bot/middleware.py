"""
Rate-limiting middleware for the Telegram bot.

Provides a sliding-window per-user command throttle to prevent a single
user from exhausting SQLite write capacity or Etherscan API quota.
"""

import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from typing import Any

from aiogram import BaseMiddleware
from aiogram.types import Message, TelegramObject


class UserRateLimitMiddleware(BaseMiddleware):
    """Limit each user to max_calls per window_seconds across all commands.

    Uses a sliding-window (deque of monotonic timestamps) per user_id.
    State is in-memory and resets on restart — acceptable for a single-process bot.
    """

    def __init__(self, max_calls: int = 10, window_seconds: float = 60.0) -> None:
        self._max_calls = max_calls
        self._window = window_seconds
        self._user_timestamps: dict[int, deque[float]] = defaultdict(deque)

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        if not isinstance(event, Message) or not (event.text and event.text.startswith("/")):
            return await handler(event, data)

        user_id = event.from_user.id if event.from_user else None
        if user_id is None:
            return await handler(event, data)

        now = time.monotonic()
        timestamps = self._user_timestamps[user_id]

        # Evict timestamps that have fallen outside the window
        while timestamps and now - timestamps[0] > self._window:
            timestamps.popleft()

        # If the deque is now empty, clean up the key and let the call through
        if not timestamps:
            del self._user_timestamps[user_id]
            timestamps = self._user_timestamps[user_id]  # fresh deque via defaultdict

        if len(timestamps) >= self._max_calls:
            await event.answer(
                "Too many requests. Please wait a moment before using commands again."
            )
            return None  # drop the update — handler is never called

        timestamps.append(now)
        return await handler(event, data)
