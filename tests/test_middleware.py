# tests/test_middleware.py
"""Tests for UserRateLimitMiddleware."""

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from aiogram.types import Message, User

from usdt_monitor_bot.middleware import UserRateLimitMiddleware

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_message(user_id: int = 1) -> AsyncMock:
    """Return a minimal AsyncMock that looks like an aiogram Message."""
    user = MagicMock(spec=User)
    user.id = user_id

    msg = AsyncMock(spec=Message)
    msg.from_user = user
    msg.answer = AsyncMock()
    return msg


async def _noop_handler(event: Any, data: dict) -> str:
    """Sentinel handler so we can assert it was (not) called."""
    return "handled"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_first_calls_pass_through():
    """Calls within the limit should reach the handler."""
    mw = UserRateLimitMiddleware(max_calls=3, window_seconds=60.0)
    msg = _make_message(user_id=42)
    handler = AsyncMock(side_effect=_noop_handler, return_value="handled")

    for _ in range(3):
        result = await mw(handler, msg, {})
        assert result == "handled"

    assert handler.await_count == 3
    msg.answer.assert_not_called()


async def test_exceeding_limit_drops_update():
    """The (max_calls+1)-th call within the window must be dropped."""
    mw = UserRateLimitMiddleware(max_calls=3, window_seconds=60.0)
    msg = _make_message(user_id=99)
    handler = AsyncMock(side_effect=_noop_handler)

    # Exhaust the quota
    for _ in range(3):
        await mw(handler, msg, {})

    # This one should be rate-limited
    result = await mw(handler, msg, {})

    assert result is None  # dropped — middleware returns None
    assert handler.await_count == 3  # handler NOT called a 4th time
    msg.answer.assert_awaited_once()
    reply_text: str = msg.answer.call_args[0][0]
    assert "Too many requests" in reply_text


async def test_window_expiry_resets_quota():
    """After the window has passed, the quota resets and calls go through again."""
    mw = UserRateLimitMiddleware(max_calls=2, window_seconds=1.0)
    msg = _make_message(user_id=7)
    handler = AsyncMock(side_effect=_noop_handler)

    # Exhaust quota
    await mw(handler, msg, {})
    await mw(handler, msg, {})
    assert handler.await_count == 2

    # Simulate time advancing past the window
    future = time.monotonic() + 1.5
    with patch("usdt_monitor_bot.middleware.time.monotonic", return_value=future):
        result = await mw(handler, msg, {})

    assert result == "handled"
    assert handler.await_count == 3
    msg.answer.assert_not_called()


async def test_different_users_independent_quotas():
    """Rate limits are tracked per user_id — one user's quota doesn't affect another."""
    mw = UserRateLimitMiddleware(max_calls=2, window_seconds=60.0)
    handler = AsyncMock(side_effect=_noop_handler)

    user_a = _make_message(user_id=1)
    user_b = _make_message(user_id=2)

    # Exhaust user_a's quota
    await mw(handler, user_a, {})
    await mw(handler, user_a, {})
    await mw(handler, user_a, {})  # dropped

    assert handler.await_count == 2
    user_a.answer.assert_awaited_once()

    # user_b should still be allowed
    result = await mw(handler, user_b, {})
    assert result == "handled"
    user_b.answer.assert_not_called()


async def test_non_message_events_pass_through():
    """Non-Message TelegramObjects are forwarded without rate-limit checks."""
    from aiogram.types import TelegramObject

    mw = UserRateLimitMiddleware(max_calls=1, window_seconds=60.0)
    handler = AsyncMock(return_value="ok")

    # Use a plain TelegramObject (not a Message)
    non_msg = MagicMock(spec=TelegramObject)
    # Ensure it is NOT an instance of Message
    assert not isinstance(non_msg, Message)

    result = await mw(handler, non_msg, {})
    assert result == "ok"
    handler.assert_awaited_once()


async def test_message_without_from_user_passes_through():
    """Messages with no from_user (channel posts) bypass rate limiting."""
    mw = UserRateLimitMiddleware(max_calls=1, window_seconds=60.0)
    handler = AsyncMock(return_value="ok")

    msg = AsyncMock(spec=Message)
    msg.from_user = None

    result = await mw(handler, msg, {})
    assert result == "ok"
    handler.assert_awaited_once()
