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


def _make_message(user_id: int = 1, text: str = "/start") -> AsyncMock:
    """Return a minimal AsyncMock that looks like an aiogram Message.

    Defaults to a command text ("/start") so tests exercise the rate-limit path.
    Pass text="" or text="hello" to simulate a non-command message.
    """
    user = MagicMock(spec=User)
    user.id = user_id

    msg = AsyncMock(spec=Message)
    msg.from_user = user
    msg.answer = AsyncMock()
    msg.text = text
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
    msg.text = "/start"  # command text, so the from_user=None path is exercised

    result = await mw(handler, msg, {})
    assert result == "ok"
    handler.assert_awaited_once()


async def test_non_command_message_passes_through_without_counting():
    """Plain text messages (no '/' prefix) bypass rate limiting entirely and are not counted."""
    mw = UserRateLimitMiddleware(max_calls=2, window_seconds=60.0)
    msg_text = _make_message(user_id=10, text="hello world")
    handler = AsyncMock(return_value="ok")

    # Send many non-command messages — none should be rate-limited or counted
    for _ in range(5):
        result = await mw(handler, msg_text, {})
        assert result == "ok"

    assert handler.await_count == 5
    msg_text.answer.assert_not_called()
    # Non-command messages must not create tracking entries
    assert 10 not in mw._user_timestamps


async def test_expired_timestamps_cleaned_up_from_user_timestamps():
    """After the window expires, the user's key is removed from _user_timestamps."""
    mw = UserRateLimitMiddleware(max_calls=3, window_seconds=1.0)
    msg = _make_message(user_id=20)
    handler = AsyncMock(side_effect=_noop_handler)

    # Exhaust the quota within the window
    for _ in range(3):
        await mw(handler, msg, {})

    assert 20 in mw._user_timestamps
    assert len(mw._user_timestamps[20]) == 3

    # Advance time past the window; the next call should evict all entries and clean up the key
    future = time.monotonic() + 2.0
    with patch("usdt_monitor_bot.middleware.time.monotonic", return_value=future):
        result = await mw(handler, msg, {})

    assert result == "handled"
    # Key must exist (re-created for the new call's timestamp), but hold exactly one entry
    assert 20 in mw._user_timestamps
    assert len(mw._user_timestamps[20]) == 1
