# tests/test_handlers.py
from unittest.mock import ANY, AsyncMock, MagicMock  # Import ANY

import pytest

# Import handlers *after* defining constants if needed locally
# from usdt_monitor_bot.handlers import ...

# --- Define constants locally for this module ---
VALID_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678"
INVALID_ADDRESS = "0xinvalid"
VALID_ADDRESS_UPPER = "0x1234567890ABCDEF1234567890ABCDEF12345678"

# Import handlers now
# ruff: noqa: E402
from usdt_monitor_bot.database import WalletAddResult # Import WalletAddResult
from usdt_monitor_bot.handlers import (
    add_wallet_handler,
    command_help_handler,
    command_start_handler,
    list_wallets_handler,
    other_message_handler,  # Keep this import if testing validation here (or test in test_utils)
    remove_wallet_handler,
)

# Mark all tests in this module as asyncio
pytestmark = pytest.mark.asyncio

# --- Test Handlers (using mocks from conftest) ---


async def test_command_start_new_user(
    mock_message: AsyncMock, mock_db_manager: AsyncMock
):
    mock_db_manager.check_user_exists.return_value = False
    user = mock_message.from_user

    await command_start_handler(mock_message, mock_db_manager)

    mock_db_manager.check_user_exists.assert_awaited_once_with(user.id)
    mock_db_manager.add_user.assert_awaited_once_with(
        user.id, user.username, user.first_name, user.last_name
    )
    assert mock_message.answer.await_count == 2
    mock_message.answer.assert_any_await(
        f"Hello there, <b>{user.full_name}</b>! Welcome!"
    )


async def test_command_start_returning_user(
    mock_message: AsyncMock, mock_db_manager: AsyncMock
):
    mock_db_manager.check_user_exists.return_value = True
    user = mock_message.from_user

    await command_start_handler(mock_message, mock_db_manager)

    mock_db_manager.check_user_exists.assert_awaited_once_with(user.id)
    # Should still be called due to INSERT OR IGNORE logic
    mock_db_manager.add_user.assert_awaited_once_with(
        user.id, user.username, user.first_name, user.last_name
    )
    assert mock_message.answer.await_count == 2
    mock_message.answer.assert_any_await(f"Welcome back, <b>{user.full_name}</b>!")


async def test_command_help(mock_message: AsyncMock, mock_db_manager: AsyncMock):
    user = mock_message.from_user
    await command_help_handler(mock_message, mock_db_manager)

    mock_db_manager.add_user.assert_awaited_once_with(
        user.id, user.username, user.first_name, user.last_name
    )
    mock_message.answer.assert_awaited_once_with(ANY)
    assert "Available Commands" in mock_message.answer.call_args[0][0]


# --- /add Command ---
async def test_add_wallet_success(
    mock_message: AsyncMock, mock_command_object: MagicMock, mock_db_manager: AsyncMock
):
    mock_command_object.args = VALID_ADDRESS
    mock_db_manager.add_wallet.return_value = WalletAddResult.ADDED

    await add_wallet_handler(mock_message, mock_command_object, mock_db_manager)

    mock_db_manager.add_wallet.assert_awaited_once_with(
        mock_message.from_user.id, VALID_ADDRESS.lower()
    )
    # Use hcode for consistency with handler's formatting
    from aiogram.utils.markdown import hcode
    expected_message = f"✅ Now monitoring for incoming USDT transfers to: {hcode(VALID_ADDRESS.lower())}"
    mock_message.reply.assert_awaited_once_with(expected_message)


async def test_add_wallet_already_exists(
    mock_message: AsyncMock, mock_command_object: MagicMock, mock_db_manager: AsyncMock
):
    mock_command_object.args = VALID_ADDRESS
    mock_db_manager.add_wallet.return_value = WalletAddResult.ALREADY_EXISTS

    await add_wallet_handler(mock_message, mock_command_object, mock_db_manager)

    mock_db_manager.add_wallet.assert_awaited_once_with(
        mock_message.from_user.id, VALID_ADDRESS.lower()
    )
    from aiogram.utils.markdown import hcode
    expected_message = f"ℹ️ Address {hcode(VALID_ADDRESS.lower())} is already in your monitoring list."
    mock_message.reply.assert_awaited_once_with(expected_message)


async def test_add_wallet_db_error(
    mock_message: AsyncMock, mock_command_object: MagicMock, mock_db_manager: AsyncMock
):
    mock_command_object.args = VALID_ADDRESS
    mock_db_manager.add_wallet.return_value = WalletAddResult.DB_ERROR

    await add_wallet_handler(mock_message, mock_command_object, mock_db_manager)

    mock_db_manager.add_wallet.assert_awaited_once_with(
        mock_message.from_user.id, VALID_ADDRESS.lower()
    )
    expected_message = "⚠️ An unexpected error occurred while adding the address. Please try again later."
    mock_message.reply.assert_awaited_once_with(expected_message)


async def test_add_wallet_invalid_address(
    mock_message: AsyncMock, mock_command_object: MagicMock, mock_db_manager: AsyncMock
):
    mock_command_object.args = INVALID_ADDRESS

    await add_wallet_handler(mock_message, mock_command_object, mock_db_manager)

    mock_db_manager.add_wallet.assert_not_awaited()
    mock_message.reply.assert_awaited_once_with(
        "❌ Invalid Ethereum address format. It should start with '0x' and be 42 characters long."
    )


async def test_add_wallet_no_args(
    mock_message: AsyncMock, mock_command_object: MagicMock, mock_db_manager: AsyncMock
):
    mock_command_object.args = "   "  # Test whitespace only args

    await add_wallet_handler(mock_message, mock_command_object, mock_db_manager)

    mock_db_manager.add_wallet.assert_not_awaited()
    mock_message.reply.assert_awaited_once_with(
        "❌ Please provide an address.\nUsage: <code>/add 0x123...</code>"
    )


# --- /list Command ---
async def test_list_wallets_empty(mock_message: AsyncMock, mock_db_manager: AsyncMock):
    mock_db_manager.list_wallets.return_value = []

    await list_wallets_handler(mock_message, mock_db_manager)

    mock_db_manager.list_wallets.assert_awaited_once_with(mock_message.from_user.id)
    mock_message.reply.assert_awaited_once_with(
        "ℹ️ You are not currently monitoring any addresses. Use /add to start."
    )


async def test_list_wallets_success(
    mock_message: AsyncMock, mock_db_manager: AsyncMock
):
    # Use the locally defined VALID_ADDRESS
    wallets = [VALID_ADDRESS, "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
    mock_db_manager.list_wallets.return_value = wallets

    await list_wallets_handler(mock_message, mock_db_manager)

    mock_db_manager.list_wallets.assert_awaited_once_with(mock_message.from_user.id)
    mock_message.reply.assert_awaited_once()
    reply_text = mock_message.reply.call_args[0][0]
    assert "Your monitored wallets (for USDT):" in reply_text
    assert f"L <code>{wallets[0]}</code>" in reply_text
    assert f"L <code>{wallets[1]}</code>" in reply_text


async def test_list_wallets_db_error(
    mock_message: AsyncMock, mock_db_manager: AsyncMock
):
    mock_db_manager.list_wallets.return_value = None  # Simulate DB error signal

    await list_wallets_handler(mock_message, mock_db_manager)

    mock_db_manager.list_wallets.assert_awaited_once_with(mock_message.from_user.id)
    mock_message.reply.assert_awaited_once_with(
        "⚠️ An error occurred while fetching your wallet list. Please try again later."
    )


# --- /remove Command ---
async def test_remove_wallet_success(
    mock_message: AsyncMock, mock_command_object: MagicMock, mock_db_manager: AsyncMock
):
    mock_command_object.args = VALID_ADDRESS_UPPER  # Test case insensitivity
    mock_db_manager.remove_wallet.return_value = True

    await remove_wallet_handler(mock_message, mock_command_object, mock_db_manager)

    mock_db_manager.remove_wallet.assert_awaited_once_with(
        mock_message.from_user.id, VALID_ADDRESS_UPPER.lower()
    )
    mock_message.reply.assert_awaited_once_with(ANY)
    assert (
        f"Stopped monitoring for incoming USDT to: <code>{VALID_ADDRESS_UPPER.lower()}</code>"
        in mock_message.reply.call_args[0][0]
    )


async def test_remove_wallet_not_found(
    mock_message: AsyncMock, mock_command_object: MagicMock, mock_db_manager: AsyncMock
):
    mock_command_object.args = VALID_ADDRESS
    mock_db_manager.remove_wallet.return_value = False  # Simulate not found or DB error

    await remove_wallet_handler(mock_message, mock_command_object, mock_db_manager)

    mock_db_manager.remove_wallet.assert_awaited_once_with(
        mock_message.from_user.id, VALID_ADDRESS.lower()
    )
    mock_message.reply.assert_awaited_once_with(ANY)
    assert (
        "was not found in your monitored list or a database error occurred"
        in mock_message.reply.call_args[0][0]
    )


async def test_remove_wallet_invalid_address(
    mock_message: AsyncMock, mock_command_object: MagicMock, mock_db_manager: AsyncMock
):
    mock_command_object.args = INVALID_ADDRESS

    await remove_wallet_handler(mock_message, mock_command_object, mock_db_manager)

    mock_db_manager.remove_wallet.assert_not_awaited()
    mock_message.reply.assert_awaited_once_with("❌ Invalid Ethereum address format.")


async def test_remove_wallet_no_args(
    mock_message: AsyncMock, mock_command_object: MagicMock, mock_db_manager: AsyncMock
):
    mock_command_object.args = None

    await remove_wallet_handler(mock_message, mock_command_object, mock_db_manager)

    mock_db_manager.remove_wallet.assert_not_awaited()
    mock_message.reply.assert_awaited_once_with(
        "❌ Please provide an address to remove.\nUsage: <code>/remove 0x123...</code>"
    )


# --- Other Message Handler ---
async def test_other_message(mock_message: AsyncMock):
    mock_message.text = "hello bot"
    await other_message_handler(mock_message)
    mock_message.reply.assert_awaited_once_with(
        "😕 Sorry, I didn't understand that. Please use /help to see the available commands."
    )
