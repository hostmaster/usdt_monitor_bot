# tests/test_handlers.py
from unittest.mock import AsyncMock, MagicMock

import pytest

from usdt_monitor_bot import messages
from usdt_monitor_bot.database import WalletAddResult
from usdt_monitor_bot.handlers import (
    add_wallet_handler,
    command_help_handler,
    command_start_handler,
    list_wallets_handler,
    other_message_handler,
    remove_wallet_handler,
)

# --- Define constants for testing ---
VALID_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678"
INVALID_ADDRESS = "0xinvalid"
VALID_ADDRESS_UPPER = "0x1234567890ABCDEF1234567890ABCDEF12345678"

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
        messages.welcome_message(user.full_name, is_returning=False)
    )
    mock_message.answer.assert_any_await(messages.START_INTRO)


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
    mock_message.answer.assert_any_await(
        messages.welcome_message(user.full_name, is_returning=True)
    )
    mock_message.answer.assert_any_await(messages.START_INTRO)


async def test_command_help(mock_message: AsyncMock, mock_db_manager: AsyncMock):
    user = mock_message.from_user
    await command_help_handler(mock_message, mock_db_manager)

    mock_db_manager.add_user.assert_awaited_once_with(
        user.id, user.username, user.first_name, user.last_name
    )
    mock_message.answer.assert_awaited_once_with(messages.HELP_TEXT)


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
    expected_message = messages.add_wallet_success(VALID_ADDRESS.lower())
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
    expected_message = messages.add_wallet_already_exists(VALID_ADDRESS.lower())
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
    mock_message.reply.assert_awaited_once_with(messages.ERROR_UNEXPECTED)


async def test_add_wallet_invalid_address(
    mock_message: AsyncMock, mock_command_object: MagicMock, mock_db_manager: AsyncMock
):
    mock_command_object.args = INVALID_ADDRESS

    await add_wallet_handler(mock_message, mock_command_object, mock_db_manager)

    mock_db_manager.add_wallet.assert_not_awaited()
    mock_message.reply.assert_awaited_once_with(messages.INVALID_ETH_ADDRESS_FORMAT)


async def test_add_wallet_no_args(
    mock_message: AsyncMock, mock_command_object: MagicMock, mock_db_manager: AsyncMock
):
    mock_command_object.args = "   "  # Test whitespace only args

    await add_wallet_handler(mock_message, mock_command_object, mock_db_manager)

    mock_db_manager.add_wallet.assert_not_awaited()
    mock_message.reply.assert_awaited_once_with(messages.add_wallet_missing_address())


# --- /list Command ---
async def test_list_wallets_empty(mock_message: AsyncMock, mock_db_manager: AsyncMock):
    mock_db_manager.list_wallets.return_value = []

    await list_wallets_handler(mock_message, mock_db_manager)

    mock_db_manager.list_wallets.assert_awaited_once_with(mock_message.from_user.id)
    mock_message.reply.assert_awaited_once_with(messages.LIST_WALLELS_EMPTY)


async def test_list_wallets_success(
    mock_message: AsyncMock, mock_db_manager: AsyncMock
):
    # Use the locally defined VALID_ADDRESS
    wallets = [VALID_ADDRESS, "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
    mock_db_manager.list_wallets.return_value = wallets

    await list_wallets_handler(mock_message, mock_db_manager)

    mock_db_manager.list_wallets.assert_awaited_once_with(mock_message.from_user.id)
    mock_message.reply.assert_awaited_once_with(messages.format_wallet_list(wallets))


async def test_list_wallets_db_error(
    mock_message: AsyncMock, mock_db_manager: AsyncMock
):
    mock_db_manager.list_wallets.return_value = None  # Simulate DB error signal

    await list_wallets_handler(mock_message, mock_db_manager)

    mock_db_manager.list_wallets.assert_awaited_once_with(mock_message.from_user.id)
    mock_message.reply.assert_awaited_once_with(messages.LIST_WALLETS_ERROR)


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
    expected_message = messages.remove_wallet_success(VALID_ADDRESS_UPPER.lower())
    mock_message.reply.assert_awaited_once_with(expected_message)


async def test_remove_wallet_not_found(
    mock_message: AsyncMock, mock_command_object: MagicMock, mock_db_manager: AsyncMock
):
    mock_command_object.args = VALID_ADDRESS
    mock_db_manager.remove_wallet.return_value = False  # Simulate not found or DB error

    await remove_wallet_handler(mock_message, mock_command_object, mock_db_manager)

    mock_db_manager.remove_wallet.assert_awaited_once_with(
        mock_message.from_user.id, VALID_ADDRESS.lower()
    )
    expected_message = messages.remove_wallet_not_found(VALID_ADDRESS.lower())
    mock_message.reply.assert_awaited_once_with(expected_message)


async def test_remove_wallet_invalid_address(
    mock_message: AsyncMock, mock_command_object: MagicMock, mock_db_manager: AsyncMock
):
    mock_command_object.args = INVALID_ADDRESS

    await remove_wallet_handler(mock_message, mock_command_object, mock_db_manager)

    mock_db_manager.remove_wallet.assert_not_awaited()
    mock_message.reply.assert_awaited_once_with(messages.REMOVE_WALLET_INVALID_ADDRESS)


async def test_remove_wallet_no_args(
    mock_message: AsyncMock, mock_command_object: MagicMock, mock_db_manager: AsyncMock
):
    mock_command_object.args = None

    await remove_wallet_handler(mock_message, mock_command_object, mock_db_manager)

    mock_db_manager.remove_wallet.assert_not_awaited()
    mock_message.reply.assert_awaited_once_with(
        messages.remove_wallet_missing_address()
    )


# --- Other Message Handler ---
async def test_other_message(mock_message: AsyncMock):
    mock_message.text = "hello bot"
    await other_message_handler(mock_message)
    mock_message.reply.assert_awaited_once_with(messages.ERROR_UNKNOWN_COMMAND)
