"""
Telegram bot handlers module.

Defines command handlers for the Telegram bot including /start, /help,
/add, /list, and /remove commands.
"""

# Standard library
import logging
import re
from typing import Optional

# Third-party
from aiogram import Dispatcher, F, Router
from aiogram.filters import Command, CommandStart
from aiogram.filters.command import CommandObject
from aiogram.types import Message

# Local
from usdt_monitor_bot import messages
from usdt_monitor_bot.database import DatabaseManager, WalletAddResult

# --- Ethereum Address Validation ---
ETH_ADDRESS_REGEX = re.compile(r"^0x[a-fA-F0-9]{40}$")


def is_valid_ethereum_address(
    address: Optional[str],
) -> bool:  # Allow None input type hint
    if not isinstance(address, str):  # Check type first to handle None/int etc.
        return False
    return bool(ETH_ADDRESS_REGEX.fullmatch(address))


# Create a router instance
router = Router()


# Middleware or alternative way to inject db_manager if needed,
# but passing directly via register function is simpler here.

# --- Handler Functions ---


@router.message(CommandStart(), F.chat.type == "private")
async def command_start_handler(message: Message, db_manager: DatabaseManager):
    user = message.from_user
    if not user:
        return  # Should not happen in private chats

    is_returning = await db_manager.check_user_exists(user.id)
    await db_manager.add_user(user.id, user.username, user.first_name, user.last_name)

    greeting = messages.welcome_message(user.full_name, is_returning)
    await message.answer(greeting)
    await message.answer(messages.START_INTRO)


@router.message(Command("help"), F.chat.type == "private")
async def command_help_handler(message: Message, db_manager: DatabaseManager):
    # Ensure user exists if they somehow skipped /start
    if message.from_user:
        await db_manager.add_user(
            message.from_user.id,
            message.from_user.username,
            message.from_user.first_name,
            message.from_user.last_name,
        )

    await message.answer(messages.HELP_TEXT)


@router.message(Command("add"), F.chat.type == "private")
async def add_wallet_handler(
    message: Message, command: CommandObject, db_manager: DatabaseManager
):
    user = message.from_user
    if not user:
        return
    await db_manager.add_user(
        user.id, user.username, user.first_name, user.last_name
    )  # Ensure user exists

    if command.args is None or not command.args.strip():
        await message.reply(messages.add_wallet_missing_address())
        return

    address = command.args.strip()
    if not is_valid_ethereum_address(address):
        await message.reply(messages.INVALID_ETH_ADDRESS_FORMAT)
        return

    address_lower = address.lower()
    status = await db_manager.add_wallet(user.id, address_lower)

    if status == WalletAddResult.ADDED:
        reply_text = messages.add_wallet_success(address_lower)
        logging.info(f"User {user.id} added wallet: {address_lower}")
    elif status == WalletAddResult.ALREADY_EXISTS:
        reply_text = messages.add_wallet_already_exists(address_lower)
        logging.info(
            f"User {user.id} attempted to add existing wallet: {address_lower}"
        )
    elif status == WalletAddResult.DB_ERROR:
        reply_text = messages.ERROR_UNEXPECTED
        logging.error(
            f"DB_ERROR while user {user.id} attempted to add wallet: {address_lower}"
        )
    else:  # Should not happen with the defined Enum
        reply_text = messages.ERROR_UNEXPECTED
        logging.error(
            f"Unknown WalletAddResult status {status} for user {user.id}, address {address_lower}"
        )

    await message.reply(reply_text)


@router.message(Command("list"), F.chat.type == "private")
async def list_wallets_handler(message: Message, db_manager: DatabaseManager):
    user = message.from_user
    if not user:
        return
    await db_manager.add_user(
        user.id, user.username, user.first_name, user.last_name
    )  # Ensure user exists

    user_wallets = await db_manager.list_wallets(user.id)

    if user_wallets is None:
        await message.reply(messages.LIST_WALLETS_ERROR)
        logging.error(f"Failed to retrieve wallet list for user {user.id}")
    elif not user_wallets:
        await message.reply(messages.LIST_WALLETS_EMPTY)
    else:
        await message.reply(messages.format_wallet_list(user_wallets))


@router.message(Command("remove"), F.chat.type == "private")
async def remove_wallet_handler(
    message: Message, command: CommandObject, db_manager: DatabaseManager
):
    user = message.from_user
    if not user:
        return
    await db_manager.add_user(
        user.id, user.username, user.first_name, user.last_name
    )  # Ensure user exists

    if command.args is None or not command.args.strip():
        await message.reply(messages.remove_wallet_missing_address())
        return

    address_to_remove = command.args.strip()
    # Validate format even for removal to avoid confusion
    if not is_valid_ethereum_address(address_to_remove):
        await message.reply(messages.REMOVE_WALLET_INVALID_ADDRESS)
        return

    address_lower = address_to_remove.lower()
    removed = await db_manager.remove_wallet(user.id, address_lower)

    if removed:
        reply_text = messages.remove_wallet_success(address_lower)
        logging.info(f"User {user.id} removed wallet: {address_lower}")
    else:
        reply_text = messages.remove_wallet_not_found(address_lower)

    await message.reply(reply_text)


@router.message(F.chat.type == "private")
async def other_message_handler(message: Message):
    """Handles any other text messages in private chat."""
    await message.reply(messages.ERROR_UNKNOWN_COMMAND)


def register_handlers(dp: Dispatcher, db_manager: DatabaseManager):
    """Registers all command and message handlers with the dispatcher."""
    # Pass db_manager to handlers that need it using functools.partial or lambda
    # Aiogram 3.x supports passing dependencies directly if defined in handler signature
    # and provided during router/dispatcher setup (which we do below)
    dp.include_router(router)
    logging.info("Bot handlers registered.")
