# handlers.py
import logging
import re
from typing import Optional  # Import Optional

from aiogram import Dispatcher, F, Router
from aiogram.filters import Command, CommandStart
from aiogram.filters.command import CommandObject
from aiogram.types import Message
from aiogram.utils.markdown import hbold, hcode

from usdt_monitor_bot.database import DatabaseManager

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

    greeting = (
        f"Welcome back, {hbold(user.full_name)}!"
        if is_returning
        else f"Hello there, {hbold(user.full_name)}! Welcome!"
    )
    await message.answer(greeting)
    await message.answer(
        "I can monitor your Ethereum addresses for incoming USDT transfers.\n"
        "Use /help to see the commands."
    )


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

    help_text = (
        f"{hbold('Available Commands:')}\n"
        f"/start - Start interaction\n"
        f"/help - Show this help message\n"
        f"/add {hcode('<eth_address>')} - Monitor address for incoming USDT\n"
        f"/list - List your monitored addresses\n"
        f"/remove {hcode('<eth_address>')} - Stop monitoring address\n\n"
        f"ℹ️ I check wallets every few minutes for new {hbold('incoming USDT')} "
        f"transfers and notify you if found."
    )
    await message.answer(help_text)


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
        await message.reply(
            f"❌ Please provide an address.\nUsage: {hcode('/add 0x123...')}"
        )
        return

    address = command.args.strip()
    if not is_valid_ethereum_address(address):
        await message.reply(
            "❌ Invalid Ethereum address format. It should start with '0x' and be 42 characters long."
        )
        return

    address_lower = address.lower()
    success = await db_manager.add_wallet(user.id, address_lower)

    if success:
        await message.reply(
            f"✅ Now monitoring for incoming USDT transfers to: {hcode(address_lower)}"
        )
        logging.info(f"User {user.id} added wallet: {address_lower}")
    else:
        # Could be duplicate or DB error, check logs for specifics
        await message.reply(
            f"⚠️ Address {hcode(address_lower)} is already being monitored or a database error occurred."
        )


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
        await message.reply(
            "⚠️ An error occurred while fetching your wallet list. Please try again later."
        )
        logging.error(f"Failed to retrieve wallet list for user {user.id}")
    elif not user_wallets:
        await message.reply(
            "ℹ️ You are not currently monitoring any addresses. Use /add to start."
        )
    else:
        response = [f"{hbold('Your monitored wallets (for USDT):')}"] + [
            f" L {hcode(addr)}" for addr in user_wallets
        ]
        await message.reply("\n".join(response))


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
        await message.reply(
            f"❌ Please provide an address to remove.\nUsage: {hcode('/remove 0x123...')}"
        )
        return

    address_to_remove = command.args.strip()
    # Validate format even for removal to avoid confusion
    if not is_valid_ethereum_address(address_to_remove):
        await message.reply("❌ Invalid Ethereum address format.")
        return

    address_lower = address_to_remove.lower()
    removed = await db_manager.remove_wallet(user.id, address_lower)

    if removed:
        await message.reply(
            f"🗑️ Stopped monitoring for incoming USDT to: {hcode(address_lower)}"
        )
        logging.info(f"User {user.id} removed wallet: {address_lower}")
    else:
        await message.reply(
            f"⚠️ Address {hcode(address_lower)} was not found in your monitored list or a database error occurred."
        )


@router.message(F.chat.type == "private")
async def other_message_handler(message: Message):
    """Handles any other text messages in private chat."""
    await message.reply(
        "😕 Sorry, I didn't understand that. Please use /help to see the available commands."
    )


def register_handlers(dp: Dispatcher, db_manager: DatabaseManager):
    """Registers all command and message handlers with the dispatcher."""
    # Pass db_manager to handlers that need it using functools.partial or lambda
    # Aiogram 3.x supports passing dependencies directly if defined in handler signature
    # and provided during router/dispatcher setup (which we do below)
    dp.include_router(router)
    logging.info("Bot handlers registered.")
