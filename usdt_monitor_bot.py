import asyncio
import logging
import os
import sys
import sqlite3
import functools
import re
import time
from datetime import datetime
from decimal import Decimal  # Use Decimal for precision with currency values

# External Libs
import aiohttp
from apscheduler.schedulers.asyncio import AsyncIOScheduler

# Aiogram imports
from aiogram import Bot, Dispatcher, types, F
from aiogram.enums import ParseMode
from aiogram.filters import CommandStart, Command
from aiogram.filters.command import CommandObject
from aiogram.types import Message
from aiogram.utils.markdown import hbold, hcode, hlink
from aiogram.exceptions import (
    TelegramRetryAfter,
    TelegramForbiddenError,
    TelegramBadRequest,
)
from aiogram.client.default import DefaultBotProperties

# Make sure ParseMode is also imported if not already
from aiogram.enums import ParseMode

# --- Configuration ---
try:
    BOT_TOKEN = os.environ["BOT_TOKEN"]
    ETHERSCAN_API_KEY = os.environ["ETHERSCAN_API_KEY"]
except KeyError as e:
    logging.error(f"!!! Environment variable {e} not found!")
    sys.exit(f"Environment variable {e} not configured. Exiting.")

# Define a data directory inside the container's working directory
DATA_DIR = "data"
DATABASE_FILE = os.path.join(DATA_DIR, "users_usdt_monitor.db")  # Use path.join

# Ensure the data directory exists inside the container when the script runs
os.makedirs(DATA_DIR, exist_ok=True)  # Create data/ dir if it doesn't exist

ETHERSCAN_API_URL = "https://api.etherscan.io/api"
# Official USDT (Tether USD) Contract Address on Ethereum Mainnet
USDT_CONTRACT_ADDRESS = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
USDT_DECIMALS = 6  # USDT has 6 decimal places

CHECK_INTERVAL_SECONDS = 300  # 5 minutes
ETHERSCAN_REQUEST_DELAY = 1.1  # Delay between Etherscan API calls

# --- Bot Setup ---
dp = Dispatcher()

# --- Ethereum Address Validation ---
ETH_ADDRESS_REGEX = re.compile(r"^0x[a-fA-F0-9]{40}$")


def is_valid_ethereum_address(address: str) -> bool:
    return bool(ETH_ADDRESS_REGEX.fullmatch(address))


# --- Database Setup & Functions ---
# (Database functions _execute_db_query, init_db, sync/async user/wallet functions remain largely the same)
# ... (Keep the existing DB functions: _execute_db_query, init_db, _add_user_sync,
#      _check_user_exists_sync, _add_wallet_sync, _list_wallets_sync, _remove_wallet_sync,
#      _get_distinct_addresses_sync, _get_users_for_address_sync,
#      _get_last_checked_block_sync, _update_last_checked_block_sync, and their async wrappers)
# Make sure init_db creates all three tables: users, wallets, tracked_addresses
# --- Database Setup & Functions (Copy from previous example) ---


def _execute_db_query(
    query: str, params: tuple = (), fetch_one=False, fetch_all=False, commit=False
):
    conn = None
    result = False  # Default to False for write operations
    try:
        conn = sqlite3.connect(DATABASE_FILE, timeout=10)
        conn.execute("PRAGMA foreign_keys = ON;")
        cursor = conn.cursor()
        cursor.execute(query, params)

        if commit:
            conn.commit()
            # Check rowcount AFTER commit for INSERT, UPDATE, DELETE
            # rowcount indicates the number of rows affected by the last statement.
            # For INSERT OR IGNORE, it's 1 if inserted, 0 if ignored.
            # For INSERT OR REPLACE, it reflects rows changed.
            result = cursor.rowcount > 0
        elif fetch_one:
            result = cursor.fetchone()  # Will be None if no rows match
            # Ensure we don't return False on successful fetch_one returning None
            if result is None and not cursor.connection.total_changes:
                pass  # Keep result as None
            elif result is not None:
                pass  # Keep the fetched result
            else:  # Handle cases where fetch_one is True but the query wasn't a SELECT
                result = True  # Assume non-select query execution success if fetch_one was mistakenly set
        elif fetch_all:
            result = cursor.fetchall()  # Will be [] if no rows match
            # Ensure we don't return False on successful fetch_all returning []
            if not result and not cursor.connection.total_changes:
                pass  # Keep result as []
            elif result:
                pass  # Keep the fetched list
            else:  # Handle cases where fetch_all is True but the query wasn't a SELECT
                result = True  # Assume non-select query execution success if fetch_all was mistakenly set
        else:
            # For non-commit, non-fetch queries (like CREATE TABLE) assume success if no error
            result = True

        return result

    except sqlite3.Error as e:
        logging.error(f"Database error: {e} | Query: {query} | Params: {params}")
        # Keep the default 'False' for write errors, return None for read errors
        return None if fetch_one or fetch_all else False
    finally:
        if conn:
            conn.close()


def init_db():
    # Users Table
    users_table_query = """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY, username TEXT, first_name TEXT, last_name TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP )"""
    _execute_db_query(users_table_query, commit=True)
    # Wallets Table
    wallets_table_query = """
        CREATE TABLE IF NOT EXISTS wallets (
            wallet_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, address TEXT NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE, UNIQUE(user_id, address) )"""
    _execute_db_query(wallets_table_query, commit=True)
    # Tracked Addresses Table
    tracked_addresses_query = """
        CREATE TABLE IF NOT EXISTS tracked_addresses (
            address TEXT PRIMARY KEY,
            last_checked_block INTEGER DEFAULT 0,
            last_check_time TIMESTAMP
        )"""
    _execute_db_query(tracked_addresses_query, commit=True)
    logging.info("Database initialization check complete.")


# --- Sync DB Functions ---
def _add_user_sync(
    user_id: int, username: str | None, first_name: str, last_name: str | None
):
    query = "INSERT OR IGNORE INTO users (user_id, username, first_name, last_name) VALUES (?, ?, ?, ?)"
    _execute_db_query(query, (user_id, username, first_name, last_name), commit=True)


def _check_user_exists_sync(user_id: int) -> bool:
    result = _execute_db_query(
        "SELECT 1 FROM users WHERE user_id = ? LIMIT 1", (user_id,), fetch_one=True
    )
    return result is not None


def _add_wallet_sync(user_id: int, address: str) -> bool:
    # Add to wallets table
    added = _execute_db_query(
        "INSERT OR IGNORE INTO wallets (user_id, address) VALUES (?, ?)",
        (user_id, address.lower()),
        commit=True,
    )
    # Ensure address exists in tracked_addresses (lowercase)
    _execute_db_query(
        "INSERT OR IGNORE INTO tracked_addresses (address) VALUES (?)",
        (address.lower(),),
        commit=True,
    )
    return added


def _list_wallets_sync(user_id: int) -> list[str] | None:
    results = _execute_db_query(
        "SELECT address FROM wallets WHERE user_id = ? ORDER BY added_at",
        (user_id,),
        fetch_all=True,
    )
    return [row[0] for row in results] if isinstance(results, list) else None


def _remove_wallet_sync(user_id: int, address: str) -> bool:
    return _execute_db_query(
        "DELETE FROM wallets WHERE user_id = ? AND address = ?",
        (user_id, address.lower()),
        commit=True,
    )


def _get_distinct_addresses_sync() -> list[str] | None:
    results = _execute_db_query("SELECT DISTINCT address FROM wallets", fetch_all=True)
    return [row[0] for row in results] if isinstance(results, list) else None


def _get_users_for_address_sync(address: str) -> list[int] | None:
    results = _execute_db_query(
        "SELECT user_id FROM wallets WHERE address = ?",
        (address.lower(),),
        fetch_all=True,
    )
    return [row[0] for row in results] if isinstance(results, list) else None


def _get_last_checked_block_sync(address: str) -> int:
    result = _execute_db_query(
        "SELECT last_checked_block FROM tracked_addresses WHERE address = ?",
        (address.lower(),),
        fetch_one=True,
    )
    if result is None:
        _execute_db_query(
            "INSERT OR IGNORE INTO tracked_addresses (address) VALUES (?)",
            (address.lower(),),
            commit=True,
        )
        return 0
    return result[0] if result and result[0] is not None else 0


def _update_last_checked_block_sync(address: str, block_number: int) -> bool:
    query = "INSERT OR REPLACE INTO tracked_addresses (address, last_checked_block, last_check_time) VALUES (?, ?, ?)"
    return _execute_db_query(
        query, (address.lower(), block_number, datetime.now()), commit=True
    )


# --- Async DB Wrappers ---
async def run_db_operation(func, *args):
    try:
        return await asyncio.to_thread(func, *args)
    except AttributeError:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, functools.partial(func, *args))


async def add_user_to_db(user: types.User):
    if user:
        await run_db_operation(
            _add_user_sync, user.id, user.username, user.first_name, user.last_name
        )


async def check_user_exists(user_id: int) -> bool:
    return await run_db_operation(_check_user_exists_sync, user_id)


async def add_wallet(user_id: int, address: str) -> bool:
    return await run_db_operation(_add_wallet_sync, user_id, address)


async def list_wallets(user_id: int) -> list[str] | None:
    return await run_db_operation(_list_wallets_sync, user_id)


async def remove_wallet(user_id: int, address: str) -> bool:
    return await run_db_operation(_remove_wallet_sync, user_id, address)


async def get_distinct_addresses() -> list[str] | None:
    return await run_db_operation(_get_distinct_addresses_sync)


async def get_users_for_address(address: str) -> list[int] | None:
    return await run_db_operation(_get_users_for_address_sync, address)


async def get_last_checked_block(address: str) -> int:
    return await run_db_operation(_get_last_checked_block_sync, address)


async def update_last_checked_block(address: str, block_number: int) -> bool:
    return await run_db_operation(
        _update_last_checked_block_sync, address, block_number
    )


# --- Etherscan USDT Transaction Checking Job ---


async def check_usdt_transactions(bot: Bot, session: aiohttp.ClientSession):
    logging.info("Starting USDT transaction check cycle...")
    addresses_to_check = await get_distinct_addresses()
    if not addresses_to_check:
        logging.info("No addresses found in the database to check.")
        return

    latest_block_processed = {}

    for address in addresses_to_check:
        try:
            await asyncio.sleep(ETHERSCAN_REQUEST_DELAY)  # Respect rate limits

            start_block = await get_last_checked_block(address)
            query_start_block = start_block + 1 if start_block > 0 else 0

            params = {
                "module": "account",
                "action": "tokentx",  # Use token transactions endpoint
                "contractaddress": USDT_CONTRACT_ADDRESS,  # Filter for USDT contract
                "address": address,  # The address we are monitoring
                "startblock": query_start_block,
                "endblock": 99999999,
                "sort": "asc",
                "apikey": ETHERSCAN_API_KEY,
            }
            logging.debug(
                f"Checking USDT txs for {address} from block {query_start_block}"
            )

            async with session.get(
                ETHERSCAN_API_URL, params=params, timeout=30
            ) as response:
                if response.status != 200:
                    logging.error(
                        f"Etherscan API error (USDT) for {address}: Status {response.status} - {await response.text()}"
                    )
                    continue

                data = await response.json()

                if data.get("status") == "0":
                    if data.get("message") == "No transactions found":
                        logging.debug(
                            f"No new USDT transactions found for {address} since block {start_block}."
                        )
                        latest_block_processed[address] = start_block
                    # Handle "MAX RATE LIMIT REACHED" specifically if needed
                    elif "rate limit" in data.get("message", "").lower():
                        logging.warning(
                            f"Etherscan rate limit reached checking {address}. Will retry next cycle."
                        )
                        # Don't update block number if rate limited before getting results
                    else:
                        logging.error(
                            f"Etherscan API error (USDT) for {address}: {data.get('message')} - Result: {data.get('result')}"
                        )
                    continue

                transactions = data.get("result", [])
                if not isinstance(transactions, list):
                    logging.error(
                        f"Unexpected Etherscan API result format (USDT) for {address}: {transactions}"
                    )
                    continue
                if not transactions:
                    logging.debug(
                        f"No new USDT transactions returned for {address} (API result empty)."
                    )
                    latest_block_processed[address] = start_block
                    continue

                logging.info(
                    f"Found {len(transactions)} potential new USDT transaction(s) involving {address}"
                )

                user_ids = await get_users_for_address(address)
                if not user_ids:
                    logging.warning(
                        f"Found USDT transactions for {address}, but no users are tracking it."
                    )
                    if transactions:
                        latest_block_processed[address] = int(
                            transactions[-1]["blockNumber"]
                        )
                    continue

                current_max_block_for_addr = start_block
                for tx in transactions:
                    try:
                        tx_block = int(tx["blockNumber"])
                        if tx_block <= start_block:
                            continue  # Skip txs from blocks already processed

                        # Check if it's an *incoming* USDT transaction for the monitored address
                        is_incoming_usdt = (
                            tx["contractAddress"].lower()
                            == USDT_CONTRACT_ADDRESS.lower()
                            and tx["to"].lower() == address.lower()
                        )

                        if is_incoming_usdt:
                            tx_hash = tx["hash"]
                            from_addr = tx["from"]
                            token_decimal = int(
                                tx.get("tokenDecimal", USDT_DECIMALS)
                            )  # Use provided decimal or default
                            # Use Decimal for precise calculation
                            value_smallest_unit = Decimal(tx["value"])
                            value_usdt = value_smallest_unit / (
                                Decimal(10) ** token_decimal
                            )

                            tx_time_ts = int(tx["timeStamp"])
                            tx_datetime = datetime.fromtimestamp(tx_time_ts).strftime(
                                "%Y-%m-%d %H:%M:%S UTC"
                            )
                            etherscan_link = f"https://etherscan.io/tx/{tx_hash}"

                            message_text = (
                                f"🔔 {hbold('New Incoming USDT Transfer!')}\n\n"
                                f"💰 To Address: {hcode(address)}\n"
                                f"💵 Amount: {hbold(f'{value_usdt:,.{token_decimal}f} USDT')}\n"  # Format with commas and correct decimals
                                f"➡️ From: {hcode(from_addr)}\n"
                                f"⏰ Time: {tx_datetime}\n"
                                f"🔗 {hlink('View on Etherscan', etherscan_link)}"
                            )

                            for user_id in user_ids:
                                try:
                                    await bot.send_message(
                                        user_id,
                                        message_text,
                                        parse_mode=ParseMode.HTML,
                                        disable_web_page_preview=True,
                                    )
                                    logging.info(
                                        f"Notified user {user_id} about USDT tx {tx_hash} for address {address}"
                                    )
                                    await asyncio.sleep(0.1)
                                except TelegramRetryAfter as e:
                                    logging.warning(
                                        f"Rate limited sending to user {user_id}. Sleeping for {e.retry_after}s"
                                    )
                                    await asyncio.sleep(e.retry_after)
                                    await bot.send_message(
                                        user_id,
                                        message_text,
                                        parse_mode=ParseMode.HTML,
                                        disable_web_page_preview=True,
                                    )  # Retry
                                except (
                                    TelegramForbiddenError,
                                    TelegramBadRequest,
                                ) as e:
                                    logging.error(
                                        f"Failed to send notification to user {user_id}: {e}."
                                    )
                                except Exception as e:
                                    logging.error(
                                        f"Unexpected error sending USDT notification to user {user_id}: {e}"
                                    )

                        # Update the max block seen for this address in this cycle
                        current_max_block_for_addr = max(
                            current_max_block_for_addr, tx_block
                        )

                    except Exception as e:
                        logging.error(
                            f"Error processing USDT transaction {tx.get('hash', 'N/A')} for {address}: {e}",
                            exc_info=True,
                        )

                latest_block_processed[address] = current_max_block_for_addr

        except aiohttp.ClientError as e:
            logging.error(f"Network error checking USDT for {address}: {e}")
        except asyncio.TimeoutError:
            logging.error(f"Timeout checking USDT for {address}")
        except Exception as e:
            logging.error(
                f"Unexpected error in USDT check cycle for {address}: {e}",
                exc_info=True,
            )

    # Update database after checking all addresses
    logging.info("Finished checking USDT addresses. Updating last checked blocks...")
    update_tasks = []
    for addr, block_num in latest_block_processed.items():
        if block_num >= 0:
            update_tasks.append(update_last_checked_block(addr, block_num))
    if update_tasks:
        results = await asyncio.gather(*update_tasks, return_exceptions=True)
        # Optional: Log success/failure of DB updates based on results

    logging.info("USDT transaction check cycle complete.")


# --- Aiogram Handlers ---
# (Handlers remain largely the same, just update help text and maybe logs)


@dp.message(CommandStart(), F.chat.type == "private")
async def command_start_handler(message: Message):
    user = message.from_user
    if not user:
        return
    is_returning = await check_user_exists(user.id)
    await add_user_to_db(user)
    greeting = (
        f"Welcome back, {hbold(user.full_name)}!"
        if is_returning
        else f"Hello there, {hbold(user.full_name)}! Welcome!"
    )
    await message.answer(greeting)
    await message.answer(
        "I can monitor your Ethereum addresses for incoming USDT transactions. Use /help."
    )


@dp.message(Command(commands=["help"]), F.chat.type == "private")
async def command_help_handler(message: Message):
    await add_user_to_db(message.from_user)
    help_text = (
        f"{hbold('Available Commands:')}\n"
        f"/start - Start interaction\n"
        f"/help - Show this help message\n"
        f"/add_wallet {hcode('<eth_address>')} - Monitor address for incoming USDT\n"
        f"/list_wallets - List your monitored addresses\n"
        f"/remove_wallet {hcode('<eth_address>')} - Stop monitoring address\n\n"
        f"ℹ️ I check wallets every few minutes for new {hbold('incoming USDT')} transfers and notify you."
    )
    await message.answer(help_text, parse_mode=ParseMode.HTML)


@dp.message(Command(commands=["add_wallet"]), F.chat.type == "private")
async def add_wallet_handler(message: Message, command: CommandObject):
    user = message.from_user
    if not user:
        return
    await add_user_to_db(user)
    if command.args is None:
        await message.reply(f"Provide address: {hcode('/add_wallet 0x...')}")
        return
    address = command.args.strip().lower()  # Ensure lowercase
    if not is_valid_ethereum_address(address):
        await message.reply("Invalid Ethereum address format.")
        return
    success = await add_wallet(user.id, address)
    if success:
        await message.reply(
            f"✅ Monitoring for incoming USDT started for: {hcode(address)}"
        )
        logging.info(f"User {user.id} added wallet for USDT monitoring: {address}")
    else:
        await message.reply(
            f"⚠️ Could not add {hcode(address)}. You might already be monitoring it, or a DB error occurred."
        )


@dp.message(Command(commands=["list_wallets"]), F.chat.type == "private")
async def list_wallets_handler(message: Message):
    user = message.from_user
    if not user:
        return
    await add_user_to_db(user)
    user_wallets = await list_wallets(user.id)
    if user_wallets is None:
        await message.reply("⚠️ Error fetching wallets.")
    elif not user_wallets:
        await message.reply("You are not monitoring any wallets for USDT.")
    else:
        response = [f"{hbold('Your monitored wallets (for USDT):')}"] + [
            f"- {hcode(addr)}" for addr in user_wallets
        ]
        await message.reply("\n".join(response), parse_mode=ParseMode.HTML)


@dp.message(Command(commands=["remove_wallet"]), F.chat.type == "private")
async def remove_wallet_handler(message: Message, command: CommandObject):
    user = message.from_user
    if not user:
        return
    await add_user_to_db(user)
    if command.args is None:
        await message.reply(
            f"Provide address to remove: {hcode('/remove_wallet 0x...')}"
        )
        return
    address_to_remove = command.args.strip().lower()  # Ensure lowercase
    if not is_valid_ethereum_address(address_to_remove):
        await message.reply("Invalid address format.")
        return
    removed = await remove_wallet(user.id, address_to_remove)
    if removed:
        await message.reply(
            f"🗑️ Stopped USDT monitoring for: {hcode(address_to_remove)}"
        )
        logging.info(
            f"User {user.id} removed wallet for USDT monitoring: {address_to_remove}"
        )
    else:
        await message.reply(
            f"Could not remove {hcode(address_to_remove)}. Ensure you are monitoring it."
        )


@dp.message(F.chat.type == "private")  # Catch non-command messages in private chat
async def other_message_handler(message: Message):
    await message.reply(
        "I only understand commands. Use /help to see them.", parse_mode=ParseMode.HTML
    )


# --- Main Function ---
async def main() -> None:
    init_db()
    bot = Bot(BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))

    async with aiohttp.ClientSession() as session:
        scheduler = AsyncIOScheduler(timezone="UTC")
        scheduler.add_job(
            check_usdt_transactions,  # Use the new job function
            "interval",
            seconds=CHECK_INTERVAL_SECONDS,
            args=(bot, session),
            next_run_time=datetime.now(),
        )
        scheduler.start()
        logging.info(
            f"Scheduler started. Checking USDT transactions every {CHECK_INTERVAL_SECONDS} seconds."
        )

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s",
        )
        logging.getLogger("apscheduler.executors.default").setLevel(logging.WARNING)
        logging.info("Starting bot polling...")

        try:
            await dp.start_polling(bot, skip_updates=True)
        finally:
            logging.info("Shutting down scheduler...")
            scheduler.shutdown()
            logging.info("Bot stopped.")


# --- Entry Point ---
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logging.info("Bot stopped.")
    except Exception as e:
        logging.critical(f"Critical unexpected error in main: {e}", exc_info=True)
