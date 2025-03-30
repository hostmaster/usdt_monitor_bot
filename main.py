#!/usr/bin/env python
# pylint: disable=unused-argument, import-error, logging-fstring-interpolation, global-statement, fixme

import os
import sys
import json
import requests
import html
from requests.exceptions import HTTPError, RequestException

import shelve

import logging

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
)
from telegram.constants import ParseMode

# Enable logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
# set higher logging level for httpx to avoid all GET and POST requests being logged
logging.getLogger("httpx").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

USDT_CONTRACT = "0xdac17f958d2ee523a2206206994597c13d831ec7"  # USDT
ETHERSCAN_API_KEY = None  # etherscan_api_key
WALLET_ADDRESS = None  # wallet_address

HTTP_TIMEOUT = 5  # HTTP timeout


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Sends explanation on how to use the bot.

    Args:
        update (Update): The update object.
        context (ContextTypes.DEFAULT_TYPE): The context object.
    """
    await update.message.reply_text("Hi! Let's get started!")


def get_latest_tx(token: str, contract: str, address: str) -> dict:
    """Get the latest transaction for a given address on ETH blockchain.

    Args:
        token (str): The Etherscan API key.
        contract (str): The contract address.
        address (str): The wallet address.
    """

    url = "https://api.etherscan.io/api"
    params = {
        "module": "account",
        "action": "tokentx",
        "contractaddress": contract,
        "address": address,
        "page": 1,
        "offset": 10,
        "startblock": 0,
        "endblock": 99999999,
        "sort": "desc",
        "apikey": token,
    }

    try:
        response = requests.get(url, params=params, timeout=HTTP_TIMEOUT)
        response.raise_for_status()

        response_json = response.json()
        if "message" in response_json and response_json["message"] == "NOTOK":
            raise RuntimeError(response.json())
        data = response.json()
        result = data.get("result", [])
        return result[0]

    except HTTPError as http_e:
        logger.error(
            f"HTTP error fetching transactions for {address} on ETH blockchain: {http_e}"
        )
        return None
    except (
        RequestException,
        RuntimeError,
    ) as e:
        logger.error(
            f"Error fetching transactions for {address} on ETH blockchain: {e}"
        )
        return None
    except json.JSONDecodeError:
        logger.error("Error decoding JSON response")
        return None


def is_new_tx(tx_hash: str) -> bool:
    """Check if the transaction is new.

    Args:
        tx_hash (str): The transaction hash.

    Returns:
        bool: True if transaction is new, False if already processed
    """
    with shelve.open("tx") as db:
        is_new = tx_hash not in db
        if not is_new:
            logger.debug(f"Transaction {tx_hash} already processed")
        else:
            db[tx_hash] = True
        return is_new


def get_direction(transaction: dict, address: str) -> str:
    """Detect transaction direction.

    Args:
        transaction (dict): The transaction.
        address (str): The wallet address.

    Returns:
        str: Direction of the transaction (Outgoing/Incoming/Unknown)
    """
    address = address.lower()
    tx_from = transaction["from"].lower()
    tx_to = transaction["to"].lower()

    if tx_from == address:
        return "📤 Outgoing"
    if tx_to == address:
        return "📥 Incoming"
    return "Unknown"


async def callback_minute(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Keep track of ETH transactions regularly.

    Args:
        context (ContextTypes.DEFAULT_TYPE): The context object.
    """

    tx = get_latest_tx(
        token=ETHERSCAN_API_KEY, contract=USDT_CONTRACT, address=WALLET_ADDRESS
    )
    if tx is not None:
        logger.debug(f"The latest transaction is {tx}")
        tx_hash = tx.get("hash")
        usdt = float(tx.get("value")) / 10**6
        if is_new_tx(tx_hash):
            etherscan_link = f'<a href="https://etherscan.io/tx/{html.escape(tx_hash)}">Etherscan</a>'
            direction = get_direction(transaction=tx, address=WALLET_ADDRESS)
            await context.bot.send_message(
                chat_id=context.job.chat_id,
                text=f"{direction} ETH transaction detected {etherscan_link} {usdt:.2f} USDT",
                parse_mode=ParseMode.HTML,
            )


def read_docker_secret(secret_name: str) -> str:
    """Read secret from Docker secret file.

    Args:
        secret_name (str): Name of the secret file to read

    Returns:
        str: Contents of the secret file

    Raises:
        ValueError: If secret file is missing, inaccessible, or empty
        OSError: If other OS-level errors occur reading the file
    """
    from pathlib import Path

    secret_path = Path("/run/secrets") / secret_name
    try:
        content = secret_path.read_text(encoding="utf-8").strip()
        if not content:
            logger.error(f"Secret '{secret_name}' is empty")
            raise ValueError(f"Secret '{secret_name}' cannot be empty")
        return content
    except FileNotFoundError:
        logger.error(f"Secret '{secret_name}' not found")
        raise ValueError(f"Required secret '{secret_name}' is missing")
    except PermissionError:
        logger.error(f"Permission denied reading secret '{secret_name}'")
        raise ValueError(f"Cannot access secret '{secret_name}' - permission denied")
    except OSError as e:
        logger.error(f"OS error reading secret '{secret_name}': {e}")
        raise OSError(f"Failed to read secret '{secret_name}': {e}")
    except UnicodeDecodeError:
        logger.error(f"Secret '{secret_name}' contains invalid UTF-8 data")
        raise ValueError(f"Secret '{secret_name}' must contain valid UTF-8 text")


def setup_telegram_bot(tg_bot_token: str, tg_chat_id: str) -> Application:
    """Set up and configure the Telegram bot application.

    Args:
        tg_bot_token (str): Telegram bot API token
        tg_chat_id (str): Telegram chat ID for notifications

    Returns:
        Application: Configured Telegram bot application
    """
    application = Application.builder().token(tg_bot_token).build()

    # Add command handlers
    application.add_handler(CommandHandler(["start", "help"], start))

    # Configure scheduled jobs
    job_queue = application.job_queue
    job_queue.run_repeating(callback_minute, interval=60, first=10, chat_id=tg_chat_id)

    return application


def load_secrets() -> tuple[str, str, str, str]:
    """Load required secrets from Docker secrets.

    Returns:
        tuple: Contains etherscan_api_key, wallet_address, tg_chat_id, tg_bot_token
    """
    global ETHERSCAN_API_KEY, WALLET_ADDRESS
    ETHERSCAN_API_KEY = read_docker_secret("etherscan_api_key")
    WALLET_ADDRESS = read_docker_secret("wallet_address")
    tg_chat_id = read_docker_secret("tg_chat_id")
    tg_bot_token = read_docker_secret("tg_bot_token")
    return ETHERSCAN_API_KEY, WALLET_ADDRESS, tg_chat_id, tg_bot_token

def main() -> None:
    """Run the Telegram bot application."""
    try:
        # Load secrets and start bot
        _, _, tg_chat_id, tg_bot_token = load_secrets()
        application = setup_telegram_bot(tg_bot_token, tg_chat_id)
        application.run_polling(allowed_updates=Update.ALL_TYPES)

    except (FileNotFoundError, RuntimeError, ValueError) as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    """Run the bot.

    Args:
        None.
    """

    try:
        main()
    except KeyboardInterrupt:
        logger.info("Interrupted")
        try:
            sys.exit(130)
        except SystemExit:
            os._exit(130)
