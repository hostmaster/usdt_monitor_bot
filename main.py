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
    """

    # TODO: Keeping only last X transactions
    with shelve.open("tx") as db:
        if tx_hash in db:
            logger.debug(f"Transaction {tx_hash} already processed")
            return False
        db[tx_hash] = True
        return True


def get_direction(transaction: dict, address: str) -> str:
    """Detect transaction direction.

    Args:
        transaction (dict): The transaction.
        address (str): The wallet address.
    """

    if transaction["from"].lower() == address.lower():
        direction = "📤 Outgoing"
    elif transaction["to"].lower() == address.lower():
        direction = "📥 Incoming"
    else:
        direction = "Unknown"
    return direction


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
        secret_name (str): The secret name.
    """

    secret_path = f"/run/secrets/{secret_name}"
    try:
        with open(secret_path, "r", encoding="utf-8") as secret_file:
            secret_value = secret_file.read().strip()
            return secret_value
    except FileNotFoundError:
        logger.error(f"Secret '{secret_name}' not found.")
        return None


def load_global_secrets() -> None:
    """Load secrets from docker secrets.

    Args:
        None.
    """

    global ETHERSCAN_API_KEY, WALLET_ADDRESS
    ETHERSCAN_API_KEY = read_docker_secret("etherscan_api_key")
    WALLET_ADDRESS = read_docker_secret("wallet_address")


def main() -> None:
    """Run bot.

    Args:
        None.
    """

    try:
        load_global_secrets()

        tg_chat_id = read_docker_secret("tg_chat_id")
        tg_bot_token = read_docker_secret("tg_bot_token")

        # Create the Application and pass it your bot's token.
        application = Application.builder().token(tg_bot_token).build()
        job_queue = application.job_queue

        # on different commands - answer in Telegram
        application.add_handler(CommandHandler(["start", "help"], start))

        job_queue.run_repeating(
            callback_minute, interval=60, first=10, chat_id=tg_chat_id
        )

        # Run the bot until the user presses Ctrl-C
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
