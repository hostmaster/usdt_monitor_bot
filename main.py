#!/usr/bin/env python3
# pylint: disable=unused-argument, import-error, logging-fstring-interpolation

import os
import sys
import logging
import html
from typing import Optional

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
)
from telegram.constants import ParseMode

from config import settings
from api import EtherscanClient
from storage import TransactionStorage

# Enable logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
# set higher logging level for httpx to avoid all GET and POST requests being logged
logging.getLogger("httpx").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send explanation on how to use the bot.

    Args:
        update: The update object
        context: The context object
    """
    await update.message.reply_text(
        "Hi! I'm a crypto wallet tracker bot. "
        "I'll notify you about new transactions for your configured wallet address."
    )


def get_direction(transaction: dict, address: str) -> str:
    """Detect transaction direction.

    Args:
        transaction: The transaction data
        address: The wallet address

    Returns:
        Direction of the transaction (Outgoing/Incoming/Unknown)
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
        context: The context object
    """
    try:
        client = EtherscanClient(settings.ETHERSCAN_API_KEY)
        storage = TransactionStorage()

        tx = client.get_latest_transaction(
            contract_address=settings.USDT_CONTRACT,
            wallet_address=settings.WALLET_ADDRESS,
        )

        if tx is not None:
            logger.debug(f"Latest transaction: {tx}")
            tx_hash = tx.get("hash")
            if tx_hash and storage.is_new_transaction(tx_hash):
                usdt = float(tx.get("value", 0)) / 10**6
                etherscan_link = f'<a href="https://etherscan.io/tx/{html.escape(tx_hash)}">Etherscan</a>'
                direction = get_direction(
                    transaction=tx, address=settings.WALLET_ADDRESS
                )

                await context.bot.send_message(
                    chat_id=context.job.chat_id,
                    text=f"{direction} ETH transaction detected {etherscan_link} {usdt:.2f} USDT",
                    parse_mode=ParseMode.HTML,
                )
    except Exception as e:
        logger.error(f"Error in transaction monitoring: {e}")


def setup_telegram_bot() -> Application:
    """Set up and configure the Telegram bot application.

    Returns:
        Configured Telegram bot application
    """
    application = Application.builder().token(settings.TG_BOT_TOKEN).build()

    # Add command handlers
    application.add_handler(CommandHandler(["start", "help"], start))

    # Configure scheduled jobs
    job_queue = application.job_queue
    job_queue.run_repeating(
        callback_minute,
        interval=settings.POLLING_INTERVAL,
        first=settings.POLLING_START_DELAY,
        chat_id=settings.TG_CHAT_ID,
    )

    return application


def main() -> None:
    """Run the Telegram bot application."""
    try:
        application = setup_telegram_bot()
        application.run_polling(allowed_updates=Update.ALL_TYPES)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Interrupted")
        try:
            sys.exit(130)
        except SystemExit:
            os._exit(130)
