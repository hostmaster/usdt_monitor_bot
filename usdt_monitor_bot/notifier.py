# notifier.py
import asyncio
import logging
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict

from aiogram import Bot
from aiogram.enums import ParseMode
from aiogram.exceptions import (
    TelegramBadRequest,
    TelegramForbiddenError,
    TelegramRetryAfter,
)
from aiogram.utils.markdown import hbold, hcode, hlink

from usdt_monitor_bot.config import BotConfig


class NotificationService:
    """Handles formatting and sending notifications via Telegram."""

    def __init__(self, bot: Bot, config: BotConfig):
        self._bot = bot
        self._config = config
        logging.info("NotificationService initialized.")

    def _format_token_message(
        self, monitored_address: str, tx: Dict[str, Any], token_type: str
    ) -> str:
        """Formats the notification message for an incoming token transaction."""
        try:
            tx_hash = tx["hash"]
            from_addr = tx["from"]
            # Use provided decimal or default, handle potential missing key robustly
            token_decimal = int(
                tx.get(
                    "tokenDecimal",
                    self._config.usdt_decimals
                    if token_type == "USDT"
                    else self._config.usdc_decimals,
                )
            )
            value_smallest_unit = Decimal(tx["value"])
            value_token = value_smallest_unit / (Decimal(10) ** token_decimal)

            tx_time_ts = int(tx["timeStamp"])
            tx_datetime = datetime.fromtimestamp(tx_time_ts).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
            etherscan_link = f"https://etherscan.io/tx/{tx_hash}"

            # Format amount with commas and correct decimal places
            amount_str = f"{value_token:,.{token_decimal}f} {token_type}"

            message_text = (
                f"🔔 {hbold(f'New Incoming {token_type} Transfer!')}\n\n"
                f"💰 To Address: {hcode(monitored_address)}\n"
                f"💵 Amount: {hbold(amount_str)}\n"
                f"➡️ From: {hcode(from_addr)}\n"
                f"⏰ Time: {tx_datetime}\n"
                f"🔗 {hlink('View on Etherscan', etherscan_link)}"
            )
            return message_text
        except KeyError as e:
            logging.error(f"Missing key {e} in transaction data: {tx}")
            return f"⚠️ Error formatting transaction {tx.get('hash', 'N/A')}. Data might be incomplete."
        except Exception as e:
            logging.error(
                f"Error formatting message for tx {tx.get('hash', 'N/A')}: {e}"
            )
            return f"⚠️ Error formatting transaction {tx.get('hash', 'N/A')}."

    async def send_token_notification(
        self,
        user_id: int,
        monitored_address: str,
        tx_data: Dict[str, Any],
        token_type: str,
    ):
        """Sends a formatted token transaction notification to a user."""
        message_text = self._format_token_message(
            monitored_address, tx_data, token_type
        )
        if message_text.startswith("⚠️"):  # Don't send malformed messages
            logging.warning(
                f"Skipping notification to {user_id} due to formatting error for tx {tx_data.get('hash')}"
            )
            return

        try:
            await self._bot.send_message(
                user_id,
                message_text,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
            logging.debug(
                f"Sent {token_type} notification to {user_id} for tx {tx_data['hash']}"
            )
            await asyncio.sleep(0.1)  # Small delay between sends
        except TelegramRetryAfter as e:
            logging.warning(
                f"Rate limited sending to user {user_id}. Sleeping for {e.retry_after}s"
            )
            await asyncio.sleep(e.retry_after)
            try:
                await self._bot.send_message(
                    user_id,
                    message_text,
                    parse_mode=ParseMode.HTML,
                    disable_web_page_preview=True,
                )  # Retry
            except Exception as inner_e:
                logging.error(
                    f"Failed to send notification to user {user_id} after retry: {inner_e}"
                )
        except (TelegramForbiddenError, TelegramBadRequest) as e:
            logging.error(
                f"Telegram API error sending to user {user_id}: {e}. User might have blocked the bot or chat not found."
                # Consider removing user/wallet if forbidden for extended periods?
            )
        except Exception as e:
            logging.error(
                f"Unexpected error sending {token_type} notification to user {user_id}: {e}"
            )
