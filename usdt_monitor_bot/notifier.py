# notifier.py
import logging
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict

from aiogram import Bot
from aiogram.enums import ParseMode
from aiogram.utils.markdown import hbold, hcode, hlink

from usdt_monitor_bot.config import BotConfig, TokenConfig


class NotificationService:
    """Handles formatting and sending notifications via Telegram."""

    def __init__(self, bot: Bot, config: BotConfig):
        self._bot = bot
        self._config = config
        logging.info("NotificationService initialized.")

    def _format_token_message(
        self, tx_data: Dict[str, Any], token_config: TokenConfig
    ) -> str:
        """Formats a token transaction message with proper decimals and symbols."""
        try:
            # Validate required fields
            required_fields = ["hash", "from", "to", "value", "timeStamp"]
            for field in required_fields:
                if field not in tx_data:
                    logging.error(f"Missing required field {field} in transaction data")
                    return None

            tx_hash = tx_data["hash"]
            from_address = tx_data["from"]
            value = tx_data["value"]
            timestamp = tx_data["timeStamp"]

            # Format value with proper decimals
            try:
                decimal_value = Decimal(value) / Decimal(10**token_config.decimals)
                formatted_value = f"{decimal_value:.2f}"
            except (ValueError, TypeError, InvalidOperation) as e:
                logging.error(f"Could not format value {value} for tx {tx_hash}: {e}")
                return None

            # Format timestamp
            try:
                timestamp_int = int(timestamp)
                formatted_time = datetime.fromtimestamp(
                    timestamp_int, tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S UTC")
            except (ValueError, TypeError) as e:
                logging.error(
                    f"Could not format timestamp {timestamp} for tx {tx_hash}: {e}"
                )
                return None

            # Create message for incoming transaction
            message = (
                f"🔔 New Incoming {token_config.symbol} Transfer!\n\n"
                f"Amount: {hbold(f'{formatted_value} {token_config.symbol}')}\n"
                f"From: {hcode(from_address)}\n"
                f"Time: {formatted_time}\n"
                f"Tx: {hlink('View on Etherscan', f'{token_config.explorer_url}/tx/{tx_hash}')}"
            )

            return message

        except Exception as e:
            error_msg = f"Error formatting transaction {tx_hash}: {str(e)}"
            logging.error(error_msg)
            return None

    async def send_token_notification(
        self,
        user_id: int,
        tx: dict,
        token_type: str,
    ) -> None:
        """
        Send a notification for a token transaction.

        Args:
            user_id: The Telegram user ID to send the notification to
            tx: The transaction data from Etherscan
            token_type: The token symbol (e.g. 'USDT', 'USDC')
        """
        if not tx:
            logging.warning("Received empty transaction data, skipping notification")
            return

        try:
            # Get token configuration
            token_config = self._config.token_registry.get_token(token_type)
            if not token_config:
                logging.error(f"Token configuration not found for {token_type}")
                return

            # Format the message using token-specific configuration
            message = self._format_token_message(tx, token_config)

            # Only send the message if it was successfully formatted
            if message is not None:
                # Send the message
                await self._bot.send_message(
                    chat_id=user_id,
                    text=message,
                    parse_mode=ParseMode.HTML,
                    disable_web_page_preview=True,
                )
                logging.info(
                    f"Sent notification to user {user_id} for tx {tx.get('hash', 'unknown')}"
                )
            else:
                logging.warning(
                    f"Message formatting failed for tx {tx.get('hash', 'unknown')}, skipping notification"
                )

        except Exception as e:
            logging.error(
                f"Error sending notification to user {user_id} for tx {tx.get('hash', 'unknown')}: {e}",
                exc_info=True,
            )

    async def _send_token_notification(
        self, user_id: int, tx: dict, token_config: TokenConfig
    ) -> None:
        """Send a notification for a specific token transaction."""
        try:
            # Format the message using token-specific configuration
            message = self._format_token_message(tx, token_config)

            # Only send the message if it was successfully formatted
            if message is not None:
                # Send the message
                await self._bot.send_message(
                    chat_id=user_id,
                    text=message,
                    parse_mode=ParseMode.HTML,
                    disable_web_page_preview=True,
                )
                logging.info(f"Sent notification to user {user_id} for tx {tx['hash']}")

        except Exception as e:
            logging.error(
                f"Error sending notification to user {user_id} for tx {tx.get('hash', 'unknown')}: {e}"
            )
            raise
