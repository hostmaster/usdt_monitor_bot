# notifier.py
import logging
from datetime import datetime

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
        self,
        tx_hash: str,
        address: str,
        value: float,
        token_config: TokenConfig,
        is_incoming: bool,
        timestamp: int,
    ) -> str:
        """Format a token transaction notification message.

        Args:
            tx_hash: The transaction hash
            address: The address to display (sender for incoming, recipient for outgoing)
            value: The transaction amount as a float
            token_config: Configuration for the token type (USDT, USDC, etc.)
            is_incoming: True if this is an incoming transaction, False if outgoing
            timestamp: Unix timestamp of the transaction

        Returns:
            str: Formatted HTML message for Telegram notification, or None if formatting fails
        """
        try:
            formatted_value = format_token_amount(value, token_config.decimals)
            address_to_show = format_address(address)
            formatted_time = format_timestamp(timestamp)

            if not all([formatted_value, address_to_show, formatted_time]):
                return None

            address_label = "From" if is_incoming else "To"

            message = (
                f"🔔 New {token_config.symbol} Transfer!\n"
                f"Amount: {hbold(f'{formatted_value} {token_config.symbol}')}\n"
                f"{address_label}: {hcode(address_to_show)}\n"
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

            # Add monitored address to transaction data for message formatting
            tx_data = dict(tx)
            monitored_address = tx_data.get("monitored_address")

            # Handle self-transfers (when from and to are the same address)
            if tx_data.get("from") == tx_data.get("to"):
                is_incoming = (
                    False  # Treat self-transfers as outgoing for notification purposes
                )
            else:
                is_incoming = monitored_address == tx_data.get("to")

            # Select the address to show based on transaction direction
            address_to_show = tx_data.get("from") if is_incoming else tx_data.get("to")

            # Format the message using token-specific configuration
            message = self._format_token_message(
                tx_data["hash"],
                address_to_show,
                float(tx_data["value"]),
                token_config,
                is_incoming,
                int(tx_data["timeStamp"]),
            )

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
            message = self._format_token_message(
                tx["hash"],
                tx["monitored_address"],
                float(tx["value"]),
                token_config,
                tx["monitored_address"] == tx["from"],
                int(tx["timeStamp"]),
            )

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


def format_token_amount(value: float, decimals: int = 6) -> str:
    """Format token amount with 2 decimal places, considering token decimals."""
    try:
        actual_value = float(value) / (10**decimals)
        return f"{actual_value:.2f}"
    except (ValueError, TypeError):
        return None


def format_address(address: str) -> str:
    """Format address for display."""
    if not address:
        return None
    return address  # Show full address


def format_timestamp(timestamp: int) -> str:
    """Format timestamp as human-readable date."""
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None
