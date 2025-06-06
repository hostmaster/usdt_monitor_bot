# notifier.py
import logging
from datetime import datetime, timezone

from aiogram import Bot
from aiogram.enums import ParseMode
from aiogram.utils.markdown import hbold, hcode, hlink

from usdt_monitor_bot.config import BotConfig, TokenConfig

# Constants
ALLOWED_FUTURE_TIME_SECONDS = 3600  # 1 hour in seconds, for clock drift tolerance


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
            # Quick validation of required fields
            if not all([tx_hash, address, token_config]):
                logging.warning(f"Missing required fields for transaction {tx_hash}")
                return None

            # Validate transaction hash
            if not isinstance(tx_hash, str):
                logging.warning(f"Invalid transaction hash: {tx_hash}")
                return None
            if not tx_hash.startswith("0x"):
                logging.warning(f"Transaction hash {tx_hash} must start with '0x'")
                return None

            # Validate address
            if not isinstance(address, str):
                logging.warning(f"Invalid address: {address}")
                return None
            if not address.startswith("0x"):
                logging.warning(f"Address {address} must start with '0x'")
                return None

            # Validate value
            if not isinstance(value, (int, float)):
                logging.warning(
                    f"Invalid value type: {type(value)}, expected int or float"
                )
                return None
            if value < 0:
                logging.warning(f"Negative value not allowed: {value}")
                return None

            # Validate token config
            if not isinstance(token_config, TokenConfig):
                logging.warning(f"Invalid token configuration: {token_config}")
                return None

            # Validate timestamp
            if not isinstance(timestamp, int):
                logging.warning(
                    f"Invalid timestamp type: {type(timestamp)}, expected int"
                )
                return None
            current_time = int(datetime.now(timezone.utc).timestamp())
            if timestamp < 0 or timestamp > current_time + ALLOWED_FUTURE_TIME_SECONDS:
                logging.warning(f"Timestamp {timestamp} is out of valid range")
                return None

            # Format the value with proper error handling
            try:
                formatted_value = format_token_amount(value, token_config.decimals)
                if formatted_value is None:
                    logging.warning(
                        f"Could not format value {value} for transaction {tx_hash}"
                    )
                    return None
            except (ValueError, TypeError) as e:
                logging.warning(
                    f"Error formatting value for transaction {tx_hash}: {e}",
                    exc_info=True,
                )
                return None

            # Format the address with proper error handling
            try:
                address_to_show = format_address(address)
                if not address_to_show:
                    logging.warning(f"Invalid address format for transaction {tx_hash}")
                    return None
            except Exception as e:
                logging.warning(
                    f"Error formatting address for transaction {tx_hash}: {e}",
                    exc_info=True,
                )
                return None

            # Format the timestamp with proper error handling
            try:
                formatted_time = format_timestamp(timestamp)
                if not formatted_time:
                    logging.warning(
                        f"Invalid timestamp {timestamp} for transaction {tx_hash}"
                    )
                    # Skip returning None here to allow further processing
            except Exception as e:
                logging.warning(
                    f"Error formatting timestamp for transaction {tx_hash}: {e}",
                    exc_info=True,
                )
                return None

            # Determine the direction label
            address_label = "From" if is_incoming else "To"

            # Construct the message with proper error handling
            try:
                message = (
                    f"🔔 New {token_config.symbol} Transfer!\n"
                    f"Amount: {hbold(f'{formatted_value} {token_config.symbol}')}\n"
                    f"{address_label}: {hcode(address_to_show)}\n"
                    f"Time: {formatted_time}\n"
                    f"Tx: {hlink('View on Etherscan', f'{token_config.explorer_url}/tx/{tx_hash}')}"
                )
                return message
            except Exception as e:
                logging.error(
                    f"Error constructing message for transaction {tx_hash}: {e}",
                    exc_info=True,
                )
                return None

        except Exception as e:
            error_msg = f"Unexpected error formatting transaction {tx_hash}: {str(e)}"
            logging.error(error_msg, exc_info=True)
            return None

    async def send_token_notification(
        self,
        user_id: int,
        tx: dict,
        token_type: str,
        monitored_address: str,
    ) -> None:
        """
        Send a notification for a token transaction.

        Args:
            user_id: The Telegram user ID to send the notification to
            tx: The transaction data from Etherscan
            token_type: The token symbol (e.g. 'USDT', 'USDC')
            monitored_address: The address being monitored
        """
        if not tx:
            logging.warning("Received empty transaction data, skipping notification")
            return

        try:
            # Validate user_id
            if not isinstance(user_id, int) or user_id <= 0:
                logging.warning(f"Invalid user_id: {user_id}, skipping notification")
                return

            # Get token configuration
            token_config = self._config.token_registry.get_token(token_type)
            if not token_config:
                logging.error(f"Token configuration not found for {token_type}")
                return

            # Add monitored address to transaction data for message formatting
            tx_data = dict(tx)
            # monitored_address is now a parameter

            # Ensure monitored_address is lowercased for consistent comparison
            monitored_address_lower = monitored_address.lower()

            # Handle self-transfers (when from and to are the same address)
            # Ensure all address comparisons are case-insensitive
            tx_from_lower = tx_data.get("from", "").lower()
            tx_to_lower = tx_data.get("to", "").lower()

            if tx_from_lower == tx_to_lower:
                is_incoming = (
                    False  # Treat self-transfers as outgoing for notification purposes
                )
                logging.info(
                    f"Self-transfer detected for transaction {tx_data.get('hash', 'unknown')}"
                )
            else:
                is_incoming = monitored_address_lower == tx_to_lower

            # Select the address to show based on transaction direction
            address_to_show = tx_data.get("from") if is_incoming else tx_data.get("to")

            # Format the message using token-specific configuration
            message = self._format_token_message(
                tx_data["hash"],
                address_to_show, # This is already correctly selected
                float(tx_data["value"]),
                token_config,
                is_incoming,
                int(tx_data["timeStamp"]),
            )

            # Only send the message if it was successfully formatted
            if message is not None:
                try:
                    # Send the message
                    await self._bot.send_message(
                        chat_id=user_id,
                        text=message,
                        parse_mode=ParseMode.HTML,
                        disable_web_page_preview=True,
                    )
                    logging.info(
                        f"Successfully sent notification to user {user_id} for tx {tx.get('hash', 'unknown')}"
                    )
                except Exception as e:
                    logging.error(
                        f"Failed to send message to user {user_id} for tx {tx.get('hash', 'unknown')}: {e}",
                        exc_info=True,
                    )
            else:
                logging.warning(
                    f"Message formatting failed for tx {tx.get('hash', 'unknown')}, skipping notification"
                )

        except Exception as e:
            logging.error(
                f"Unexpected error sending notification to user {user_id} for tx {tx.get('hash', 'unknown')}: {e}",
                exc_info=True,
            )


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
