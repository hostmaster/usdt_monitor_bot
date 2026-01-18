"""
Notification service module.

Handles formatting and sending Telegram notifications for token transactions,
including spam risk warnings.
"""

# Standard library
import logging
from datetime import datetime, timezone
from typing import Optional

# Third-party
from aiogram import Bot
from aiogram.enums import ParseMode
from aiogram.utils.markdown import hbold, hcode, hlink

# Local
from usdt_monitor_bot.config import BotConfig, TokenConfig
from usdt_monitor_bot.spam_detector import RiskAnalysis

# Constants
ALLOWED_FUTURE_TIME_SECONDS = 3600  # 1 hour in seconds, for clock drift tolerance


class NotificationService:
    """Handles formatting and sending notifications via Telegram."""

    def __init__(self, bot: Bot, config: BotConfig):
        self._bot = bot
        self._config = config
        logging.debug("NotificationService initialized")

    def _format_token_message(
        self,
        tx_hash: str,
        address: str,
        value: float,
        token_config: TokenConfig,
        is_incoming: bool,
        timestamp: int,
        risk_analysis: Optional[RiskAnalysis] = None,
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
                logging.debug(f"Missing fields for tx {tx_hash}")
                return None

            # Validate transaction hash
            if not isinstance(tx_hash, str) or not tx_hash.startswith("0x"):
                logging.debug(f"Invalid tx hash: {tx_hash}")
                return None

            # Validate address
            if not isinstance(address, str) or not address.startswith("0x"):
                logging.debug(f"Invalid address: {address}")
                return None

            # Validate value
            if not isinstance(value, (int, float)) or value < 0:
                logging.debug(f"Invalid value: {value}")
                return None

            # Validate token config
            if not isinstance(token_config, TokenConfig):
                logging.debug(f"Invalid token config: {token_config}")
                return None

            # Validate timestamp
            current_time = int(datetime.now(timezone.utc).timestamp())
            if not isinstance(timestamp, int) or timestamp < 0 or timestamp > current_time + ALLOWED_FUTURE_TIME_SECONDS:
                logging.debug(f"Invalid timestamp: {timestamp}")
                return None

            # Format the value
            try:
                formatted_value = format_token_amount(value, token_config.decimals)
                if formatted_value is None:
                    logging.debug(f"Value format failed: {value}")
                    return None
            except (ValueError, TypeError) as e:
                logging.debug(f"Value format error: {e}")
                return None

            # Format the address
            try:
                address_to_show = format_address(address)
                if not address_to_show:
                    logging.debug(f"Address format failed: {address}")
                    return None
            except Exception as e:
                logging.debug(f"Address format error: {e}")
                return None

            # Format the timestamp
            try:
                formatted_time = format_timestamp(timestamp)
                if not formatted_time:
                    logging.debug(f"Timestamp format failed: {timestamp}")
            except Exception as e:
                logging.debug(f"Timestamp format error: {e}")
                return None

            # For spam transactions, send a short notice instead of full details
            if risk_analysis and risk_analysis.is_suspicious:
                try:
                    main_flag = risk_analysis.flags[0].value if risk_analysis.flags else "Suspicious"
                    message = (
                        f"⚠️ {hbold('Spam Detected')}\n"
                        f"From: {hcode(address_to_show)}\n"
                        f"Amount: {formatted_value} {token_config.symbol}\n"
                        f"Risk: {risk_analysis.score}/100 ({main_flag})\n"
                        f"Tx: {hlink('View', f'{token_config.explorer_url}/tx/{tx_hash}')}"
                    )
                    return message
                except Exception as e:
                    logging.debug(f"Spam notice build error: {e}")
                    return None

            # Normal transaction - full details
            # Determine the direction label
            address_label = "From" if is_incoming else "To"

            # Construct the message
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
                logging.debug(f"Message build error: {e}")
                return None

        except Exception as e:
            logging.debug(f"Format tx error {tx_hash[:16]}: {e}")
            return None

    async def send_token_notification(
        self,
        user_id: int,
        tx: dict,
        token_type: str,
        monitored_address: str,
        risk_analysis: Optional[RiskAnalysis] = None,
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
            logging.debug("Empty tx data, skip notification")
            return

        try:
            # Validate user_id
            if not isinstance(user_id, int) or user_id <= 0:
                logging.debug(f"Invalid user_id: {user_id}")
                return

            # Get token configuration
            token_config = self._config.token_registry.get_token(token_type)
            if not token_config:
                logging.debug(f"Unknown token: {token_type}")
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
                is_incoming = False  # Treat self-transfers as outgoing
                logging.debug(f"Self-transfer: {tx_data.get('hash', 'N/A')[:16]}...")
            else:
                is_incoming = monitored_address_lower == tx_to_lower

            # Select the address to show based on transaction direction
            address_to_show = tx_data.get("from") if is_incoming else tx_data.get("to")

            # Format the message using token-specific configuration
            message = self._format_token_message(
                tx_data["hash"],
                address_to_show,  # This is already correctly selected
                float(tx_data["value"]),
                token_config,
                is_incoming,
                int(tx_data["timeStamp"]),
                risk_analysis,
            )

            # Only send the message if it was successfully formatted
            if message is not None:
                try:
                    await self._bot.send_message(
                        chat_id=user_id,
                        text=message,
                        parse_mode=ParseMode.HTML,
                        disable_web_page_preview=True,
                    )
                    logging.info(f"Notify user={user_id} tx={tx.get('hash', 'N/A')[:16]}...")
                except Exception as e:
                    logging.error(f"Send failed user={user_id}: {e}")
            else:
                logging.debug(f"Format failed, skip notify for tx={tx.get('hash', 'N/A')[:16]}")

        except Exception as e:
            logging.error(f"Notify error user={user_id}: {e}")


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
