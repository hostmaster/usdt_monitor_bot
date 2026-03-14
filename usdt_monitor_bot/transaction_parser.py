"""Pure parsing and conversion functions for transaction data."""

import logging
from datetime import datetime, timezone
from decimal import Decimal
from typing import List, Optional

from usdt_monitor_bot.spam_detector_models import RiskAnalysis, TransactionMetadata

# Must match _MAX_VALID_BLOCK_NUMBER in etherscan.py
_MAX_VALID_BLOCK_NUMBER = 10**9


def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Parse timestamp from database format (ISO or Unix).

    Args:
        timestamp_str: Timestamp string from database

    Returns:
        Parsed datetime or None if invalid
    """
    try:
        if "T" in timestamp_str or "+" in timestamp_str:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        return datetime.fromtimestamp(float(timestamp_str), tz=timezone.utc)
    except (ValueError, TypeError):
        logging.debug(f"Invalid DB timestamp: {timestamp_str}")
        return None


def convert_to_transaction_metadata(
    tx: dict, token_decimals: int
) -> Optional[TransactionMetadata]:
    """
    Convert Etherscan transaction dict to TransactionMetadata.

    Args:
        tx: Transaction dictionary from Etherscan API
        token_decimals: Number of decimals for the token (e.g., 6 for USDT)

    Returns:
        TransactionMetadata object or None if conversion fails
    """
    try:
        tx_hash = tx.get("hash")
        from_address = tx.get("from", "")
        to_address = tx.get("to", "")
        block_number = int(tx.get("blockNumber", 0))
        timestamp_str = tx.get("timeStamp", "0")
        value_str = tx.get("value", "0")

        if not tx_hash or not from_address or not to_address:
            logging.debug(f"Missing fields in tx: {tx.get('hash', 'N/A')[:16]}")
            return None

        # Convert timestamp
        try:
            timestamp = datetime.fromtimestamp(int(timestamp_str), tz=timezone.utc)
        except (ValueError, TypeError) as e:
            logging.debug(f"Invalid timestamp in tx {tx_hash[:16]}: {e}")
            return None

        # Convert value from token units to USDT (divide by 10^decimals)
        try:
            value_raw = Decimal(value_str)
            value_usdt = value_raw / Decimal(10**token_decimals)
        except (ValueError, TypeError) as e:
            logging.debug(f"Invalid value in tx {tx_hash[:16]}: {e}")
            return None

        return TransactionMetadata(
            tx_hash=tx_hash,
            from_address=from_address,
            to_address=to_address,
            value=value_usdt,
            block_number=block_number,
            timestamp=timestamp,
            is_new_address=False,  # Set by caller after database check
            contract_age_blocks=0,  # Set by caller after Etherscan query
            gas_price=0,  # Not available in token transfer API
        )
    except Exception as e:
        logging.debug(f"Metadata conversion error: {e}", exc_info=True)
        return None


def convert_db_transaction_to_metadata(
    db_tx: dict,
) -> Optional[TransactionMetadata]:
    """
    Convert database transaction dict to TransactionMetadata.

    Args:
        db_tx: Transaction dictionary from database

    Returns:
        TransactionMetadata or None if conversion fails
    """
    timestamp = parse_timestamp(db_tx.get("timestamp", ""))
    if timestamp is None:
        return None

    try:
        return TransactionMetadata(
            tx_hash=db_tx.get("tx_hash", ""),
            from_address=db_tx.get("from_address", ""),
            to_address=db_tx.get("to_address", ""),
            value=Decimal(str(db_tx.get("value", 0))),
            block_number=db_tx.get("block_number", 0),
            timestamp=timestamp,
            is_new_address=False,  # Will be determined separately
            contract_age_blocks=0,  # Not stored in DB
            gas_price=0,
        )
    except Exception as e:
        logging.debug(f"DB tx conversion error: {e}", exc_info=True)
        return None


def filter_transactions(
    all_transactions: List[dict],
    start_block: int,
    max_age_days: int,
    max_per_check: int,
) -> List[dict]:
    """
    Filter transactions by block, age, and limit the count.

    Args:
        all_transactions: List of all transactions to filter
        start_block: Block number to filter from (exclusive)
        max_age_days: Maximum transaction age in days
        max_per_check: Maximum number of transactions to return

    Returns:
        Filtered and sorted list of transactions ready for processing
    """
    current_time = datetime.now(timezone.utc)
    max_age_seconds = max_age_days * 24 * 60 * 60

    filtered = []
    for tx in all_transactions:
        try:
            block_num = int(tx.get("blockNumber", 0))
            if not (0 < block_num <= _MAX_VALID_BLOCK_NUMBER):
                logging.warning(f"Block number out of range ({block_num}), skipping tx {tx.get('hash', 'N/A')[:16]}")
                continue
            if block_num <= start_block:
                continue

            age_seconds = (
                current_time
                - datetime.fromtimestamp(
                    int(tx.get("timeStamp", 0)), tz=timezone.utc
                )
            ).total_seconds()

            if age_seconds > max_age_seconds:
                logging.debug(f"Skip old tx: {tx.get('hash', '')[:16]}...")
                continue

            filtered.append(tx)
        except (ValueError, TypeError) as e:
            logging.debug(f"Invalid tx data {tx.get('hash', 'N/A')[:16]}: {e}")

    # Sort ascending, then take the last N to get the newest, already in chronological order
    filtered.sort(key=lambda x: int(x.get("blockNumber", 0)))
    return filtered[-max_per_check:] if max_per_check > 0 else []


def format_transaction_log(
    tx_metadata: TransactionMetadata,
    token_symbol: str,
    address_lower: str,
    risk_analysis: RiskAnalysis,
) -> str:
    """
    Format a compact, informative log line for a detected transaction.

    Args:
        tx_metadata: Transaction metadata
        token_symbol: Token symbol (USDT, USDC, etc.)
        address_lower: The monitored address
        risk_analysis: Risk analysis result

    Returns:
        Formatted log string
    """
    # Direction indicator
    is_incoming = tx_metadata.to_address.lower() == address_lower
    direction = "IN" if is_incoming else "OUT"

    # Amount formatting - format Decimal directly to preserve precision
    amount = f"{tx_metadata.value:.2f}"

    # Whitelist status
    is_whitelisted = (risk_analysis.details or {}).get("whitelisted", False)
    whitelist_status = "WL" if is_whitelisted else ""

    # Spam status
    if risk_analysis.is_suspicious:
        spam_status = f"SPAM:{risk_analysis.score}"
    else:
        spam_status = f"OK:{risk_analysis.score}"

    # Build compact log
    parts = [
        f"TX {direction}",
        f"{amount} {token_symbol}",
        f"score={spam_status}",
    ]
    if whitelist_status:
        parts.append(whitelist_status)

    tx_short = tx_metadata.tx_hash[:10]
    return f"[{tx_short}] {' | '.join(parts)}"
