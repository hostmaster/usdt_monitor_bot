"""
Transaction checker module.

Periodically checks for new token transactions for monitored addresses
and performs spam detection analysis.
"""

# Standard library
import asyncio
import json
import logging
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import List, Optional

# Third-party
import aiohttp

# Local
from usdt_monitor_bot.config import BotConfig
from usdt_monitor_bot.database import DatabaseManager
from usdt_monitor_bot.etherscan import (
    EtherscanClient,
    EtherscanError,
    EtherscanRateLimitError,
)
from usdt_monitor_bot.notifier import NotificationService
from usdt_monitor_bot.spam_detector import (
    RiskAnalysis,
    SpamDetector,
    TransactionMetadata,
)


@dataclass
class BlockDeterminationResult:
    """Result of determining the next block number to check."""

    final_block_number: int
    """The final block number to use for the next check."""

    resetting_to_latest: bool
    """Whether the block was reset/capped to sync with the blockchain."""


class TransactionChecker:
    """Periodically checks for new token transactions for monitored addresses."""

    def __init__(
        self,
        config: BotConfig,
        db_manager: DatabaseManager,
        etherscan_client: EtherscanClient,
        notifier: NotificationService,
        spam_detector: Optional[SpamDetector] = None,
    ):
        self._config = config
        self._db = db_manager
        self._etherscan = etherscan_client
        self._notifier = notifier
        # Initialize spam detector (optional, can be disabled by passing None explicitly)
        self._spam_detector = (
            spam_detector if spam_detector is not None else SpamDetector()
        )
        self._spam_detection_enabled = True  # Enable by default
        # Cache for contract creation blocks to avoid repeated API calls
        self._contract_creation_cache: dict[str, Optional[int]] = {}
        logging.info("TransactionChecker initialized.")

    def _handle_etherscan_error(
        self, error: Exception, token_symbol: str, address_lower: str
    ) -> None:
        """Handle Etherscan API errors with appropriate logging."""
        if isinstance(error, EtherscanRateLimitError):
            logging.warning(
                f"Rate limited while fetching {token_symbol} for {address_lower}. "
                "Some transactions may be missed in this cycle."
            )
        elif isinstance(error, EtherscanError):
            error_msg = str(error)
            # Skip logging for "No transactions found" - expected for inactive addresses
            if "No transactions found" in error_msg:
                return

            if "NOTOK" in error_msg:
                logging.warning(
                    f"Error checking {token_symbol} transactions for {address_lower}: {error_msg}. "
                    "This may indicate a query timeout or API issue. The address will be retried in the next cycle."
                )
            else:
                logging.error(
                    f"Error checking {token_symbol} transactions for {address_lower}: {error_msg}"
                )
        else:
            # Unexpected error
            logging.error(
                f"Unexpected error fetching {token_symbol} for {address_lower}: {error}",
                exc_info=True,
            )

    async def _fetch_transactions_for_address(
        self, address_lower: str, query_start_block: int
    ) -> list[dict]:
        """
        Fetch all token transactions for a single address from a specific block.

        Args:
            address_lower: The Ethereum address to check (lowercase)
            query_start_block: The block number to start checking from

        Returns:
            List of transaction dictionaries from Etherscan API
        """
        all_transactions = []
        logging.debug(
            f"Fetching transactions for {address_lower} from block {query_start_block}"
        )

        for token in self._config.token_registry.get_all_tokens().values():
            try:
                await asyncio.sleep(self._config.etherscan_request_delay / 2 or 0.1)

                transactions = await self._etherscan.get_token_transactions(
                    token.contract_address,
                    address_lower,
                    start_block=query_start_block,
                )
                for tx in transactions:
                    tx["token_symbol"] = token.symbol
                all_transactions.extend(transactions)
            except Exception as e:
                self._handle_etherscan_error(e, token.symbol, address_lower)

        return all_transactions

    def _filter_transactions(
        self, all_transactions: List[dict], start_block: int
    ) -> List[dict]:
        """
        Filter transactions by block, age, and limit the count.

        Args:
            all_transactions: List of all transactions to filter
            start_block: Block number to filter from (exclusive)

        Returns:
            Filtered and sorted list of transactions ready for processing
        """
        current_time = datetime.now(timezone.utc)
        max_age_seconds = self._config.max_transaction_age_days * 24 * 60 * 60

        filtered = []
        for tx in all_transactions:
            try:
                if int(tx.get("blockNumber", 0)) <= start_block:
                    continue

                age_seconds = (
                    current_time
                    - datetime.fromtimestamp(
                        int(tx.get("timeStamp", 0)), tz=timezone.utc
                    )
                ).total_seconds()

                if age_seconds > max_age_seconds:
                    logging.debug(f"Skipping transaction {tx.get('hash')} due to age.")
                    continue

                filtered.append(tx)
            except (ValueError, TypeError) as e:
                logging.warning(
                    f"Invalid data in transaction {tx.get('hash', 'unknown')}: {e}. Skipping."
                )

        # Sort by block number descending to get the newest transactions first
        filtered.sort(key=lambda x: int(x.get("blockNumber", 0)), reverse=True)

        # Limit the number of transactions and then sort them chronologically for processing
        processing_batch = filtered[: self._config.max_transactions_per_check]
        processing_batch.sort(key=lambda x: int(x.get("blockNumber", 0)))

        return processing_batch

    def _convert_to_transaction_metadata(
        self, tx: dict, token_decimals: int
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
                logging.warning(
                    f"Missing required fields in transaction: {tx.get('hash', 'unknown')}"
                )
                return None

            # Convert timestamp
            try:
                timestamp = datetime.fromtimestamp(int(timestamp_str), tz=timezone.utc)
            except (ValueError, TypeError) as e:
                logging.warning(
                    f"Invalid timestamp {timestamp_str} for tx {tx_hash}: {e}"
                )
                return None

            # Convert value from token units to USDT (divide by 10^decimals)
            try:
                value_raw = Decimal(value_str)
                value_usdt = value_raw / Decimal(10**token_decimals)
            except (ValueError, TypeError) as e:
                logging.warning(f"Invalid value {value_str} for tx {tx_hash}: {e}")
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
            logging.error(
                f"Error converting transaction to metadata: {e}",
                exc_info=True,
            )
            return None

    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
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
            logging.warning(f"Invalid timestamp format in DB: {timestamp_str}")
            return None

    def _convert_db_transaction_to_metadata(
        self, db_tx: dict
    ) -> Optional[TransactionMetadata]:
        """
        Convert database transaction dict to TransactionMetadata.

        Args:
            db_tx: Transaction dictionary from database

        Returns:
            TransactionMetadata or None if conversion fails
        """
        timestamp = self._parse_timestamp(db_tx.get("timestamp", ""))
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
            logging.warning(
                f"Error converting DB transaction to metadata: {e}",
                exc_info=True,
            )
            return None

    async def _get_historical_transactions_metadata(
        self, address_lower: str, limit: int = 20
    ) -> List[TransactionMetadata]:
        """
        Get historical transactions from database and convert to TransactionMetadata.

        Args:
            address_lower: The monitored address (lowercase)
            limit: Maximum number of historical transactions to retrieve (default: 20)

        Returns:
            List of TransactionMetadata objects, empty list on error
        """
        try:
            db_transactions = await self._db.get_recent_transactions(
                address_lower, limit
            )
            historical_metadata = []

            for db_tx in db_transactions:
                metadata = self._convert_db_transaction_to_metadata(db_tx)
                if metadata:
                    historical_metadata.append(metadata)

            return historical_metadata
        except Exception as e:
            logging.error(
                f"Error retrieving historical transactions for {address_lower}: {e}",
                exc_info=True,
            )
            return []

    async def _get_contract_age_blocks(self, address: str, current_block: int) -> int:
        """
        Get the age of a contract in blocks.

        Uses cached contract creation blocks to avoid repeated API calls.
        Returns 0 for non-contract addresses or if unable to determine.

        Args:
            address: The contract address to check
            current_block: The current block number

        Returns:
            Age in blocks, or 0 if unable to determine (not a contract or error)
        """
        address_lower = address.lower()

        # Check cache first
        if address_lower in self._contract_creation_cache:
            creation_block = self._contract_creation_cache[address_lower]
            if creation_block is not None:
                return max(0, current_block - creation_block)
            return 0  # Cached as None (not a contract or error)

        # Fetch from Etherscan (with error handling)
        try:
            creation_block = await self._etherscan.get_contract_creation_block(
                address_lower
            )
            # Cache the result (even if None)
            self._contract_creation_cache[address_lower] = creation_block

            if creation_block is not None:
                return max(0, current_block - creation_block)
        except Exception as e:
            logging.warning(
                f"Error getting contract age for {address_lower}: {e}",
                exc_info=True,
            )
            # Cache None to avoid repeated failed calls
            self._contract_creation_cache[address_lower] = None

        return 0  # Default to 0 if unable to determine

    async def _enrich_transaction_metadata(
        self,
        tx_metadata: TransactionMetadata,
        address_lower: str,
        historical_metadata: List[TransactionMetadata],
    ) -> RiskAnalysis:
        """
        Enrich transaction metadata with spam detection data and perform risk analysis.

        Args:
            tx_metadata: Transaction metadata to enrich
            address_lower: The monitored address
            historical_metadata: Historical transactions for context

        Returns:
            RiskAnalysis object
        """
        # Check if sender is new
        is_new_sender = await self._db.is_new_sender_address(
            address_lower, tx_metadata.from_address
        )
        tx_metadata.is_new_address = is_new_sender

        # Get contract age (with caching)
        contract_age = await self._get_contract_age_blocks(
            tx_metadata.from_address, tx_metadata.block_number
        )
        tx_metadata.contract_age_blocks = contract_age

        # Build whitelist: monitored address + official token contract addresses
        whitelisted_addresses = {
            address_lower
        }  # Whitelist the monitored address itself
        # Add all official token contract addresses to whitelist
        for token in self._config.token_registry.get_all_tokens().values():
            whitelisted_addresses.add(token.contract_address)

        # Analyze transaction with whitelist
        risk_analysis = self._spam_detector.analyze_transaction(
            tx_metadata,
            historical_metadata,
            whitelisted_addresses=whitelisted_addresses,
        )

        if risk_analysis.is_suspicious:
            logging.warning(
                f"Suspicious transaction detected: {tx_metadata.tx_hash} "
                f"(score: {risk_analysis.score}/100, flags: {[f.value for f in risk_analysis.flags]})"
            )

        return risk_analysis

    async def _store_transaction_safely(
        self,
        tx_metadata: TransactionMetadata,
        token_symbol: str,
        address_lower: str,
        risk_score: Optional[int],
    ) -> None:
        """Store transaction in database, logging warnings on failure."""
        try:
            await self._db.store_transaction(
                tx_hash=tx_metadata.tx_hash,
                monitored_address=address_lower,
                from_address=tx_metadata.from_address,
                to_address=tx_metadata.to_address,
                value=float(tx_metadata.value),
                block_number=tx_metadata.block_number,
                timestamp=tx_metadata.timestamp.isoformat(),
                token_symbol=token_symbol,
                risk_score=risk_score,
            )
        except Exception as e:
            logging.warning(
                f"Failed to store transaction {tx_metadata.tx_hash} in database: {e}",
                exc_info=True,
            )

    async def _process_single_transaction(
        self,
        tx: dict,
        user_ids: List[int],
        address_lower: str,
        historical_metadata: List[TransactionMetadata],
    ) -> int:
        """
        Process a single transaction: analyze, store, and notify.

        Args:
            tx: Transaction dictionary
            user_ids: List of user IDs to notify
            address_lower: The monitored address
            historical_metadata: Historical transactions (will be updated)

        Returns:
            Number of notifications sent
        """
        tx_hash = tx.get("hash")
        tx_token_symbol = tx.get("token_symbol")

        if not tx_hash or not tx_token_symbol:
            logging.warning(f"Transaction missing hash or symbol, skipping: {tx}")
            return 0

        # Get token config
        token_config = self._config.token_registry.get_token(tx_token_symbol)
        if not token_config:
            logging.warning(
                f"Token config not found for {tx_token_symbol}, skipping spam detection"
            )

        # Process with spam detection (only if token config is available)
        risk_analysis: Optional[RiskAnalysis] = None
        tx_metadata: Optional[TransactionMetadata] = None

        if token_config and self._spam_detection_enabled:
            tx_metadata = self._convert_to_transaction_metadata(
                tx, token_config.decimals
            )
            if tx_metadata:
                risk_analysis = await self._enrich_transaction_metadata(
                    tx_metadata, address_lower, historical_metadata
                )
                historical_metadata.append(tx_metadata)

        # Store transaction if metadata was created
        if tx_metadata:
            await self._store_transaction_safely(
                tx_metadata,
                tx_token_symbol,
                address_lower,
                risk_analysis.score if risk_analysis else None,
            )

        # Send notifications
        for user_id in user_ids:
            await self._notifier.send_token_notification(
                user_id, tx, tx_token_symbol, address_lower, risk_analysis
            )

        return len(user_ids)

    async def _send_notifications_for_batch(
        self, user_ids: List[int], batch: List[dict], address_lower: str
    ) -> None:
        """
        Send notifications for a batch of transactions with spam detection.

        Args:
            user_ids: List of user IDs to notify
            batch: List of transaction dictionaries to process
            address_lower: The monitored address (lowercase)
        """
        historical_metadata = await self._get_historical_transactions_metadata(
            address_lower, limit=20
        )

        notifications_sent = 0
        for tx in batch:
            try:
                notifications_sent += await self._process_single_transaction(
                    tx, user_ids, address_lower, historical_metadata
                )
            except Exception as e:
                logging.error(
                    f"Unexpected error processing transaction {tx.get('hash', 'N/A')}: {e}",
                    exc_info=True,
                )

        if notifications_sent > 0:
            logging.info(
                f"Sent {notifications_sent} notifications for {address_lower}."
            )

    async def _process_address_transactions(
        self,
        address_lower: str,
        all_transactions: list[dict],
        start_block: int,
        latest_block: Optional[int] = None,
    ) -> tuple[int, int]:
        """
        Orchestrate filtering, notification, and determine the max block to update to.

        Args:
            address_lower: The monitored address (lowercase)
            all_transactions: All transactions fetched from Etherscan
            start_block: The starting block number

        Returns:
            Tuple of (highest_block_number, processed_transaction_count)
        """
        # #region agent log
        try:
            print(
                json.dumps(
                    {
                        "sessionId": "debug-session",
                        "runId": "run1",
                        "hypothesisId": "A",
                        "location": "checker.py:553",
                        "message": "_process_address_transactions entry",
                        "data": {
                            "address": address_lower,
                            "start_block": start_block,
                            "tx_count": len(all_transactions),
                        },
                        "timestamp": int(time.time() * 1000),
                    }
                ),
                file=sys.stdout,
                flush=True,
            )
        except Exception:  # nosec B110
            pass
        # #endregion
        if not all_transactions:
            # No transactions found - return start_block to indicate we've checked up to this point
            # The caller will update the block number to record the check
            return (start_block, 0)

        # Always update to the highest block seen to avoid re-scanning
        # But cap it to latest_block if available to prevent getting ahead of blockchain
        tx_block_numbers = [int(tx.get("blockNumber", 0)) for tx in all_transactions]
        max_seen_block = max(tx_block_numbers) if tx_block_numbers else 0
        if latest_block is not None and max_seen_block > latest_block:
            logging.debug(
                f"Capping max_seen_block ({max_seen_block}) to latest_block ({latest_block}) "
                f"for {address_lower} to prevent getting ahead of blockchain."
            )
            max_seen_block = latest_block
        # #region agent log
        try:
            print(
                json.dumps(
                    {
                        "sessionId": "debug-session",
                        "runId": "run1",
                        "hypothesisId": "A",
                        "location": "checker.py:559",
                        "message": "max_seen_block calculated",
                        "data": {
                            "address": address_lower,
                            "max_seen_block": max_seen_block,
                            "tx_block_numbers": tx_block_numbers[:10],
                            "start_block": start_block,
                        },
                        "timestamp": int(time.time() * 1000),
                    }
                ),
                file=sys.stdout,
                flush=True,
            )
        except Exception:  # nosec B110
            pass
        # #endregion

        processing_batch = self._filter_transactions(all_transactions, start_block)

        if not processing_batch:
            logging.debug(
                f"No transactions to notify for {address_lower} after filtering."
            )
            return (max(start_block, max_seen_block), 0)

        user_ids = await self._db.get_users_for_address(address_lower)
        if not user_ids:
            logging.warning(
                f"Found {len(processing_batch)} tx(s) for {address_lower}, but no users are tracking it."
            )
            # No users tracking this address, so nothing is actually processed
            processed_count = 0
        else:
            processed_count = len(processing_batch)
            logging.info(f"Processing {processed_count} new tx(s) for {address_lower}")
            await self._send_notifications_for_batch(
                user_ids, processing_batch, address_lower
            )

        new_last_block = max(start_block, max_seen_block)
        # Cap new_last_block to latest_block if available to prevent getting ahead of blockchain
        # This handles the case where start_block is already ahead of latest_block
        if latest_block is not None and new_last_block > latest_block:
            logging.debug(
                f"Capping new_last_block ({new_last_block}) to latest_block ({latest_block}) "
                f"for {address_lower} to prevent getting ahead of blockchain."
            )
            new_last_block = latest_block
        # #region agent log
        try:
            print(
                json.dumps(
                    {
                        "sessionId": "debug-session",
                        "runId": "run1",
                        "hypothesisId": "C",
                        "location": "checker.py:583",
                        "message": "_process_address_transactions exit",
                        "data": {
                            "address": address_lower,
                            "new_last_block": new_last_block,
                            "start_block": start_block,
                            "max_seen_block": max_seen_block,
                            "processed_count": processed_count,
                        },
                        "timestamp": int(time.time() * 1000),
                    }
                ),
                file=sys.stdout,
                flush=True,
            )
        except Exception:  # nosec B110
            pass
        # #endregion
        return (new_last_block, processed_count)

    def _handle_latest_block_unavailable(
        self,
        start_block: int,
        new_last_block: int,
        raw_transactions: List[dict],
        address_lower: str,
    ) -> BlockDeterminationResult:
        """
        Handle case when latest block number cannot be retrieved.

        Args:
            start_block: The starting block number
            new_last_block: The block number from processing
            raw_transactions: List of raw transactions found
            address_lower: The monitored address for logging

        Returns:
            BlockDeterminationResult
        """
        final_block = new_last_block
        # Only advance if no transactions found to prevent getting stuck
        if not raw_transactions and new_last_block == start_block:
            final_block = start_block + 1
            logging.warning(
                f"Could not get latest block number for {address_lower}. "
                f"Advancing from {start_block} to {final_block} to prevent getting stuck."
            )
        return BlockDeterminationResult(
            final_block_number=final_block,
            resetting_to_latest=False,
        )

    def _sync_block_with_blockchain(
        self,
        start_block: int,
        new_last_block: int,
        latest_block: int,
        address_lower: str,
    ) -> tuple[int, bool]:
        """
        Sync block number with actual blockchain state.

        Args:
            start_block: The starting block number
            new_last_block: The block number from processing
            latest_block: The latest block from blockchain
            address_lower: The monitored address for logging

        Returns:
            Tuple of (final_block, resetting_to_latest)
        """
        resetting_to_latest = False

        if latest_block < start_block:
            # Database is ahead of blockchain - reset
            logging.warning(
                f"Latest block ({latest_block}) < start_block ({start_block}) for {address_lower}. "
                f"Database appears ahead of blockchain. Resetting to {latest_block}."
            )
            return latest_block, True

        if new_last_block > latest_block:
            # Processed block is ahead - cap it
            # This can happen if Etherscan returns transactions with block numbers ahead of current latest_block
            # (e.g., due to timing, reorgs, or API inconsistencies)
            logging.warning(
                f"Processed block ({new_last_block}) > latest block ({latest_block}) for {address_lower}. "
                f"Capping to {latest_block} to prevent getting ahead of blockchain."
            )
            return latest_block, True

        return new_last_block, resetting_to_latest

    async def _determine_next_block(
        self,
        start_block: int,
        new_last_block: int,
        raw_transactions: List[dict],
        address_lower: str,
        latest_block: Optional[int] = None,
    ) -> BlockDeterminationResult:
        """
        Determine the next block number to check, verifying against actual blockchain.

        Args:
            start_block: The starting block number from the database
            new_last_block: The block number determined from processing transactions
            raw_transactions: List of raw transactions found (empty if none)
            address_lower: The monitored address (lowercase) for logging

        Returns:
            BlockDeterminationResult with final_block_number and resetting_to_latest flag
        """
        # #region agent log
        try:
            print(
                json.dumps(
                    {
                        "sessionId": "debug-session",
                        "runId": "run1",
                        "hypothesisId": "B",
                        "location": "checker.py:675",
                        "message": "_determine_next_block entry",
                        "data": {
                            "address": address_lower,
                            "start_block": start_block,
                            "new_last_block": new_last_block,
                            "tx_count": len(raw_transactions),
                        },
                        "timestamp": int(time.time() * 1000),
                    }
                ),
                file=sys.stdout,
                flush=True,
            )
        except Exception:  # nosec B110
            pass
        # #endregion
        # Fetch latest block if not provided (for backward compatibility)
        if latest_block is None:
            latest_block = await self._etherscan.get_latest_block_number()
        # #region agent log
        try:
            print(
                json.dumps(
                    {
                        "sessionId": "debug-session",
                        "runId": "run1",
                        "hypothesisId": "B",
                        "location": "checker.py:675",
                        "message": "latest_block fetched",
                        "data": {
                            "address": address_lower,
                            "latest_block": latest_block,
                            "start_block": start_block,
                            "new_last_block": new_last_block,
                        },
                        "timestamp": int(time.time() * 1000),
                    }
                ),
                file=sys.stdout,
                flush=True,
            )
        except Exception:  # nosec B110
            pass
        # #endregion

        # Handle case when latest block cannot be retrieved
        if latest_block is None:
            return self._handle_latest_block_unavailable(
                start_block, new_last_block, raw_transactions, address_lower
            )

        # Sync with blockchain
        final_block, resetting_to_latest = self._sync_block_with_blockchain(
            start_block, new_last_block, latest_block, address_lower
        )
        # #region agent log
        try:
            print(
                json.dumps(
                    {
                        "sessionId": "debug-session",
                        "runId": "run1",
                        "hypothesisId": "D",
                        "location": "checker.py:684",
                        "message": "after sync_block_with_blockchain",
                        "data": {
                            "address": address_lower,
                            "final_block": final_block,
                            "resetting_to_latest": resetting_to_latest,
                            "start_block": start_block,
                            "new_last_block": new_last_block,
                            "latest_block": latest_block,
                        },
                        "timestamp": int(time.time() * 1000),
                    }
                ),
                file=sys.stdout,
                flush=True,
            )
        except Exception:  # nosec B110
            pass
        # #endregion

        # If no transactions found and blockchain hasn't advanced, update to latest
        # BUT only if latest_block >= start_block to prevent getting ahead of blockchain
        if not raw_transactions and final_block == start_block:
            if latest_block > start_block:
                logging.debug(
                    f"Advancing block for {address_lower} from {start_block} to {latest_block}"
                )
                final_block = latest_block
            elif latest_block == start_block:
                logging.debug(
                    f"Blockchain hasn't advanced for {address_lower}. "
                    f"Updating to {latest_block} to record check."
                )
                final_block = latest_block
            # If latest_block < start_block, the sync already handled it (reset to latest_block)
            # so we don't need to do anything here

        return BlockDeterminationResult(
            final_block_number=final_block,
            resetting_to_latest=resetting_to_latest,
        )

    async def _process_single_address(
        self,
        address_lower: str,
        stats: dict,
        update_tasks: list,
    ) -> None:
        """
        Process a single address: fetch, analyze, and update block number.

        Args:
            address_lower: The address to process (lowercase)
            stats: Dictionary to update with statistics
            update_tasks: List to append block update tasks
        """
        try:
            await asyncio.sleep(self._config.etherscan_request_delay)
            start_block = await self._db.get_last_checked_block(address_lower)
            # #region agent log
            try:
                print(
                    json.dumps(
                        {
                            "sessionId": "debug-session",
                            "runId": "run1",
                            "hypothesisId": "D",
                            "location": "checker.py:722",
                            "message": "start_block from DB",
                            "data": {
                                "address": address_lower,
                                "start_block": start_block,
                            },
                            "timestamp": int(time.time() * 1000),
                        }
                    ),
                    file=sys.stdout,
                    flush=True,
                )
            except Exception:  # nosec B110
                pass
            # #endregion

            logging.debug(f"Checking {address_lower} from block {start_block + 1}")

            # Fetch latest block early to cap transaction block numbers and prevent getting ahead
            latest_block = await self._etherscan.get_latest_block_number()
            if latest_block is None:
                logging.warning(
                    f"Could not fetch latest block for {address_lower}. Proceeding without cap."
                )
                latest_block = None  # Will be handled in _determine_next_block

            raw_transactions = await self._fetch_transactions_for_address(
                address_lower, start_block + 1
            )
            # #region agent log
            try:
                tx_blocks = (
                    [int(tx.get("blockNumber", 0)) for tx in raw_transactions]
                    if raw_transactions
                    else []
                )
                print(
                    json.dumps(
                        {
                            "sessionId": "debug-session",
                            "runId": "run1",
                            "hypothesisId": "A",
                            "location": "checker.py:726",
                            "message": "transactions fetched",
                            "data": {
                                "address": address_lower,
                                "tx_count": len(raw_transactions),
                                "tx_block_numbers": tx_blocks[:10],
                                "fetch_from_block": start_block + 1,
                            },
                            "timestamp": int(time.time() * 1000),
                        }
                    ),
                    file=sys.stdout,
                    flush=True,
                )
            except Exception:  # nosec B110
                pass
            # #endregion

            stats["total_transactions_found"] += len(raw_transactions)
            if raw_transactions:
                stats["addresses_with_transactions"] += 1

            new_last_block, processed_count = await self._process_address_transactions(
                address_lower, raw_transactions, start_block, latest_block
            )
            stats["total_transactions_processed"] += processed_count

            # Determine next block and update if needed
            block_result = await self._determine_next_block(
                start_block,
                new_last_block,
                raw_transactions,
                address_lower,
                latest_block,
            )

            if self._should_update_block(start_block, block_result):
                self._log_block_update(address_lower, start_block, block_result)
                # #region agent log
                try:
                    print(
                        json.dumps(
                            {
                                "sessionId": "debug-session",
                                "runId": "run1",
                                "hypothesisId": "D",
                                "location": "checker.py:744",
                                "message": "updating DB block",
                                "data": {
                                    "address": address_lower,
                                    "old_block": start_block,
                                    "new_block": block_result.final_block_number,
                                    "resetting": block_result.resetting_to_latest,
                                },
                                "timestamp": int(time.time() * 1000),
                            }
                        ),
                        file=sys.stdout,
                        flush=True,
                    )
                except Exception:  # nosec B110
                    pass
                # #endregion
                update_tasks.append(
                    self._db.update_last_checked_block(
                        address_lower, block_result.final_block_number
                    )
                )
                stats["addresses_updated"] += 1

        except EtherscanRateLimitError:
            logging.warning(f"Rate limit for {address_lower}. Skipping this cycle.")
            stats["warnings_count"] += 1
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.error(f"Network error for {address_lower}: {e}. Skipping.")
            stats["errors_count"] += 1
        except Exception as e:
            logging.error(
                f"Critical error processing {address_lower}: {e}",
                exc_info=True,
            )
            stats["errors_count"] += 1

    def _should_update_block(
        self, start_block: int, block_result: BlockDeterminationResult
    ) -> bool:
        """Check if block number should be updated."""
        return (
            block_result.final_block_number >= start_block
            or block_result.resetting_to_latest
        )

    def _log_block_update(
        self,
        address_lower: str,
        start_block: int,
        block_result: BlockDeterminationResult,
    ) -> None:
        """Log block update with appropriate level."""
        new_block = block_result.final_block_number
        if block_result.resetting_to_latest:
            logging.info(
                f"Resetting block for {address_lower} from {start_block} to {new_block} to sync with blockchain"
            )
        elif new_block > start_block:
            logging.debug(
                f"Updating block for {address_lower} from {start_block} to {new_block}"
            )
        else:
            logging.debug(
                f"Recording check for {address_lower} at block {start_block} (no new transactions, no advancement)"
            )

    def _log_cycle_summary(
        self, stats: dict, cycle_duration: float, address_count: int
    ) -> None:
        """Log cycle summary and detailed statistics."""
        summary_parts = []
        if stats["total_transactions_processed"] > 0:
            summary_parts.append(
                f"processed {stats['total_transactions_processed']} new transaction(s)"
            )
        if stats["errors_count"] > 0:
            summary_parts.append(f"{stats['errors_count']} error(s)")
        if stats["warnings_count"] > 0:
            summary_parts.append(f"{stats['warnings_count']} warning(s)")

        if summary_parts:
            logging.info(
                f"Transaction check cycle complete: {', '.join(summary_parts)} in {cycle_duration:.2f}s"
            )
        else:
            logging.info(f"Transaction check cycle complete in {cycle_duration:.2f}s")

        logging.debug(
            f"Cycle statistics: checked {address_count} address(es), "
            f"found {stats['total_transactions_found']} transaction(s), "
            f"processed {stats['total_transactions_processed']} new transaction(s) "
            f"from {stats['addresses_with_transactions']} address(es), "
            f"updated {stats['addresses_updated']} address(es), "
            f"{stats['errors_count']} error(s), {stats['warnings_count']} warning(s)"
        )

    async def check_all_addresses(self) -> None:
        """
        Main entry point: check all tracked addresses for new transactions.

        Fetches all monitored addresses from the database and processes
        transactions for each address, updating block numbers and sending
        notifications as needed.
        """
        cycle_start_time = time.time()
        addresses_to_check = await self._db.get_distinct_addresses()

        if not addresses_to_check:
            logging.info("Transaction check cycle: No addresses to monitor.")
            return

        logging.info("Starting transaction check cycle...")
        logging.debug(
            f"Checking {len(addresses_to_check)} address(es) for new transactions"
        )

        stats = {
            "total_transactions_found": 0,
            "total_transactions_processed": 0,
            "addresses_with_transactions": 0,
            "addresses_updated": 0,
            "errors_count": 0,
            "warnings_count": 0,
        }
        update_tasks = []

        for address in addresses_to_check:
            await self._process_single_address(address.lower(), stats, update_tasks)

        if update_tasks:
            logging.debug(
                f"Updating last checked blocks for {len(update_tasks)} addresses..."
            )
            await asyncio.gather(*update_tasks, return_exceptions=True)

        cycle_duration = time.time() - cycle_start_time
        self._log_cycle_summary(stats, cycle_duration, len(addresses_to_check))
