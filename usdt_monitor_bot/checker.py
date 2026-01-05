"""
Transaction checker module.

Periodically checks for new token transactions for monitored addresses
and performs spam detection analysis.
"""

# Standard library
import asyncio
import logging
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
            except EtherscanRateLimitError:
                logging.warning(
                    f"Rate limited while fetching {token.symbol} for {address_lower}. "
                    "Some transactions may be missed in this cycle."
                )
            except EtherscanError as e:
                error_msg = str(e)
                # Skip logging for "No transactions found" as it's expected for addresses without activity
                if "No transactions found" not in error_msg:
                    # For NOTOK errors, provide more context
                    if "NOTOK" in error_msg:
                        logging.warning(
                            f"Error checking {token.symbol} transactions for {address_lower}: {error_msg}. "
                            "This may indicate a query timeout or API issue. The address will be retried in the next cycle."
                        )
                    else:
                        logging.error(
                            f"Error checking {token.symbol} transactions for {address_lower}: {error_msg}"
                        )
            except Exception as e:
                logging.error(
                    f"Unexpected error fetching {token.symbol} for {address_lower}: {e}",
                    exc_info=True,
                )
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

    async def _get_historical_transactions_metadata(
        self, address_lower: str, limit: int = 20
    ) -> List[TransactionMetadata]:
        """
        Get historical transactions from database and convert to TransactionMetadata.

        Retrieves recent transactions from the database for a monitored address
        and converts them to TransactionMetadata objects for spam detection analysis.

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
                try:
                    # Note: Value is already stored in USDT format in database, no conversion needed

                    # Parse timestamp
                    timestamp_str = db_tx.get("timestamp", "")
                    try:
                        # Try parsing ISO format
                        if "T" in timestamp_str or "+" in timestamp_str:
                            timestamp = datetime.fromisoformat(
                                timestamp_str.replace("Z", "+00:00")
                            )
                        else:
                            # Fallback to Unix timestamp
                            timestamp = datetime.fromtimestamp(
                                float(timestamp_str), tz=timezone.utc
                            )
                    except (ValueError, TypeError):
                        logging.warning(
                            f"Invalid timestamp format in DB: {timestamp_str}, skipping transaction"
                        )
                        continue

                    # Convert value back to Decimal (stored as REAL in DB)
                    value_usdt = Decimal(str(db_tx.get("value", 0)))

                    metadata = TransactionMetadata(
                        tx_hash=db_tx.get("tx_hash", ""),
                        from_address=db_tx.get("from_address", ""),
                        to_address=db_tx.get("to_address", ""),
                        value=value_usdt,
                        block_number=db_tx.get("block_number", 0),
                        timestamp=timestamp,
                        is_new_address=False,  # Will be determined separately
                        contract_age_blocks=0,  # Not stored in DB
                        gas_price=0,
                    )
                    historical_metadata.append(metadata)
                except Exception as e:
                    logging.warning(
                        f"Error converting DB transaction to metadata: {e}",
                        exc_info=True,
                    )
                    continue

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

    async def _send_notifications_for_batch(
        self, user_ids: List[int], batch: List[dict], address_lower: str
    ) -> None:
        """
        Send notifications for a batch of transactions with spam detection.

        Processes each transaction in the batch, performs spam detection analysis,
        stores transactions in the database, and sends notifications to users.

        Args:
            user_ids: List of user IDs to notify
            batch: List of transaction dictionaries to process
            address_lower: The monitored address (lowercase)
        """
        notifications_sent = 0

        # Get historical transactions from database
        historical_metadata = await self._get_historical_transactions_metadata(
            address_lower, limit=20
        )

        for tx in batch:
            try:
                tx_hash = tx.get("hash")
                tx_token_symbol = tx.get("token_symbol")
                if not tx_hash or not tx_token_symbol:
                    logging.warning(
                        f"Transaction missing hash or symbol, skipping: {tx}"
                    )
                    continue

                # Get token config for decimals
                token_config = self._config.token_registry.get_token(tx_token_symbol)
                if not token_config:
                    logging.warning(
                        f"Token config not found for {tx_token_symbol}, skipping spam detection"
                    )
                    # Still send notification without spam detection
                    for user_id in user_ids:
                        await self._notifier.send_token_notification(
                            user_id, tx, tx_token_symbol, address_lower
                        )
                        notifications_sent += 1
                    continue

                # Convert to TransactionMetadata for spam detection
                risk_analysis: Optional[RiskAnalysis] = None
                tx_metadata: Optional[TransactionMetadata] = None
                if self._spam_detection_enabled:
                    tx_metadata = self._convert_to_transaction_metadata(
                        tx, token_config.decimals
                    )
                    if tx_metadata:
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

                        # Analyze transaction using historical transactions from database
                        risk_analysis = self._spam_detector.analyze_transaction(
                            tx_metadata, historical_metadata
                        )

                        if risk_analysis.is_suspicious:
                            logging.warning(
                                f"Suspicious transaction detected: {tx_hash} "
                                f"(score: {risk_analysis.score}/100, flags: {[f.value for f in risk_analysis.flags]})"
                            )

                        # Add to history for next transaction in batch
                        historical_metadata.append(tx_metadata)

                # Store transaction in database for future historical analysis
                if tx_metadata:
                    try:
                        await self._db.store_transaction(
                            tx_hash=tx_metadata.tx_hash,
                            monitored_address=address_lower,
                            from_address=tx_metadata.from_address,
                            to_address=tx_metadata.to_address,
                            value=float(tx_metadata.value),
                            block_number=tx_metadata.block_number,
                            timestamp=tx_metadata.timestamp.isoformat(),
                            token_symbol=tx_token_symbol,
                            risk_score=risk_analysis.score if risk_analysis else None,
                        )
                    except Exception as e:
                        logging.warning(
                            f"Failed to store transaction {tx_hash} in database: {e}",
                            exc_info=True,
                        )

                # Send notification with risk analysis
                for user_id in user_ids:
                    await self._notifier.send_token_notification(
                        user_id, tx, tx_token_symbol, address_lower, risk_analysis
                    )
                    notifications_sent += 1

            except Exception as e:
                logging.error(
                    f"Unexpected error during single tx processing {tx.get('hash', 'N/A')}: {e}",
                    exc_info=True,
                )

        if notifications_sent > 0:
            logging.info(
                f"Sent {notifications_sent} notifications for {address_lower}."
            )

    async def _process_address_transactions(
        self, address_lower: str, all_transactions: list[dict], start_block: int
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
        if not all_transactions:
            # No transactions found - return start_block to indicate we've checked up to this point
            # The caller will update the block number to record the check
            return (start_block, 0)

        # Always update to the highest block seen to avoid re-scanning
        max_seen_block = max(int(tx.get("blockNumber", 0)) for tx in all_transactions)

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

        return (max(start_block, max_seen_block), processed_count)

    async def _determine_next_block(
        self,
        start_block: int,
        new_last_block: int,
        raw_transactions: List[dict],
        address_lower: str,
    ) -> BlockDeterminationResult:
        """
        Determine the next block number to check, verifying against actual blockchain.

        Fetches the latest block from the blockchain and determines the correct next block
        number, handling cases where the database might be ahead of the blockchain.

        Args:
            start_block: The starting block number from the database
            new_last_block: The block number determined from processing transactions
            raw_transactions: List of raw transactions found (empty if none)
            address_lower: The monitored address (lowercase) for logging

        Returns:
            BlockDeterminationResult with final_block_number and resetting_to_latest flag
        """
        resetting_to_latest = False
        query_start_block = start_block + 1

        # get_latest_block_number handles exceptions internally and returns None on failure
        latest_block = await self._etherscan.get_latest_block_number()

        # Guard clause: handle case where we can't get latest block
        if latest_block is None:
            # If we can't get latest block, only advance if no transactions found
            if len(raw_transactions) == 0 and new_last_block == start_block:
                new_last_block = query_start_block
                logging.warning(
                    f"Could not get latest block number for {address_lower}. "
                    f"Advancing from {start_block} to {new_last_block} (query_start_block) to prevent getting stuck."
                )
            return BlockDeterminationResult(
                final_block_number=new_last_block,
                resetting_to_latest=resetting_to_latest,
            )

        # Main logic: latest_block is available, verify against it
        # Always ensure we never advance beyond the actual blockchain
        # This prevents getting ahead due to stale/forked transaction data
        if latest_block < start_block:
            # Database start_block is ahead of blockchain - reset to latest_block
            logging.warning(
                f"Latest block ({latest_block}) < start_block ({start_block}) for {address_lower}. "
                f"Database appears ahead of blockchain. Resetting to latest_block ({latest_block}) to sync."
            )
            new_last_block = latest_block
            resetting_to_latest = True
        elif new_last_block > latest_block:
            # new_last_block is ahead of actual blockchain - cap it to latest_block
            logging.warning(
                f"new_last_block ({new_last_block}) > latest_block ({latest_block}) for {address_lower}. "
                f"Capping to latest_block to prevent database from getting ahead of blockchain."
            )
            new_last_block = latest_block
            resetting_to_latest = True
        elif len(raw_transactions) == 0 and new_last_block == start_block:
            # No transactions found and blockchain hasn't advanced - update to latest_block
            # This prevents getting stuck on the same block
            # Note: latest_block >= start_block and latest_block >= new_last_block are guaranteed here
            if latest_block > start_block:
                logging.debug(
                    f"Advancing block for {address_lower} from {start_block} to latest block {latest_block}"
                )
            else:  # latest_block == start_block
                logging.debug(
                    f"Blockchain hasn't advanced for {address_lower}. "
                    f"Latest block ({latest_block}) equals start_block ({start_block}). "
                    f"Updating to {latest_block} to record check."
                )
            new_last_block = latest_block

        return BlockDeterminationResult(
            final_block_number=new_last_block,
            resetting_to_latest=resetting_to_latest,
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

        # Statistics tracking
        total_transactions_found = 0
        total_transactions_processed = 0
        addresses_with_transactions = 0
        addresses_updated = 0
        errors_count = 0
        warnings_count = 0

        update_tasks = []
        for address in addresses_to_check:
            address_lower = address.lower()
            try:
                await asyncio.sleep(self._config.etherscan_request_delay)
                start_block = await self._db.get_last_checked_block(address_lower)

                logging.debug(f"Checking {address_lower} from block {start_block + 1}")

                query_start_block = start_block + 1
                raw_transactions = await self._fetch_transactions_for_address(
                    address_lower, query_start_block
                )

                total_transactions_found += len(raw_transactions)
                if raw_transactions:
                    addresses_with_transactions += 1

                (
                    new_last_block,
                    processed_count,
                ) = await self._process_address_transactions(
                    address_lower, raw_transactions, start_block
                )
                total_transactions_processed += processed_count

                # Determine the next block to check, verifying against actual blockchain
                block_result = await self._determine_next_block(
                    start_block, new_last_block, raw_transactions, address_lower
                )
                new_last_block = block_result.final_block_number
                resetting_to_latest = block_result.resetting_to_latest

                # Always update block number to prevent getting stuck
                # Allow update even if new_last_block < start_block when we're resetting to sync with blockchain
                # Note: new_last_block is always >= start_block unless resetting_to_latest is True,
                # so this condition will always be true
                if new_last_block >= start_block or resetting_to_latest:
                    if resetting_to_latest:
                        logging.info(
                            f"Resetting block for {address_lower} from {start_block} to {new_last_block} to sync with blockchain"
                        )
                    elif new_last_block > start_block:
                        logging.debug(
                            f"Updating block for {address_lower} from {start_block} to {new_last_block}"
                        )
                    else:
                        logging.debug(
                            f"Recording check for {address_lower} at block {start_block} (no new transactions, no advancement)"
                        )
                    update_tasks.append(
                        self._db.update_last_checked_block(
                            address_lower, new_last_block
                        )
                    )
                    addresses_updated += 1
            except EtherscanRateLimitError:
                logging.warning(f"Rate limit for {address_lower}. Skipping this cycle.")
                warnings_count += 1
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logging.error(f"Network error for {address_lower}: {e}. Skipping.")
                errors_count += 1
            except Exception as e:
                logging.error(
                    f"Critical error in check cycle for {address_lower}: {e}",
                    exc_info=True,
                )
                errors_count += 1

        if update_tasks:
            logging.debug(
                f"Updating last checked blocks for {len(update_tasks)} addresses..."
            )
            await asyncio.gather(*update_tasks, return_exceptions=True)

        cycle_duration = time.time() - cycle_start_time

        # Log summary at INFO level - include all relevant information
        summary_parts = []
        if total_transactions_processed > 0:
            summary_parts.append(
                f"processed {total_transactions_processed} new transaction(s)"
            )
        if errors_count > 0:
            summary_parts.append(f"{errors_count} error(s)")
        if warnings_count > 0:
            summary_parts.append(f"{warnings_count} warning(s)")

        if summary_parts:
            logging.info(
                f"Transaction check cycle complete: {', '.join(summary_parts)} in {cycle_duration:.2f}s"
            )
        else:
            logging.info(f"Transaction check cycle complete in {cycle_duration:.2f}s")

        # Log detailed statistics at DEBUG level
        logging.debug(
            f"Cycle statistics: checked {len(addresses_to_check)} address(es), "
            f"found {total_transactions_found} transaction(s), "
            f"processed {total_transactions_processed} new transaction(s) "
            f"from {addresses_with_transactions} address(es), "
            f"updated {addresses_updated} address(es), "
            f"{errors_count} error(s), {warnings_count} warning(s)"
        )
