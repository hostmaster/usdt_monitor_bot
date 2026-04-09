"""
Transaction checker module.

Periodically checks for new token transactions for monitored addresses
and performs spam detection analysis.
"""

# Standard library
import asyncio
import contextlib
import logging
import time
from collections import deque
from dataclasses import dataclass

# Third-party
import aiohttp

# Local
from usdt_monitor_bot.block_tracker import BlockDeterminationResult, BlockTracker
from usdt_monitor_bot.blockchain_provider import BlockchainProvider
from usdt_monitor_bot.config import BotConfig
from usdt_monitor_bot.database import DatabaseManager
from usdt_monitor_bot.etherscan import (
    EtherscanError,
    EtherscanRateLimitError,
)
from usdt_monitor_bot.notifier import NotificationService
from usdt_monitor_bot.spam_detector import (
    RiskAnalysis,
    SpamDetector,
    TransactionMetadata,
)
from usdt_monitor_bot.transaction_parser import (
    convert_db_transaction_to_metadata,
    convert_to_transaction_metadata,
    filter_transactions,
    format_transaction_log,
)


@dataclass
class AddressProcessingResult:
    new_last_block: int
    processed_count: int
    max_block_in_processed_batch: int  # 0 if no batch was processed


@dataclass
class EnrichmentContext:
    """Pre-fetched enrichment data shared across a batch of txs for one address.

    Populated once per address before the per-tx loop to eliminate the N+1
    query pattern in spam detection. ``known_senders`` is a mutable set
    intentionally — the per-tx loop adds newly-observed senders as it goes
    so that the same sender appearing twice in one batch is classified as
    "new" only on its first occurrence, matching the pre-batching semantics
    (the old code ran ``store_transaction`` between iterations and would
    flip the DB state mid-loop).
    """

    known_senders: set[str]


class TransactionChecker:
    """Periodically checks for new token transactions for monitored addresses."""

    def __init__(
        self,
        config: BotConfig,
        db_manager: DatabaseManager,
        etherscan_client: BlockchainProvider,
        notifier: NotificationService,
        spam_detector: SpamDetector | None = None,
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
        # Cache for contract creation blocks to avoid repeated API calls.
        # Bounded to prevent unbounded growth in long-running bots.
        self._contract_creation_cache: dict[str, int | None] = {}
        self._contract_creation_cache_max_size = config.contract_creation_cache_size
        # Bounded in-memory cache of (user_id, tx_hash) to suppress duplicate notifications
        self._notification_sent_cache: set[tuple[int, str]] = set()
        self._notification_sent_order: deque[tuple[int, str]] = deque()
        self._notification_dedup_max_size = config.notification_dedup_cache_size
        self._block_tracker = BlockTracker(etherscan_client)
        logging.debug("TransactionChecker initialized")

    def _handle_etherscan_error(
        self, error: Exception, token_symbol: str, address_lower: str
    ) -> None:
        """Handle Etherscan API errors with appropriate logging."""
        addr_short = f"{address_lower[:8]}..."
        if isinstance(error, EtherscanRateLimitError):
            logging.warning(f"Rate limited: {token_symbol} for {addr_short}")
        elif isinstance(error, EtherscanError):
            error_msg = str(error)
            # Skip logging for "No transactions found" - expected for inactive addresses
            if "No transactions found" in error_msg:
                return
            if "NOTOK" in error_msg:
                logging.warning(f"API error {token_symbol}/{addr_short}: {error_msg}")
            else:
                logging.error(
                    f"Etherscan error {token_symbol}/{addr_short}: {error_msg}"
                )
        else:
            logging.error(
                f"Fetch error {token_symbol}/{addr_short}: {error}", exc_info=True
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

    async def _get_historical_transactions_metadata(
        self, address_lower: str, limit: int = 20
    ) -> list[TransactionMetadata]:
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
                metadata = convert_db_transaction_to_metadata(db_tx)
                if metadata:
                    historical_metadata.append(metadata)

            return historical_metadata
        except Exception as e:
            logging.warning(
                f"Historical tx error for {address_lower[:8]}: {e}", exc_info=True
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
            self._cache_contract_block(address_lower, creation_block)
            if creation_block is not None:
                return max(0, current_block - creation_block)
        except Exception as e:
            logging.debug(f"Contract age lookup failed for {address_lower[:8]}: {e}")
            self._cache_contract_block(address_lower, None)

        return 0  # Default to 0 if unable to determine

    def _cache_contract_block(self, address_lower: str, block: int | None) -> None:
        """Store a contract creation block in the bounded cache, evicting oldest if at capacity."""
        if (
            address_lower not in self._contract_creation_cache
            and len(self._contract_creation_cache) >= self._contract_creation_cache_max_size
        ):
            self._contract_creation_cache.pop(next(iter(self._contract_creation_cache)))
        self._contract_creation_cache[address_lower] = block

    async def _enrich_transaction_metadata(
        self,
        tx_metadata: TransactionMetadata,
        address_lower: str,
        historical_metadata: list[TransactionMetadata],
        ctx: EnrichmentContext | None = None,
    ) -> RiskAnalysis:
        """
        Enrich transaction metadata with spam detection data and perform risk analysis.

        When ``ctx`` is provided, sender-history and contract-age data are
        read from the pre-fetched context / contract-creation cache instead
        of hitting the DB and Etherscan per transaction. ``ctx`` is mutated
        to mark the current sender as known for subsequent iterations
        within the same batch.

        Args:
            tx_metadata: Transaction metadata to enrich
            address_lower: The monitored address
            historical_metadata: Historical transactions for context
            ctx: Optional pre-fetched enrichment context (batch mode).
                If None, falls back to per-tx DB / Etherscan lookups.

        Returns:
            RiskAnalysis object
        """
        sender_lower = tx_metadata.from_address.lower()

        # Check if sender is new — batch path reads from the pre-fetched set,
        # fallback path does a single-address DB lookup.
        if ctx is not None:
            tx_metadata.is_new_address = sender_lower not in ctx.known_senders
            # Mark as seen so repeated senders in the same batch don't all
            # get flagged as "new" (matches pre-batching semantics where
            # store_transaction() ran between iterations).
            ctx.known_senders.add(sender_lower)
        else:
            tx_metadata.is_new_address = await self._db.is_new_sender_address(
                address_lower, tx_metadata.from_address
            )

        # Get contract age. Batch mode pre-populates the cache, so this is
        # a pure in-memory lookup in the common case; cold cache falls back
        # to the per-address path.
        tx_metadata.contract_age_blocks = await self._get_contract_age_blocks(
            tx_metadata.from_address, tx_metadata.block_number
        )

        # Build whitelist of trusted addresses (token contracts only)
        # The monitored address is passed separately to enable spam detection on incoming transactions
        whitelisted_addresses = set()
        for token in self._config.token_registry.get_all_tokens().values():
            whitelisted_addresses.add(token.contract_address)

        # Analyze transaction with whitelist and monitored address
        return self._spam_detector.analyze_transaction(
            tx_metadata,
            historical_metadata,
            whitelisted_addresses=whitelisted_addresses,
            monitored_address=address_lower,
        )

    async def _store_transaction_safely(
        self,
        tx_metadata: TransactionMetadata,
        token_symbol: str,
        address_lower: str,
        risk_score: int | None,
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
                f"DB store failed: tx={tx_metadata.tx_hash[:16]}... err={e}",
                exc_info=True,
            )

    def _add_notification_sent(self, user_id: int, tx_hash: str) -> None:
        """Record (user_id, tx_hash) in the bounded dedup cache and evict oldest if over cap."""
        if self._notification_dedup_max_size <= 0:
            return  # Cache disabled when size is not positive
        key = (user_id, tx_hash)
        if key in self._notification_sent_cache:
            return
        while (
            len(self._notification_sent_order) >= self._notification_dedup_max_size
            and self._notification_sent_order
        ):
            old = self._notification_sent_order.popleft()
            self._notification_sent_cache.discard(old)
        self._notification_sent_cache.add(key)
        self._notification_sent_order.append(key)

    def _remove_notification_sent(self, user_id: int, tx_hash: str) -> None:
        """Roll back a dedup cache entry — used when a notification send fails."""
        key = (user_id, tx_hash)
        self._notification_sent_cache.discard(key)
        with contextlib.suppress(ValueError):
            self._notification_sent_order.remove(key)

    async def _process_single_transaction(
        self,
        tx: dict,
        user_ids: list[int],
        address_lower: str,
        historical_metadata: list[TransactionMetadata],
        enrichment_ctx: EnrichmentContext | None = None,
    ) -> int:
        """
        Process a single transaction: analyze, store, log, and notify.

        Spam transactions are logged but not notified to users (suppressed).
        Users can view spam transactions via /spam command.

        Args:
            tx: Transaction dictionary
            user_ids: List of user IDs to notify
            address_lower: The monitored address
            historical_metadata: Historical transactions (will be updated)

        Returns:
            Number of notifications sent (excludes suppressed spam)
        """
        tx_hash = tx.get("hash")
        tx_token_symbol = tx.get("token_symbol")

        if not tx_hash or not tx_token_symbol:
            logging.debug(
                f"Skipping tx without hash/symbol: {tx.get('hash', 'N/A')[:16]}"
            )
            return 0

        # Get token config
        token_config = self._config.token_registry.get_token(tx_token_symbol)
        if not token_config:
            logging.debug(f"Unknown token {tx_token_symbol}, skipping transaction")
            return 0

        # Process with spam detection (only if token config is available)
        risk_analysis: RiskAnalysis | None = None
        tx_metadata: TransactionMetadata | None = None

        if self._spam_detection_enabled:
            tx_metadata = convert_to_transaction_metadata(tx, token_config.decimals)
            if tx_metadata:
                risk_analysis = await self._enrich_transaction_metadata(
                    tx_metadata,
                    address_lower,
                    historical_metadata,
                    enrichment_ctx,
                )
                historical_metadata.append(tx_metadata)

                # Log detected transaction with compact format
                log_line = format_transaction_log(
                    tx_metadata, tx_token_symbol, address_lower, risk_analysis
                )
                if risk_analysis.is_suspicious:
                    logging.warning(log_line)
                else:
                    logging.info(log_line)

        # Store transaction if metadata was created
        if tx_metadata:
            await self._store_transaction_safely(
                tx_metadata,
                tx_token_symbol,
                address_lower,
                risk_analysis.score if risk_analysis else None,
            )

        # Suppress notifications for spam transactions
        if risk_analysis and risk_analysis.is_suspicious:
            logging.debug(f"Suppressing notification for spam tx={tx_hash[:16]}...")
            return 0

        # Send notifications for legitimate transactions only (skip if already sent recently when cache enabled)
        # Register in dedup cache BEFORE the await to close the window between check and send;
        # roll back on failure so the next cycle can retry.
        sent_count = 0
        for user_id in user_ids:
            if self._notification_dedup_max_size > 0 and (user_id, tx_hash) in self._notification_sent_cache:
                logging.debug(f"Skip duplicate notify user={user_id} tx={tx_hash[:16]}...")
                continue
            self._add_notification_sent(user_id, tx_hash)
            try:
                await self._notifier.send_token_notification(
                    user_id, tx, tx_token_symbol, address_lower, risk_analysis
                )
                sent_count += 1
            except Exception:
                self._remove_notification_sent(user_id, tx_hash)
        return sent_count

    async def _prefetch_enrichment_context(
        self, batch: list[dict], address_lower: str
    ) -> EnrichmentContext:
        """Pre-fetch sender history and contract ages for an entire batch.

        Eliminates the N+1 query pattern in the per-tx spam detection loop by:
        1. A single bulk ``get_known_senders`` DB query for all unique senders.
        2. A batched ``get_contract_creation_blocks`` HTTP call for all
           uncached senders, which populates ``_contract_creation_cache``.

        If the contract-creation cache is too small to hold all unique
        senders in this batch (a config smell), logs a warning and skips
        bulk pre-fetch for contract ages — the per-tx path will fall back
        to single-address lookups, matching pre-feature behaviour.
        """
        unique_senders = list(
            {
                (tx.get("from") or "").lower()
                for tx in batch
                if tx.get("from")
            }
        )

        # 1. Bulk sender-history lookup: 1 DB roundtrip instead of N.
        known_senders: set[str] = set()
        if unique_senders:
            try:
                known_senders = await self._db.get_known_senders(
                    address_lower, unique_senders
                )
            except Exception as e:
                logging.warning(
                    f"Bulk known-senders lookup failed for {address_lower[:8]}...: {e}",
                    exc_info=True,
                )
                known_senders = set()

        # 2. Bulk contract-age pre-fetch: only addresses not already cached.
        uncached = [
            s
            for s in unique_senders
            if s and s not in self._contract_creation_cache
        ]
        if uncached:
            # Guard against a cache smaller than the batch's unique senders:
            # if we pre-fetched N addresses into a cache of size < N, we would
            # start evicting our own pre-fetched data mid-loop. Fall back to
            # the per-tx path and flag the misconfiguration.
            if len(uncached) > self._contract_creation_cache_max_size:
                logging.warning(
                    f"Skipping bulk contract-creation pre-fetch for "
                    f"{address_lower[:8]}...: {len(uncached)} uncached senders "
                    f"> cache size {self._contract_creation_cache_max_size}. "
                    f"Consider raising contract_creation_cache_size."
                )
            else:
                try:
                    creation_blocks = (
                        await self._etherscan.get_contract_creation_blocks(uncached)
                    )
                except Exception as e:
                    logging.warning(
                        f"Bulk contract-creation lookup failed for "
                        f"{address_lower[:8]}...: {e}",
                        exc_info=True,
                    )
                    creation_blocks = {}
                # Cache every address we asked about — including explicit
                # misses — so the next cycle does not re-query them.
                for addr in uncached:
                    self._cache_contract_block(
                        addr, creation_blocks.get(addr)
                    )

        return EnrichmentContext(known_senders=known_senders)

    async def _send_notifications_for_batch(
        self, user_ids: list[int], batch: list[dict], address_lower: str
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

        # Bulk pre-fetch sender-history + contract ages for the whole batch,
        # so the per-tx loop below is a pure in-memory lookup in the common case.
        enrichment_ctx = await self._prefetch_enrichment_context(batch, address_lower)

        notifications_sent = 0
        for tx in batch:
            try:
                notifications_sent += await self._process_single_transaction(
                    tx,
                    user_ids,
                    address_lower,
                    historical_metadata,
                    enrichment_ctx,
                )
            except Exception as e:
                logging.error(
                    f"Process tx error {tx.get('hash', 'N/A')[:16]}: {e}", exc_info=True
                )

        if notifications_sent > 0:
            logging.debug(
                f"Sent {notifications_sent} notifications for {address_lower[:8]}..."
            )

    async def _process_address_transactions(
        self,
        address_lower: str,
        all_transactions: list[dict],
        start_block: int,
        latest_block: int | None = None,
    ) -> AddressProcessingResult:
        """
        Orchestrate filtering, notification, and determine the max block to update to.

        Args:
            address_lower: The monitored address (lowercase)
            all_transactions: All transactions fetched from Etherscan
            start_block: The starting block number

        Returns:
            AddressProcessingResult with new_last_block, processed_count, and
            max_block_in_processed_batch (highest block among processed txs; 0 if none processed).
            max_block_in_processed_batch ensures we never persist a lower block and re-notify.
        """
        if not all_transactions:
            # No transactions found - return start_block to indicate we've checked up to this point
            # The caller will update the block number to record the check
            # Cap start_block to latest_block if available to prevent getting ahead of blockchain
            final_block = self._block_tracker.cap_block_to_latest(
                start_block,
                latest_block,
                address_lower,
                context="no transactions found",
            )
            return AddressProcessingResult(final_block, 0, 0)

        # Always update to the highest block seen to avoid re-scanning
        # But cap it to latest_block if available to prevent getting ahead of blockchain
        tx_block_numbers = [int(tx.get("blockNumber", 0)) for tx in all_transactions]
        max_seen_block = max(tx_block_numbers) if tx_block_numbers else 0
        max_seen_block = self._block_tracker.cap_block_to_latest(
            max_seen_block, latest_block, address_lower
        )

        processing_batch = filter_transactions(
            all_transactions,
            start_block,
            self._config.max_transaction_age_days,
            self._config.max_transactions_per_check,
        )
        # Dedupe by tx_hash: API can return duplicate events (same tx in multiple token responses,
        # or multiple transfer events for the same token in one tx). Notify at most once per user per tx per cycle.
        seen_hashes: set[str] = set()
        unique_batch: list[dict] = []
        for tx in processing_batch:
            h = tx.get("hash")
            if h and h not in seen_hashes:
                seen_hashes.add(h)
                unique_batch.append(tx)
        processing_batch = unique_batch

        if not processing_batch:
            logging.debug(f"No tx after filtering for {address_lower[:8]}...")
            # Cap to latest_block if available to prevent getting ahead of blockchain
            result_block = max(start_block, max_seen_block)
            result_block = self._block_tracker.cap_block_to_latest(
                result_block,
                latest_block,
                address_lower,
                context="no transactions after filtering",
            )
            return AddressProcessingResult(result_block, 0, 0)

        # Highest block among txs we are about to process; we must never persist a lower block
        max_block_in_batch = max(
            int(tx.get("blockNumber", 0)) for tx in processing_batch
        )

        user_ids = await self._db.get_users_for_address(address_lower)
        if not user_ids:
            logging.debug(
                f"No users tracking {address_lower[:8]}... ({len(processing_batch)} tx found)"
            )
            processed_count = 0
        else:
            processed_count = len(processing_batch)
            logging.debug(f"Processing {processed_count} tx for {address_lower[:8]}...")
            await self._send_notifications_for_batch(
                user_ids, processing_batch, address_lower
            )

        new_last_block = max(start_block, max_seen_block)
        # Cap new_last_block to latest_block if available to prevent getting ahead of blockchain
        # This handles the case where start_block is already ahead of latest_block
        new_last_block = self._block_tracker.cap_block_to_latest(
            new_last_block, latest_block, address_lower
        )
        return AddressProcessingResult(new_last_block, processed_count, max_block_in_batch)

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
        actual_block: int | None = None,
    ) -> None:
        """Log block update with appropriate level."""
        new_block = (
            actual_block
            if actual_block is not None
            else block_result.final_block_number
        )
        addr_short = f"{address_lower[:8]}..."
        if block_result.resetting_to_latest:
            logging.info(f"Block reset {addr_short}: {start_block}->{new_block}")
        elif new_block > start_block:
            logging.debug(f"Block update {addr_short}: {start_block}->{new_block}")
        else:
            logging.debug(f"Block unchanged {addr_short}: {start_block}")

    def _log_cycle_summary(
        self, stats: dict, cycle_duration: float, address_count: int
    ) -> None:
        """Log cycle summary and detailed statistics."""
        tx_proc = stats["total_transactions_processed"]
        errors = stats["errors_count"]
        warnings = stats["warnings_count"]

        # Compact INFO summary
        parts = [f"{address_count} addr"]
        if tx_proc > 0:
            parts.append(f"{tx_proc} tx")
        if errors > 0:
            parts.append(f"{errors} err")
        if warnings > 0:
            parts.append(f"{warnings} warn")
        parts.append(f"{cycle_duration:.1f}s")

        logging.info(f"Cycle done: {', '.join(parts)}")

        # Detailed DEBUG stats
        logging.debug(
            f"Cycle stats: found={stats['total_transactions_found']} "
            f"processed={tx_proc} from_addr={stats['addresses_with_transactions']} "
            f"updated={stats['addresses_updated']} err={errors} warn={warnings}"
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

            logging.debug(f"Check {address_lower[:8]}... from block {start_block + 1}")

            # Fetch latest block early to cap transaction block numbers
            latest_block = await self._etherscan.get_latest_block_number()
            if latest_block is None:
                logging.debug(
                    f"No latest block for {address_lower[:8]}..., proceeding without cap"
                )

            raw_transactions = await self._fetch_transactions_for_address(
                address_lower, start_block + 1
            )

            stats["total_transactions_found"] += len(raw_transactions)
            if raw_transactions:
                stats["addresses_with_transactions"] += 1

            result = await self._process_address_transactions(
                address_lower, raw_transactions, start_block, latest_block
            )
            new_last_block = result.new_last_block
            processed_count = result.processed_count
            max_block_in_processed_batch = result.max_block_in_processed_batch
            stats["total_transactions_processed"] += processed_count

            # Determine next block and update if needed
            block_result = await self._block_tracker.determine_next_block(
                start_block,
                new_last_block,
                raw_transactions,
                address_lower,
                latest_block,
            )

            if self._should_update_block(start_block, block_result):
                if latest_block is None:
                    logging.warning(
                        f"Defensive block cap skipped for {address_lower[:8]}...: "
                        f"could not fetch latest block, persisting uncapped {block_result.final_block_number}"
                    )
                final_block_to_update = self._block_tracker.cap_block_to_latest(
                    block_result.final_block_number,
                    latest_block,
                    address_lower,
                    context="defensive check before database update",
                    log_level="warning",
                )
                # Never persist a block lower than the highest we already processed, or we will
                # re-fetch and re-notify the same transactions next cycle (e.g. when API returns
                # txs in blocks ahead of reported "latest" block)
                if max_block_in_processed_batch > 0:
                    final_block_to_update = max(
                        final_block_to_update, max_block_in_processed_batch
                    )

                self._log_block_update(
                    address_lower, start_block, block_result, final_block_to_update
                )
                update_tasks.append(
                    self._db.update_last_checked_block(
                        address_lower, final_block_to_update
                    )
                )
                stats["addresses_updated"] += 1

        except EtherscanRateLimitError:
            logging.warning(f"Rate limit: {address_lower[:8]}..., skip cycle")
            stats["warnings_count"] += 1
        except (TimeoutError, aiohttp.ClientError) as e:
            logging.error(f"Network error {address_lower[:8]}...: {e}")
            stats["errors_count"] += 1
        except Exception as e:
            logging.error(
                f"Error processing {address_lower[:8]}...: {e}", exc_info=True
            )
            stats["errors_count"] += 1

    async def check_all_addresses(self) -> None:
        """
        Main entry point: check all tracked addresses for new transactions.

        Fetches all monitored addresses from the database and processes
        transactions for each address, updating block numbers and sending
        notifications as needed.
        """
        cycle_start_time = time.monotonic()
        addresses_to_check = await self._db.get_distinct_addresses()

        if not addresses_to_check:
            logging.debug("No addresses to monitor")
            return

        logging.debug(f"Checking {len(addresses_to_check)} addresses")

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
            logging.debug(f"Updating blocks for {len(update_tasks)} addresses")
            await asyncio.gather(*update_tasks, return_exceptions=True)

        cycle_duration = time.monotonic() - cycle_start_time
        self._log_cycle_summary(stats, cycle_duration, len(addresses_to_check))
