# checker.py
import asyncio
import logging
from datetime import datetime, timezone
from typing import List

import aiohttp  # Import needed if creating session here or for type hints

from usdt_monitor_bot.config import BotConfig
from usdt_monitor_bot.database import DatabaseManager
from usdt_monitor_bot.etherscan import (
    EtherscanClient,
    EtherscanError,
    EtherscanRateLimitError,
)
from usdt_monitor_bot.notifier import NotificationService


class TransactionChecker:
    """Periodically checks for new token transactions for monitored addresses."""

    def __init__(
        self,
        config: BotConfig,
        db_manager: DatabaseManager,
        etherscan_client: EtherscanClient,
        notifier: NotificationService,
    ):
        self._config = config
        self._db = db_manager
        self._etherscan = etherscan_client
        self._notifier = notifier
        logging.info("TransactionChecker initialized.")

    async def _fetch_transactions_for_address(
        self, address_lower: str, query_start_block: int
    ) -> list[dict]:
        """
        Fetches all token transactions for a single address from a specific block.
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
                if "No transactions found" not in str(e):
                    logging.error(
                        f"Error fetching {token.symbol} transactions for {address_lower}: {e}"
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
        """Filters transactions by block, age, and limits the count."""
        current_time = datetime.now(timezone.utc)
        max_age_seconds = self._config.max_transaction_age_days * 24 * 60 * 60

        filtered = []
        for tx in all_transactions:
            try:
                if int(tx.get("blockNumber", 0)) <= start_block:
                    continue

                age_seconds = (
                    current_time
                    - datetime.fromtimestamp(int(tx.get("timeStamp", 0)), tz=timezone.utc)
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

    async def _send_notifications_for_batch(
        self, user_ids: List[int], batch: List[dict], address_lower: str
    ):
        """Sends notifications for a batch of transactions."""
        notifications_sent = 0
        for tx in batch:
            try:
                tx_hash = tx.get("hash")
                tx_token_symbol = tx.get("token_symbol")
                if not tx_hash or not tx_token_symbol:
                    logging.warning(f"Transaction missing hash or symbol, skipping: {tx}")
                    continue

                for user_id in user_ids:
                    await self._notifier.send_token_notification(
                        user_id, tx, tx_token_symbol, address_lower
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
    ) -> int:
        """
        Orchestrates filtering, notification, and determines the max block to update to.
        """
        if not all_transactions:
            return start_block

        # Always update to the highest block seen to avoid re-scanning
        max_seen_block = max(int(tx.get("blockNumber", 0)) for tx in all_transactions)

        processing_batch = self._filter_transactions(all_transactions, start_block)

        if not processing_batch:
            logging.debug(f"No transactions to notify for {address_lower} after filtering.")
            return max(start_block, max_seen_block)

        user_ids = await self._db.get_users_for_address(address_lower)
        if not user_ids:
            logging.warning(
                f"Found {len(processing_batch)} tx(s) for {address_lower}, but no users are tracking it."
            )
        else:
            logging.info(f"Processing {len(processing_batch)} new tx(s) for {address_lower}")
            await self._send_notifications_for_batch(user_ids, processing_batch, address_lower)
        
        return max(start_block, max_seen_block)

    async def check_all_addresses(self):
        """The main loop executed periodically to check all addresses."""
        logging.info("Starting transaction check cycle...")
        addresses_to_check = await self._db.get_distinct_addresses()

        if not addresses_to_check:
            logging.info("No addresses found in the database to check.")
            return

        update_tasks = []
        for address in addresses_to_check:
            address_lower = address.lower()
            try:
                await asyncio.sleep(self._config.etherscan_request_delay)
                start_block = await self._db.get_last_checked_block(address_lower)
                
                logging.info(f"Checking {address_lower} from block {start_block + 1}")

                raw_transactions = await self._fetch_transactions_for_address(
                    address_lower, start_block + 1
                )

                new_last_block = await self._process_address_transactions(
                    address_lower, raw_transactions, start_block
                )

                if new_last_block > start_block:
                    update_tasks.append(
                        self._db.update_last_checked_block(address_lower, new_last_block)
                    )
            except EtherscanRateLimitError:
                logging.warning(f"Rate limit for {address_lower}. Skipping this cycle.")
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logging.error(f"Network error for {address_lower}: {e}. Skipping.")
            except Exception as e:
                logging.error(
                    f"Critical error in check cycle for {address_lower}: {e}", exc_info=True
                )

        if update_tasks:
            logging.info(f"Updating last checked blocks for {len(update_tasks)} addresses...")
            await asyncio.gather(*update_tasks, return_exceptions=True)

        logging.info("Transaction check cycle complete.")
