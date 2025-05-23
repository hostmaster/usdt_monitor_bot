# checker.py
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict

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
                # Short delay before each Etherscan request within the token loop
                # This is in addition to the per-address delay in check_all_addresses
                await asyncio.sleep(self._config.etherscan_request_delay / 2 or 0.1) # Smaller delay here

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
                    f"Rate limited while fetching {token.symbol} for {address_lower} "
                    f"from block {query_start_block}. Some transactions for this address may be missed in this cycle."
                )
                # Continue to next token, partial results are possible
                continue
            except EtherscanError as e:
                if "No transactions found" in str(e):
                    if logging.getLogger().isEnabledFor(logging.DEBUG):
                        logging.debug(
                            f"No {token.symbol} transactions found for {address_lower} "
                            f"from block {query_start_block}"
                        )
                else:
                    logging.error(
                        f"Error fetching {token.symbol} transactions for {address_lower}: {e}"
                    )
                # Continue to next token
                continue
            except Exception as e: # Catch any other unexpected error during Etherscan call
                logging.error(
                    f"Unexpected error fetching {token.symbol} for {address_lower}: {e}",
                    exc_info=True
                )
                continue
        return all_transactions

    async def _filter_and_process_transactions(
        self, address_lower: str, all_transactions: list[dict], start_block: int
    ) -> int:
        """
        Filters transactions, sends notifications, and determines the max processed block.
        Returns the new maximum block number to be considered as 'last_checked_block'.
        """
        current_max_block_for_addr = start_block # Initialize with the original start_block

        if not all_transactions:
            logging.debug(f"No transactions to process for {address_lower} after fetching.")
            return current_max_block_for_addr

        # Filter transactions by age and limit count
        current_time = datetime.now(timezone.utc)
        max_age_seconds = self._config.max_transaction_age_days * 24 * 60 * 60

        filtered_transactions = []
        for tx in all_transactions:
            try:
                tx_block = int(tx.get("blockNumber", 0))
                # Ensure we only process transactions strictly newer than start_block
                if tx_block <= start_block:
                    continue

                tx_timestamp = int(tx.get("timeStamp", 0))
                tx_time = datetime.fromtimestamp(tx_timestamp, tz=timezone.utc)
                age_seconds = (current_time - tx_time).total_seconds()

                if age_seconds > max_age_seconds:
                    logging.debug(
                        f"Skipping transaction {tx.get('hash')} due to age: {age_seconds}s old."
                    )
                    continue
                filtered_transactions.append(tx)
            except (ValueError, TypeError) as e:
                logging.warning(
                    f"Invalid data in transaction {tx.get('hash', 'unknown')}: {e}. Skipping tx."
                )
                continue

        # Sort by block number (ascending to process oldest first, then reverse for picking latest)
        # Actually, sorting descending to pick the MAX_TRANSACTIONS_PER_CHECK newest ones
        filtered_transactions.sort(
            key=lambda x: int(x.get("blockNumber", 0)), reverse=True
        )
        # Limit the number of transactions to process as per config
        processing_batch = filtered_transactions[:self._config.max_transactions_per_check]
        # Reverse again to process in chronological order for notifications, if desired (optional)
        processing_batch.sort(key=lambda x: int(x.get("blockNumber", 0)))


        if not processing_batch:
            # This can happen if all fetched transactions were older than start_block or too old by timestamp
            # We need to ensure that current_max_block_for_addr is at least the highest block number
            # seen in all_transactions, even if none are processed for notification.
            # This prevents re-fetching very old transactions if no new ones arrive.
            if all_transactions: # Check if there were any transactions at all
                 max_seen_block = max(int(tx.get("blockNumber", 0)) for tx in all_transactions if tx.get("blockNumber"))
                 current_max_block_for_addr = max(start_block, max_seen_block)
            logging.debug(f"No transactions to notify for {address_lower} after filtering. Max seen block: {current_max_block_for_addr}")
            return current_max_block_for_addr

        user_ids = await self._db.get_users_for_address(address_lower)
        if not user_ids:
            logging.warning(
                f"Found {len(processing_batch)} transactions for {address_lower}, "
                "but no users are tracking it. Skipping notification."
            )
            # Still, update current_max_block_for_addr to the highest block in this batch
            current_max_block_for_addr = max(
                start_block, int(processing_batch[-1].get("blockNumber", 0)) # Last one due to sort
            )
            return current_max_block_for_addr

        logging.info(
            f"Processing {len(processing_batch)} new tx(s) for {address_lower}"
        )

        notifications_sent = 0
        processed_tx_hashes = set()

        for tx in processing_batch: # Iterate through the potentially reduced and sorted batch
            try:
                tx_hash = tx.get("hash")
                if tx_hash is None:
                    logging.warning(f"Transaction has no hash, skipping: {tx}")
                    continue
                if tx_hash in processed_tx_hashes: # Should not happen if API returns unique txs per call
                    continue
                processed_tx_hashes.add(tx_hash)

                # This check for tx_to/tx_from might be redundant if Etherscan already filters,
                # but good for safety. The core logic is handled by Etherscan's address query.
                # The main purpose here is to ensure it's one of *our* monitored tokens.
                tx_token_symbol = tx.get("token_symbol") # Added in _fetch_transactions_for_address
                if not tx_token_symbol:
                     logging.warning(f"Transaction {tx_hash} missing token_symbol. Skipping.")
                     continue

                # All transactions returned by _fetch_transactions_for_address are relevant by address.
                # We primarily need to ensure the token is still valid/configured if that check is needed here.
                # For now, tx_token_symbol is sufficient.

                for user_id in user_ids:
                    await self._notifier.send_token_notification(
                        user_id, tx, tx_token_symbol, address_lower # address_lower is the monitored one
                    )
                    notifications_sent += 1
                
                # Update the max block seen with this transaction's block number
                current_max_block_for_addr = max(
                    current_max_block_for_addr, int(tx.get("blockNumber", 0))
                )

            except (ValueError, KeyError, TypeError) as e:
                logging.error(
                    f"Error processing transaction data {tx.get('hash', 'N/A')} for {address_lower}: {e}. Skipping tx.",
                    exc_info=False,
                )
            except Exception as e:
                logging.error(
                    f"Unexpected error during single tx processing {tx.get('hash', 'N/A')} for {address_lower}: {e}",
                    exc_info=True,
                )
        
        if notifications_sent > 0:
            logging.info(
                f"Sent {notifications_sent} notifications for {address_lower} up to block {current_max_block_for_addr}."
            )
        
        # If processing_batch was empty but all_transactions was not, current_max_block_for_addr
        # would have been updated before user_ids check. This final return is correct.
        return current_max_block_for_addr

    async def check_all_addresses(self):
        """The main loop executed periodically to check all addresses."""
        logging.info("Starting transaction check cycle...")
        addresses_to_check = await self._db.get_distinct_addresses()

        if not addresses_to_check:
            logging.info("No addresses found in the database to check.")
            return

        latest_block_processed: Dict[str, int] = {}

        for address in addresses_to_check:
            address_lower = address.lower()
            try:
                # Per-address delay, applied before any operation for this address
                await asyncio.sleep(self._config.etherscan_request_delay)

                start_block = await self._db.get_last_checked_block(address_lower)
                query_start_block = start_block + 1
                
                logging.info(
                    f"Checking address {address_lower} from block {query_start_block}"
                )

                # 1. Fetch transactions
                # Errors within _fetch_transactions_for_address (like per-token rate limits or API errors)
                # are handled internally by that method (logged, and it returns whatever it could get).
                # Top-level EtherscanRateLimitError or EtherscanError here would imply a more global issue
                # or an error from a call made directly by check_all_addresses if any.
                # The @retry on get_token_transactions should handle most transient issues.
                raw_transactions = await self._fetch_transactions_for_address(
                    address_lower, query_start_block
                )

                # If _fetch_transactions_for_address itself throws an exception (e.g. if not caught internally,
                # or a critical one like DB error if it were to use DB), it would be caught by the outer try-except.
                # For now, it's designed to return a list, possibly empty.

                if not raw_transactions:
                    logging.debug(
                        f"No new transactions returned by fetch for {address_lower} from block {query_start_block}. "
                        f"Last checked block remains {start_block}."
                    )
                    # We still want to record that we checked this address, up to 'start_block',
                    # especially if no transactions were found. If _fetch had an issue and returned empty,
                    # we don't want to advance the block number aggressively.
                    # The _filter_and_process_transactions will return 'start_block' if raw_transactions is empty.
                    # And if raw_transactions contains items that are all filtered out (e.g. too old, or before start_block),
                    # it will also return an appropriately updated block (potentially still start_block or a bit higher).
                    current_max_block_for_addr = await self._filter_and_process_transactions(
                        address_lower, raw_transactions, start_block # raw_transactions is empty here
                    )
                    latest_block_processed[address_lower] = current_max_block_for_addr
                    continue # Move to the next address

                # 2. Filter and process transactions
                # This method handles filtering, notifications, and returns the highest block processed.
                current_max_block_for_addr = await self._filter_and_process_transactions(
                    address_lower, raw_transactions, start_block
                )
                latest_block_processed[address_lower] = current_max_block_for_addr
                
                # Logging for successful processing of an address is now inside _filter_and_process_transactions

            except EtherscanRateLimitError: # Should be less frequent here due to tenacity in EtherscanClient
                logging.warning(
                    f"Overall rate limit hit while attempting to process {address_lower}. "
                    "Skipping this address for this cycle. Block number not updated."
                )
                # Do not add this address to latest_block_processed, so its block isn't updated
            except EtherscanError as e: # General Etherscan errors not caught by specific handlers
                logging.error(
                    f"A general Etherscan API error occurred for {address_lower}: {e}. "
                    "Skipping this address for this cycle. Block number not updated."
                )
            except aiohttp.ClientError as e: # Network errors not caught by tenacity
                logging.error(f"A network error occurred while processing {address_lower}: {e}. "
                                "Skipping this address for this cycle.")
            except asyncio.TimeoutError as e: # Timeout errors not caught by tenacity
                logging.error(f"A timeout occurred while processing {address_lower}: {e}. "
                                "Skipping this address for this cycle.")
            except Exception as e:
                logging.error(
                    f"Critical unexpected error in check cycle for address {address_lower}: {e}",
                    exc_info=True,
                )
                # Depending on policy, might decide not to update block for this address
                # For now, if an unexpected error occurs, we skip adding to latest_block_processed for safety.

        # --- Update database after checking all addresses ---
        if latest_block_processed:
            logging.info(
                f"Updating last checked blocks for {len(latest_block_processed)} addresses..."
            )
            update_tasks = [
                self._db.update_last_checked_block(addr, block_num)
                for addr, block_num in latest_block_processed.items()
                # Only update if the block number is valid (>= 0)
                if isinstance(block_num, int) and block_num >= 0
            ]
            if update_tasks:
                results = await asyncio.gather(*update_tasks, return_exceptions=True)
                for addr, result in zip(latest_block_processed.keys(), results):
                    if isinstance(result, Exception):
                        logging.error(
                            f"Failed to update last checked block for {addr}: {result}"
                        )
                    elif not result:
                        logging.warning(
                            f"Update last checked block for {addr} did not report success (no rows changed?)."
                        )

        logging.info("Transaction check cycle complete.")
