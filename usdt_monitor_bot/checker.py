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

    async def check_all_addresses(self):
        """The main loop executed periodically to check all addresses."""
        logging.info("Starting transaction check cycle...")
        addresses_to_check = await self._db.get_distinct_addresses()

        if not addresses_to_check:
            logging.info("No addresses found in the database to check.")
            return

        latest_block_processed: Dict[str, int] = {}  # Keep track of updates per address

        for address in addresses_to_check:
            address_lower = address.lower()  # Ensure consistency
            try:
                # Short delay before each address check to be nice to Etherscan
                await asyncio.sleep(self._config.etherscan_request_delay)

                start_block = await self._db.get_last_checked_block(address_lower)
                # Query from the block *after* the last checked one
                query_start_block = start_block + 1

                logging.debug(
                    f"Checking address {address_lower} from block {query_start_block}"
                )

                # Get all supported tokens
                all_transactions = []
                for token in self._config.token_registry.get_all_tokens().values():
                    try:
                        transactions = await self._etherscan.get_token_transactions(
                            token.contract_address,
                            address_lower,
                            start_block=query_start_block,
                        )
                        # Add token information to each transaction
                        for tx in transactions:
                            tx["token_symbol"] = token.symbol
                        all_transactions.extend(transactions)
                    except EtherscanRateLimitError:
                        logging.warning(
                            f"Rate limited checking {address_lower} for {token.symbol}. "
                            "Will retry next cycle. Not updating block number."
                        )
                        continue
                    except EtherscanError as e:
                        # Check if this is a "No transactions found" response
                        if "No transactions found" in str(e):
                            if logging.getLogger().isEnabledFor(logging.DEBUG):
                                logging.debug(
                                    f"No {token.symbol} transactions found for {address_lower} "
                                    f"from block {query_start_block}"
                                )
                            continue
                        logging.error(
                            f"Error checking {token.symbol} transactions for {address_lower}: {e}"
                        )
                        continue

                if not all_transactions:
                    # No new transactions found via API, keep last checked block as is
                    # We only update if transactions *were* processed successfully up to a certain block
                    latest_block_processed[address_lower] = start_block
                    logging.debug(
                        f"No new tx found for {address_lower} > block {start_block}."
                    )
                    continue  # Move to the next address

                # Filter transactions by age and limit count
                current_time = datetime.now(timezone.utc)
                max_age_seconds = self._config.max_transaction_age_days * 24 * 60 * 60

                filtered_transactions = []
                for tx in all_transactions:
                    try:
                        # Skip transactions before the start block
                        tx_block = int(tx.get("blockNumber", 0))
                        if tx_block <= start_block:
                            continue

                        # Skip transactions that are too old
                        tx_timestamp = int(tx.get("timeStamp", 0))
                        tx_time = datetime.fromtimestamp(tx_timestamp, tz=timezone.utc)
                        age_seconds = (current_time - tx_time).total_seconds()

                        logging.debug(
                            f"Transaction {tx.get('hash')}: age_seconds={age_seconds}, max_age_seconds={max_age_seconds}"
                        )

                        if age_seconds > max_age_seconds:
                            logging.debug(
                                f"Skipping transaction {tx.get('hash')} due to age"
                            )
                            continue
                        filtered_transactions.append(tx)
                    except (ValueError, TypeError) as e:
                        logging.warning(
                            f"Invalid timestamp in transaction {tx.get('hash', 'unknown')}: {e}"
                        )
                        continue

                # Sort by block number and take the most recent ones
                filtered_transactions.sort(
                    key=lambda x: int(x.get("blockNumber", 0)), reverse=True
                )
                filtered_transactions = filtered_transactions[
                    : self._config.max_transactions_per_check
                ]

                if not filtered_transactions:
                    latest_block_processed[address_lower] = start_block
                    continue

                user_ids = await self._db.get_users_for_address(address_lower)
                if not user_ids:
                    logging.warning(
                        f"Found {len(filtered_transactions)} transactions for {address_lower}, "
                        "but no users are tracking it. Skipping notification."
                    )
                    # Still need to update the last checked block if txs were found
                    current_max_block_for_addr = max(
                        int(tx["blockNumber"])
                        for tx in filtered_transactions
                        if tx.get("blockNumber")
                    )
                    latest_block_processed[address_lower] = max(
                        start_block, current_max_block_for_addr
                    )
                    continue

                logging.info(
                    f"Processing {len(filtered_transactions)} potential new tx(s) involving {address_lower}"
                )

                current_max_block_for_addr = start_block
                notifications_sent = 0
                processed_tx_hashes = set()  # Track processed transactions

                for tx in filtered_transactions:
                    try:
                        # Skip if we've already processed this transaction
                        tx_hash = tx.get("hash")
                        if tx_hash is None:
                            logging.warning(f"Transaction has no hash, skipping: {tx}")
                            continue
                        if tx_hash in processed_tx_hashes:
                            continue
                        processed_tx_hashes.add(tx_hash)

                        # Check if it's a token transaction for the monitored address
                        tx_to = tx.get("to")
                        tx_from = tx.get("from")
                        if (tx_to and tx_to.lower() == address_lower) or (
                            tx_from and tx_from.lower() == address_lower
                        ):
                            # Look up the token by contract address
                            tx_token = self._config.token_registry.get_token_by_address(
                                tx["contractAddress"]
                            )
                            if tx_token:
                                for user_id in user_ids:
                                    await self._notifier.send_token_notification(
                                        user_id, tx, tx_token.symbol
                                    )
                                    notifications_sent += 1
                            else:
                                logging.warning(
                                    f"Token not found for contract address {tx.get('contractAddress')} in tx {tx.get('hash')}"
                                )

                        # Update the max block seen *in this batch* for this address
                        current_max_block_for_addr = max(
                            current_max_block_for_addr, int(tx.get("blockNumber", 0))
                        )

                    except (ValueError, KeyError, TypeError) as e:
                        logging.error(
                            f"Error processing transaction data {tx.get('hash', 'N/A')} for {address_lower}: {e}. Skipping tx.",
                            exc_info=False,  # Keep log cleaner unless debugging
                        )
                    except Exception as e:
                        logging.error(
                            f"Unexpected error during single tx processing {tx.get('hash', 'N/A')} for {address_lower}: {e}",
                            exc_info=True,
                        )

                # Record the highest block number processed for this address in this cycle
                latest_block_processed[address_lower] = current_max_block_for_addr
                if notifications_sent > 0:
                    logging.info(
                        f"Sent {notifications_sent} notifications for {address_lower} up to block {current_max_block_for_addr}."
                    )

            except EtherscanRateLimitError:
                logging.warning(
                    f"Rate limited checking {address_lower}. Will retry next cycle. Not updating block number."
                )
                # Do not add to latest_block_processed if rate limited before getting data
            except EtherscanError as e:
                logging.error(
                    f"Etherscan API error for {address_lower}: {e}. Not updating block number."
                )
            except aiohttp.ClientError as e:
                logging.error(f"Network error checking {address_lower}: {e}")
            except asyncio.TimeoutError:
                logging.error(f"Timeout checking {address_lower}")
            except Exception as e:
                logging.error(
                    f"Unexpected error in check cycle for address {address_lower}: {e}",
                    exc_info=True,
                )
            # Ensure we proceed to the next address even if one fails

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
