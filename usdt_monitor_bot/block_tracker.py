"""Block number tracking and determination for transaction checking."""

import logging
from dataclasses import dataclass
from typing import List, Literal, Optional

from usdt_monitor_bot.blockchain_provider import BlockchainProvider


@dataclass
class BlockDeterminationResult:
    """Result of determining the next block number to check."""

    final_block_number: int
    """The final block number to use for the next check."""

    resetting_to_latest: bool
    """Whether the block was reset/capped to sync with the blockchain."""


class BlockTracker:
    """Manages block number advancement and capping for a monitored address."""

    def __init__(self, etherscan_client: BlockchainProvider) -> None:
        self._etherscan = etherscan_client

    async def determine_next_block(
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
            latest_block: Latest block from blockchain (fetched if None)

        Returns:
            BlockDeterminationResult with final_block_number and resetting_to_latest flag
        """
        # Fetch latest block if not provided (for backward compatibility)
        if latest_block is None:
            latest_block = await self._etherscan.get_latest_block_number()

        # Handle case when latest block cannot be retrieved
        if latest_block is None:
            return self.handle_latest_block_unavailable(
                start_block, new_last_block, raw_transactions, address_lower
            )

        # Sync with blockchain
        final_block, resetting_to_latest = self.sync_block_with_blockchain(
            start_block, new_last_block, latest_block, address_lower
        )

        # If no transactions found and blockchain hasn't advanced, update to latest
        if not raw_transactions and final_block == start_block:
            if latest_block >= start_block:
                logging.debug(
                    f"Advance {address_lower[:8]}... {start_block}->{latest_block}"
                )
                final_block = latest_block

        return BlockDeterminationResult(
            final_block_number=final_block,
            resetting_to_latest=resetting_to_latest,
        )

    @staticmethod
    def cap_block_to_latest(
        block_value: int,
        latest_block: Optional[int],
        address_lower: str,
        context: str = "",
        log_level: Literal["debug", "warning"] = "debug",
    ) -> int:
        """
        Cap a block number to the latest blockchain block to prevent getting ahead.

        Args:
            block_value: The block number to potentially cap
            latest_block: The latest block number from blockchain (None if unavailable)
            address_lower: The monitored address for logging
            context: Additional context for the log message
            log_level: Logging level - "debug" or "warning" (default: "debug")

        Returns:
            The capped block value (or original if no capping needed)
        """
        if latest_block is not None and block_value > latest_block:
            context_str = f" ({context})" if context else ""
            msg = f"Capping block {block_value}->{latest_block} for {address_lower[:8]}...{context_str}"
            if log_level == "warning":
                logging.warning(msg)
            else:
                logging.debug(msg)
            return latest_block
        return block_value

    @staticmethod
    def handle_latest_block_unavailable(
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
                f"No latest block for {address_lower[:8]}..., advancing {start_block}->{final_block}"
            )
        return BlockDeterminationResult(
            final_block_number=final_block,
            resetting_to_latest=False,
        )

    @staticmethod
    def sync_block_with_blockchain(
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
            logging.warning(
                f"DB ahead of chain for {address_lower[:8]}...: {start_block}->{latest_block}"
            )
            return latest_block, True

        if new_last_block > latest_block:
            logging.warning(
                f"Block cap for {address_lower[:8]}...: {new_last_block}->{latest_block}"
            )
            return latest_block, True

        return new_last_block, resetting_to_latest
