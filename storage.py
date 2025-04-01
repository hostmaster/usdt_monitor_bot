from typing import Optional
import logging
import shelve
from pathlib import Path

from config import settings

logger = logging.getLogger(__name__)


class TransactionStorage:
    """Storage for tracking processed transactions."""

    def __init__(self, db_path: str = settings.DB_PATH):
        """Initialize the transaction storage.

        Args:
            db_path: Path to the database file
        """
        self.db_path = db_path
        self._ensure_db_dir()

    def _ensure_db_dir(self) -> None:
        """Ensure the database directory exists."""
        db_dir = Path(self.db_path).parent
        if db_dir:
            db_dir.mkdir(parents=True, exist_ok=True)

    def is_new_transaction(self, tx_hash: str) -> bool:
        """Check if a transaction is new and mark it as processed.

        Args:
            tx_hash: Transaction hash to check

        Returns:
            True if transaction is new, False if already processed
        """
        try:
            with shelve.open(self.db_path, writeback=True) as db:
                is_new = tx_hash not in db
                if is_new:
                    db[tx_hash] = True
                    logger.debug(f"Marked transaction {tx_hash} as processed")
                else:
                    logger.debug(f"Transaction {tx_hash} already processed")
                return is_new
        except Exception as e:
            logger.error(f"Error checking transaction {tx_hash}: {e}")
            return False

    def cleanup_old_transactions(self, max_age_days: int = 30) -> None:
        """Clean up old transactions from the database.

        Args:
            max_age_days: Maximum age of transactions to keep in days
        """
        # TODO: Implement cleanup logic
        logger.info("Transaction cleanup not implemented yet")
