"""
Database management module.

Handles all interactions with the SQLite database including user management,
wallet tracking, and transaction history storage.
"""

# Standard library
import asyncio
import functools
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import List, Optional


class WalletAddResult(Enum):
    """Result of wallet addition operation."""

    ADDED = auto()
    ALREADY_EXISTS = auto()
    DB_ERROR = auto()


class DatabaseManager:
    """Manages all interactions with the SQLite database."""

    def __init__(self, db_path: str, timeout: int = 10):
        self.db_path = db_path
        self.timeout = timeout
        logging.info(f"DatabaseManager initialized with path: {self.db_path}")

    def _execute_db_query(
        self,
        query: str,
        params: tuple = (),
        fetch_one: bool = False,
        fetch_all: bool = False,
        commit: bool = False,
    ):
        conn = None
        # For commit operations, we'll return rowcount on success, -1 on error.
        # For fetch_one/fetch_all, result is data or None.
        # For other operations (like CREATE), result is True/False.
        try:
            # Use a context manager for the connection
            with sqlite3.connect(
                self.db_path, timeout=self.timeout, check_same_thread=False
            ) as conn:
                conn.execute("PRAGMA foreign_keys = ON;")
                cursor = conn.cursor()
                cursor.execute(query, params)

                if commit:
                    conn.commit()
                    result = cursor.rowcount  # Return actual rowcount
                elif fetch_one:
                    result = cursor.fetchone()
                elif fetch_all:
                    result = cursor.fetchall()
                else:
                    # For non-commit, non-fetch queries (like CREATE TABLE)
                    result = True
            return result

        except sqlite3.Error as e:
            logging.error(f"Database error: {e} | Query: {query} | Params: {params}")
            if commit:
                return -1  # Special value for error in commit operation
            return None if fetch_one or fetch_all else False
        # No finally needed, 'with' handles closing

    async def _run_sync_db_operation(self, func, *args):
        """Runs synchronous DB functions in a separate thread."""
        # Prefer asyncio.to_thread if available (Python 3.9+)
        try:
            return await asyncio.to_thread(func, *args)
        except AttributeError:
            loop = asyncio.get_running_loop()
            # Fallback for older Python versions
            return await loop.run_in_executor(None, functools.partial(func, *args))

    # --- Initialization ---
    def _init_db_sync(self) -> bool:
        """
        Synchronously initialize database tables.

        Creates all required tables if they don't exist, including indexes.

        Returns:
            True if initialization succeeded, False otherwise
        """
        logging.info("Initializing database tables...")
        queries = [
            """CREATE TABLE IF NOT EXISTS users (
                   user_id INTEGER PRIMARY KEY, username TEXT, first_name TEXT, last_name TEXT,
                   first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
               )""",
            """CREATE TABLE IF NOT EXISTS wallets (
                   wallet_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, address TEXT NOT NULL,
                   added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                   UNIQUE(user_id, address)
               )""",
            """CREATE TABLE IF NOT EXISTS tracked_addresses (
                   address TEXT PRIMARY KEY,
                   last_checked_block INTEGER DEFAULT 0,
                   last_check_time TIMESTAMP
               )""",
            """CREATE TABLE IF NOT EXISTS transaction_history (
                   tx_hash TEXT PRIMARY KEY,
                   monitored_address TEXT NOT NULL,
                   from_address TEXT NOT NULL,
                   to_address TEXT NOT NULL,
                   value REAL NOT NULL,
                   block_number INTEGER NOT NULL,
                   timestamp TEXT NOT NULL,
                   token_symbol TEXT NOT NULL,
                   risk_score INTEGER,
                   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   FOREIGN KEY(monitored_address) REFERENCES tracked_addresses(address)
               )""",
            """CREATE INDEX IF NOT EXISTS idx_tx_history_monitored_address
                   ON transaction_history(monitored_address, block_number DESC)""",
            """CREATE INDEX IF NOT EXISTS idx_tx_history_timestamp
                   ON transaction_history(timestamp)""",
        ]
        success = True
        for query in queries:
            if not self._execute_db_query(
                query, commit=False
            ):  # CREATE doesn't need commit usually
                logging.error(f"Failed to execute table creation: {query[:50]}...")
                success = False
        if success:
            logging.info("Database initialization check complete.")
        else:
            logging.error("Errors occurred during database initialization.")
        return success

    async def init_db(self) -> bool:
        """Asynchronously initializes the database tables."""
        return await self._run_sync_db_operation(self._init_db_sync)

    # --- User Operations (Sync versions for internal use) ---
    def _add_user_sync(
        self,
        user_id: int,
        username: Optional[str],
        first_name: str,
        last_name: Optional[str],
    ) -> bool:
        query = "INSERT OR IGNORE INTO users (user_id, username, first_name, last_name) VALUES (?, ?, ?, ?)"
        return self._execute_db_query(
            query, (user_id, username, first_name, last_name), commit=True
        )

    def _check_user_exists_sync(self, user_id: int) -> bool:
        result = self._execute_db_query(
            "SELECT 1 FROM users WHERE user_id = ? LIMIT 1", (user_id,), fetch_one=True
        )
        return result is not None

    # --- Wallet Operations (Sync versions for internal use) ---
    def _add_wallet_sync(self, user_id: int, address: str) -> WalletAddResult:
        address_lower = address.lower()
        # Attempt to add to wallets table
        rowcount = self._execute_db_query(
            "INSERT OR IGNORE INTO wallets (user_id, address) VALUES (?, ?)",
            (user_id, address_lower),
            commit=True,
        )

        if rowcount > 0:
            # Successfully inserted a new wallet, now ensure it's in tracked_addresses
            tracked_rowcount = self._execute_db_query(
                "INSERT OR IGNORE INTO tracked_addresses (address) VALUES (?)",
                (address_lower,),
                commit=True,
            )
            if tracked_rowcount == -1:  # Error adding to tracked_addresses
                logging.error(
                    f"DB error while ensuring {address_lower} is in tracked_addresses after adding to wallets table for user {user_id}."
                )
                # This is a tricky state. The wallet is added for the user, but tracking might fail.
                # For now, report as ADDED because the primary user-facing operation succeeded.
                # Consider a compensating transaction or more robust error handling here if critical.
                return WalletAddResult.ADDED  # Or a new specific error state
            return WalletAddResult.ADDED
        elif rowcount == 0:
            # No rows affected means (user_id, address) already exists
            # Still ensure it's in tracked_addresses, as it might have been added by another user
            # and this user is just re-adding it.
            tracked_rowcount = self._execute_db_query(
                "INSERT OR IGNORE INTO tracked_addresses (address) VALUES (?)",
                (address_lower,),
                commit=True,
            )
            if tracked_rowcount == -1:  # Error adding to tracked_addresses
                logging.error(
                    f"DB error while ensuring {address_lower} is in tracked_addresses for an ALREADY_EXISTS wallet for user {user_id}."
                )
            # If this fails, it's not critical for the "already exists" status for this user.
            return WalletAddResult.ALREADY_EXISTS
        else:  # rowcount == -1, meaning DB error during INSERT OR IGNORE into wallets
            return WalletAddResult.DB_ERROR

    def _list_wallets_sync(self, user_id: int) -> Optional[List[str]]:
        results = self._execute_db_query(
            "SELECT address FROM wallets WHERE user_id = ? ORDER BY added_at",
            (user_id,),
            fetch_all=True,
        )
        return [row[0] for row in results] if isinstance(results, list) else None

    def _remove_wallet_sync(self, user_id: int, address: str) -> bool:
        return self._execute_db_query(
            "DELETE FROM wallets WHERE user_id = ? AND address = ?",
            (user_id, address.lower()),
            commit=True,
        )

    def _get_distinct_addresses_sync(self) -> Optional[List[str]]:
        results = self._execute_db_query(
            "SELECT DISTINCT address FROM wallets", fetch_all=True
        )
        # Filter out addresses that no user is tracking anymore - might be optional
        # This requires an extra join or subquery, consider performance if many addresses
        # For simplicity, we return all distinct addresses from wallets for now.
        # If needed, add cleanup logic separately.
        return [row[0] for row in results] if isinstance(results, list) else None

    def _get_users_for_address_sync(self, address: str) -> Optional[List[int]]:
        results = self._execute_db_query(
            "SELECT user_id FROM wallets WHERE address = ?",
            (address.lower(),),
            fetch_all=True,
        )
        return [row[0] for row in results] if isinstance(results, list) else None

    def _get_last_checked_block_sync(self, address: str) -> int:
        address_lower = address.lower()
        result = self._execute_db_query(
            "SELECT last_checked_block FROM tracked_addresses WHERE address = ?",
            (address_lower,),
            fetch_one=True,
        )
        if result is None:
            # Address might be new, ensure it's in tracked_addresses
            self._execute_db_query(
                "INSERT OR IGNORE INTO tracked_addresses (address) VALUES (?)",
                (address_lower,),
                commit=True,
            )
            return 0  # Default to 0 if not found
        # result is a tuple like (block_num,) or (None,)
        return result[0] if result and result[0] is not None else 0

    def _update_last_checked_block_sync(self, address: str, block_number: int) -> bool:
        query = "INSERT OR REPLACE INTO tracked_addresses (address, last_checked_block, last_check_time) VALUES (?, ?, ?)"
        # Convert datetime to ISO 8601 string format (UTC recommended)
        now_iso = datetime.now(timezone.utc).isoformat()
        return self._execute_db_query(
            query,
            (address.lower(), block_number, now_iso),
            commit=True,  # Pass string
        )

    # --- Async Public Methods ---
    async def add_user(
        self,
        user_id: int,
        username: Optional[str],
        first_name: str,
        last_name: Optional[str],
    ) -> bool:
        return await self._run_sync_db_operation(
            self._add_user_sync, user_id, username, first_name, last_name
        )

    async def check_user_exists(self, user_id: int) -> bool:
        return await self._run_sync_db_operation(self._check_user_exists_sync, user_id)

    async def add_wallet(self, user_id: int, address: str) -> WalletAddResult:
        return await self._run_sync_db_operation(
            self._add_wallet_sync, user_id, address
        )

    async def list_wallets(self, user_id: int) -> Optional[List[str]]:
        return await self._run_sync_db_operation(self._list_wallets_sync, user_id)

    async def remove_wallet(self, user_id: int, address: str) -> bool:
        return await self._run_sync_db_operation(
            self._remove_wallet_sync, user_id, address
        )

    async def get_distinct_addresses(self) -> Optional[List[str]]:
        return await self._run_sync_db_operation(self._get_distinct_addresses_sync)

    async def get_users_for_address(self, address: str) -> Optional[List[int]]:
        return await self._run_sync_db_operation(
            self._get_users_for_address_sync, address
        )

    async def get_last_checked_block(self, address: str) -> int:
        # Returns 0 if address not found or block is None/0
        result = await self._run_sync_db_operation(
            self._get_last_checked_block_sync, address
        )
        return result if isinstance(result, int) else 0

    async def update_last_checked_block(self, address: str, block_number: int) -> bool:
        return await self._run_sync_db_operation(
            self._update_last_checked_block_sync, address, block_number
        )

    # --- Transaction History Operations (Sync versions) ---
    def _store_transaction_sync(
        self,
        tx_hash: str,
        monitored_address: str,
        from_address: str,
        to_address: str,
        value: float,
        block_number: int,
        timestamp: str,  # ISO format string
        token_symbol: str,
        risk_score: Optional[int] = None,
    ) -> bool:
        """
        Store a transaction in the history table.

        Args:
            tx_hash: Transaction hash (primary key)
            monitored_address: The address being monitored
            from_address: Sender address
            to_address: Recipient address
            value: Transaction value in USDT
            block_number: Block number
            timestamp: ISO format timestamp string
            token_symbol: Token symbol (USDT, USDC, etc.)
            risk_score: Optional risk score from spam detection

        Returns:
            True if successful, False otherwise
        """
        query = """INSERT OR REPLACE INTO transaction_history
                   (tx_hash, monitored_address, from_address, to_address, value,
                    block_number, timestamp, token_symbol, risk_score)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"""
        rowcount = self._execute_db_query(
            query,
            (
                tx_hash,
                monitored_address.lower(),
                from_address.lower(),
                to_address.lower(),
                value,
                block_number,
                timestamp,
                token_symbol,
                risk_score,
            ),
            commit=True,
        )
        return rowcount > 0

    def _get_recent_transactions_sync(
        self, monitored_address: str, limit: int = 20
    ) -> List[dict]:
        """
        Get recent transactions for a monitored address, ordered by block number descending.

        Args:
            monitored_address: The address being monitored
            limit: Maximum number of transactions to return

        Returns:
            List of transaction dictionaries with keys matching TransactionMetadata fields
        """
        query = """SELECT tx_hash, from_address, to_address, value, block_number,
                          timestamp, token_symbol, risk_score
                   FROM transaction_history
                   WHERE monitored_address = ?
                   ORDER BY block_number DESC, timestamp DESC
                   LIMIT ?"""
        results = self._execute_db_query(
            query, (monitored_address.lower(), limit), fetch_all=True
        )
        if not results:
            return []

        transactions = []
        for row in results:
            transactions.append(
                {
                    "tx_hash": row[0],
                    "from_address": row[1],
                    "to_address": row[2],
                    "value": row[3],
                    "block_number": row[4],
                    "timestamp": row[5],
                    "token_symbol": row[6],
                    "risk_score": row[7],
                }
            )
        return transactions

    def _cleanup_old_transactions_sync(self, days_to_keep: int = 30) -> int:
        """
        Remove transactions older than specified days.

        Args:
            days_to_keep: Number of days of history to keep

        Returns:
            Number of transactions deleted
        """
        # Calculate cutoff timestamp
        cutoff = datetime.now(timezone.utc) - timedelta(days=days_to_keep)
        cutoff_iso = cutoff.isoformat()

        query = "DELETE FROM transaction_history WHERE timestamp < ?"
        rowcount = self._execute_db_query(query, (cutoff_iso,), commit=True)
        return rowcount if rowcount > 0 else 0

    def _is_new_sender_address_sync(
        self, monitored_address: str, sender_address: str
    ) -> bool:
        """
        Check if a sender address has been seen before for this monitored address.

        Args:
            monitored_address: The address being monitored
            sender_address: The sender address to check

        Returns:
            True if this is a new sender, False if seen before
        """
        query = """SELECT 1 FROM transaction_history
                   WHERE monitored_address = ? AND from_address = ?
                   LIMIT 1"""
        result = self._execute_db_query(
            query,
            (monitored_address.lower(), sender_address.lower()),
            fetch_one=True,
        )
        return result is None

    # --- Async Public Methods for Transaction History ---
    async def store_transaction(
        self,
        tx_hash: str,
        monitored_address: str,
        from_address: str,
        to_address: str,
        value: float,
        block_number: int,
        timestamp: str,
        token_symbol: str,
        risk_score: Optional[int] = None,
    ) -> bool:
        """Store a transaction in the history table."""
        return await self._run_sync_db_operation(
            self._store_transaction_sync,
            tx_hash,
            monitored_address,
            from_address,
            to_address,
            value,
            block_number,
            timestamp,
            token_symbol,
            risk_score,
        )

    async def get_recent_transactions(
        self, monitored_address: str, limit: int = 20
    ) -> List[dict]:
        """Get recent transactions for a monitored address."""
        return await self._run_sync_db_operation(
            self._get_recent_transactions_sync, monitored_address, limit
        )

    async def cleanup_old_transactions(self, days_to_keep: int = 30) -> int:
        """Remove transactions older than specified days."""
        return await self._run_sync_db_operation(
            self._cleanup_old_transactions_sync, days_to_keep
        )

    async def is_new_sender_address(
        self, monitored_address: str, sender_address: str
    ) -> bool:
        """Check if a sender address has been seen before."""
        return await self._run_sync_db_operation(
            self._is_new_sender_address_sync, monitored_address, sender_address
        )
