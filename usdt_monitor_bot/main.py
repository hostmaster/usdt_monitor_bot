"""
Main application entry point.

Initializes and starts the USDT Monitor Bot, including database setup,
Telegram bot configuration, and transaction checking scheduler.
"""

# Standard library
import asyncio
import logging
import os
import time
from datetime import datetime
from pathlib import Path

# Third-party
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from apscheduler.schedulers.asyncio import AsyncIOScheduler

# Local
from usdt_monitor_bot.checker import TransactionChecker
from usdt_monitor_bot.config import load_config
from usdt_monitor_bot.database import DatabaseManager
from usdt_monitor_bot.etherscan import EtherscanClient
from usdt_monitor_bot.handlers import register_handlers
from usdt_monitor_bot.notifier import NotificationService

# Debug log path - works in both local and container environments
_DEBUG_LOG_PATH = None


def _get_debug_log_path() -> str:
    """Get the debug log file path, creating it if necessary."""
    global _DEBUG_LOG_PATH
    if _DEBUG_LOG_PATH is None:
        # Try to find workspace root by looking for .cursor directory or pyproject.toml
        current = Path.cwd()
        for parent in [current] + list(current.parents):
            if (parent / ".cursor").exists() or (parent / "pyproject.toml").exists():
                _DEBUG_LOG_PATH = str(parent / ".cursor" / "debug.log")
                # Ensure .cursor directory exists
                (parent / ".cursor").mkdir(exist_ok=True)
                break
        else:
            # Fallback: use current directory
            _DEBUG_LOG_PATH = str(Path.cwd() / ".cursor" / "debug.log")
            Path(_DEBUG_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
    return _DEBUG_LOG_PATH


async def main() -> None:
    # 1. Configure basic logging first (before config load, which also logs)
    # We'll adjust the level after loading config
    logging.basicConfig(
        level=logging.INFO,  # Start with INFO, will adjust based on config
        format="%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s",
        # Optional: Add file handler
        # handlers=[
        #     logging.StreamHandler(),
        #     logging.FileHandler("bot.log")
        # ]
    )

    # 2. Load Configuration
    config = load_config()

    # 3. Adjust logging level based on verbose setting
    if config.verbose_logging:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled (DEBUG level).")
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.info("Logging configured (INFO level).")

    # Suppress verbose logs from third-party libraries
    logging.getLogger("apscheduler.executors.default").setLevel(logging.WARNING)
    logging.getLogger("aiosqlite").setLevel(logging.WARNING)

    # 3. Initialize Database
    db_manager = DatabaseManager(db_path=config.db_path)
    if not await db_manager.init_db():
        logging.critical("Database initialization failed. Exiting.")
        return  # Or raise an exception

    # 4. Initialize Bot and Dispatcher
    bot = Bot(
        token=config.telegram_bot_token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = Dispatcher(db_manager=db_manager)  # Pass db_manager here for handler injection
    logging.info("Aiogram Bot and Dispatcher initialized.")

    # 5. Initialize Services (Clients, Notifier, Checker)
    etherscan_client = EtherscanClient(config=config)
    notifier = NotificationService(bot=bot, config=config)
    transaction_checker = TransactionChecker(
        config=config,
        db_manager=db_manager,
        etherscan_client=etherscan_client,
        notifier=notifier,
    )

    # 6. Register Handlers
    register_handlers(dp, db_manager)  # db_manager already passed to Dispatcher

    # 7. Setup and Start Scheduler
    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        transaction_checker.check_all_addresses,
        "interval",
        seconds=config.check_interval_seconds,
        next_run_time=datetime.now(),
        id="usdt_check_job",
        replace_existing=True,
    )
    scheduler.start()
    logging.info(
        f"Scheduler started. Checking transactions every {config.check_interval_seconds} seconds."
    )

    # 8. Start Bot Polling
    logging.info("Starting bot polling...")
    try:
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    finally:
        logging.info("Shutting down...")
        scheduler.shutdown(wait=True)  # Wait for running jobs to complete
        # #region agent log
        try:
            fd_count = len(os.listdir('/proc/self/fd')) if os.path.exists('/proc/self/fd') else -1
            with open(_get_debug_log_path(), 'a') as f:
                import json
                f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"D","location":"main.py:103","message":"Before closing resources","data":{"fd_count":fd_count},"timestamp":int(time.time()*1000)}) + '\n')
        except Exception:
            pass
        # #endregion
        await etherscan_client.close()
        # #region agent log
        try:
            fd_count = len(os.listdir('/proc/self/fd')) if os.path.exists('/proc/self/fd') else -1
            with open(_get_debug_log_path(), 'a') as f:
                import json
                f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"D","location":"main.py:105","message":"After etherscan_client.close()","data":{"fd_count":fd_count},"timestamp":int(time.time()*1000)}) + '\n')
        except Exception:
            pass
        # #endregion
        await bot.session.close()
        # #region agent log
        try:
            fd_count = len(os.listdir('/proc/self/fd')) if os.path.exists('/proc/self/fd') else -1
            with open(_get_debug_log_path(), 'a') as f:
                import json
                f.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"D","location":"main.py:106","message":"After bot.session.close()","data":{"fd_count":fd_count},"timestamp":int(time.time()*1000)}) + '\n')
        except Exception:
            pass
        # #endregion
        logging.info("Scheduler shut down. Bot session closed. Exiting.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logging.info("Bot stopped manually.")
    except Exception as e:
        # Log any critical error that might happen outside the main loop setup
        logging.critical(
            f"Critical unexpected error in main execution: {e}", exc_info=True
        )
