"""
Main application entry point.

Initializes and starts the USDT Monitor Bot, including database setup,
Telegram bot configuration, and transaction checking scheduler.
"""

# Standard library
import asyncio
import logging
from datetime import datetime

# Third-party
import aiohttp
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.enums import ParseMode
from apscheduler.schedulers.asyncio import AsyncIOScheduler

# Local
from usdt_monitor_bot.checker import TransactionChecker
from usdt_monitor_bot.config import load_config
from usdt_monitor_bot.database import DatabaseManager
from usdt_monitor_bot.etherscan import EtherscanClient
from usdt_monitor_bot.handlers import register_handlers
from usdt_monitor_bot.notifier import NotificationService

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
    # FIX: Configure custom connector with strict limits to prevent FD leaks
    # The default aiogram session uses limit=100 which can accumulate FDs over time
    bot_connector = aiohttp.TCPConnector(
        limit=10,  # Maximum total connections (reduced from default 100)
        limit_per_host=5,  # Maximum connections per host (Telegram API)
        enable_cleanup_closed=True,  # Clean up closed SSL transports to prevent FD leaks
        force_close=True,  # Close connections after each request
        ttl_dns_cache=300,  # DNS cache TTL (5 minutes)
    )
    bot_session = AiohttpSession(connector=bot_connector)
    bot = Bot(
        token=config.telegram_bot_token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
        session=bot_session,
    )
    dp = Dispatcher(db_manager=db_manager)  # Pass db_manager here for handler injection
    logging.info("Aiogram Bot and Dispatcher initialized with custom session.")

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
        await etherscan_client.close()
        await bot.session.close()
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
