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
    # 1. Configure basic logging first (before config load)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # 2. Load Configuration
    config = load_config()

    # 3. Adjust logging level based on verbose setting
    if config.verbose_logging:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("DEBUG logging enabled")

    # Suppress verbose logs from third-party libraries
    logging.getLogger("apscheduler.executors.default").setLevel(logging.WARNING)
    logging.getLogger("aiosqlite").setLevel(logging.WARNING)

    # 4. Initialize Database
    db_manager = DatabaseManager(db_path=config.db_path)
    if not await db_manager.init_db():
        logging.critical("Database init failed, exiting")
        return

    # 5. Initialize Bot and Dispatcher
    bot_session = AiohttpSession(limit=10)
    bot = Bot(
        token=config.telegram_bot_token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
        session=bot_session,
    )
    dp = Dispatcher(db_manager=db_manager)
    logging.debug("Bot initialized with session limit=10")

    # 6. Initialize Services
    etherscan_client = EtherscanClient(config=config)
    notifier = NotificationService(bot=bot, config=config)
    transaction_checker = TransactionChecker(
        config=config,
        db_manager=db_manager,
        etherscan_client=etherscan_client,
        notifier=notifier,
    )

    # 7. Register Handlers
    register_handlers(dp, db_manager)

    # 8. Setup and Start Scheduler
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

    # 9. Start Bot Polling
    logging.info("Bot started, polling for updates...")
    try:
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    finally:
        logging.info("Shutting down...")
        scheduler.shutdown(wait=True)
        await etherscan_client.close()
        await bot.session.close()
        logging.debug("Cleanup complete")


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
