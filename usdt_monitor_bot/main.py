# main.py
import asyncio
import logging
from datetime import datetime

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from apscheduler.schedulers.asyncio import AsyncIOScheduler

# Import refactored components
from usdt_monitor_bot.checker import TransactionChecker
from usdt_monitor_bot.config import load_config
from usdt_monitor_bot.database import DatabaseManager
from usdt_monitor_bot.etherscan import EtherscanClient
from usdt_monitor_bot.handlers import register_handlers
from usdt_monitor_bot.notifier import NotificationService


async def main() -> None:
    # 1. Configure Logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s",
        # Optional: Add file handler
        # handlers=[
        #     logging.StreamHandler(),
        #     logging.FileHandler("bot.log")
        # ]
    )
    logging.getLogger("apscheduler.executors.default").setLevel(logging.WARNING)
    logging.getLogger("aiosqlite").setLevel(
        logging.WARNING
    )  # Quieten DB logs if needed
    logging.info("Logging configured.")

    # 2. Load Configuration
    config = load_config()
    logging.info("Configuration loaded.")

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
        scheduler.shutdown()
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
