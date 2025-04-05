# main.py
import asyncio
import datetime
import logging

import aiohttp
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
    db_manager = DatabaseManager(db_path=config.database_file)
    if not await db_manager.init_db():
        logging.critical("Database initialization failed. Exiting.")
        return  # Or raise an exception

    # 4. Initialize Bot and Dispatcher
    bot = Bot(
        token=config.bot_token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = Dispatcher(db_manager=db_manager)  # Pass db_manager here for handler injection
    logging.info("Aiogram Bot and Dispatcher initialized.")

    # 5. Setup Network Client (aiohttp session)
    async with aiohttp.ClientSession() as session:
        logging.info("Aiohttp ClientSession created.")

        # 6. Initialize Services (Clients, Notifier, Checker)
        etherscan_client = EtherscanClient(
            session=session,
            api_key=config.etherscan_api_key,
            api_url=config.etherscan_api_url,
            usdt_contract=config.usdt_contract_address,
            timeout=config.etherscan_timeout_seconds,
        )
        notifier = NotificationService(bot=bot, config=config)
        transaction_checker = TransactionChecker(
            config=config,
            db_manager=db_manager,
            etherscan_client=etherscan_client,
            notifier=notifier,
        )

        # 7. Register Handlers
        # Pass necessary dependencies to the registration function
        register_handlers(dp, db_manager)  # db_manager already passed to Dispatcher

        # 8. Setup and Start Scheduler
        scheduler = AsyncIOScheduler(timezone="UTC")
        scheduler.add_job(
            transaction_checker.check_all_addresses,  # Use the method from the checker instance
            "interval",
            seconds=config.check_interval_seconds,
            next_run_time=datetime.now(),  # Run immediately on start
            id="usdt_check_job",
            replace_existing=True,  # Avoid duplicate jobs on restart if needed
        )
        scheduler.start()
        logging.info(
            f"Scheduler started. Checking transactions every {config.check_interval_seconds} seconds."
        )

        # 9. Start Bot Polling
        logging.info("Starting bot polling...")
        try:
            # Start polling without skipping updates initially to process any missed ones
            await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
        finally:
            logging.info("Shutting down...")
            scheduler.shutdown()
            # Session is closed automatically by async with
            await bot.session.close()  # Gracefully close bot session
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
