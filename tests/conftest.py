# tests/conftest.py

import os
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

# Import Aiogram components needed for mocking/specs
from aiogram import Bot
from aiogram.filters.command import CommandObject
from aiogram.types import Chat, Message, User

from usdt_monitor_bot.checker import TransactionChecker

# Import project components
from usdt_monitor_bot.config import BotConfig
from usdt_monitor_bot.database import DatabaseManager
from usdt_monitor_bot.etherscan import EtherscanClient
from usdt_monitor_bot.notifier import NotificationService


@pytest.fixture
def mock_config() -> BotConfig:
    """Provides a basic BotConfig for testing."""
    # Set required environment variables
    os.environ["TELEGRAM_BOT_TOKEN"] = "fake_token"
    os.environ["ETHERSCAN_API_KEY"] = "fake_etherscan_key"
    os.environ["DB_PATH"] = ":memory:"
    os.environ["ETHERSCAN_BASE_URL"] = "https://api-test.etherscan.io/api"
    os.environ["ETHERSCAN_REQUEST_DELAY"] = "0.1"
    os.environ["USDT_CONTRACT_ADDRESS"] = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    os.environ["USDC_CONTRACT_ADDRESS"] = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

    return BotConfig(
        telegram_bot_token=os.environ["TELEGRAM_BOT_TOKEN"],
        etherscan_api_key=os.environ["ETHERSCAN_API_KEY"],
    )


@pytest.fixture
async def memory_db_manager(tmp_path) -> DatabaseManager:  # Use pytest's tmp_path
    """Provides an initialized DatabaseManager using a temporary file DB."""
    db_path = tmp_path / "test_db.sqlite"  # Simpler filename using tmp_path
    db_manager = DatabaseManager(db_path=str(db_path))  # Pass path as string
    initialized = await db_manager.init_db()
    assert initialized, f"Temp file DB initialization failed at {db_path}"
    # No manual yield/cleanup needed, tmp_path handles it
    return db_manager  # Return instance directly


# --- Mocks for Aiogram Objects ---


@pytest.fixture
def mock_user() -> MagicMock:
    # Use spec=User for better mocking
    user = MagicMock(spec=User)
    user.id = 12345
    user.username = "testuser"
    user.first_name = "Test"
    user.last_name = "User"
    user.full_name = "Test User"
    return user


@pytest.fixture
def mock_chat() -> MagicMock:
    # Use spec=Chat
    chat = MagicMock(spec=Chat)
    chat.id = 12345
    chat.type = "private"
    return chat


@pytest.fixture
def mock_message(mock_user, mock_chat) -> AsyncMock:
    # Use spec=Message
    message = AsyncMock(spec=Message)
    message.from_user = mock_user
    message.chat = mock_chat
    message.text = ""
    message.message_id = 1
    # Mock async methods directly on the AsyncMock instance
    message.reply = AsyncMock()
    message.answer = AsyncMock()
    return message


@pytest.fixture
def mock_command_object() -> MagicMock:
    # Use spec=CommandObject
    command = MagicMock(spec=CommandObject)
    command.args = None
    return command


@pytest.fixture
def mock_bot() -> AsyncMock:
    # Use spec=Bot
    bot = AsyncMock(spec=Bot)
    bot.send_message = AsyncMock()
    bot.session = AsyncMock()
    bot.session.close = AsyncMock()
    return bot


# --- Mocks for Service Dependencies ---


@pytest.fixture
def mock_db_manager() -> AsyncMock:
    """Provides a mocked DatabaseManager."""
    return AsyncMock(spec=DatabaseManager)


@pytest.fixture
def mock_etherscan_client() -> AsyncMock:
    """Provides a mocked EtherscanClient."""
    return AsyncMock(spec=EtherscanClient)


@pytest.fixture
def mock_notifier() -> AsyncMock:
    """Provides a mocked NotificationService."""
    return AsyncMock(spec=NotificationService)


@pytest.fixture
def checker(
    mock_config: BotConfig,
    mock_db_manager: AsyncMock,
    mock_etherscan_client: AsyncMock,
    mock_notifier: AsyncMock,
) -> TransactionChecker:
    """Provides a TransactionChecker with mocked dependencies."""
    return TransactionChecker(
        config=mock_config,
        db_manager=mock_db_manager,
        etherscan_client=mock_etherscan_client,
        notifier=mock_notifier,
    )


@pytest.fixture
def mock_aiohttp_session() -> MagicMock:
    """Mocks aiohttp.ClientSession correctly for 'async with session.get(...)' usage."""
    mock_session = MagicMock(spec=aiohttp.ClientSession)

    # 1. This is the final response object (the result of __aenter__)
    mock_response = AsyncMock(spec=aiohttp.ClientResponse)
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={"status": "1", "message": "OK", "result": []}
    )
    mock_response.text = AsyncMock(
        return_value='{"status": "1", "message": "OK", "result": []}'
    )
    mock_response.raise_for_status = MagicMock()

    # 2. This object *is* the async context manager.
    #    It must have awaitable __aenter__ and __aexit__.
    mock_context_manager = AsyncMock()  # <<< Use AsyncMock for the manager itself
    mock_context_manager.__aenter__ = AsyncMock(
        return_value=mock_response
    )  # __aenter__ returns the response
    mock_context_manager.__aexit__ = AsyncMock(return_value=None)

    # 3. Configure session.get to be a SYNCHRONOUS MagicMock
    #    that directly RETURNS the mock_context_manager object.
    mock_session.get = MagicMock(return_value=mock_context_manager)

    mock_session.close = AsyncMock()

    return mock_session
