# tests/conftest.py

from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

# Import Aiogram components needed for mocking/specs
from aiogram import Bot
from aiogram.filters.command import CommandObject
from aiogram.types import Chat, Message, User

# Import project components
from usdt_monitor_bot.config import BotConfig
from usdt_monitor_bot.database import DatabaseManager
from usdt_monitor_bot.etherscan import EtherscanClient
from usdt_monitor_bot.notifier import NotificationService


@pytest.fixture
def mock_config() -> BotConfig:
    """Provides a basic BotConfig for testing."""
    return BotConfig(
        bot_token="fake_token",
        etherscan_api_key="fake_etherscan_key",
        database_file=":memory:",
        check_interval_seconds=10,
        etherscan_request_delay=0.1,
        usdt_contract_address="0xdAC17F958D2ee523a2206206994597C13D831ec7".lower(),
        usdt_decimals=6,
        etherscan_api_url="https://api.etherscan.io/api",
        etherscan_timeout_seconds=5,
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
    # Use spec=DatabaseManager
    manager = AsyncMock(spec=DatabaseManager)
    manager.init_db = AsyncMock(return_value=True)
    manager.add_user = AsyncMock(return_value=True)  # Simulate successful first add
    manager.check_user_exists = AsyncMock(return_value=False)  # Default to not existing
    manager.add_wallet = AsyncMock(return_value=True)  # Simulate successful first add
    manager.list_wallets = AsyncMock(return_value=[])  # Default to empty list
    manager.remove_wallet = AsyncMock(return_value=True)  # Simulate successful remove
    manager.get_distinct_addresses = AsyncMock(return_value=[])  # Default to empty list
    manager.get_users_for_address = AsyncMock(return_value=[])  # Default to empty list
    manager.get_last_checked_block = AsyncMock(return_value=0)  # Default to 0
    manager.update_last_checked_block = AsyncMock(return_value=True)  # Simulate success
    return manager


@pytest.fixture
def mock_etherscan_client() -> AsyncMock:
    # Use spec=EtherscanClient
    client = AsyncMock(spec=EtherscanClient)
    client.get_usdt_token_transactions = AsyncMock(
        return_value=[]
    )  # Default to empty list
    return client


@pytest.fixture
def mock_notifier() -> AsyncMock:
    # Use spec=NotificationService
    notifier = AsyncMock(spec=NotificationService)
    notifier.send_usdt_notification = AsyncMock()
    return notifier


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
