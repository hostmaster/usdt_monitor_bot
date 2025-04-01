#!/usr/bin/env python3
"""Test script to verify all dependencies work correctly."""

import asyncio
import logging
from typing import Any

import aiohttp
import pydantic
import requests
import structlog
import tenacity
from dotenv import load_dotenv
from pydantic_settings import BaseSettings
from telegram import Bot
from telegram.constants import ParseMode

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
log = structlog.get_logger()


class TestSettings(BaseSettings):
    """Test settings."""

    test_value: str = "test"


@tenacity.retry(stop=tenacity.stop_after_attempt(3))
async def test_aiohttp() -> None:
    """Test aiohttp functionality."""
    async with aiohttp.ClientSession() as session:
        async with session.get("https://api.github.com") as response:
            assert response.status == 200
            log.info("aiohttp test passed")


def test_requests() -> None:
    """Test requests functionality."""
    response = requests.get("https://api.github.com")
    assert response.status_code == 200
    log.info("requests test passed")


def test_pydantic() -> None:
    """Test pydantic functionality."""
    settings = TestSettings()
    assert settings.test_value == "test"
    log.info("pydantic test passed")


def test_pydantic_settings() -> None:
    """Test pydantic-settings functionality."""
    load_dotenv()
    settings = TestSettings()
    assert isinstance(settings, BaseSettings)
    log.info("pydantic-settings test passed")


def test_structlog() -> None:
    """Test structlog functionality."""
    log.info("structlog test message")
    log.info("structlog test passed")


async def test_telegram() -> None:
    """Test telegram functionality."""
    # This is a mock test since we don't have actual credentials
    bot = Bot("dummy_token")
    assert isinstance(bot, Bot)
    log.info("telegram test passed")


async def main() -> None:
    """Run all dependency tests."""
    try:
        # Test synchronous dependencies
        test_requests()
        test_pydantic()
        test_pydantic_settings()
        test_structlog()

        # Test asynchronous dependencies
        await test_aiohttp()
        await test_telegram()

        log.info("All dependency tests passed successfully")
    except Exception as e:
        log.error("Dependency test failed", error=str(e))
        raise


if __name__ == "__main__":
    asyncio.run(main())
