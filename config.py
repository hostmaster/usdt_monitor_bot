from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings."""

    # API Configuration
    ETHERSCAN_API_KEY: str = Field(..., description="Etherscan API key")
    USDT_CONTRACT: str = Field(
        "0xdac17f958d2ee523a2206206994597c13d831ec7",
        description="USDT contract address",
    )
    HTTP_TIMEOUT: int = Field(5, description="HTTP request timeout in seconds")

    # Telegram Configuration
    TG_BOT_TOKEN: str = Field(..., description="Telegram bot token")
    TG_CHAT_ID: str = Field(..., description="Telegram chat ID for notifications")

    # Wallet Configuration
    WALLET_ADDRESS: str = Field(..., description="Ethereum wallet address to monitor")

    # Application Configuration
    DB_PATH: str = Field("tx", description="Path to the transaction database")
    POLLING_INTERVAL: int = Field(
        60, description="Transaction polling interval in seconds"
    )
    POLLING_START_DELAY: int = Field(
        10, description="Initial delay before starting polling in seconds"
    )

    class Config:
        env_file = ".env"
        case_sensitive = True


# Create global settings instance
settings = Settings()
