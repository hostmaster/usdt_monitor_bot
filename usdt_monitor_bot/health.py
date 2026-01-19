"""Health check for container orchestration."""

from usdt_monitor_bot.config import check_required_env_vars


def ready() -> bool:
    """Return True if required environment variables are set."""
    return check_required_env_vars()
