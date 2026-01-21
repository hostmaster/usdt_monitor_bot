from datetime import datetime

from aiogram.utils.markdown import hbold, hcode


# --- General Messages ---
ERROR_UNEXPECTED = "⚠️ An unexpected error occurred. Please try again later."
ERROR_UNKNOWN_COMMAND = "😕 Sorry, I didn't understand that. Please use /help to see the available commands."
INVALID_ETH_ADDRESS_FORMAT = "❌ Invalid Ethereum address format. It should start with '0x' and be 42 characters long."

# --- /start Command ---
START_INTRO = "I can monitor your Ethereum addresses for incoming USDT transfers.\nUse /help to see the commands."

def welcome_message(full_name: str, is_returning: bool) -> str:
    """Generates the welcome message for the /start command."""
    greeting = "Welcome back" if is_returning else "Hello there"
    return f"{greeting}, {hbold(full_name)}! Welcome!"

# --- /help Command ---
HELP_TEXT = (
    f"{hbold('Available Commands:')}\n"
    "/start - Start interaction\n"
    "/help - Show this help message\n"
    f"/add {hcode('<eth_address>')} - Monitor address for incoming USDT\n"
    "/list - List your monitored addresses\n"
    f"/remove {hcode('<eth_address>')} - Stop monitoring address\n"
    "/spam - View detected spam transactions report\n\n"
    f"ℹ️ I check wallets every few minutes for new {hbold('incoming USDT')} "
    "transfers and notify you if found.\n"
    "Spam/dust transactions are automatically filtered and can be reviewed via /spam."
)

# --- /add Command ---
def add_wallet_missing_address() -> str:
    """Message for when /add is called without an address."""
    return f"❌ Please provide an address.\nUsage: {hcode('/add 0x123...')}"

def add_wallet_success(address: str) -> str:
    """Message for successfully adding a wallet."""
    return f"✅ Now monitoring for incoming USDT transfers to: {hcode(address)}"

def add_wallet_already_exists(address: str) -> str:
    """Message for when the wallet is already being monitored."""
    return f"ℹ️ Address {hcode(address)} is already in your monitoring list."

# --- /list Command ---
LIST_WALLETS_ERROR = "⚠️ An error occurred while fetching your wallet list. Please try again later."
LIST_WALLETS_EMPTY = "ℹ️ You are not currently monitoring any addresses. Use /add to start."

def format_wallet_list(wallets: list[str]) -> str:
    """Formats the list of monitored wallets."""
    header = f"{hbold('Your monitored wallets (for USDT):')}"
    items = [f"• {hcode(addr)}" for addr in wallets]
    return "\n".join([header] + items)

# --- /remove Command ---
def remove_wallet_missing_address() -> str:
    """Message for when /remove is called without an address."""
    return f"❌ Please provide an address to remove.\nUsage: {hcode('/remove 0x123...')}"

def remove_wallet_success(address: str) -> str:
    """Message for successfully removing a wallet."""
    return f"🗑️ Stopped monitoring for incoming USDT to: {hcode(address)}"

def remove_wallet_not_found(address: str) -> str:
    """Message for when the wallet to remove is not found."""
    return f"⚠️ Address {hcode(address)} was not found in your monitored list or a database error occurred."

# Note: The "Invalid Ethereum address format" message for /remove in the original handlers.py
# was slightly different ("❌ Invalid Ethereum address format.").
# I am using the more descriptive, shared constant INVALID_ETH_ADDRESS_FORMAT for consistency.
# If a different message is truly desired, it can be defined here.
REMOVE_WALLET_INVALID_ADDRESS = "❌ Invalid Ethereum address format."

# --- /spam Command ---
SPAM_REPORT_EMPTY = "✅ No spam transactions detected for your monitored addresses."
SPAM_REPORT_ERROR = "⚠️ An error occurred while fetching spam report. Please try again later."


def format_spam_summary(summary: dict) -> str:
    """Format spam summary statistics."""
    count = summary.get("count", 0)
    total_value = summary.get("total_value", 0.0)
    avg_score = summary.get("avg_score", 0)
    max_score = summary.get("max_score", 0)

    return (
        f"{hbold('Spam Detection Summary')}\n"
        f"Total blocked: {hbold(str(count))} transactions\n"
        f"Total dust value: {total_value:.4f} tokens\n"
        f"Risk scores: avg {avg_score}/100, max {max_score}/100"
    )


def format_spam_transaction(tx: dict, index: int) -> str:
    """Format a single spam transaction for display."""
    from_addr = tx.get("from_address", "")
    value = tx.get("value", 0.0)
    token = tx.get("token_symbol", "???")
    risk_score = tx.get("risk_score", 0)
    timestamp = tx.get("timestamp", "")

    # Format timestamp if available
    time_str = ""
    if timestamp:
        try:
            if "T" in timestamp:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                time_str = dt.strftime("%m/%d %H:%M")
            else:
                dt = datetime.fromtimestamp(float(timestamp))
                time_str = dt.strftime("%m/%d %H:%M")
        except (ValueError, TypeError):
            time_str = ""

    # Short address format
    from_short = f"{from_addr[:6]}...{from_addr[-4:]}" if len(from_addr) >= 10 else from_addr

    return (
        f"{index}. {hbold(f'Score: {risk_score}/100')}\n"
        f"   From: {hcode(from_short)}\n"
        f"   Amount: {value:.4f} {token}\n"
        f"   {time_str}"
    )


def format_spam_report(summary: dict, transactions: list[dict], limit: int = 10) -> str:
    """
    Format the full spam report with summary and recent transactions.

    Args:
        summary: Spam summary statistics
        transactions: List of spam transaction dictionaries
        limit: Maximum number of transactions to show

    Returns:
        Formatted spam report string
    """
    parts = [format_spam_summary(summary), ""]

    if transactions:
        parts.append(f"{hbold('Recent Spam Transactions')} (showing up to {limit}):\n")
        for i, tx in enumerate(transactions[:limit], 1):
            parts.append(format_spam_transaction(tx, i))
            parts.append("")  # Empty line between transactions

        if len(transactions) > limit:
            parts.append(f"...and {len(transactions) - limit} more")
    else:
        parts.append("No individual spam transactions to display.")

    return "\n".join(parts)
