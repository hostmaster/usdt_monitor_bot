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
    f"/start - Start interaction\n"
    f"/help - Show this help message\n"
    f"/add {hcode('<eth_address>')} - Monitor address for incoming USDT\n"
    f"/list - List your monitored addresses\n"
    f"/remove {hcode('<eth_address>')} - Stop monitoring address\n\n"
    f"ℹ️ I check wallets every few minutes for new {hbold('incoming USDT')} "
    f"transfers and notify you if found."
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
    items = [f" L {hcode(addr)}" for addr in wallets]
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
