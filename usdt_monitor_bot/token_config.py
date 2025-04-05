from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class TokenConfig:
    """Configuration for a supported token."""

    name: str
    contract_address: str
    decimals: int
    symbol: str
    display_name: str
    explorer_url: str
    # Add any additional token-specific settings here

    def __post_init__(self):
        """Validate token configuration after initialization."""
        if not self.contract_address.startswith("0x"):
            raise ValueError(
                f"Invalid contract address for {self.name}: {self.contract_address}"
            )
        if self.decimals <= 0:
            raise ValueError(f"Invalid decimals for {self.name}: {self.decimals}")


class TokenRegistry:
    """Registry of supported tokens."""

    def __init__(self):
        self._tokens: Dict[str, TokenConfig] = {}

    def register_token(self, token: TokenConfig) -> None:
        """Register a new token configuration."""
        if token.symbol in self._tokens:
            raise ValueError(f"Token with symbol {token.symbol} already registered")
        self._tokens[token.symbol] = token

    def get_token(self, symbol: str) -> Optional[TokenConfig]:
        """Get token configuration by symbol."""
        return self._tokens.get(symbol.upper())

    def get_token_by_address(self, address: str) -> Optional[TokenConfig]:
        """Get token configuration by contract address."""
        address = address.lower()
        for token in self._tokens.values():
            if token.contract_address.lower() == address:
                return token
        return None

    def get_all_tokens(self) -> Dict[str, TokenConfig]:
        """Get all registered tokens."""
        return self._tokens.copy()

    def is_supported_token(self, address: str) -> bool:
        """Check if a token address is supported."""
        return self.get_token_by_address(address) is not None
