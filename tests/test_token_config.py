# tests/test_token_config.py
"""Tests for TokenConfig validation and TokenRegistry."""
import pytest

from usdt_monitor_bot.token_config import TokenConfig, TokenRegistry

USDT_ADDR = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
USDC_ADDR = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"


def make_token(symbol="USDT", address=USDT_ADDR, decimals=6):
    return TokenConfig(
        name="Test Token",
        contract_address=address,
        decimals=decimals,
        symbol=symbol,
        display_name=symbol,
        explorer_url=f"https://etherscan.io/token/{address}",
    )


# --- TokenConfig validation ---


def test_token_config_valid():
    token = make_token()
    assert token.symbol == "USDT"
    assert token.decimals == 6


def test_token_config_invalid_address_no_0x():
    with pytest.raises(ValueError, match="Invalid contract address"):
        make_token(address="dAC17F958D2ee523a2206206994597C13D831ec7")


def test_token_config_invalid_decimals_zero():
    with pytest.raises(ValueError, match="Invalid decimals"):
        make_token(decimals=0)


def test_token_config_invalid_decimals_negative():
    with pytest.raises(ValueError, match="Invalid decimals"):
        make_token(decimals=-1)


def test_token_config_decimals_one_is_valid():
    token = make_token(decimals=1)
    assert token.decimals == 1


# --- TokenRegistry ---


def test_registry_register_and_get():
    registry = TokenRegistry()
    token = make_token()
    registry.register_token(token)
    assert registry.get_token("USDT") is token


def test_registry_get_case_insensitive():
    registry = TokenRegistry()
    registry.register_token(make_token())
    assert registry.get_token("usdt") is not None
    assert registry.get_token("USDT") is not None


def test_registry_get_unknown_returns_none():
    registry = TokenRegistry()
    assert registry.get_token("DAI") is None


def test_registry_duplicate_symbol_raises():
    registry = TokenRegistry()
    registry.register_token(make_token())
    with pytest.raises(ValueError, match="already registered"):
        registry.register_token(make_token())


def test_registry_get_token_by_address():
    registry = TokenRegistry()
    token = make_token()
    registry.register_token(token)
    result = registry.get_token_by_address(USDT_ADDR.lower())
    assert result is token


def test_registry_get_token_by_address_case_insensitive():
    registry = TokenRegistry()
    token = make_token()
    registry.register_token(token)
    # Registry lowercases the lookup address
    assert registry.get_token_by_address(USDT_ADDR.upper()) is token
    assert registry.get_token_by_address(USDT_ADDR.lower()) is token


def test_registry_get_token_by_address_unknown_returns_none():
    registry = TokenRegistry()
    assert registry.get_token_by_address("0xdeadbeef") is None


def test_registry_is_supported_token_true():
    registry = TokenRegistry()
    registry.register_token(make_token())
    assert registry.is_supported_token(USDT_ADDR) is True


def test_registry_is_supported_token_false():
    registry = TokenRegistry()
    assert registry.is_supported_token(USDT_ADDR) is False


def test_registry_get_all_tokens():
    registry = TokenRegistry()
    usdt = make_token("USDT", USDT_ADDR)
    usdc = make_token("USDC", USDC_ADDR)
    registry.register_token(usdt)
    registry.register_token(usdc)
    all_tokens = registry.get_all_tokens()
    assert set(all_tokens.keys()) == {"USDT", "USDC"}


def test_registry_get_all_tokens_returns_copy():
    registry = TokenRegistry()
    registry.register_token(make_token())
    copy1 = registry.get_all_tokens()
    copy1["EXTRA"] = make_token("EXTRA", "0x" + "a" * 40)
    assert "EXTRA" not in registry.get_all_tokens()
