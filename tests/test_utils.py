# tests/test_utils.py
"""
Tests for utility functions like address validation.

Note: Token message formatting tests are in test_notifier.py.
"""

import pytest

from usdt_monitor_bot.handlers import is_valid_ethereum_address


class TestAddressValidation:
    """Tests for Ethereum address validation."""

    @pytest.mark.parametrize(
        "addr",
        [
            "0x1234567890123456789012345678901234567890",
            "0xabcdef0123456789abcdef0123456789abcdef01",
        ],
        ids=["lower_0_9", "lower_a_f"],
    )
    def test_valid_lowercase_address(self, addr: str):
        assert is_valid_ethereum_address(addr)

    def test_valid_uppercase_address(self):
        assert is_valid_ethereum_address("0xABCDEF0123456789ABCDEF0123456789ABCDEF01")

    def test_valid_mixed_case_address(self):
        assert is_valid_ethereum_address("0xAbCdEf0123456789aBcDeF0123456789AbCdEf01")

    @pytest.mark.parametrize(
        "addr",
        [
            "1234567890123456789012345678901234567890",
            "0x123",
            "0x12345678901234567890123456789012345678",
            "0x123456789012345678901234567890123456789012",
            "0xghijklmnopqrstuvwxyz1234567890123456",
            "0x123456789012345678901234567890123456789g",
            "not_an_address",
            "",
            "hello world",
        ],
        ids=[
            "no_0x",
            "too_short_0x123",
            "too_short_39_hex",
            "too_long",
            "non_hex_letters",
            "non_hex_tail",
            "not_address",
            "empty",
            "hello_world",
        ],
    )
    def test_invalid_addresses_rejected(self, addr: str):
        assert not is_valid_ethereum_address(addr)

    def test_invalid_none_input(self):
        assert not is_valid_ethereum_address(None)

    @pytest.mark.parametrize(
        "addr",
        [12345, ["0x1234567890123456789012345678901234567890"], {"address": "0x123"}],
        ids=["int", "list", "dict"],
    )
    def test_invalid_non_string_input(self, addr: object):
        assert not is_valid_ethereum_address(addr)  # type: ignore[arg-type]

    def test_valid_checksum_address(self):
        assert is_valid_ethereum_address("0xdAC17F958D2ee523a2206206994597C13D831ec7")
        assert is_valid_ethereum_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
