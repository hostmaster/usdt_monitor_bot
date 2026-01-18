# tests/test_utils.py
"""
Tests for utility functions like address validation.

Note: Token message formatting tests are in test_notifier.py.
"""

from usdt_monitor_bot.handlers import is_valid_ethereum_address


class TestAddressValidation:
    """Tests for Ethereum address validation."""

    def test_valid_lowercase_address(self):
        """Valid lowercase hex address should pass."""
        assert is_valid_ethereum_address("0x1234567890123456789012345678901234567890")
        assert is_valid_ethereum_address("0xabcdef0123456789abcdef0123456789abcdef01")

    def test_valid_uppercase_address(self):
        """Valid uppercase hex address should pass."""
        assert is_valid_ethereum_address("0xABCDEF0123456789ABCDEF0123456789ABCDEF01")

    def test_valid_mixed_case_address(self):
        """Valid mixed case hex address should pass."""
        assert is_valid_ethereum_address("0xAbCdEf0123456789aBcDeF0123456789AbCdEf01")

    def test_invalid_no_0x_prefix(self):
        """Address without 0x prefix should fail."""
        assert not is_valid_ethereum_address(
            "1234567890123456789012345678901234567890"
        )

    def test_invalid_too_short(self):
        """Address that's too short should fail."""
        assert not is_valid_ethereum_address("0x123")
        assert not is_valid_ethereum_address("0x12345678901234567890123456789012345678")

    def test_invalid_too_long(self):
        """Address that's too long should fail."""
        assert not is_valid_ethereum_address(
            "0x123456789012345678901234567890123456789012"
        )

    def test_invalid_non_hex_characters(self):
        """Address with non-hex characters should fail."""
        assert not is_valid_ethereum_address(
            "0xghijklmnopqrstuvwxyz1234567890123456"
        )
        assert not is_valid_ethereum_address(
            "0x123456789012345678901234567890123456789g"
        )

    def test_invalid_not_an_address(self):
        """Random strings should fail."""
        assert not is_valid_ethereum_address("not_an_address")
        assert not is_valid_ethereum_address("")
        assert not is_valid_ethereum_address("hello world")

    def test_invalid_none_input(self):
        """None input should fail gracefully."""
        assert not is_valid_ethereum_address(None)

    def test_invalid_non_string_input(self):
        """Non-string inputs should fail gracefully."""
        assert not is_valid_ethereum_address(12345)
        assert not is_valid_ethereum_address(["0x1234567890123456789012345678901234567890"])
        assert not is_valid_ethereum_address({"address": "0x123"})

    def test_valid_checksum_address(self):
        """EIP-55 checksum addresses should pass (we don't validate checksum, just format)."""
        # Real USDT contract address
        assert is_valid_ethereum_address("0xdAC17F958D2ee523a2206206994597C13D831ec7")
        # Real USDC contract address
        assert is_valid_ethereum_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
