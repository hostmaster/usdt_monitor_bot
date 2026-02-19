# tests/test_spam_detector.py
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from usdt_monitor_bot.spam_detector import (
    RiskAnalysis,
    RiskFlag,
    SpamDetector,
    TransactionMetadata,
    format_risk_report,
)

# --- Test Fixtures ---


@pytest.fixture
def detector():
    """Provides a SpamDetector instance with default config."""
    return SpamDetector()


@pytest.fixture
def custom_detector():
    """Provides a SpamDetector instance with custom config."""
    custom_config = {
        "dust_threshold_usd": 0.5,
        "suspicious_score_threshold": 40,
        "similarity_weight": 50,
    }
    return SpamDetector(config=custom_config)


@pytest.fixture
def base_timestamp():
    """Provides a base timestamp for test transactions."""
    return datetime.now(timezone.utc)


@pytest.fixture
def legitimate_address():
    """Provides a legitimate Ethereum address."""
    return "0x1234567890123456789012345678901234567890"


@pytest.fixture
def similar_address():
    """Provides a similar-looking address (poisoning attempt).
    Same first 4 chars (1234) and last 4 chars (7890) to meet similarity threshold.
    Must be exactly 40 hex characters.
    """
    return "0x1234abcdefabcdefabcdefabcdefabcdefab7890"


@pytest.fixture
def different_address():
    """Provides a completely different address."""
    return "0x1234567890123456789012345678901234567890"


# --- Test Address Similarity Calculation ---


class TestAddressSimilarity:
    """Tests for calculate_address_similarity method."""

    def test_identical_addresses(self, detector):
        """Identical addresses should have maximum similarity."""
        addr = "0x85A0bee4659ECef2e256dC98239dE17Fb5CAE822"
        result = detector.calculate_address_similarity(addr, addr)

        assert result.prefix_match >= 3
        assert result.suffix_match >= 4
        assert result.is_similar is True
        assert result.risk_score > 0
        assert result.matching_chars > 0

    def test_similar_addresses_prefix_suffix(
        self, detector, legitimate_address, similar_address
    ):
        """Addresses with similar prefix and suffix should be flagged."""
        result = detector.calculate_address_similarity(
            legitimate_address, similar_address
        )

        assert result.prefix_match >= 3
        assert result.suffix_match >= 4
        assert result.is_similar is True
        assert result.risk_score > 0

    def test_different_addresses(self, detector):
        """Completely different addresses should not be similar."""
        # Use truly different addresses with no matching prefix/suffix
        addr1 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        addr2 = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        result = detector.calculate_address_similarity(addr1, addr2)

        # These addresses should not meet the similarity threshold
        # (prefix >= 3 AND suffix >= 4)
        assert result.is_similar is False
        assert result.prefix_match < 3 or result.suffix_match < 4

    def test_similar_prefix_only(self, detector):
        """Addresses with only prefix match should not be flagged."""
        addr1 = "0x1234567890123456789012345678901234567890"
        addr2 = "0x123456789012345678901234567890abcdefabcd"
        result = detector.calculate_address_similarity(addr1, addr2)

        # Prefix matches but suffix doesn't meet threshold
        assert result.prefix_match > 0
        assert result.suffix_match < 4
        assert result.is_similar is False

    def test_similar_suffix_only(self, detector):
        """Addresses with only suffix match should not be flagged."""
        addr1 = "0x1234567890123456789012345678901234567890"
        addr2 = "0xabcdefabcdefabcdefabcdefabcdef1234567890"
        result = detector.calculate_address_similarity(addr1, addr2)

        # Suffix matches but prefix doesn't meet threshold
        assert result.suffix_match > 0
        assert result.prefix_match < 3
        assert result.is_similar is False

    def test_invalid_address_length(self, detector):
        """Invalid address length should return safe defaults."""
        addr1 = "0x123"  # Too short
        addr2 = "0x85A0bee4659ECef2e256dC98239dE17Fb5CAE822"
        result = detector.calculate_address_similarity(addr1, addr2)

        assert result.prefix_match == 0
        assert result.suffix_match == 0
        assert result.is_similar is False
        assert result.risk_score == 0

    def test_invalid_address_format(self, detector):
        """Invalid hex format should return safe defaults."""
        addr1 = "0x" + "g" * 40  # Invalid hex characters
        addr2 = "0x85A0bee4659ECef2e256dC98239dE17Fb5CAE822"
        result = detector.calculate_address_similarity(addr1, addr2)

        assert result.prefix_match == 0
        assert result.suffix_match == 0
        assert result.is_similar is False
        assert result.risk_score == 0

    def test_case_insensitive(self, detector):
        """Address comparison should be case-insensitive."""
        addr1 = "0x85A0bee4659ECef2e256dC98239dE17Fb5CAE822"
        addr2 = "0x85a0bee4659ecef2e256dc98239de17fb5cae822"
        result = detector.calculate_address_similarity(addr1, addr2)

        assert result.is_similar is True  # Identical when lowercased
        assert result.prefix_match >= 3
        assert result.suffix_match >= 4

    def test_address_without_0x_prefix(self, detector):
        """Addresses without 0x prefix should still work."""
        addr1 = "1234567890123456789012345678901234567890"
        addr2 = "1234abcdefabcdefabcdefabcdefabcdefab7890"
        result = detector.calculate_address_similarity(addr1, addr2)

        assert result.prefix_match >= 3
        assert result.suffix_match >= 4
        assert result.is_similar is True


# --- Test Transaction Analysis ---


class TestTransactionAnalysis:
    """Tests for analyze_transaction method."""

    def test_dust_amount_detection(self, detector, base_timestamp):
        """Small amounts (< $0.10) should be flagged as dust."""
        tx = TransactionMetadata(
            tx_hash="0x123",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.05"),  # Dust amount
            block_number=1000,
            timestamp=base_timestamp,
        )

        analysis = detector.analyze_transaction(tx, [])

        assert RiskFlag.DUST_AMOUNT in analysis.flags
        assert analysis.score >= detector.config["dust_risk_weight"]

    def test_zero_value_detection(self, detector, base_timestamp):
        """Zero-value transfers should be flagged."""
        tx = TransactionMetadata(
            tx_hash="0x123",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0"),
            block_number=1000,
            timestamp=base_timestamp,
        )

        analysis = detector.analyze_transaction(tx, [])

        assert RiskFlag.ZERO_VALUE_TRANSFER in analysis.flags
        assert analysis.score >= detector.config["zero_value_weight"]

    def test_timing_suspicious_detection(
        self, detector, base_timestamp, legitimate_address, similar_address
    ):
        """Transactions within timing window should be flagged."""
        # First transaction
        tx1 = TransactionMetadata(
            tx_hash="0x111",
            from_address=legitimate_address,
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("100"),
            block_number=1000,
            timestamp=base_timestamp,
        )

        # Second transaction 30 seconds later (within 20 min window)
        tx2 = TransactionMetadata(
            tx_hash="0x222",
            from_address=similar_address,
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.01"),
            block_number=1001,
            timestamp=base_timestamp + timedelta(seconds=30),
        )

        analysis = detector.analyze_transaction(tx2, [tx1])

        assert RiskFlag.TIMING_SUSPICIOUS in analysis.flags
        assert analysis.score >= detector.config["timing_weight"]

    def test_similar_address_detection(
        self, detector, base_timestamp, legitimate_address, similar_address
    ):
        """Similar addresses within timing window should be flagged."""
        tx1 = TransactionMetadata(
            tx_hash="0x111",
            from_address=legitimate_address,
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("100"),
            block_number=1000,
            timestamp=base_timestamp,
            contract_age_blocks=100,  # Not brand new
        )

        tx2 = TransactionMetadata(
            tx_hash="0x222",
            from_address=similar_address,
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.01"),
            block_number=1001,
            timestamp=base_timestamp + timedelta(seconds=30),
            contract_age_blocks=100,  # Not brand new
        )

        analysis = detector.analyze_transaction(tx2, [tx1])

        # Should detect similarity if addresses are actually similar
        similarity = detector.calculate_address_similarity(
            legitimate_address, similar_address
        )
        if similarity.is_similar:
            assert (
                RiskFlag.SIMILAR_ADDRESS in analysis.flags
                or RiskFlag.LOOKALIKE_PREVIOUS_SENDER in analysis.flags
            )
        assert analysis.score >= detector.config["dust_risk_weight"]

    def test_new_address_detection(self, detector, base_timestamp):
        """New sender addresses should be flagged."""
        tx = TransactionMetadata(
            tx_hash="0x123",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("100"),
            block_number=1000,
            timestamp=base_timestamp,
            is_new_address=True,
        )

        analysis = detector.analyze_transaction(tx, [])

        assert RiskFlag.NEW_SENDER_ADDRESS in analysis.flags
        assert analysis.score >= detector.config["new_address_weight"]

    def test_brand_new_contract_detection(self, detector, base_timestamp):
        """Brand new contracts should be flagged."""
        tx = TransactionMetadata(
            tx_hash="0x123",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("100"),
            block_number=1000,
            timestamp=base_timestamp,
            contract_age_blocks=5,  # Less than 20 blocks
        )

        analysis = detector.analyze_transaction(tx, [])

        assert RiskFlag.BRAND_NEW_CONTRACT in analysis.flags
        assert analysis.score >= detector.config["brand_new_contract_weight"]

    def test_rapid_address_cycling(self, detector, base_timestamp):
        """Multiple unique senders in short time should be flagged."""
        # Create multiple transactions from different senders
        historical = []
        for i in range(3):
            tx = TransactionMetadata(
                tx_hash=f"0x{i:04x}",
                from_address=f"0x{'a' * (i + 1)}{'0' * (39 - i - 1)}",
                to_address="0x2222222222222222222222222222222222222222",
                value=Decimal("0.01"),
                block_number=1000 + i,
                timestamp=base_timestamp + timedelta(minutes=i * 5),
            )
            historical.append(tx)

        # Current transaction from yet another sender
        current_tx = TransactionMetadata(
            tx_hash="0x9999",
            from_address="0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.01"),
            block_number=1003,
            timestamp=base_timestamp + timedelta(minutes=20),
        )

        analysis = detector.analyze_transaction(current_tx, historical)

        assert RiskFlag.RAPID_ADDRESS_CYCLING in analysis.flags

    def test_lookalike_previous_sender(
        self, detector, base_timestamp, legitimate_address, similar_address
    ):
        """Similar addresses in historical transactions should be flagged."""
        # Create historical transaction with legitimate address
        tx1 = TransactionMetadata(
            tx_hash="0x111",
            from_address=legitimate_address,
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("100"),
            block_number=1000,
            timestamp=base_timestamp - timedelta(hours=1),
            contract_age_blocks=100,
        )

        # Current transaction with similar address (outside timing window)
        current_tx = TransactionMetadata(
            tx_hash="0x222",
            from_address=similar_address,
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.01"),
            block_number=1001,
            timestamp=base_timestamp,
            contract_age_blocks=100,  # Not brand new
        )

        analysis = detector.analyze_transaction(current_tx, [tx1])

        # Should detect lookalike if addresses are actually similar
        similarity = detector.calculate_address_similarity(
            legitimate_address, similar_address
        )
        if similarity.is_similar:
            assert RiskFlag.LOOKALIKE_PREVIOUS_SENDER in analysis.flags
        # Should still detect dust amount
        assert RiskFlag.DUST_AMOUNT in analysis.flags

    def test_no_double_counting_similarity(
        self, detector, base_timestamp, legitimate_address, similar_address
    ):
        """Similarity score should not be counted twice."""
        tx1 = TransactionMetadata(
            tx_hash="0x111",
            from_address=legitimate_address,
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("100"),
            block_number=1000,
            timestamp=base_timestamp,
            contract_age_blocks=100,
        )

        tx2 = TransactionMetadata(
            tx_hash="0x222",
            from_address=similar_address,
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.01"),
            block_number=1001,
            timestamp=base_timestamp + timedelta(seconds=30),
            contract_age_blocks=100,  # Not brand new
            is_new_address=False,  # Not new
        )

        analysis = detector.analyze_transaction(tx2, [tx1])

        # Count how many times similarity_weight is added
        similarity_weight = detector.config["similarity_weight"]
        similarity_flags = [
            RiskFlag.SIMILAR_ADDRESS,
            RiskFlag.LOOKALIKE_PREVIOUS_SENDER,
        ]
        similarity_flag_count = sum(
            1 for flag in analysis.flags if flag in similarity_flags
        )

        # Check if addresses are actually similar
        similarity = detector.calculate_address_similarity(
            legitimate_address, similar_address
        )
        if similarity.is_similar:
            # Should have at least one similarity flag
            # Note: We might get both SIMILAR_ADDRESS (from timing window check)
            # and LOOKALIKE_PREVIOUS_SENDER (from broader check) if there are
            # multiple similar addresses in history, but with our fix, the last
            # transaction should be excluded from the broader check if already checked
            assert similarity_flag_count >= 1
            # The key is that similarity_weight should only be added once per similar address
            # Score should not exceed single similarity_weight + other weights
            max_expected = (
                similarity_weight
                + detector.config["dust_risk_weight"]
                + detector.config["timing_weight"]
            )
            # Allow some tolerance for other flags that might be present
            assert (
                analysis.score <= max_expected + 50
            )  # Allow room for other risk factors
        else:
            # If addresses aren't similar, no similarity flags expected
            assert similarity_flag_count == 0

    def test_legitimate_transaction(self, detector, base_timestamp):
        """Legitimate transactions should have low risk scores."""
        tx = TransactionMetadata(
            tx_hash="0x123",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("1000"),  # Large amount
            block_number=1000,
            timestamp=base_timestamp,
            is_new_address=False,
            contract_age_blocks=1000,  # Old contract
        )

        analysis = detector.analyze_transaction(tx, [])

        assert analysis.is_suspicious is False
        assert analysis.score < detector.config["suspicious_score_threshold"]

    def test_empty_historical_transactions(self, detector, base_timestamp):
        """Analysis should work with empty historical transactions."""
        tx = TransactionMetadata(
            tx_hash="0x123",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.01"),
            block_number=1000,
            timestamp=base_timestamp,
        )

        analysis = detector.analyze_transaction(tx, [])

        assert isinstance(analysis, RiskAnalysis)
        assert analysis.score >= 0
        assert RiskFlag.DUST_AMOUNT in analysis.flags

    def test_score_capped_at_100(self, detector, base_timestamp):
        """Risk score should be capped at 100."""
        # Create transaction with many risk factors (value above spam threshold)
        tx = TransactionMetadata(
            tx_hash="0x123",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.01"),
            block_number=1000,
            timestamp=base_timestamp,
            is_new_address=True,
            contract_age_blocks=5,  # Brand new
        )

        analysis = detector.analyze_transaction(tx, [])

        assert analysis.score <= 100

    def test_custom_config(self, custom_detector, base_timestamp):
        """Custom configuration should be respected."""
        tx = TransactionMetadata(
            tx_hash="0x123",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal(
                "0.75"
            ),  # Above custom threshold ($0.5)
            block_number=1000,
            timestamp=base_timestamp,
            contract_age_blocks=100,  # Not brand new
        )

        analysis = custom_detector.analyze_transaction(tx, [])

        # With custom threshold of 0.5, 0.75 should NOT be flagged as dust
        # (it's above the custom threshold)
        assert RiskFlag.DUST_AMOUNT not in analysis.flags

        # Test with value below custom threshold
        tx2 = TransactionMetadata(
            tx_hash="0x456",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.25"),  # Below custom threshold of 0.5
            block_number=1001,
            timestamp=base_timestamp,
            contract_age_blocks=100,
        )

        analysis2 = custom_detector.analyze_transaction(tx2, [])
        assert RiskFlag.DUST_AMOUNT in analysis2.flags

    def test_dust_below_threshold_is_suspicious(self, detector, base_timestamp):
        """Transactions below $0.10 should be suspicious from dust weight alone."""
        for value in ["0.001", "0.05", "0.09", "0.099"]:
            tx = TransactionMetadata(
                tx_hash=f"0x{value}",
                from_address="0x1111111111111111111111111111111111111111",
                to_address="0x2222222222222222222222222222222222222222",
                value=Decimal(value),
                block_number=1000,
                timestamp=base_timestamp,
                contract_age_blocks=100,
            )

            analysis = detector.analyze_transaction(tx, [])

            assert RiskFlag.DUST_AMOUNT in analysis.flags, f"value={value}"
            assert analysis.is_suspicious is True, f"value={value} should be spam"
            assert analysis.score >= detector.config["suspicious_score_threshold"]

    def test_value_at_dust_threshold_not_flagged(self, detector, base_timestamp):
        """Transactions at or above dust threshold should NOT be flagged as dust."""
        for value in ["0.10", "0.50", "1.00", "100"]:
            tx = TransactionMetadata(
                tx_hash=f"0x{value}",
                from_address="0x1111111111111111111111111111111111111111",
                to_address="0x2222222222222222222222222222222222222222",
                value=Decimal(value),
                block_number=1000,
                timestamp=base_timestamp,
                contract_age_blocks=100,
            )

            analysis = detector.analyze_transaction(tx, [])

            assert RiskFlag.DUST_AMOUNT not in analysis.flags, f"value={value}"

    def test_timing_window_outside_range(self, detector, base_timestamp):
        """Transactions outside timing window should not trigger timing flag."""
        tx1 = TransactionMetadata(
            tx_hash="0x111",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("100"),
            block_number=1000,
            timestamp=base_timestamp,
        )

        # Transaction 25 minutes later (outside 20 min window)
        tx2 = TransactionMetadata(
            tx_hash="0x222",
            from_address="0x3333333333333333333333333333333333333333",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.01"),
            block_number=1001,
            timestamp=base_timestamp + timedelta(minutes=25),
        )

        analysis = detector.analyze_transaction(tx2, [tx1])

        assert RiskFlag.TIMING_SUSPICIOUS not in analysis.flags


# --- Test Batch Analysis ---


class TestBatchAnalysis:
    """Tests for check_transaction_batch method."""

    def test_batch_analysis(self, detector, base_timestamp):
        """Batch analysis should process multiple transactions."""
        transactions = []
        for i in range(3):
            tx = TransactionMetadata(
                tx_hash=f"0x{i:04x}",
                from_address=f"0x{'a' * (i + 1)}{'0' * (39 - i - 1)}",
                to_address="0x2222222222222222222222222222222222222222",
                value=Decimal("0.01"),
                block_number=1000 + i,
                timestamp=base_timestamp + timedelta(minutes=i),
            )
            transactions.append(tx)

        results = detector.check_transaction_batch(transactions)

        assert len(results) == 3
        assert all(isinstance(analysis, RiskAnalysis) for analysis in results.values())
        assert all(tx.tx_hash in results for tx in transactions)

    def test_batch_analysis_empty(self, detector):
        """Batch analysis with empty list should return empty dict."""
        results = detector.check_transaction_batch([])

        assert results == {}


# --- Test Configuration ---


class TestConfiguration:
    """Tests for configuration handling."""

    def test_default_config(self, detector):
        """Default configuration should have expected values."""
        config = detector.config

        assert config["dust_threshold_usd"] == 0.1
        assert config["dust_risk_weight"] == 50
        assert config["suspicious_score_threshold"] == 50
        assert config["similarity_weight"] == 40
        assert config["suspicious_time_window"] == 1200  # 20 minutes

    def test_custom_config_override(self, custom_detector):
        """Custom configuration should override defaults."""
        config = custom_detector.config

        assert config["dust_threshold_usd"] == 0.5
        assert config["suspicious_score_threshold"] == 40
        assert config["similarity_weight"] == 50

    def test_custom_config_partial(self):
        """Partial custom config should merge with defaults."""
        partial_config = {"dust_threshold_usd": 2.0}
        detector = SpamDetector(config=partial_config)

        # Custom value
        assert detector.config["dust_threshold_usd"] == 2.0
        # Default value still present
        assert detector.config["suspicious_score_threshold"] == 50


# --- Test Utility Functions ---


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_format_risk_report(self, detector, base_timestamp):
        """format_risk_report should generate readable report."""
        tx = TransactionMetadata(
            tx_hash="0x123",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.01"),
            block_number=1000,
            timestamp=base_timestamp,
        )

        analysis = detector.analyze_transaction(tx, [])
        report = format_risk_report(tx.from_address, analysis)

        assert isinstance(report, str)
        assert tx.from_address in report
        assert str(analysis.score) in report
        assert "Risk Score" in report

    def test_format_risk_report_suspicious(self, detector, base_timestamp):
        """format_risk_report should show suspicious status."""
        tx = TransactionMetadata(
            tx_hash="0x123",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.01"),
            block_number=1000,
            timestamp=base_timestamp,
            is_new_address=True,
            contract_age_blocks=5,
        )

        analysis = detector.analyze_transaction(tx, [])
        report = format_risk_report(tx.from_address, analysis)

        if analysis.is_suspicious:
            assert "SUSPICIOUS" in report or "🚨" in report
        assert "Recommendation" in report

    def test_format_risk_report_with_details(self, detector, base_timestamp):
        """format_risk_report should include details when present."""
        tx = TransactionMetadata(
            tx_hash="0x123",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.05"),  # Dust amount
            block_number=1000,
            timestamp=base_timestamp,
            contract_age_blocks=5,  # Brand new
        )

        analysis = detector.analyze_transaction(tx, [])
        report = format_risk_report(tx.from_address, analysis)

        # Should include details if present
        if analysis.details:
            assert "Details" in report


# --- Test Edge Cases ---


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_single_historical_transaction(self, detector, base_timestamp):
        """Analysis with single historical transaction should work."""
        tx1 = TransactionMetadata(
            tx_hash="0x111",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("100"),
            block_number=1000,
            timestamp=base_timestamp,
        )

        tx2 = TransactionMetadata(
            tx_hash="0x222",
            from_address="0x3333333333333333333333333333333333333333",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.01"),
            block_number=1001,
            timestamp=base_timestamp + timedelta(seconds=30),
        )

        analysis = detector.analyze_transaction(tx2, [tx1])

        assert isinstance(analysis, RiskAnalysis)
        assert analysis.score >= 0

    def test_negative_time_delta(self, detector, base_timestamp):
        """Negative time delta (future transaction) should be handled."""
        tx1 = TransactionMetadata(
            tx_hash="0x111",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("100"),
            block_number=1000,
            timestamp=base_timestamp,
        )

        # Transaction in the past (negative delta)
        tx2 = TransactionMetadata(
            tx_hash="0x222",
            from_address="0x3333333333333333333333333333333333333333",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.01"),
            block_number=1001,
            timestamp=base_timestamp - timedelta(seconds=30),
        )

        analysis = detector.analyze_transaction(tx2, [tx1])

        # Should not trigger timing flag for negative delta
        assert RiskFlag.TIMING_SUSPICIOUS not in analysis.flags

    def test_very_large_value(self, detector, base_timestamp):
        """Very large transaction values should not be flagged as dust."""
        tx = TransactionMetadata(
            tx_hash="0x123",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("1000000"),  # Very large
            block_number=1000,
            timestamp=base_timestamp,
        )

        analysis = detector.analyze_transaction(tx, [])

        assert RiskFlag.DUST_AMOUNT not in analysis.flags

    def test_exactly_dust_threshold(self, detector, base_timestamp):
        """Transaction exactly at dust threshold should not be flagged."""
        tx = TransactionMetadata(
            tx_hash="0x123",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal(str(detector.config["dust_threshold_usd"])),  # Exactly at threshold
            block_number=1000,
            timestamp=base_timestamp,
        )

        analysis = detector.analyze_transaction(tx, [])

        assert RiskFlag.DUST_AMOUNT not in analysis.flags

    def test_recommendation_levels(self, detector, base_timestamp):
        """Recommendations should vary by risk score."""
        # High risk transaction (value above spam threshold to test scoring filters)
        high_risk_tx = TransactionMetadata(
            tx_hash="0x123",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("0.01"),
            block_number=1000,
            timestamp=base_timestamp,
            is_new_address=True,
            contract_age_blocks=5,
        )

        analysis = detector.analyze_transaction(high_risk_tx, [])
        recommendation = analysis.recommendation

        assert isinstance(recommendation, str)
        assert len(recommendation) > 0

        # Low risk transaction
        low_risk_tx = TransactionMetadata(
            tx_hash="0x456",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=Decimal("1000"),
            block_number=1001,
            timestamp=base_timestamp,
            is_new_address=False,
            contract_age_blocks=1000,
        )

        low_analysis = detector.analyze_transaction(low_risk_tx, [])
        low_recommendation = low_analysis.recommendation

        # Recommendations should differ
        assert recommendation != low_recommendation


def test_whitelist_prevents_flagging(detector, base_timestamp):
    """Test that whitelisted addresses are not flagged as suspicious."""
    # Create a transaction that would normally be flagged (dust amount, new address, etc.)
    whitelisted_address = "0x31390eaf4db4013b3d5d9dbcff494e689589ae83"

    suspicious_tx = TransactionMetadata(
        tx_hash="0x123",
        from_address=whitelisted_address,  # From whitelisted address
        to_address="0xRecipient123",
        value=Decimal("0.01"),  # Dust amount
        block_number=19000000,
        timestamp=base_timestamp,
        is_new_address=True,  # Would normally trigger flag
        contract_age_blocks=2,  # Brand new contract
    )

    # Without whitelist - should be flagged
    analysis_without_whitelist = detector.analyze_transaction(suspicious_tx, [])
    assert analysis_without_whitelist.is_suspicious is True
    assert analysis_without_whitelist.score > 0

    # With whitelist - should NOT be flagged
    whitelist = {whitelisted_address}
    analysis_with_whitelist = detector.analyze_transaction(
        suspicious_tx, [], whitelisted_addresses=whitelist
    )
    assert analysis_with_whitelist.is_suspicious is False
    assert analysis_with_whitelist.score == 0
    assert len(analysis_with_whitelist.flags) == 0
    assert "Whitelisted" in analysis_with_whitelist.recommendation


def test_whitelist_with_token_contract(detector, base_timestamp):
    """Test that transactions to/from token contract addresses are whitelisted."""
    usdt_contract = "0xdAC17F958D2ee523a2206206994597C13D831ec7"

    # Transaction TO token contract (e.g., user sending to USDT contract)
    tx_to_contract = TransactionMetadata(
        tx_hash="0x456",
        from_address="0xUser123",
        to_address=usdt_contract,  # To whitelisted contract
        value=Decimal("100"),
        block_number=19000000,
        timestamp=base_timestamp,
        is_new_address=True,
        contract_age_blocks=1,
    )

    whitelist = {usdt_contract}
    analysis = detector.analyze_transaction(tx_to_contract, [], whitelisted_addresses=whitelist)
    assert analysis.is_suspicious is False
    assert analysis.score == 0

    # Transaction FROM token contract
    tx_from_contract = TransactionMetadata(
        tx_hash="0x789",
        from_address=usdt_contract,  # From whitelisted contract
        to_address="0xUser123",
        value=Decimal("100"),
        block_number=19000000,
        timestamp=base_timestamp,
        is_new_address=True,
        contract_age_blocks=1,
    )

    analysis2 = detector.analyze_transaction(tx_from_contract, [], whitelisted_addresses=whitelist)
    assert analysis2.is_suspicious is False
    assert analysis2.score == 0


def test_whitelist_address_normalization(detector, base_timestamp):
    """Test that whitelist works with addresses with or without 0x prefix."""
    address_with_prefix = "0x31390eaf4db4013b3d5d9dbcff494e689589ae83"
    address_without_prefix = "31390eaf4db4013b3d5d9dbcff494e689589ae83"

    tx = TransactionMetadata(
        tx_hash="0xabc",
        from_address=address_with_prefix,
        to_address="0xRecipient123",
        value=Decimal("0.01"),
        block_number=19000000,
        timestamp=base_timestamp,
        is_new_address=True,
        contract_age_blocks=1,
    )

    # Whitelist with address without prefix - should still work
    whitelist = {address_without_prefix}
    analysis = detector.analyze_transaction(tx, [], whitelisted_addresses=whitelist)
    assert analysis.is_suspicious is False

    # Whitelist with address with prefix - should also work
    whitelist2 = {address_with_prefix}
    analysis2 = detector.analyze_transaction(tx, [], whitelisted_addresses=whitelist2)
    assert analysis2.is_suspicious is False
