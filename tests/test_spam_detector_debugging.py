"""
Test spam detector debugging instrumentation.

Demonstrates how debug logging helps identify spam bypass cases.
"""

import logging
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from usdt_monitor_bot.spam_detector import (
    SpamDebuggingLogger,
    SpamDetector,
    TransactionMetadata,
    enable_spam_detector_debugging,
)


@pytest.fixture(autouse=True)
def reset_debug_logger_state():
    """Reset SpamDebuggingLogger state before each test to ensure test isolation."""
    # Save original values
    original_debug_enabled = SpamDebuggingLogger.DEBUG_ENABLED
    original_min_score = SpamDebuggingLogger.MIN_SCORE_FOR_DEBUG
    
    # Reset to defaults before each test
    SpamDebuggingLogger.DEBUG_ENABLED = False
    SpamDebuggingLogger.MIN_SCORE_FOR_DEBUG = 45
    
    yield
    
    # Restore original values after test (though autouse=True means this runs before each test)
    SpamDebuggingLogger.DEBUG_ENABLED = original_debug_enabled
    SpamDebuggingLogger.MIN_SCORE_FOR_DEBUG = original_min_score


def test_debug_logging_enabled():
    """Test that debug logging can be enabled."""
    enable_spam_detector_debugging(min_score=40)
    assert SpamDebuggingLogger.DEBUG_ENABLED is True
    assert SpamDebuggingLogger.MIN_SCORE_FOR_DEBUG == 40


def test_debug_logging_filter_evaluation(caplog):
    """Test that filter evaluations are logged when debug enabled."""
    enable_spam_detector_debugging()
    
    detector = SpamDetector()
    now = datetime.now(timezone.utc)
    
    tx = TransactionMetadata(
        tx_hash="0xdebugtest123456",
        from_address="0x1111111111111111111111111111111111111111",
        to_address="0x2222222222222222222222222222222222222222",
        value=Decimal("0.50"),  # Dust amount
        block_number=1000,
        timestamp=now,
    )
    
    with caplog.at_level(logging.DEBUG):
        detector.analyze_transaction(tx, [])
    
    # Check that debug logs were generated
    log_text = caplog.text
    assert "[FILTER]" in log_text or "[SPAM_VERDICT]" in log_text
    assert "debugtest" in log_text  # Our tx hash appears


def test_debug_logging_bypass_case(caplog):
    """Test logging of bypass case with multiple flags but low score."""
    enable_spam_detector_debugging(min_score=10)
    
    detector = SpamDetector(config={"dust_risk_weight": 5, "new_address_weight": 8})
    now = datetime.now(timezone.utc)
    
    # Transaction with multiple risk flags but low score
    tx = TransactionMetadata(
        tx_hash="0xbypasscase9999",
        from_address="0x3333333333333333333333333333333333333333",
        to_address="0x4444444444444444444444444444444444444444",
        value=Decimal("0.01"),  # Dust
        block_number=1000,
        timestamp=now,
        is_new_address=True,  # New sender
        contract_age_blocks=5,  # Brand new contract
    )
    
    with caplog.at_level(logging.WARNING):
        detector.analyze_transaction(tx, [])
    
    log_text = caplog.text
    # Should see bypass case in logs or verdict
    assert "[SPAM_BYPASS_CASE]" in log_text or "[SPAM_VERDICT]" in log_text
    assert "bypasscase" in log_text


def test_debug_logging_similarity(caplog):
    """Test detailed similarity analysis logging."""
    enable_spam_detector_debugging()
    
    # Log similarity analysis
    with caplog.at_level(logging.DEBUG):
        SpamDebuggingLogger.log_similarity_analysis(
            tx_hash="0xsimilarity123",
            from_addr="0x1234567890abcdef1234567890abcdef12345678",
            to_addr="0xrecipient",
            reference_addr="0x1234567890fedcba1234567890fedcba12345678",
            prefix_match=4,
            suffix_match=5,
            prefix_threshold=3,
            suffix_threshold=4,
            is_similar=True,
        )
    
    # Verify log was produced (debug is enabled, so it should always appear)
    log_text = caplog.text
    assert "[SIMILARITY]" in log_text
    assert "similarity123" in log_text or "0xsimilarity" in log_text
    assert "SIMILAR" in log_text  # Should show SIMILAR since is_similar=True
    assert "prefix: 4/3" in log_text
    assert "suffix: 5/4" in log_text


def test_debug_logging_disabled_by_default():
    """Test that debug logging is disabled by default."""
    # Verify default state (fixture ensures clean state before each test)
    assert SpamDebuggingLogger.DEBUG_ENABLED is False
    assert SpamDebuggingLogger.MIN_SCORE_FOR_DEBUG == 45
    
    # Create detector without enabling debug - should not change state
    SpamDetector()
    
    # State should still be disabled
    assert SpamDebuggingLogger.DEBUG_ENABLED is False


def test_whitelist_check_logging(caplog):
    """Test whitelist check logging."""
    enable_spam_detector_debugging()
    
    with caplog.at_level(logging.DEBUG):
        SpamDebuggingLogger.log_whitelist_check(
            tx_hash="0xwhitelist123",
            from_addr="0xdAC17F958D2ee523a2206206994597C13D831ec7",
            to_addr="0x1234567890123456789012345678901234567890",
            whitelisted_from=True,
            whitelisted_to=False,
            from_is_monitored=False,
        )
    
    # Verify log was produced
    log_text = caplog.text
    assert "[WHITELIST]" in log_text
    assert "whitelist123" in log_text or "0xwhitelist" in log_text
    assert "FROM_WHITELISTED" in log_text
    assert "dac17f958d" in log_text.lower()  # Truncated from address


def test_multiple_filters_bypass_detection(caplog):
    """Test case where multiple filters are triggered but score stays below threshold."""
    enable_spam_detector_debugging(min_score=30)
    
    # Custom config with lower weights
    custom_config = {
        "dust_risk_weight": 10,
        "timing_weight": 10,
        "similarity_weight": 10,
        "new_address_weight": 10,
        "brand_new_contract_weight": 10,
        "zero_value_weight": 20,
        "suspicious_score_threshold": 80,  # High threshold
    }
    
    detector = SpamDetector(config=custom_config)
    now = datetime.now(timezone.utc)
    
    # Transaction that triggers multiple filters
    tx1 = TransactionMetadata(
        tx_hash="0x111",
        from_address="0x1111111111111111111111111111111111111111",
        to_address="0x2222222222222222222222222222222222222222",
        value=Decimal("100"),
        block_number=1000,
        timestamp=now,
    )
    
    tx2 = TransactionMetadata(
        tx_hash="0x222",
        from_address="0x3333333333333333333333333333333333333333",
        to_address="0x2222222222222222222222222222222222222222",
        value=Decimal("0.50"),  # Dust
        block_number=1001,
        timestamp=now,  # Same time (or within window)
        is_new_address=True,
        contract_age_blocks=5,
    )
    
    with caplog.at_level(logging.DEBUG):
        analysis = detector.analyze_transaction(tx2, [tx1])
    
    # Multiple flags triggered but score < 80
    assert len(analysis.flags) >= 2
    assert analysis.score < 80
    assert analysis.is_suspicious is False
    
    # Check logs
    log_text = caplog.text
    assert "[SPAM_VERDICT]" in log_text


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
