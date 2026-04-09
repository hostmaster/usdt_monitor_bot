"""Debugging logger for spam detector bypass analysis."""

import logging
from decimal import Decimal

logger = logging.getLogger(__name__)


class SpamDebuggingLogger:
    """
    Instrumentation for reverse debugging spam bypass cases.

    Provides structured logging with full context for analyzing transactions
    that unexpectedly bypass spam detection or fail to reach expected scores.
    """

    # Enable detailed debugging via environment or config
    DEBUG_ENABLED = False
    MIN_SCORE_FOR_DEBUG = 45  # Log transactions scoring close to threshold

    @staticmethod
    def enable_debug_logging(min_score: int = 45) -> None:
        """Enable detailed spam bypass debugging."""
        SpamDebuggingLogger.DEBUG_ENABLED = True
        SpamDebuggingLogger.MIN_SCORE_FOR_DEBUG = min_score

    @staticmethod
    def _truncate_addr(addr: str, length: int = 10) -> str:
        """Truncate address for compact logging."""
        addr_norm = addr.lower().replace("0x", "")
        return addr_norm[:length] if addr_norm else "unknown"

    @staticmethod
    def log_analysis_decision(
        tx_hash: str,
        score: int,
        is_suspicious: bool,
        flags: list,
        threshold: int,
    ) -> None:
        """
        Log key decision point: whether transaction passed or failed spam detection.

        Args:
            tx_hash: Transaction hash
            score: Final risk score
            is_suspicious: Whether marked as spam
            flags: List of detected risk flags
            threshold: Spam detection threshold
        """
        if not logger.isEnabledFor(logging.DEBUG):
            return

        tx_short = tx_hash[:16]
        flag_names = [f.value for f in flags] if flags else ["NONE"]

        logger.debug(
            f"[SPAM_VERDICT] {tx_short}: score={score}/{threshold} "
            f"suspicious={is_suspicious} flags={','.join(flag_names)}"
        )

    @staticmethod
    def log_filter_evaluation(
        tx_hash: str,
        from_addr: str,
        filter_name: str,
        triggered: bool,
        score_delta: int,
        details: str | None = None,
    ) -> None:
        """
        Log evaluation of each spam filter for this transaction.

        Args:
            tx_hash: Transaction hash
            from_addr: Sender address
            filter_name: Name of filter (e.g., "DUST_AMOUNT", "SIMILAR_ADDRESS")
            triggered: Whether filter was triggered
            score_delta: Score added by this filter
            details: Additional context about filter evaluation (as string)
        """
        if not SpamDebuggingLogger.DEBUG_ENABLED:
            return

        addr_short = SpamDebuggingLogger._truncate_addr(from_addr)
        tx_short = tx_hash[:16]

        status = "✓ TRIGGERED" if triggered else "✗ passed"
        detail_str = f" ({details})" if details else ""

        logger.debug(
            f"[FILTER] {tx_short} {filter_name:25} {status:15} "
            f"+{score_delta:3} | from={addr_short}{detail_str}"
        )

    @staticmethod
    def log_similarity_analysis(
        tx_hash: str,
        from_addr: str,
        to_addr: str,
        reference_addr: str,
        prefix_match: int,
        suffix_match: int,
        prefix_threshold: int,
        suffix_threshold: int,
        is_similar: bool,
    ) -> None:
        """
        Log detailed address similarity analysis for debugging.

        Args:
            tx_hash: Transaction hash
            from_addr: Sender address being checked
            to_addr: Recipient address
            reference_addr: Address being compared against
            prefix_match: Number of matching prefix characters
            suffix_match: Number of matching suffix characters
            prefix_threshold: Configured prefix threshold
            suffix_threshold: Configured suffix threshold
            is_similar: Whether addresses deemed similar
        """
        if not SpamDebuggingLogger.DEBUG_ENABLED:
            return

        from_short = SpamDebuggingLogger._truncate_addr(from_addr, 6)
        ref_short = SpamDebuggingLogger._truncate_addr(reference_addr, 6)
        tx_short = tx_hash[:12]

        verdict = "SIMILAR" if is_similar else "different"

        logger.debug(
            f"[SIMILARITY] {tx_short} {verdict:10} | "
            f"from={from_short} vs ref={ref_short} | "
            f"prefix: {prefix_match}/{prefix_threshold} | "
            f"suffix: {suffix_match}/{suffix_threshold}"
        )

    @staticmethod
    def log_whitelist_check(
        tx_hash: str,
        from_addr: str,
        to_addr: str,
        whitelisted_from: bool,
        whitelisted_to: bool,
        from_is_monitored: bool,
    ) -> None:
        """
        Log whitelist evaluation for transaction.

        Args:
            tx_hash: Transaction hash
            from_addr: Sender address
            to_addr: Recipient address
            whitelisted_from: Whether sender is whitelisted
            whitelisted_to: Whether recipient is whitelisted
            from_is_monitored: Whether sender is the monitored address
        """
        if not SpamDebuggingLogger.DEBUG_ENABLED:
            return

        from_short = SpamDebuggingLogger._truncate_addr(from_addr)
        to_short = SpamDebuggingLogger._truncate_addr(to_addr)
        tx_short = tx_hash[:12]

        checks = []
        if whitelisted_from:
            checks.append("FROM_WHITELISTED")
        if whitelisted_to:
            checks.append("TO_WHITELISTED")
        if from_is_monitored:
            checks.append("FROM_MONITORED")

        status = f"[{','.join(checks)}]" if checks else "NONE"

        logger.debug(
            f"[WHITELIST] {tx_short} {status:35} "
            f"from={from_short} to={to_short}"
        )

    @staticmethod
    def log_timing_context(
        tx_hash: str,
        time_since_prev_tx: int | None,
        timing_window: int,
        timing_triggered: bool,
        historical_count: int,
    ) -> None:
        """
        Log timing analysis context for spam detection.

        Args:
            tx_hash: Transaction hash
            time_since_prev_tx: Seconds since last transaction (None if no history)
            timing_window: Configured timing window in seconds
            timing_triggered: Whether timing filter was triggered
            historical_count: Number of historical transactions available
        """
        if not SpamDebuggingLogger.DEBUG_ENABLED:
            return

        tx_short = tx_hash[:12]

        if time_since_prev_tx is not None:
            time_str = f"{time_since_prev_tx}s"
            in_window = "IN" if timing_triggered else "OUT"
            logger.debug(
                f"[TIMING] {tx_short} last_tx={time_str:6} window={timing_window}s "
                f"[{in_window}_WINDOW] history={historical_count}"
            )
        else:
            logger.debug(
                f"[TIMING] {tx_short} no_previous_tx history={historical_count}"
            )

    @staticmethod
    def log_score_accumulation(
        tx_hash: str,
        from_addr: str,
        final_score: int,
        threshold: int,
        score_breakdown: dict[str, int],
    ) -> None:
        """
        Log final score accumulation with breakdown.

        Args:
            tx_hash: Transaction hash
            from_addr: Sender address
            final_score: Final score after capping
            threshold: Spam detection threshold
            score_breakdown: Dictionary of filter_name -> score_contributed
        """
        if final_score < SpamDebuggingLogger.MIN_SCORE_FOR_DEBUG:
            return

        addr_short = SpamDebuggingLogger._truncate_addr(from_addr)
        tx_short = tx_hash[:12]

        breakdown = " + ".join(
            [f"{name}({score})" for name, score in score_breakdown.items() if score > 0]
        ) or "NONE"

        logger.info(
            f"[SCORE_CLOSE_TO_THRESHOLD] {tx_short} score={final_score}/{threshold} "
            f"from={addr_short} breakdown: {breakdown}"
        )

    @staticmethod
    def log_bypass_case(
        tx_hash: str,
        from_addr: str,
        to_addr: str,
        value: Decimal,
        score: int,
        threshold: int,
        triggered_flags: list,
        reason: str,
    ) -> None:
        """
        Log cases where transaction bypassed spam detection unexpectedly.

        Called when:
        - Transaction has multiple risk flags but score stays below threshold
        - Transaction has high-risk indicators but wasn't flagged

        Args:
            tx_hash: Transaction hash
            from_addr: Sender address
            to_addr: Recipient address
            value: Transaction value in USDT
            score: Final risk score
            threshold: Spam detection threshold
            triggered_flags: List of detected flags
            reason: Human-readable reason for bypass
        """
        from_short = SpamDebuggingLogger._truncate_addr(from_addr)
        to_short = SpamDebuggingLogger._truncate_addr(to_addr)
        tx_short = tx_hash[:12]
        flag_list = ",".join([f.value for f in triggered_flags]) if triggered_flags else "NONE"

        logger.warning(
            f"[SPAM_BYPASS_CASE] {tx_short} from={from_short} to={to_short} "
            f"value={value:.2f} score={score}/{threshold} flags=[{flag_list}] "
            f"reason={reason}"
        )


def enable_spam_detector_debugging(min_score: int | None = None) -> None:
    """
    Enable detailed debugging for spam detector bypass cases.

    Useful for analyzing why transactions bypass spam detection.
    Call this early in application startup if debugging is needed.

    Args:
        min_score: Minimum score to log (default: threshold - 5)
    """
    if min_score is None:
        min_score = 45  # Default threshold is 50, so 45 catches near-misses
    SpamDebuggingLogger.enable_debug_logging(min_score)
    logging.info(f"Spam detector debugging enabled (min_score={min_score})")
