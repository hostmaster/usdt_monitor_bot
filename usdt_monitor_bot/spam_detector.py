"""
Malicious Transaction Detector for USDT Monitor Bot
Detects address poisoning, dust attacks, and spam transactions

Research-based detection thresholds:
- Address similarity: prefix >= 3 AND suffix >= 4
- Timing window: 20 minutes (1200 seconds)
- Dust threshold: < $1 USDT
- Risk score threshold: >= 50/100
"""

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum
from typing import Dict, List, Optional, Set

# Ethereum address validation pattern (hex characters only)
ETH_HEX_PATTERN = re.compile(r"^[0-9a-f]{40}$")

# Create logger for spam detector
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
        flags: List,
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
        details: Optional[str] = None,
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
        time_since_prev_tx: Optional[int],
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
        score_breakdown: Dict[str, int],
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
        triggered_flags: List,
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


class RiskFlag(Enum):
    """Enumeration of detected risk factors"""

    DUST_AMOUNT = "DUST_AMOUNT"
    ZERO_VALUE_TRANSFER = "ZERO_VALUE_TRANSFER"
    TIMING_SUSPICIOUS = "TIMING_SUSPICIOUS"
    SIMILAR_ADDRESS = "SIMILAR_ADDRESS"
    NEW_SENDER_ADDRESS = "NEW_SENDER_ADDRESS"
    LOOKALIKE_PREVIOUS_SENDER = "LOOKALIKE_PREVIOUS_SENDER"
    RAPID_ADDRESS_CYCLING = "RAPID_ADDRESS_CYCLING"
    BRAND_NEW_CONTRACT = "BRAND_NEW_CONTRACT"


@dataclass
class AddressSimilarity:
    """Result of address similarity analysis"""

    prefix_match: int
    suffix_match: int
    is_similar: bool
    risk_score: int
    matching_chars: int


@dataclass
class TransactionMetadata:
    """Enhanced transaction data for analysis"""

    tx_hash: str
    from_address: str
    to_address: str
    value: Decimal  # in USDT
    block_number: int
    timestamp: datetime
    is_new_address: bool = False
    contract_age_blocks: int = 0
    gas_price: int = 0


@dataclass
class RiskAnalysis:
    """Complete risk assessment of a transaction"""

    score: int  # 0-100
    flags: List[RiskFlag]
    is_suspicious: bool
    similarity_score: int = 0
    recommendation: str = ""
    details: Dict = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


class SpamDetector:
    """Main spam/malicious transaction detector"""

    def __init__(self, config: Optional[Dict] = None, enable_debug_logging: bool = False):
        """
        Initialize detector with configuration

        Args:
            config: Dictionary with detection thresholds
            enable_debug_logging: Whether to enable detailed spam bypass debugging
        """
        self.config = self._default_config()
        if config:
            self.config.update(config)
        
        if enable_debug_logging:
            SpamDebuggingLogger.enable_debug_logging(
                min_score=self.config.get("suspicious_score_threshold", 50) - 5
            )

    @staticmethod
    def _default_config() -> Dict:
        """Default configuration values based on research"""
        return {
            # Value thresholds (in USDT)
            "dust_threshold_usd": 1.0,
            "zero_value_flag": True,
            # Address similarity
            "prefix_match_threshold": 3,  # Matching first N chars
            "suffix_match_threshold": 4,  # Matching last N chars
            # Timing windows (seconds)
            "suspicious_time_window": 1200,  # 20 minutes
            "min_blocks_for_address_age": 20,
            # Risk scoring weights
            "dust_risk_weight": 30,
            "zero_value_weight": 50,
            "timing_weight": 25,
            "similarity_weight": 40,
            "new_address_weight": 15,
            "brand_new_contract_weight": 35,
            # Thresholds
            "suspicious_score_threshold": 50,
            # Multi-address detection
            "rapid_cycling_threshold": 3,
            "rapid_cycling_window": 1800,  # 30 minutes
            "rapid_cycling_weight": 30,
        }

    @staticmethod
    def calculate_address_similarity(
        address_a: str, address_b: str
    ) -> AddressSimilarity:
        """
        Calculate visual similarity between two Ethereum addresses

        Strategy: Compare prefix (first chars) and suffix (last chars)
        This mimics how humans read addresses and how attackers craft poisoning addresses

        Args:
            address_a: First address (e.g., legitimate recipient)
            address_b: Second address (e.g., suspicious sender)

        Returns:
            AddressSimilarity with metrics and risk score
        """
        # Normalize addresses (lowercase and remove 0x prefix)
        addr_a = address_a.lower().replace("0x", "")
        addr_b = address_b.lower().replace("0x", "")

        # Validate format: must be exactly 40 hex characters
        if (
            len(addr_a) != 40
            or len(addr_b) != 40
            or not ETH_HEX_PATTERN.match(addr_a)
            or not ETH_HEX_PATTERN.match(addr_b)
        ):
            return AddressSimilarity(
                prefix_match=0,
                suffix_match=0,
                is_similar=False,
                risk_score=0,
                matching_chars=0,
            )

        # Calculate prefix matches (first chars match)
        prefix_matches = 0
        for i in range(min(8, len(addr_a))):
            if addr_a[i] == addr_b[i]:
                prefix_matches += 1
            else:
                break  # Stop at first mismatch

        # Calculate suffix matches (last chars match)
        suffix_matches = 0
        for i in range(1, min(8, len(addr_a)) + 1):
            if addr_a[-i] == addr_b[-i]:
                suffix_matches += 1
            else:
                break

        # Research-based thresholds:
        # Flag if (prefix >= 3) AND (suffix >= 4)
        # This reduces false positives while catching real attacks
        is_suspicious = (prefix_matches >= 3) and (suffix_matches >= 4)

        # Calculate risk score
        risk_score = 0
        if prefix_matches >= 3:
            risk_score += prefix_matches * 10
        if suffix_matches >= 4:
            risk_score += suffix_matches * 8

        return AddressSimilarity(
            prefix_match=prefix_matches,
            suffix_match=suffix_matches,
            is_similar=is_suspicious,
            risk_score=min(100, risk_score),
            matching_chars=prefix_matches + suffix_matches,
        )

    @staticmethod
    def _create_whitelisted_result(reason: str, details: dict) -> RiskAnalysis:
        """Create a RiskAnalysis result for whitelisted transactions."""
        return RiskAnalysis(
            score=0,
            flags=[],
            is_suspicious=False,
            similarity_score=0,
            recommendation=f"✅ {reason}",
            details={"whitelisted": True, **details},
        )

    @staticmethod
    def _normalize_address(addr: str) -> str:
        """Normalize an Ethereum address for comparison (lowercase, no 0x prefix)."""
        return addr.lower().replace("0x", "")

    def analyze_transaction(
        self,
        tx: TransactionMetadata,
        historical_transactions: List[TransactionMetadata],
        whitelisted_addresses: Optional[Set[str]] = None,
        monitored_address: Optional[str] = None,
    ) -> RiskAnalysis:
        """
        Comprehensive analysis of transaction for spam/malicious indicators

        Args:
            tx: Transaction to analyze
            historical_transactions: Previous transactions for comparison
            whitelisted_addresses: Set of addresses to whitelist (can include 0x prefix, case-insensitive).
                                   Token contracts and other trusted addresses. Whitelist applies to both
                                   FROM and TO directions.
            monitored_address: The user's monitored address. This address is only whitelisted when it's
                               the FROM address (outgoing). Incoming transactions TO this address from
                               untrusted senders are still analyzed for spam.

        Returns:
            RiskAnalysis with score, flags, and recommendation
        """
        # Normalize addresses for comparison
        tx_from_normalized = self._normalize_address(tx.from_address)
        tx_to_normalized = self._normalize_address(tx.to_address)

        whitelist_normalized = {
            self._normalize_address(addr)
            for addr in (whitelisted_addresses or [])
            if len(self._normalize_address(addr)) == 40  # Valid Ethereum address
        }

        monitored_normalized = (
            self._normalize_address(monitored_address) if monitored_address else None
        )

        # Whitelist logic:
        # 1. If FROM is in whitelist (token contracts) -> whitelist
        # 2. If TO is in whitelist (token contracts) -> whitelist
        # 3. If FROM is the monitored address -> whitelist (outgoing from user)
        # 4. If TO is the monitored address AND FROM is not whitelisted -> DO NOT whitelist (incoming spam check)
        
        # Log whitelist checks
        SpamDebuggingLogger.log_whitelist_check(
            tx.tx_hash,
            tx.from_address,
            tx.to_address,
            tx_from_normalized in whitelist_normalized,
            tx_to_normalized in whitelist_normalized,
            monitored_normalized and tx_from_normalized == monitored_normalized,
        )
        
        if tx_from_normalized in whitelist_normalized:
            return self._create_whitelisted_result(
                "Whitelisted sender address - Low risk transaction",
                {"whitelisted_from": True},
            )
        if tx_to_normalized in whitelist_normalized:
            return self._create_whitelisted_result(
                "Whitelisted recipient address - Low risk transaction",
                {"whitelisted_to": True},
            )
        if monitored_normalized and tx_from_normalized == monitored_normalized:
            return self._create_whitelisted_result(
                "Outgoing transaction from monitored address - Low risk",
                {"outgoing_from_monitored": True},
            )

        score = 0
        flags: Set[RiskFlag] = set()
        details = {}
        score_breakdown: Dict[str, int] = {}

        # ========== FILTER 1: Value Threshold ==========
        if Decimal("0") < tx.value < Decimal(str(self.config["dust_threshold_usd"])):
            score += self.config["dust_risk_weight"]
            flags.add(RiskFlag.DUST_AMOUNT)
            details["dust_amount"] = float(tx.value)
            score_breakdown["DUST_AMOUNT"] = self.config["dust_risk_weight"]
            SpamDebuggingLogger.log_filter_evaluation(
                tx.tx_hash,
                tx.from_address,
                "DUST_AMOUNT",
                True,
                self.config["dust_risk_weight"],
                f"value={float(tx.value):.2f}",
            )
        else:
            SpamDebuggingLogger.log_filter_evaluation(
                tx.tx_hash,
                tx.from_address,
                "DUST_AMOUNT",
                False,
                0,
                f"value={float(tx.value):.2f}",
            )

        # ========== FILTER 2: Zero-Value Transfer ==========
        if tx.value == Decimal("0"):
            score += self.config["zero_value_weight"]
            flags.add(RiskFlag.ZERO_VALUE_TRANSFER)
            score_breakdown["ZERO_VALUE"] = self.config["zero_value_weight"]
            SpamDebuggingLogger.log_filter_evaluation(
                tx.tx_hash,
                tx.from_address,
                "ZERO_VALUE_TRANSFER",
                True,
                self.config["zero_value_weight"],
            )
        else:
            SpamDebuggingLogger.log_filter_evaluation(
                tx.tx_hash,
                tx.from_address,
                "ZERO_VALUE_TRANSFER",
                False,
                0,
            )

        # ========== FILTER 3: Timing + Address Similarity ==========
        last_tx_checked_for_similarity = False
        
        if historical_transactions:
            last_tx = historical_transactions[-1]
            time_delta = (tx.timestamp - last_tx.timestamp).total_seconds()
            
            # Log timing context
            SpamDebuggingLogger.log_timing_context(
                tx.tx_hash,
                int(time_delta) if time_delta >= 0 else None,
                self.config["suspicious_time_window"],
                0 < time_delta < self.config["suspicious_time_window"],
                len(historical_transactions),
            )

            # Within 20 minutes of previous transaction
            if 0 < time_delta < self.config["suspicious_time_window"]:
                score += self.config["timing_weight"]
                flags.add(RiskFlag.TIMING_SUSPICIOUS)
                score_breakdown["TIMING_SUSPICIOUS"] = self.config["timing_weight"]
                details["time_since_prev_tx_seconds"] = int(time_delta)

                # Check address similarity with last sender
                similarity = self.calculate_address_similarity(
                    tx.from_address, last_tx.from_address
                )
                
                SpamDebuggingLogger.log_similarity_analysis(
                    tx.tx_hash,
                    tx.from_address,
                    tx.to_address,
                    last_tx.from_address,
                    similarity.prefix_match,
                    similarity.suffix_match,
                    self.config["prefix_match_threshold"],
                    self.config["suffix_match_threshold"],
                    similarity.is_similar,
                )

                if similarity.is_similar:
                    score += self.config["similarity_weight"]
                    flags.add(RiskFlag.SIMILAR_ADDRESS)
                    score_breakdown["SIMILAR_ADDRESS"] = self.config["similarity_weight"]
                    details["similarity_to_last"] = {
                        "prefix_match": similarity.prefix_match,
                        "suffix_match": similarity.suffix_match,
                        "is_similar": similarity.is_similar,
                    }
                    last_tx_checked_for_similarity = True
                    SpamDebuggingLogger.log_filter_evaluation(
                        tx.tx_hash,
                        tx.from_address,
                        "SIMILAR_ADDRESS",
                        True,
                        self.config["similarity_weight"],
                        f"prefix={similarity.prefix_match} suffix={similarity.suffix_match}",
                    )
                else:
                    SpamDebuggingLogger.log_filter_evaluation(
                        tx.tx_hash,
                        tx.from_address,
                        "SIMILAR_ADDRESS",
                        False,
                        0,
                        f"prefix={similarity.prefix_match} suffix={similarity.suffix_match}",
                    )

            # ========== FILTER 4: Check all Recent Addresses ==========
            # Compare against last 10 transactions (broader check)
            # Exclude the last transaction if it was already checked in FILTER 3
            transactions_to_check = (
                historical_transactions[-10:-1]
                if last_tx_checked_for_similarity and len(historical_transactions) > 1
                else historical_transactions[-10:]
            )

            for prev_tx in transactions_to_check:
                if prev_tx.from_address == tx.from_address:
                    continue  # Skip if same address

                similarity = self.calculate_address_similarity(
                    tx.from_address, prev_tx.from_address
                )
                
                SpamDebuggingLogger.log_similarity_analysis(
                    tx.tx_hash,
                    tx.from_address,
                    tx.to_address,
                    prev_tx.from_address,
                    similarity.prefix_match,
                    similarity.suffix_match,
                    self.config["prefix_match_threshold"],
                    self.config["suffix_match_threshold"],
                    similarity.is_similar,
                )

                if similarity.is_similar:
                    score += self.config["similarity_weight"]
                    flags.add(RiskFlag.LOOKALIKE_PREVIOUS_SENDER)
                    score_breakdown["LOOKALIKE_SENDER"] = self.config["similarity_weight"]
                    details["lookalike_reference"] = {
                        "similar_to": prev_tx.from_address,
                        "prefix_match": similarity.prefix_match,
                        "suffix_match": similarity.suffix_match,
                    }
                    SpamDebuggingLogger.log_filter_evaluation(
                        tx.tx_hash,
                        tx.from_address,
                        "LOOKALIKE_PREVIOUS_SENDER",
                        True,
                        self.config["similarity_weight"],
                        f"prefix={similarity.prefix_match} suffix={similarity.suffix_match}",
                    )
                    break  # Don't count multiple matches
        else:
            SpamDebuggingLogger.log_timing_context(
                tx.tx_hash,
                None,
                self.config["suspicious_time_window"],
                False,
                0,
            )

        # ========== FILTER 5: New Address Detection ==========
        if tx.is_new_address:
            score += self.config["new_address_weight"]
            flags.add(RiskFlag.NEW_SENDER_ADDRESS)
            score_breakdown["NEW_SENDER"] = self.config["new_address_weight"]
            SpamDebuggingLogger.log_filter_evaluation(
                tx.tx_hash,
                tx.from_address,
                "NEW_SENDER_ADDRESS",
                True,
                self.config["new_address_weight"],
            )
        else:
            SpamDebuggingLogger.log_filter_evaluation(
                tx.tx_hash,
                tx.from_address,
                "NEW_SENDER_ADDRESS",
                False,
                0,
            )

        # ========== FILTER 6: Brand New Contract Age ==========
        if 0 <= tx.contract_age_blocks < self.config["min_blocks_for_address_age"]:
            score += self.config["brand_new_contract_weight"]
            flags.add(RiskFlag.BRAND_NEW_CONTRACT)
            score_breakdown["BRAND_NEW_CONTRACT"] = self.config["brand_new_contract_weight"]
            details["contract_age_blocks"] = tx.contract_age_blocks
            SpamDebuggingLogger.log_filter_evaluation(
                tx.tx_hash,
                tx.from_address,
                "BRAND_NEW_CONTRACT",
                True,
                self.config["brand_new_contract_weight"],
                f"age={tx.contract_age_blocks} blocks",
            )
        else:
            SpamDebuggingLogger.log_filter_evaluation(
                tx.tx_hash,
                tx.from_address,
                "BRAND_NEW_CONTRACT",
                False,
                0,
                f"age={tx.contract_age_blocks} blocks",
            )

        # ========== FILTER 7: Rapid Address Cycling ==========
        if historical_transactions:
            unique_senders = self._detect_rapid_cycling(tx, historical_transactions)
            if unique_senders:
                score += self.config.get("rapid_cycling_weight", 30)
                flags.add(RiskFlag.RAPID_ADDRESS_CYCLING)
                score_breakdown["RAPID_CYCLING"] = self.config.get("rapid_cycling_weight", 30)
                details["rapid_cycling_senders"] = unique_senders
                SpamDebuggingLogger.log_filter_evaluation(
                    tx.tx_hash,
                    tx.from_address,
                    "RAPID_ADDRESS_CYCLING",
                    True,
                    self.config.get("rapid_cycling_weight", 30),
                    f"unique_senders={unique_senders}",
                )
            else:
                SpamDebuggingLogger.log_filter_evaluation(
                    tx.tx_hash,
                    tx.from_address,
                    "RAPID_ADDRESS_CYCLING",
                    False,
                    0,
                )

        # Cap score at 100
        score = min(100, score)

        # Determine if suspicious
        is_suspicious = score >= self.config["suspicious_score_threshold"]

        # Generate recommendation
        recommendation = self._generate_recommendation(flags, score, tx)

        # Log analysis decision
        SpamDebuggingLogger.log_analysis_decision(
            tx.tx_hash,
            score,
            is_suspicious,
            flags,
            self.config["suspicious_score_threshold"],
        )

        # Log score accumulation for debugging
        SpamDebuggingLogger.log_score_accumulation(
            tx.tx_hash,
            tx.from_address,
            score,
            self.config["suspicious_score_threshold"],
            score_breakdown,
        )

        # Detect and log bypass cases
        if len(flags) > 0 and not is_suspicious:
            reason = f"score_below_threshold ({score}/{self.config['suspicious_score_threshold']})"
            SpamDebuggingLogger.log_bypass_case(
                tx.tx_hash,
                tx.from_address,
                tx.to_address,
                tx.value,
                score,
                self.config["suspicious_score_threshold"],
                flags,
                reason,
            )

        return RiskAnalysis(
            score=score,
            flags=sorted(list(flags), key=lambda x: x.value),
            is_suspicious=is_suspicious,
            similarity_score=details.get("similarity_to_last", {}).get(
                "prefix_match", 0
            ),
            recommendation=recommendation,
            details=details,
        )

    def _detect_rapid_cycling(
        self, current_tx: TransactionMetadata, historical_txs: List[TransactionMetadata]
    ) -> Optional[int]:
        """
        Detect if multiple different senders appear in rapid succession
        Indicates automated poisoning attack campaign

        Args:
            current_tx: Current transaction
            historical_txs: Recent transaction history

        Returns:
            Number of unique senders if rapid cycling detected, None otherwise
        """
        recent_addresses: Set[str] = set()
        window_start = current_tx.timestamp - timedelta(
            seconds=self.config["rapid_cycling_window"]
        )

        # Count unique senders in time window
        for tx in historical_txs:
            if tx.timestamp >= window_start:
                recent_addresses.add(tx.from_address)

        # Include current transaction
        recent_addresses.add(current_tx.from_address)

        # Flag if more unique senders than threshold
        if len(recent_addresses) >= self.config["rapid_cycling_threshold"]:
            return len(recent_addresses)

        return None

    @staticmethod
    def _generate_recommendation(
        flags: List[RiskFlag], score: int, tx: TransactionMetadata
    ) -> str:
        """Generate human-readable recommendation based on findings"""

        if score >= 80:
            return (
                "🚨 EXTREMELY HIGH RISK - Likely address poisoning attempt. "
                "NEVER copy this address from history. Verify on Etherscan before any action."
            )
        elif score >= 60:
            return (
                "⚠️ HIGH RISK - Suspicious address detected. "
                "Double-check sender address on blockchain explorer before trusting."
            )
        elif score >= 50:
            return (
                "⚠️ MODERATE RISK - Some suspicious indicators detected. "
                "Verify sender identity before interacting."
            )
        else:
            return "✅ Low risk - Normal transaction pattern"

    def check_transaction_batch(
        self, transactions: List[TransactionMetadata]
    ) -> Dict[str, RiskAnalysis]:
        """
        Analyze multiple transactions, providing context

        Args:
            transactions: List of transactions in chronological order

        Returns:
            Dictionary mapping tx_hash to RiskAnalysis
        """
        results = {}
        for i, tx in enumerate(transactions):
            # Include all previous transactions for context
            history = transactions[:i]
            analysis = self.analyze_transaction(tx, history)
            results[tx.tx_hash] = analysis

        return results


# ========== Utility Functions ==========


def enable_spam_detector_debugging(min_score: Optional[int] = None) -> None:
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


def format_risk_report(address: str, analysis: RiskAnalysis) -> str:
    """
    Format risk analysis into human-readable report for Telegram

    Args:
        address: The suspicious address
        analysis: RiskAnalysis object

    Returns:
        Formatted report string
    """
    report = (
        "⚠️ **TRANSACTION RISK ASSESSMENT** ⚠️\n\n"
        f"**Address:** `{address}`\n"
        f"**Risk Score:** {analysis.score}/100\n"
        f"**Status:** {'🚨 SUSPICIOUS' if analysis.is_suspicious else '✅ OK'}\n\n"
    )

    if analysis.flags:
        report += "**Detected Indicators:**\n"
        for flag in analysis.flags:
            report += f"• {flag.value}\n"

    if analysis.details:
        report += "\n**Details:**\n"
        if "dust_amount" in analysis.details:
            report += f"• Dust amount: ${analysis.details['dust_amount']}\n"
        if "time_since_prev_tx_seconds" in analysis.details:
            secs = analysis.details["time_since_prev_tx_seconds"]
            report += f"• Time since previous: {secs} seconds\n"
        if "contract_age_blocks" in analysis.details:
            report += f"• Address age: {analysis.details['contract_age_blocks']} blocks (brand new)\n"

    report += f"\n**Recommendation:**\n{analysis.recommendation}"

    return report


# ========== Testing Example ==========

if __name__ == "__main__":
    # Create detector
    detector = SpamDetector()

    # Example: Create test transactions
    now = datetime.now()

    # Legitimate transaction
    legitimate_tx = TransactionMetadata(
        tx_hash="0x123abc",
        from_address="0x85A0bee4659ECef2e256dC98239dE17Fb5CAE822",
        to_address="0xRecipient123",
        value=Decimal("1100"),
        block_number=19000000,
        timestamp=now,
        is_new_address=False,
        contract_age_blocks=100,
    )

    # Poisoning attack (30 seconds later, similar address, small amount)
    poisoning_tx = TransactionMetadata(
        tx_hash="0x456def",
        from_address="0x85a0c3788d81257612e2581a6ea0ada244853a91",  # Similar!
        to_address="0xRecipient123",
        value=Decimal("0.01"),  # Dust amount
        block_number=19000001,
        timestamp=now + timedelta(seconds=30),
        is_new_address=True,
        contract_age_blocks=2,
    )

    # Analyze the poisoning transaction with legitimate as history
    analysis = detector.analyze_transaction(poisoning_tx, [legitimate_tx])

    print(format_risk_report(poisoning_tx.from_address, analysis))
    print(f"\nRisk Score: {analysis.score}")
    print(f"Flags: {[f.value for f in analysis.flags]}")
    print(f"Is Suspicious: {analysis.is_suspicious}")
