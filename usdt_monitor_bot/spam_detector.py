"""
Malicious Transaction Detector for USDT Monitor Bot
Detects address poisoning, dust attacks, and spam transactions

Research-based detection thresholds:
- Address similarity: prefix >= 3 AND suffix >= 4
- Timing window: 20 minutes (1200 seconds)
- Dust threshold: < $0.10 USDT/USDC
- Risk score threshold: >= 50/100
"""

import logging
import re
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, List, Optional, Set

from usdt_monitor_bot.spam_detector_logging import (  # noqa: F401
    SpamDebuggingLogger,
    enable_spam_detector_debugging,
)
from usdt_monitor_bot.spam_detector_models import (  # noqa: F401
    AddressSimilarity,
    RiskAnalysis,
    RiskFlag,
    TransactionMetadata,
)

# Ethereum address validation pattern (hex characters only)
ETH_HEX_PATTERN = re.compile(r"^[0-9a-f]{40}$")

# Create logger for spam detector
logger = logging.getLogger(__name__)


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
            # Value thresholds (in USDT/USDC)
            "dust_threshold_usd": 0.1,
            "zero_value_flag": True,
            # Address similarity
            "prefix_match_threshold": 3,  # Matching first N chars
            "suffix_match_threshold": 4,  # Matching last N chars
            # Timing windows (seconds)
            "suspicious_time_window": 1200,  # 20 minutes
            "min_blocks_for_address_age": 20,
            # Risk scoring weights
            "dust_risk_weight": 50,
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

    def _apply_filter(
        self,
        triggered: bool,
        flag: RiskFlag,
        weight_key: str,
        bd_key: str,
        flags: set,
        score_breakdown: dict,
        tx_hash: str,
        from_address: str,
        filter_name: str,
        detail_str: str = "",
    ) -> int:
        """Apply one filter: update flags/score_breakdown, log, return score delta."""
        weight = self.config[weight_key]
        SpamDebuggingLogger.log_filter_evaluation(
            tx_hash, from_address, filter_name, triggered, weight if triggered else 0, detail_str
        )
        if triggered:
            flags.add(flag)
            score_breakdown[bd_key] = weight
            return weight
        return 0

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
            bool(monitored_normalized and tx_from_normalized == monitored_normalized),
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
        score += self._apply_filter(
            Decimal("0") < tx.value < Decimal(str(self.config["dust_threshold_usd"])),
            RiskFlag.DUST_AMOUNT, "dust_risk_weight", "DUST_AMOUNT",
            flags, score_breakdown, tx.tx_hash, tx.from_address, "DUST_AMOUNT",
            f"value={float(tx.value):.2f}",
        )
        if RiskFlag.DUST_AMOUNT in flags:
            details["dust_amount"] = float(tx.value)

        # ========== FILTER 2: Zero-Value Transfer ==========
        score += self._apply_filter(
            tx.value == Decimal("0"),
            RiskFlag.ZERO_VALUE_TRANSFER, "zero_value_weight", "ZERO_VALUE",
            flags, score_breakdown, tx.tx_hash, tx.from_address, "ZERO_VALUE_TRANSFER",
        )

        # ========== FILTER 3: Timing + Address Similarity ==========
        _matched_last_sender = False  # set True if filter 3 already scored the last sender

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
                    _matched_last_sender = True
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
            # Exclude the last tx from broader scan only if filter 3 already matched it,
            # to avoid adding similarity_weight twice for the same address
            transactions_to_check = (
                historical_transactions[-10:-1]
                if _matched_last_sender and len(historical_transactions) > 1
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
        score += self._apply_filter(
            tx.is_new_address,
            RiskFlag.NEW_SENDER_ADDRESS, "new_address_weight", "NEW_SENDER",
            flags, score_breakdown, tx.tx_hash, tx.from_address, "NEW_SENDER_ADDRESS",
        )

        # ========== FILTER 6: Brand New Contract Age ==========
        score += self._apply_filter(
            0 <= tx.contract_age_blocks < self.config["min_blocks_for_address_age"],
            RiskFlag.BRAND_NEW_CONTRACT, "brand_new_contract_weight", "BRAND_NEW_CONTRACT",
            flags, score_breakdown, tx.tx_hash, tx.from_address, "BRAND_NEW_CONTRACT",
            f"age={tx.contract_age_blocks} blocks",
        )
        if RiskFlag.BRAND_NEW_CONTRACT in flags:
            details["contract_age_blocks"] = tx.contract_age_blocks

        # ========== FILTER 7: Rapid Address Cycling ==========
        if historical_transactions:
            unique_senders = self._detect_rapid_cycling(tx, historical_transactions)
            if unique_senders:
                score += self.config["rapid_cycling_weight"]
                flags.add(RiskFlag.RAPID_ADDRESS_CYCLING)
                score_breakdown["RAPID_CYCLING"] = self.config["rapid_cycling_weight"]
                details["rapid_cycling_senders"] = unique_senders
                SpamDebuggingLogger.log_filter_evaluation(
                    tx.tx_hash,
                    tx.from_address,
                    "RAPID_ADDRESS_CYCLING",
                    True,
                    self.config["rapid_cycling_weight"],
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
        recommendation = self._generate_recommendation(list(flags), score, tx)

        # Log analysis decision
        SpamDebuggingLogger.log_analysis_decision(
            tx.tx_hash,
            score,
            is_suspicious,
            list(flags),
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
                list(flags),
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
