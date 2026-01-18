"""
Malicious Transaction Detector for USDT Monitor Bot
Detects address poisoning, dust attacks, and spam transactions

Research-based detection thresholds:
- Address similarity: prefix >= 3 AND suffix >= 4
- Timing window: 20 minutes (1200 seconds)
- Dust threshold: < $1 USDT
- Risk score threshold: >= 50/100
"""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum
from typing import Dict, List, Optional, Set

# Ethereum address validation pattern (hex characters only)
ETH_HEX_PATTERN = re.compile(r"^[0-9a-f]{40}$")


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

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize detector with configuration

        Args:
            config: Dictionary with detection thresholds
        """
        self.config = self._default_config()
        if config:
            self.config.update(config)

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
        # Normalize whitelist addresses for comparison
        whitelist_normalized = set()
        if whitelisted_addresses:
            for addr in whitelisted_addresses:
                # Normalize: lowercase, remove 0x prefix
                normalized = addr.lower().replace("0x", "")
                if len(normalized) == 40:  # Valid Ethereum address length
                    whitelist_normalized.add(normalized)

        # Normalize monitored address
        monitored_normalized = None
        if monitored_address:
            monitored_normalized = monitored_address.lower().replace("0x", "")

        # Check if transaction involves a whitelisted address
        tx_from_normalized = tx.from_address.lower().replace("0x", "")
        tx_to_normalized = tx.to_address.lower().replace("0x", "")

        # Whitelist logic:
        # 1. If FROM is in whitelist (token contracts) -> whitelist
        # 2. If TO is in whitelist (token contracts) -> whitelist
        # 3. If FROM is the monitored address -> whitelist (outgoing from user)
        # 4. If TO is the monitored address AND FROM is not whitelisted -> DO NOT whitelist (incoming spam check)
        if whitelist_normalized:
            if tx_from_normalized in whitelist_normalized:
                return RiskAnalysis(
                    score=0,
                    flags=[],
                    is_suspicious=False,
                    similarity_score=0,
                    recommendation="✅ Whitelisted sender address - Low risk transaction",
                    details={"whitelisted": True, "whitelisted_from": True},
                )
            if tx_to_normalized in whitelist_normalized:
                return RiskAnalysis(
                    score=0,
                    flags=[],
                    is_suspicious=False,
                    similarity_score=0,
                    recommendation="✅ Whitelisted recipient address - Low risk transaction",
                    details={"whitelisted": True, "whitelisted_to": True},
                )

        # Check monitored address separately - only whitelist outgoing transactions
        if monitored_normalized and tx_from_normalized == monitored_normalized:
            return RiskAnalysis(
                score=0,
                flags=[],
                is_suspicious=False,
                similarity_score=0,
                recommendation="✅ Outgoing transaction from monitored address - Low risk",
                details={"whitelisted": True, "outgoing_from_monitored": True},
            )

        score = 0
        flags: Set[RiskFlag] = set()
        details = {}

        # ========== FILTER 1: Value Threshold ==========
        if Decimal("0") < tx.value < Decimal(str(self.config["dust_threshold_usd"])):
            score += self.config["dust_risk_weight"]
            flags.add(RiskFlag.DUST_AMOUNT)
            details["dust_amount"] = float(tx.value)

        # ========== FILTER 2: Zero-Value Transfer ==========
        if tx.value == Decimal("0"):
            score += self.config["zero_value_weight"]
            flags.add(RiskFlag.ZERO_VALUE_TRANSFER)

        # ========== FILTER 3: Timing + Address Similarity ==========
        last_tx_checked_for_similarity = False
        if historical_transactions:
            last_tx = historical_transactions[-1]
            time_delta = (tx.timestamp - last_tx.timestamp).total_seconds()

            # Within 20 minutes of previous transaction
            if 0 < time_delta < self.config["suspicious_time_window"]:
                score += self.config["timing_weight"]
                flags.add(RiskFlag.TIMING_SUSPICIOUS)
                details["time_since_prev_tx_seconds"] = int(time_delta)

                # Check address similarity with last sender
                similarity = self.calculate_address_similarity(
                    tx.from_address, last_tx.from_address
                )

                if similarity.is_similar:
                    score += self.config["similarity_weight"]
                    flags.add(RiskFlag.SIMILAR_ADDRESS)
                    details["similarity_to_last"] = {
                        "prefix_match": similarity.prefix_match,
                        "suffix_match": similarity.suffix_match,
                        "is_similar": similarity.is_similar,
                    }
                    last_tx_checked_for_similarity = True

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

                if similarity.is_similar:
                    score += self.config["similarity_weight"]
                    flags.add(RiskFlag.LOOKALIKE_PREVIOUS_SENDER)
                    details["lookalike_reference"] = {
                        "similar_to": prev_tx.from_address,
                        "prefix_match": similarity.prefix_match,
                        "suffix_match": similarity.suffix_match,
                    }
                    break  # Don't count multiple matches

        # ========== FILTER 5: New Address Detection ==========
        if tx.is_new_address:
            score += self.config["new_address_weight"]
            flags.add(RiskFlag.NEW_SENDER_ADDRESS)

        # ========== FILTER 6: Brand New Contract Age ==========
        if 0 <= tx.contract_age_blocks < self.config["min_blocks_for_address_age"]:
            score += self.config["brand_new_contract_weight"]
            flags.add(RiskFlag.BRAND_NEW_CONTRACT)
            details["contract_age_blocks"] = tx.contract_age_blocks

        # ========== FILTER 7: Rapid Address Cycling ==========
        if historical_transactions:
            unique_senders = self._detect_rapid_cycling(tx, historical_transactions)
            if unique_senders:
                score += self.config.get("rapid_cycling_weight", 30)
                flags.add(RiskFlag.RAPID_ADDRESS_CYCLING)
                details["rapid_cycling_senders"] = unique_senders

        # Cap score at 100
        score = min(100, score)

        # Determine if suspicious
        is_suspicious = score >= self.config["suspicious_score_threshold"]

        # Generate recommendation
        recommendation = self._generate_recommendation(flags, score, tx)

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
