"""Data models for spam detection: enums and dataclasses."""

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum


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
    flags: list[RiskFlag]
    is_suspicious: bool
    similarity_score: int = 0
    recommendation: str = ""
    details: dict | None = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}
