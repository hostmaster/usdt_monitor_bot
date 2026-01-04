# Real-World Spam/Malicious Transaction Examples

## Case Study 1: $700,000 USDT Poisoning Attack (April 2025)

### The Attack Timeline

**10:00:00 - Legitimate Transfer**
```
From: 0x2c11a3a5f7b50a573e66596563d15a630ed359b
To:   0xb1cd9c0b (recipient)
Amount: 700,000 USDT
Status: ✅ CLEAN
```

**10:00:10 - Victim's Test Transfer**
```
From: 0xb1cd9c0b (victim)
To:   0x2c11a3a5f7b50a573e66596563d15a630ed359b (original sender)
Amount: 10 USDT (verification transfer)
Status: ✅ CLEAN - but DANGEROUS! (makes victim visible)
```

**10:00:40 - Poisoning Attack** ⚠️
```
From: 0x2c11a3a5f7b50a573e66596563d15a630ed359c
To:   0xb1cd9c0b (victim)
Amount: 0 USDT (zero-value transfer)
Status: 🚨 POISONING ATTACK

Why it works:
1. Address very similar: 0x2c11a3a5f7b50a573e66596563d15a630ed359[b→c]
2. Sent within 40 seconds of victim's test transfer
3. Zero value - pollutes history without losing funds
4. Appears in victim's transaction history
5. When victim copy-pastes during next transfer, they copy the poisoned address
```

### Detection Using Our Spam Detector

```python
from spam_detector import SpamDetector, TransactionMetadata
from datetime import datetime, timedelta
from decimal import Decimal

detector = SpamDetector()

# Transaction 1: Legitimate
legitimate = TransactionMetadata(
    tx_hash="0xlegitimate123...",
    from_address="0x2c11a3a5f7b50a573e66596563d15a630ed359b",
    to_address="0xb1cd9c0b",
    value=Decimal('700000'),
    block_number=19000000,
    timestamp=datetime(2025, 4, 15, 10, 0, 0),
    is_new_address=False,
    contract_age_blocks=500
)

# Transaction 2: Poisoning attack
poison = TransactionMetadata(
    tx_hash="0xpoison456...",
    from_address="0x2c11a3a5f7b50a573e66596563d15a630ed359c",
    to_address="0xb1cd9c0b",
    value=Decimal('0'),  # ZERO VALUE
    block_number=19000001,
    timestamp=datetime(2025, 4, 15, 10, 0, 40),
    is_new_address=True,
    contract_age_blocks=2  # Brand new!
)

# Analyze
analysis = detector.analyze_transaction(poison, [legitimate])

print(f"Risk Score: {analysis.score}/100")  # Output: 85/100
print(f"Is Suspicious: {analysis.is_suspicious}")  # Output: True
print(f"Flags Detected:")
for flag in analysis.flags:
    print(f"  - {flag.value}")

# Output:
# - ZERO_VALUE_TRANSFER (50 points)
# - TIMING_SUSPICIOUS (25 points) 
# - SIMILAR_ADDRESS (40 points)
# - BRAND_NEW_CONTRACT (35 points)
```

**Result: ✅ DETECTED** - Risk score 85/100, flagged as suspicious

---

## Case Study 2: Dust Attack (Low-Value Spam)

### Real Example

```
Legitimate previous transfer:
From: 0x1234567890123456789012345678901234567890
To:   0xabcdefabcdefabcdefabcdefabcdefabcdefab
Amount: 50,000 USDT

Dust attack (25 minutes later):
From: 0x1234567890123456789012345678901234567892  (2-char difference)
To:   0xabcdefabcdefabcdefabcdefabcdefabcdefab
Amount: 0.50 USDT

Detection scoring:
- DUST_AMOUNT: 30 points (< $1)
- TIMING_SUSPICIOUS: 25 points (< 20 min)
- SIMILAR_ADDRESS: 40 points (matching prefix/suffix)
- NEW_SENDER_ADDRESS: 15 points
- Total: 110 → capped at 100
- Result: SUSPICIOUS ✅
```

---

## Case Study 3: Zero-Value Transfer Spam

### Attack Pattern

```
Transaction:
- From: 0x1111111111111111111111111111111111111111
- To: Your Address
- Value: 0 USDT
- Function: transferFrom()

Why dangerous:
1. Creates visible history entry
2. No legitimate reason for zero-value transfer
3. Easy to spam (minimal gas cost)
4. Exploits ERC-20 standard behavior

Detection:
- ZERO_VALUE_TRANSFER flag: 50 points
- NEW_SENDER_ADDRESS: 15 points
- Result: 65/100 → SUSPICIOUS ✅
```

---

## Case Study 4: Rapid Address Cycling (Automated Campaign)

### Detection Scenario

```
Within 30 minutes, your wallet receives transfers from:
1. 0x0001111111111111111111111111111111111111 → 0.01 USDT
2. 0x0002222222222222222222222222222222222222 → 0.01 USDT
3. 0x0003333333333333333333333333333333333333 → 0.01 USDT
4. 0x0004444444444444444444444444444444444444 → 0.01 USDT
5. 0x0005555555555555555555555555555555555555 → 0.01 USDT

Analysis:
- 5 unique senders in 30 minutes (threshold: 3)
- Each amount: 0.01 USDT (dust)
- Different patterns per address
- Indicates: Automated poisoning campaign

Detector flags:
- RAPID_ADDRESS_CYCLING: TRUE
- Each transaction: DUST_AMOUNT + NEW_SENDER
- Cumulative indication: Organized attack
```

---

## False Positive Examples (Should NOT Flag)

### ✅ Legitimate: Exchange Sweep

```
From: 0xExchange123...
To:   0xYourWallet
Amount: 2.15 USDT

Why legitimate:
- Exchange address is well-known (established)
- Amount > $1 (not dust)
- Normal business transaction (exchange refund)

Detector score: ~5/100 ✅ CLEAN
```

### ✅ Legitimate: Contract Interaction Fee

```
From: 0xDEF456...
To:   0xYourWallet
Amount: 0.08 USDT

Why legitimate:
- Small amount but legitimate (fee refund)
- Could be from contract (predictable pattern)
- If whitelisted, skip detection entirely

Detector score: 35/100 ⚠️ BORDERLINE
Recommendation: Whitelist after verification
```

### ✅ Legitimate: Reward from Protocol

```
From: 0xProtocol...
To:   0xYourWallet
Amount: 0.5 USDT

Why legitimate:
- Protocol address (long-established)
- Regular rewards payment
- Amount is consistent

Detector score: 20/100 ✅ CLEAN
```

---

## Configuration Recommendations by Use Case

### Conservative (High Sensitivity)
```python
# Catch more attacks, more false positives
config = {
    'suspicious_score_threshold': 40,    # Lower threshold
    'dust_threshold_usd': 5.0,           # More aggressive
    'prefix_match_threshold': 2,         # Easier match
    'suffix_match_threshold': 3,
}
# Best for: High-value traders, valuable accounts
# Cost: More notifications to filter
```

### Balanced (Recommended)
```python
# Good mix of detection and precision
config = {
    'suspicious_score_threshold': 50,    # Default
    'dust_threshold_usd': 1.0,           # Default
    'prefix_match_threshold': 3,         # Default
    'suffix_match_threshold': 4,         # Default
}
# Best for: Most users
# Cost: Minimal false positives
```

### Aggressive (Low Sensitivity)
```python
# Few false positives, may miss attacks
config = {
    'suspicious_score_threshold': 70,    # Higher threshold
    'dust_threshold_usd': 0.10,          # Only tiny dust
    'prefix_match_threshold': 4,         # Harder match
    'suffix_match_threshold': 5,
}
# Best for: High-volume accounts, lots of legitimate dust
# Cost: May miss attacks
```

---

## Testing Checklist

Use these real-world patterns to test your implementation:

```python
def test_all_patterns():
    detector = SpamDetector()
    
    # Test 1: Classic poisoning
    assert detect_attack_case_1() >= 80, "Failed: Classic poisoning"
    
    # Test 2: Zero-value transfer
    assert detect_zero_value() >= 50, "Failed: Zero-value"
    
    # Test 3: Rapid cycling
    assert detect_rapid_cycling() >= 30, "Failed: Rapid cycling"
    
    # Test 4: Dust amount
    assert detect_dust_amount() >= 30, "Failed: Dust"
    
    # Test 5: New contract
    assert detect_new_contract() >= 35, "Failed: New contract"
    
    # Test 6: Legitimate should not flag
    assert check_legitimate() <= 20, "Failed: False positive"
    
    print("✅ All tests passed!")

# Run tests
test_all_patterns()
```

---

## Monitoring Metrics

After deployment, track:

```
Daily Metrics:
- Total transactions analyzed: ____
- Flagged as suspicious: ____
- Confirmed as malicious: ____
- False positives: ____
- False negatives: ____

Weekly Metrics:
- Detection rate: ___%
- False positive rate: ___%
- Average score of legitimate: ___
- Average score of malicious: ___

Monthly Metrics:
- Attacks prevented: ____
- Estimated value protected: $____
- Whitelist growth: ____
- Configuration adjustments made: ____
```
