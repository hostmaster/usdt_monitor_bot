# Malicious/Spam Transaction Detection for USDT Monitor Bot

## Overview

Malicious actors use **address poisoning** and **dust attack** tactics to:
1. Send very small amounts of USDT from fake addresses
2. Create addresses that visually resemble legitimate ones you've interacted with
3. Pollute your transaction history to trick you into copy-pasting wrong addresses
4. Use zero-value or near-zero-value transfers to appear in transaction logs

This guide provides practical detection strategies for your Telegram bot.

---

## Attack Patterns to Detect

### 1. **Address Similarity Attack (Prefix/Suffix Matching)**

**How it works:**
- Legitimate address: `0xd9A1b0B1e1aE382DbDc898Ea68012FfcB2853a91`
- Attacker address: `0xd9a1c3788d81257612e2581a6ea0ada244853a91`
- Notice: Same first 4 chars + same last 4 chars

**Detection metrics:**
- **Prefix match threshold:** ≥ 3 matching hex characters at start
- **Suffix match threshold:** ≥ 4 matching hex characters at end
- **Combined score:** Flag if (prefix_match ≥ 3) AND (suffix_match ≥ 4)

**Empirical research:** Address similarity with these thresholds catches majority of poisoning attempts while minimizing false positives.

### 2. **Timing-Based Detection (Dust Transaction Pattern)**

**Characteristics:**
- Occurs within **20 minutes (100-400 blocks)** after a legitimate transaction
- Sent from a previously unseen address
- To an address holding high balances
- Very small value: Often < $1 USDT

**Why it matters:** Attackers monitor wallet activity and immediately respond with similar-looking addresses.

### 3. **Value Threshold Detection**

**Red flags:**
- Transfer amount: **< $1 USDT** (or configurable threshold)
- Zero-value transfers: Some use `0 USDT` transfers via `transferFrom`
- Dust amount: Any transfer that seems designed to pollute history rather than conduct real business

### 4. **Zero-Value & Low-Gas Transfers**

**Attack variant:** ERC-20 zero-value transfers
- Technically possible via `transfer()` with amount = 0
- Creates visible history entry
- No legitimate reason for zero-value transfers
- Easy to spam since gas cost is minimal

---

## Implementation Strategy

### Phase 1: Data Collection (Enhance Your Current System)

For each incoming transaction, collect and store:

```python
transaction_metadata = {
    'hash': str,                    # tx hash
    'from': str,                    # sender address
    'to': str,                      # recipient address
    'value': Decimal,               # USDT amount
    'block_number': int,            # block number
    'timestamp': datetime,          # when confirmed
    'block_time_from_prev': int,    # seconds since last tx to monitored address
    'from_contract_age': int,       # how old is sender's contract (in blocks)
    'is_new_address': bool,         # first time seeing this sender
    'gas_price': int,              # transaction gas price
    'similar_to_previous': float,   # similarity score (0-100)
    'is_zero_value': bool,         # explicitly check for 0 USDT
}
```

### Phase 2: Similarity Scoring Function

```python
def calculate_address_similarity(address_a: str, address_b: str) -> dict:
    """
    Compare two Ethereum addresses for visual similarity.
    Returns prefix match, suffix match, and risk score.
    """
    # Normalize addresses
    addr_a = address_a.lower().replace('0x', '')
    addr_b = address_b.lower().replace('0x', '')
    
    if len(addr_a) != 40 or len(addr_b) != 40:
        return {'prefix_match': 0, 'suffix_match': 0, 'risk_score': 0}
    
    # Calculate prefix matches (first chars)
    prefix_matches = 0
    for i in range(min(8, len(addr_a))):  # check first 8 chars max
        if addr_a[i] == addr_b[i]:
            prefix_matches += 1
        else:
            break
    
    # Calculate suffix matches (last chars)
    suffix_matches = 0
    for i in range(1, min(8, len(addr_a)) + 1):
        if addr_a[-i] == addr_b[-i]:
            suffix_matches += 1
        else:
            break
    
    # Risk score: based on research thresholds
    # Flag if prefix >= 3 AND suffix >= 4
    is_suspicious = (prefix_matches >= 3) and (suffix_matches >= 4)
    
    risk_score = 0
    if prefix_matches >= 3:
        risk_score += prefix_matches * 10
    if suffix_matches >= 4:
        risk_score += suffix_matches * 8
    
    return {
        'prefix_match': prefix_matches,
        'suffix_match': suffix_matches,
        'is_similar': is_suspicious,
        'risk_score': min(100, risk_score),
    }
```

### Phase 3: Spam Detection Filters

```python
def analyze_transaction_risk(tx: dict, historical_txs: list) -> dict:
    """
    Comprehensive spam/malicious transaction detection.
    Returns risk score and specific reasons for flagging.
    """
    risk_factors = {
        'score': 0,
        'flags': [],
        'is_suspicious': False,
    }
    
    # FILTER 1: Value threshold
    if 0 < tx['value'] < 1:  # Dust threshold: < $1 USDT
        risk_factors['score'] += 30
        risk_factors['flags'].append('DUST_AMOUNT')
    
    # FILTER 2: Zero-value transfer
    if tx['value'] == 0:
        risk_factors['score'] += 50
        risk_factors['flags'].append('ZERO_VALUE_TRANSFER')
    
    # FILTER 3: Timing - check if within 20 minutes of previous tx
    if historical_txs:
        last_tx = historical_txs[-1]
        time_delta = (tx['timestamp'] - last_tx['timestamp']).total_seconds()
        
        if 0 < time_delta < 1200:  # Less than 20 minutes
            risk_factors['score'] += 25
            risk_factors['flags'].append('TIMING_SUSPICIOUS')
            
            # FILTER 4: Address similarity with recent contact
            similarity = calculate_address_similarity(tx['from'], last_tx['from'])
            if similarity['is_similar']:
                risk_factors['score'] += 40
                risk_factors['flags'].append(f"SIMILAR_ADDRESS_{similarity['prefix_match']}p_{similarity['suffix_match']}s")
    
    # FILTER 5: New address (first time seeing sender)
    if tx['is_new_address']:
        risk_factors['score'] += 15
        risk_factors['flags'].append('NEW_SENDER_ADDRESS')
    
    # FILTER 6: Check against known patterns
    # Compare against all previous senders for similarity
    for prev_tx in historical_txs[-10:]:  # Check last 10 transactions
        similarity = calculate_address_similarity(tx['from'], prev_tx['from'])
        if similarity['is_similar']:
            risk_factors['score'] += 35
            risk_factors['flags'].append(f"LOOKALIKE_PREVIOUS_SENDER")
            break  # Don't double-count
    
    # Determine if suspicious
    risk_factors['is_suspicious'] = risk_factors['score'] >= 50
    
    return risk_factors
```

---

## Configuration & Thresholds (Recommended Defaults)

```python
SPAM_DETECTION_CONFIG = {
    # Value thresholds
    'dust_threshold_usd': 1.0,          # Flag transfers < $1
    'zero_value_flag': True,             # Always flag zero-value
    
    # Address similarity
    'prefix_match_threshold': 3,         # First N chars
    'suffix_match_threshold': 4,         # Last N chars
    
    # Timing windows
    'suspicious_time_window_seconds': 1200,  # 20 minutes
    'min_blocks_for_address_age': 20,        # New addresses < 20 blocks
    
    # Risk scoring
    'dust_risk_weight': 30,
    'zero_value_weight': 50,
    'timing_weight': 25,
    'similarity_weight': 40,
    'new_address_weight': 15,
    
    # Thresholds for action
    'suspicious_score_threshold': 50,    # Flag if score >= this
    'block_threshold': 40,               # Don't flag if sender has 40+ blocks
    
    # Multi-address detection
    'rapid_address_cycling_threshold': 3,  # 3+ unique senders in 30 min
    'rapid_address_time_window': 1800,     # 30 minutes
}
```

---

## Integration Checklist

- [ ] Add transaction metadata storage (block time, contract age, etc.)
- [ ] Implement `calculate_address_similarity()` function
- [ ] Build `analyze_transaction_risk()` analysis engine
- [ ] Update database schema with risk tracking fields
- [ ] Enhance Telegram notifications with risk flags
- [ ] Add `/suspicious` command to show flagged transactions
- [ ] Create admin `/risk_config` command for threshold tuning
- [ ] Log all suspicious transactions for analysis
- [ ] Set up alerts for rapid address cycling attacks
- [ ] Test with known poisoning attack signatures

---

## API & Data Sources

**For address analysis:**
- **Etherscan API:** `eth_getTransactionByHash`, `eth_blockNumber`
- **BlockScout:** Open-source alternative
- **Alchemy:** Enhanced transaction metadata

**For threat intelligence:**
- **Chainalysis API:** Real-time threat data
- **TRM Labs:** Address risk scoring
- **Scorechain:** Token poisoning detection

---

## Testing Recommendations

1. **Create test scenarios** with synthetic poisoning attempts
2. **Compare against known attacks** from research (700k USDT loss case, etc.)
3. **Tune thresholds** based on false positive rate
4. **Monitor false negatives** by checking Etherscan for missed attacks
5. **Build whitelist** for trusted addresses (exchanges, known counterparties)
