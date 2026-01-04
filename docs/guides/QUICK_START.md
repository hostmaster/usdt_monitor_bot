# Quick Start: Add Spam Detection to Your USDT Bot

**Time to implement:** 2-4 hours for basic detection

---

## Step 1: Copy the Detector Module

Copy `spam_detector.py` to your project:
```bash
cp spam_detector.py /path/to/usdt_monitor_bot/
```

---

## Step 2: Import in Your Code

In your `main.py` or `checker.py`:

```python
from spam_detector import SpamDetector, TransactionMetadata, RiskFlag
from decimal import Decimal
from datetime import datetime

# Initialize once at startup
detector = SpamDetector()
```

---

## Step 3: Analyze Each Transaction

When checking a transaction, add risk analysis:

```python
async def check_transaction(tx_hash: str):
    # Get transaction from Etherscan (your existing code)
    tx_data = etherscan_api.get_transaction(tx_hash)

    # NEW: Prepare transaction metadata
    tx_meta = TransactionMetadata(
        tx_hash=tx_hash,
        from_address=tx_data['from'],
        to_address=tx_data['to'],
        value=Decimal(tx_data['value']) / Decimal('1e6'),  # wei to USDT
        block_number=int(tx_data['blockNumber']),
        timestamp=datetime.now(),  # TODO: Get actual block timestamp
        is_new_address=True,  # TODO: Query database
        contract_age_blocks=0,  # TODO: Query first tx block
    )

    # NEW: Get recent transactions for context
    recent_txs = get_recent_transactions_from_db(limit=20)

    # NEW: Analyze
    analysis = detector.analyze_transaction(tx_meta, recent_txs)

    # NEW: Notify user about risks
    if analysis.is_suspicious:
        await notify_suspicious_transaction(tx_data, analysis)
    else:
        await notify_normal_transaction(tx_data)
```

---

## Step 4: Send Risk Notifications

Add to your handlers:

```python
async def notify_suspicious_transaction(tx, analysis):
    """Send warning about suspicious transaction"""

    message = (
        f"🚨 **POTENTIAL SPAM TRANSACTION** 🚨\n\n"
        f"**Risk Score:** {analysis.score}/100\n"
        f"**From:** `{tx['from']}`\n"
        f"**Amount:** {tx['value']/1e6:.2f} USDT\n\n"
    )

    if analysis.flags:
        message += "**Red Flags:**\n"
        for flag in analysis.flags:
            message += f"• {flag.value}\n"

    message += f"\n⚠️ {analysis.recommendation}"

    # Send to all monitoring users
    for user_id in get_monitoring_users():
        await bot.send_message(
            chat_id=user_id,
            text=message,
            parse_mode='Markdown'
        )


async def notify_normal_transaction(tx):
    """Send normal transaction notification"""

    message = (
        f"✅ **Transaction Received**\n"
        f"From: `{tx['from']}`\n"
        f"Amount: {tx['value']/1e6:.2f} USDT"
    )

    for user_id in get_monitoring_users():
        await bot.send_message(
            chat_id=user_id,
            text=message,
            parse_mode='Markdown'
        )
```

---

## Step 5: Store Results (Optional)

Add risk score to your database:

```python
def store_transaction_risk(tx_hash, analysis):
    """Store risk assessment in database"""
    cursor = db.cursor()
    cursor.execute(
        """
        UPDATE transactions
        SET risk_score = %s, is_suspicious = %s, detection_reason = %s
        WHERE tx_hash = %s
        """,
        (
            analysis.score,
            analysis.is_suspicious,
            ', '.join([f.value for f in analysis.flags]),
            tx_hash
        )
    )
    db.commit()
```

---

## Step 6: Add Telegram Commands (Optional but Recommended)

```python
async def cmd_suspicious(update, context):
    """Show recent suspicious transactions"""

    cursor = db.cursor()
    cursor.execute(
        """
        SELECT tx_hash, sender_address, risk_score
        FROM transactions
        WHERE is_suspicious = TRUE
        ORDER BY timestamp DESC LIMIT 5
        """
    )

    message = "🚨 **Recent Suspicious Transactions**\n\n"
    for tx_hash, sender, score in cursor.fetchall():
        message += f"Score: {score} | `{sender}`\n"

    await update.message.reply_text(message, parse_mode='Markdown')


# Add to application handlers
application.add_handler(CommandHandler("suspicious", cmd_suspicious))
```

---

## Step 7: Test It

```python
# Test with known poisoning pattern
test_legitimate = TransactionMetadata(
    tx_hash="0x1",
    from_address="0x85A0bee4659ECef2e256dC98239dE17Fb5CAE822",
    to_address="0xYourAddress",
    value=Decimal('100'),
    block_number=19000000,
    timestamp=datetime.now(),
)

test_poison = TransactionMetadata(
    tx_hash="0x2",
    from_address="0x85a0c3788d81257612e2581a6ea0ada244853a91",  # Similar!
    to_address="0xYourAddress",
    value=Decimal('0.01'),  # Dust!
    block_number=19000001,
    timestamp=datetime.now(),
)

analysis = detector.analyze_transaction(test_poison, [test_legitimate])

print(f"Score: {analysis.score}")  # Should be ~80+
print(f"Flags: {[f.value for f in analysis.flags]}")
print(f"Suspicious: {analysis.is_suspicious}")  # Should be True
```

---

## Configuration Tuning

**Too many false positives?** Increase thresholds:
```python
detector.config['suspicious_score_threshold'] = 60  # Was 50
detector.config['dust_threshold_usd'] = 5.0  # Was 1.0
```

**Missing real attacks?** Decrease thresholds:
```python
detector.config['suspicious_score_threshold'] = 40  # Was 50
detector.config['prefix_match_threshold'] = 2  # Was 3
```

---

## What Gets Flagged?

### ✅ WILL be flagged:
- Dust amount ($0.01-$1) from new address → **Risk: 60+**
- Zero-value transfer → **Risk: 50+**
- Address matching first 3 + last 4 chars → **Risk: 40+**
- Within 20 minutes of previous transaction → **Risk: 25+**
- Brand new contract (< 20 blocks old) → **Risk: 35+**

### ❌ WILL NOT be flagged:
- Large transfers (> $1)
- From established addresses (> 20 blocks old)
- Unusual address patterns (random characters)
- Outside 20-minute window from other transactions

---

## Common Issues

### "NameError: name 'Decimal' is not defined"
```python
# Add this import
from decimal import Decimal
```

### "Index out of range in similarity check"
```python
# Make sure you're passing clean addresses
address = address.replace('0x', '').lower()  # Remove prefix, lowercase
```

### "All transactions marked suspicious"
```python
# Likely threshold too low
detector.config['suspicious_score_threshold'] = 60  # Increase from 50
```

### "No suspicious transactions ever detected"
```python
# Likely threshold too high OR not storing new_address/contract_age correctly
# Check that these fields are being set:
# - is_new_address: must be True for dust attacks to score high
# - contract_age_blocks: must be < 20 for contract_age flag
```

---

## Next Steps

1. **Immediate (Do Now):**
   - Copy `spam_detector.py`
   - Import and initialize `SpamDetector()`
   - Add one risk analysis call to your transaction checker
   - Test with provided examples

2. **Short-term (This Week):**
   - Add risk score storage to database
   - Implement suspicious transaction notification
   - Create `/suspicious` command
   - Monitor false positive rate

3. **Medium-term (This Month):**
   - Add whitelisting feature
   - Build admin configuration UI
   - Create analytics reports
   - Fine-tune thresholds

4. **Long-term (This Quarter):**
   - Integrate external threat feeds
   - Add ML classification
   - Monitor cross-chain patterns
   - Build community blocklist

---

## Example Output

```
🚨 **POTENTIAL SPAM DETECTED** 🚨

Risk Score: 85/100
From: `0x85a0c3788d81257612e2581a6ea0ada244853a91`
Amount: 0.01 USDT

Red Flags:
• DUST_AMOUNT
• TIMING_SUSPICIOUS
• SIMILAR_ADDRESS
• BRAND_NEW_CONTRACT

⚠️ EXTREMELY HIGH RISK - Likely address poisoning attempt.
NEVER copy this address from history. Verify on Etherscan before any action.
```

---

## Support

Check these for detailed info:
- Address similarity: See `calculate_address_similarity()` in `spam_detector.py`
- Risk scoring: See `analyze_transaction()` in `spam_detector.py`
- Integration: See [integration_examples.md](../examples/integration_examples.md) for full examples
- Thresholds: See `_default_config()` in `spam_detector.py`

---

**Good luck protecting your USDT! 🛡️**
