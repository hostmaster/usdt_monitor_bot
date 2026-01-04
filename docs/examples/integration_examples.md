# Integration Examples for USDT Monitor Bot

## Database Schema Additions

Add these tables to your existing database to track transaction risk:

```sql
-- Enhanced transactions table with risk tracking
ALTER TABLE transactions ADD COLUMN (
    risk_score INTEGER DEFAULT 0,
    risk_flags JSON,
    is_suspicious BOOLEAN DEFAULT FALSE,
    similarity_score INTEGER,
    contract_age_blocks INTEGER,
    time_since_prev_tx INTEGER,
    detection_reason VARCHAR(500),
    flagged_at TIMESTAMP,

    INDEX idx_risk_score (risk_score),
    INDEX idx_is_suspicious (is_suspicious),
    INDEX idx_flagged_at (flagged_at)
);

-- New table: Suspicious address tracking
CREATE TABLE suspicious_addresses (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    address VARCHAR(42) UNIQUE NOT NULL,
    first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    risk_score INTEGER,
    flags JSON,
    threat_level ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'),
    is_confirmed_malicious BOOLEAN DEFAULT FALSE,
    notes TEXT,
    reported_by VARCHAR(50),

    INDEX idx_address (address),
    INDEX idx_threat_level (threat_level)
);

-- Whitelist for trusted addresses
CREATE TABLE trusted_addresses (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    address VARCHAR(42) UNIQUE NOT NULL,
    label VARCHAR(100),
    added_by VARCHAR(50),
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_address (address)
);
```

---

## Integration with Your Current Bot

### Option 1: Minimal Integration (Drop-in Enhancement)

```python
# In your existing handlers.py or checker.py

from spam_detector import SpamDetector, TransactionMetadata
from datetime import datetime
from decimal import Decimal

class USDTMonitorEnhanced:
    def __init__(self, db_connection, etherscan_api, telegram_bot):
        self.db = db_connection
        self.etherscan = etherscan_api
        self.bot = telegram_bot
        self.detector = SpamDetector()  # Initialize detector

    async def check_and_notify_transaction(self, tx_hash, monitored_address):
        """
        Check transaction for spam/malicious indicators
        before notifying users
        """
        try:
            # Get transaction from Etherscan
            tx_data = self.etherscan.get_transaction(tx_hash)

            # Get block info for timestamp
            block_info = self.etherscan.get_block(tx_data['blockNumber'])

            # Prepare transaction metadata
            tx_meta = TransactionMetadata(
                tx_hash=tx_hash,
                from_address=tx_data['from'],
                to_address=tx_data['to'],
                value=Decimal(tx_data['value']) / Decimal('1e6'),  # Convert from wei to USDT
                block_number=int(tx_data['blockNumber']),
                timestamp=datetime.fromtimestamp(int(block_info['timeStamp'])),
                is_new_address=self._is_new_address(tx_data['from']),
                contract_age_blocks=self._get_contract_age(tx_data['from']),
                gas_price=int(tx_data['gasPrice'])
            )

            # Get historical transactions for context
            historical = self.get_recent_transactions(monitored_address, limit=20)

            # Analyze transaction
            analysis = self.detector.analyze_transaction(tx_meta, historical)

            # Store in database
            self.store_transaction_with_risk(tx_meta, analysis)

            # Notify user
            await self.notify_with_risk_assessment(
                monitored_address,
                tx_meta,
                analysis
            )

        except Exception as e:
            print(f"Error checking transaction {tx_hash}: {e}")

    async def notify_with_risk_assessment(self, user_id, tx, analysis):
        """
        Send notification with risk assessment to user
        """
        if analysis.is_suspicious:
            # Suspicious transaction
            message = (
                f"🚨 **POTENTIAL SPAM DETECTED** 🚨\n\n"
                f"Risk Level: {self._get_risk_level(analysis.score)}\n"
                f"Risk Score: {analysis.score}/100\n\n"
                f"From: `{tx.from_address}`\n"
                f"Amount: {tx.value} USDT\n"
                f"Hash: `{tx.tx_hash}`\n\n"
                f"**⚠️ Red Flags:**\n"
            )

            for flag in analysis.flags:
                message += f"• {flag.value}\n"

            message += (
                f"\n**Recommendation:**\n"
                f"{analysis.recommendation}\n\n"
                f"**Actions:**\n"
                f"/verify_{tx.tx_hash} - Check on Etherscan\n"
                f"/report_{tx.tx_hash} - Report as malicious\n"
                f"/whitelist_{tx.from_address} - Add to whitelist"
            )
        else:
            # Normal transaction
            message = (
                f"✅ **Transaction Received**\n\n"
                f"From: `{tx.from_address}`\n"
                f"Amount: {tx.value} USDT\n"
                f"Hash: `{tx.tx_hash}`"
            )

        await self.bot.send_message(
            chat_id=user_id,
            text=message,
            parse_mode='Markdown'
        )

    def store_transaction_with_risk(self, tx, analysis):
        """Store transaction with risk assessment in database"""
        cursor = self.db.cursor()
        cursor.execute(
            """
            INSERT INTO transactions
            (tx_hash, sender_address, value, block_number, timestamp,
             risk_score, risk_flags, is_suspicious, detection_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tx.tx_hash,
                tx.from_address,
                float(tx.value),
                tx.block_number,
                tx.timestamp,
                analysis.score,
                str(analysis.flags),
                analysis.is_suspicious,
                ', '.join([f.value for f in analysis.flags])
            )
        )
        self.db.commit()

    def _get_risk_level(self, score: int) -> str:
        """Convert risk score to human-readable level"""
        if score >= 80:
            return "CRITICAL 🚨"
        elif score >= 60:
            return "HIGH ⚠️"
        elif score >= 50:
            return "MODERATE ⚠️"
        else:
            return "LOW ✅"

    def _is_new_address(self, address: str) -> bool:
        """Check if we've seen this address before"""
        cursor = self.db.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM transactions WHERE sender_address = ?",
            (address,)
        )
        return cursor.fetchone()[0] == 0

    def _get_contract_age(self, address: str) -> int:
        """Get age of address in blocks"""
        return 0  # TODO: implement with Etherscan API

    def get_recent_transactions(self, address: str, limit: int = 20):
        """Get recent transactions to address for context"""
        cursor = self.db.cursor()
        cursor.execute(
            """
            SELECT tx_hash, sender_address, value, block_number, timestamp
            FROM transactions
            WHERE recipient_address = ?
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (address, limit)
        )

        results = []
        for row in cursor.fetchall():
            results.append(TransactionMetadata(
                tx_hash=row[0],
                from_address=row[1],
                to_address=address,
                value=Decimal(str(row[2])),
                block_number=row[3],
                timestamp=row[4]
            ))

        return results
```

---

### Option 2: Telegram Command Integration

Add these commands to your handlers:

```python
# New commands for spam detection

async def handle_suspicious_transactions(update, context):
    """
    /suspicious - Show recent suspicious transactions
    """
    user_id = update.effective_user.id

    cursor = db.cursor()
    cursor.execute(
        """
        SELECT tx_hash, sender_address, value, risk_score, detection_reason, flagged_at
        FROM transactions
        WHERE is_suspicious = TRUE
        ORDER BY flagged_at DESC
        LIMIT 10
        """
    )

    rows = cursor.fetchall()
    if not rows:
        await update.message.reply_text("✅ No suspicious transactions detected!")
        return

    message = "🚨 **Recent Suspicious Transactions:**\n\n"
    for tx_hash, sender, value, score, reason, timestamp in rows:
        message += (
            f"Score: {score}/100 | Amount: {value} USDT\n"
            f"From: `{sender}`\n"
            f"Reason: {reason}\n"
            f"Hash: `{tx_hash}`\n"
            f"Time: {timestamp}\n\n"
        )

    await update.message.reply_text(message, parse_mode='Markdown')


async def handle_whitelist_address(update, context):
    """
    /whitelist ADDRESS - Add address to trusted whitelist
    """
    if not context.args:
        await update.message.reply_text(
            "Usage: /whitelist <address>\n"
            "Example: /whitelist 0x123abc..."
        )
        return

    address = context.args[0].lower()

    # Validate address format
    if not address.startswith('0x') or len(address) != 42:
        await update.message.reply_text("❌ Invalid Ethereum address format")
        return

    cursor = db.cursor()
    try:
        cursor.execute(
            "INSERT INTO trusted_addresses (address, label) VALUES (?, ?)",
            (address, f"Whitelisted by user {update.effective_user.id}")
        )
        db.commit()

        await update.message.reply_text(
            f"✅ Address whitelisted:\n`{address}`",
            parse_mode='Markdown'
        )
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")


async def handle_report_spam(update, context):
    """
    /report TX_HASH - Report transaction as spam/malicious
    """
    if not context.args:
        await update.message.reply_text(
            "Usage: /report <tx_hash>\n"
            "Example: /report 0xabc123..."
        )
        return

    tx_hash = context.args[0].lower()
    user_id = str(update.effective_user.id)

    cursor = db.cursor()

    # Get transaction details
    cursor.execute(
        "SELECT sender_address, value FROM transactions WHERE tx_hash = ?",
        (tx_hash,)
    )

    result = cursor.fetchone()
    if not result:
        await update.message.reply_text("❌ Transaction not found")
        return

    sender_address, value = result

    # Add to suspicious addresses
    cursor.execute(
        """
        INSERT INTO suspicious_addresses
        (address, threat_level, reported_by, notes)
        VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
        threat_level = 'CRITICAL',
        reported_by = ?
        """,
        (sender_address, 'CRITICAL', user_id, f"Reported via /report command", user_id)
    )
    db.commit()

    await update.message.reply_text(
        f"✅ Transaction reported as malicious\n"
        f"Address: `{sender_address}`\n"
        f"Amount: {value} USDT",
        parse_mode='Markdown'
    )


async def handle_check_address(update, context):
    """
    /check ADDRESS - Check if address is on suspicious list
    """
    if not context.args:
        await update.message.reply_text("Usage: /check <address>")
        return

    address = context.args[0].lower()

    cursor = db.cursor()

    # Check if in whitelist
    cursor.execute(
        "SELECT label FROM trusted_addresses WHERE address = ?",
        (address,)
    )

    if cursor.fetchone():
        await update.message.reply_text(
            f"✅ **TRUSTED ADDRESS**\n`{address}`",
            parse_mode='Markdown'
        )
        return

    # Check if suspicious
    cursor.execute(
        "SELECT risk_score, threat_level FROM suspicious_addresses WHERE address = ?",
        (address,)
    )

    result = cursor.fetchone()
    if result:
        score, threat = result
        await update.message.reply_text(
            f"🚨 **SUSPICIOUS ADDRESS**\n"
            f"Threat Level: {threat}\n"
            f"Risk Score: {score}\n"
            f"`{address}`",
            parse_mode='Markdown'
        )
        return

    await update.message.reply_text(
        f"⚠️ **UNKNOWN ADDRESS**\n"
        f"Not on whitelist or reported list\n"
        f"`{address}`",
        parse_mode='Markdown'
    )
```

---

### Option 3: Configuration via Telegram

```python
async def handle_config_risk(update, context):
    """
    /risk_config - Show/adjust risk detection thresholds
    """
    if not context.args:
        # Show current config
        config = detector.config
        message = "**Current Risk Detection Configuration:**\n\n"
        message += f"Dust Threshold: ${config['dust_threshold_usd']} USDT\n"
        message += f"Suspicious Score Threshold: {config['suspicious_score_threshold']}/100\n"
        message += f"Time Window: {config['suspicious_time_window']} seconds\n"
        message += f"Prefix Match Threshold: {config['prefix_match_threshold']} chars\n"
        message += f"Suffix Match Threshold: {config['suffix_match_threshold']} chars\n\n"
        message += (
            "To adjust:\n"
            "/risk_config dust 0.50 - Set dust threshold to $0.50\n"
            "/risk_config threshold 60 - Set risk score threshold to 60"
        )

        await update.message.reply_text(message, parse_mode='Markdown')
        return

    param = context.args[0].lower()

    if len(context.args) < 2:
        await update.message.reply_text("❌ Please provide a value")
        return

    value = context.args[1]

    try:
        if param == 'dust':
            detector.config['dust_threshold_usd'] = float(value)
            await update.message.reply_text(f"✅ Dust threshold set to ${value}")

        elif param == 'threshold':
            detector.config['suspicious_score_threshold'] = int(value)
            await update.message.reply_text(f"✅ Risk threshold set to {value}/100")

        else:
            await update.message.reply_text("❌ Unknown parameter")

    except ValueError:
        await update.message.reply_text("❌ Invalid value")
```

---

## Analytics & Reporting

```python
async def generate_risk_report(start_date, end_date):
    """
    Generate daily/weekly risk report
    """
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT
            DATE(timestamp) as date,
            COUNT(*) as total_txs,
            SUM(CASE WHEN is_suspicious THEN 1 ELSE 0 END) as suspicious_txs,
            AVG(risk_score) as avg_risk,
            MAX(risk_score) as max_risk
        FROM transactions
        WHERE timestamp BETWEEN ? AND ?
        GROUP BY DATE(timestamp)
        """,
        (start_date, end_date)
    )

    report = "📊 **Risk Report** 📊\n\n"
    report += "Date | Total | Suspicious | Avg Risk | Max Risk\n"
    report += "---|---|---|---|---\n"

    for date, total, suspicious, avg_risk, max_risk in cursor.fetchall():
        pct = (suspicious/total * 100) if total > 0 else 0
        report += f"{date} | {total} | {suspicious} ({pct:.1f}%) | {avg_risk:.0f} | {max_risk}\n"

    return report
```

---

## Testing Scenarios

```python
async def test_poisoning_detection():
    """
    Test detection with known poisoning attack signature
    """
    from spam_detector import TransactionMetadata
    from datetime import timedelta

    # From research: 700k USDT loss case
    legitimate = TransactionMetadata(
        tx_hash="0xlegit",
        from_address="0x2c11a3a5f7b50a573e66596563d15a630ed359b",
        to_address="0xb1cd9c0b2c11a3a5f7b50a573e66596563d15a63",
        value=Decimal('50000'),
        block_number=19000000,
        timestamp=datetime.now(),
        is_new_address=False,
        contract_age_blocks=50
    )

    # Poisoning (detected within 30 seconds)
    poison = TransactionMetadata(
        tx_hash="0xpoison",
        from_address="0x2c11a3a5f7b50a573e66596563d15a630ed359c",  # Lookalike!
        to_address="0xb1cd9c0b2c11a3a5f7b50a573e66596563d15a63",
        value=Decimal('0'),  # Zero value!
        block_number=19000001,
        timestamp=datetime.now() + timedelta(seconds=30),
        is_new_address=True,
        contract_age_blocks=1
    )

    detector = SpamDetector()
    analysis = detector.analyze_transaction(poison, [legitimate])

    assert analysis.is_suspicious, "Should detect poisoning"
    assert analysis.score >= 80, f"Score too low: {analysis.score}"

    print(f"✅ Poisoning detection test passed (Score: {analysis.score})")
```
