# Spam Detection Feature

**Status:** ✅ Production Ready
**Version:** 1.0
**Last Updated:** 2026-01-04

## Overview

The Spam Detection feature provides comprehensive protection against address poisoning attacks, dust attacks, and other malicious transaction patterns. It analyzes incoming transactions in real-time and warns users about suspicious activity.

## Quick Links

- **[User Guide](./spam_detection_guide.md)** - Practical guide for understanding and using spam detection
- **[Research Summary](../../research/RESEARCH_SUMMARY.md)** - Research basis for detection thresholds

## Key Features

### Detection Capabilities

1. **Dust Amount Detection** - Flags transactions below $1 USDT
2. **Zero-Value Transfer Detection** - Identifies zero-value transactions
3. **Timing-Based Detection** - Detects suspicious activity patterns within 20-minute windows
4. **Address Similarity Detection** - Identifies visually similar addresses (prefix/suffix matching)
5. **New Sender Detection** - Flags transactions from previously unknown addresses
6. **Brand New Contract Detection** - Identifies contracts created very recently (< 20 blocks)
7. **Rapid Address Cycling** - Detects multiple unique senders in short timeframes

### Risk Scoring

- **Score Range:** 0-100
- **Threshold:** Transactions with score ≥ 50 are flagged as suspicious
- **Weighted System:** Each detection filter contributes to the overall risk score

### User Experience

- Real-time transaction analysis
- Enhanced notifications with risk warnings
- Clear flag indicators
- Human-readable recommendations

## Configuration

The spam detection feature is enabled by default and can be configured via the `SpamDetector` class:

```python
from usdt_monitor_bot.spam_detector import SpamDetector

# Default configuration
detector = SpamDetector()

# Custom configuration
detector = SpamDetector(config={
    "dust_threshold_usd": 0.5,
    "similarity_prefix_threshold": 4,
    "similarity_suffix_threshold": 5,
    "risk_score_threshold": 60,
})
```

## Integration

The feature is fully integrated into the bot's transaction checking workflow:

1. Transactions are fetched from Etherscan
2. Each transaction is analyzed for spam patterns
3. Risk scores and flags are calculated
4. Enhanced notifications are sent to users
5. Transaction history is stored for future analysis

## Database Schema

The feature uses a `transaction_history` table to store historical transactions for pattern analysis:

```sql
CREATE TABLE transaction_history (
    tx_hash TEXT PRIMARY KEY,
    monitored_address TEXT NOT NULL,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    value REAL NOT NULL,
    block_number INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    token_symbol TEXT NOT NULL,
    risk_score INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Testing

Comprehensive test coverage is available in:
- `tests/test_spam_detector.py` - 46+ unit tests
- `tests/test_database.py` - Database operation tests
- `tests/test_checker.py` - Integration tests

## Performance

- **Database Operations:** Optimized with indexes
- **Memory Usage:** ~4KB per monitored address
- **CPU Impact:** < 1ms per transaction analysis
- **Storage:** Automatic cleanup of transactions older than 30 days

## Security

- ✅ Address format validation
- ✅ SQL injection protection
- ✅ Input validation at multiple levels
- ✅ Graceful error handling
- ✅ No external API dependencies for risk analysis

## Related Files

- `usdt_monitor_bot/spam_detector.py` - Core detection logic
- `usdt_monitor_bot/checker.py` - Integration point
- `usdt_monitor_bot/database.py` - Database operations
- `usdt_monitor_bot/notifier.py` - Enhanced notifications

## Future Enhancements

Potential improvements for future versions:

- Machine learning-based pattern recognition
- Community-based threat intelligence
- User-specific threshold customization
- Admin commands for risk management
- Analytics and reporting dashboard

---

**For research and design decisions, see the [Research Summary](../../research/RESEARCH_SUMMARY.md) document.**

