# Spam Detector Debugging Guide

## Overview

The spam detector includes comprehensive instrumentation for debugging cases where transactions bypass spam detection or fail to reach expected risk scores. This guide explains how to use these debugging tools to reverse-engineer spam bypass cases.

## Quick Start

Enable spam detection debugging by setting an environment variable before starting the bot:

```bash
export SPAM_DETECTION_DEBUG=true
python -m usdt_monitor_bot.main
```

Or for Docker:

```bash
docker run -e SPAM_DETECTION_DEBUG=true usdt_monitor_bot
```

## What Gets Logged

When debug logging is enabled, the spam detector logs detailed information about every transaction analysis:

### 1. **Whitelist Checks** - Early Exit Detection
```
[WHITELIST] 0xabc12def [FROM_WHITELISTED]     from=0xdac17f95 to=0x1234567890
```
Helps identify if transactions are being early-whitelisted unexpectedly.

### 2. **Filter Evaluations** - Per-Filter Scoring
```
[FILTER] 0xabc12def DUST_AMOUNT                ✓ TRIGGERED     +30  | from=0xdac17f95 (value=0.50)
[FILTER] 0xabc12def SIMILAR_ADDRESS            ✗ passed        +0   | from=0xdac17f95 (prefix=2 suffix=2)
[FILTER] 0xabc12def TIMING_SUSPICIOUS          ✓ TRIGGERED     +25  | from=0xdac17f95 (time_since_prev_tx_seconds=120)
```
Shows which filters triggered and their contribution to the risk score.

### 3. **Address Similarity Analysis** - Detailed Matching
```
[SIMILARITY] 0xabc12def different  | from=0xdac17 vs ref=0x85a0be | prefix: 2/3 | suffix: 2/4
[SIMILARITY] 0xdef45678 SIMILAR   | from=0x1234ab vs ref=0x12340f | prefix: 5/3 | suffix: 5/4
```
Shows how many characters match in prefix and suffix compared to thresholds.

### 4. **Timing Context** - Historical Data
```
[TIMING] 0xabc12def last_tx=120s   window=1200s [IN_WINDOW] history=5
[TIMING] 0xabc12def no_previous_tx window=1200s [NO_HISTORY] history=0
```
Shows timing window analysis and available historical data.

### 5. **Score Close to Threshold** - Near Misses
```
[SCORE_CLOSE_TO_THRESHOLD] 0xabc12def score=45/50 from=0xdac17f95 breakdown: DUST_AMOUNT(30) + TIMING_SUSPICIOUS(25)
```
Logs transactions that score 45-50 (default threshold is 50), helping identify edge cases.

### 6. **Spam Bypass Cases** - Primary Debug Output
```
[SPAM_BYPASS_CASE] 0xabc12def from=0xdac17f95 to=0x1234567890 value=0.50 score=45/50 flags=[DUST_AMOUNT,TIMING_SUSPICIOUS] reason=score_below_threshold (45/50)
```
The main warning for transactions with multiple risk flags but score below threshold.

### 7. **Final Verdict** - Decision Point
```
[SPAM_VERDICT] 0xabc12def: score=50/50 suspicious=True flags=DUST_AMOUNT,TIMING_SUSPICIOUS,SIMILAR_ADDRESS
[SPAM_VERDICT] 0xdef45678: score=20/50 suspicious=False flags=NONE
```
Shows the final decision on whether a transaction was flagged as suspicious.

## Analyzing Bypass Cases

### Step 1: Find the Bypass Case
Look for `[SPAM_BYPASS_CASE]` or `[SCORE_CLOSE_TO_THRESHOLD]` logs:

```
[SPAM_BYPASS_CASE] 0x12345678 from=0xabc123 to=0xdef456 value=0.10 score=45/50 flags=[DUST_AMOUNT,TIMING_SUSPICIOUS,NEW_SENDER] reason=score_below_threshold (45/50)
```

### Step 2: Extract Transaction Hash
Use the hash to find all related logs for that transaction:

```bash
# Extract logs for this transaction
grep "0x12345678" /var/log/bot.log | head -50
```

### Step 3: Review Filter Contributions
Look at the `[FILTER]` logs to see what was triggered:

```
[FILTER] 0x12345678 DUST_AMOUNT                ✓ TRIGGERED     +30  | from=0xabc123 (value=0.10)
[FILTER] 0x12345678 ZERO_VALUE_TRANSFER        ✗ passed        +0   
[FILTER] 0x12345678 TIMING_SUSPICIOUS          ✓ TRIGGERED     +25  | time_since_prev_tx_seconds=150
[FILTER] 0x12345678 SIMILAR_ADDRESS            ✗ passed        +0   | prefix=1 suffix=2
[FILTER] 0x12345678 NEW_SENDER_ADDRESS         ✓ TRIGGERED     +15  
```

This shows:
- DUST_AMOUNT: +30 (value < $1)
- TIMING_SUSPICIOUS: +25 (within 20 min window)  
- NEW_SENDER: +15 (first time seeing this address)
- Total so far: 70

But wait, the log showed score=45! This means some filters didn't trigger.

### Step 4: Check for Early Exits
Look for `[WHITELIST]` entries that might have early-exited:

```
[WHITELIST] 0x12345678 [FROM_WHITELISTED]     from=0xabc123 to=0xdef456
```

If this appears, the transaction was whitelisted and analysis stopped.

### Step 5: Verify Similarity Analysis
Find `[SIMILARITY]` logs to understand address matching:

```
[SIMILARITY] 0x12345678 different  | from=0xabc123 vs ref=0x1111111 | prefix: 0/3 | suffix: 1/4
```

This shows the current sender has 0 matching prefix chars (need 3) and 1 suffix char (need 4), so didn't trigger.

### Step 6: Check Timing Details
```
[TIMING] 0x12345678 last_tx=150s window=1200s [IN_WINDOW] history=1
```

Shows timing window was triggered (150s < 1200s).

## Common Bypass Patterns

### Pattern 1: Score Below Threshold
**Symptom**: Multiple filters triggered but score < threshold

**Cause**: Individual filter weights don't add up enough

**Debug Output**:
```
[SPAM_BYPASS_CASE] ... flags=[DUST_AMOUNT,TIMING_SUSPICIOUS] reason=score_below_threshold (45/50)
```

**Fix Options**:
1. Increase filter weights in config
2. Reduce threshold (currently 50)
3. Add additional filters

### Pattern 2: Whitelist Early Exit
**Symptom**: Transaction flagged but no analysis logs

**Cause**: Hit whitelist before any filter evaluation

**Debug Output**:
```
[WHITELIST] 0x12345678 [FROM_WHITELISTED] ...
```

**Fix Options**:
1. Review whitelist configuration
2. Consider separate whitelist policies for incoming/outgoing

### Pattern 3: Missing Historical Data
**Symptom**: Timing/similarity filters not triggered

**Cause**: No previous transactions or history pruned

**Debug Output**:
```
[TIMING] 0x12345678 no_previous_tx window=1200s [NO_HISTORY] history=0
```

**Fix Options**:
1. Ensure historical transaction storage is working
2. Increase history retention window

### Pattern 4: Address Similarity Edge Case
**Symptom**: Similar addresses not caught

**Cause**: Address matching just below threshold

**Debug Output**:
```
[SIMILARITY] 0x12345678 different | from=0xabc123 vs ref=0x1234567 | prefix: 2/3 | suffix: 3/4
```

The address has 2 prefix matches (need 3) and 3 suffix matches (need 4) - both just under threshold!

**Fix Options**:
1. Lower prefix_match_threshold (currently 3)
2. Lower suffix_match_threshold (currently 4)
3. Change AND logic to OR if desired

## Environment Variables for Debugging

### Enable Debugging
```bash
export SPAM_DETECTION_DEBUG=true
```

### Adjust Minimum Score for Logging
The detector logs transactions scoring within 5 points of the threshold (45-50 for default threshold of 50). This is configurable in code:

```python
from usdt_monitor_bot.spam_detector import enable_spam_detector_debugging
enable_spam_detector_debugging(min_score=40)  # Log score >= 40
```

## Interpreting Log Levels

- **DEBUG**: Filter evaluations, similarity analysis, timing details
- **INFO**: Score close to threshold, debugging enabled message
- **WARNING**: Spam bypass cases, high-risk transactions

Filter logs only appear if `SPAM_DETECTION_DEBUG=true`.
Score and bypass logs use INFO and WARNING levels respectively.

## Quick Diagnostic Queries

### Find All Transactions Scoring Close to Threshold
```bash
grep "\[SCORE_CLOSE_TO_THRESHOLD\]" bot.log
```

### Find All Bypass Cases
```bash
grep "\[SPAM_BYPASS_CASE\]" bot.log
```

### Analyze One Transaction's Full Debug Trail
```bash
TX_HASH="0x12345678"
grep "$TX_HASH" bot.log
```

### Summary of Spam Verdicts for an Address
```bash
ADDR="0xabc123"
grep "\[SPAM_VERDICT\]" bot.log | grep "$ADDR"
```

## Performance Considerations

Debug logging is optimized for minimal performance impact:

- Whitelist checks and verdicts always logged (minimal overhead)
- Filter evaluations only logged when `DEBUG_ENABLED=true`
- Similarity analysis only logged when `DEBUG_ENABLED=true`
- Bypass detection only logs when threshold is close

When disabled (`SPAM_DETECTION_DEBUG=false`), there is **zero performance impact** beyond a single environment variable check.

## Integration with Monitoring

These logs can be integrated with monitoring systems:

```bash
# Alert on spam bypass cases
grep "\[SPAM_BYPASS_CASE\]" bot.log | wc -l

# Track pattern of bypass reasons
grep "\[SPAM_BYPASS_CASE\]" bot.log | grep -o "reason=[^ ]*" | sort | uniq -c

# Monitor similarity edge cases
grep "\[SIMILARITY\]" bot.log | grep "different" | awk '{print $(NF-4)}' | sort | uniq -c
```

## Testing Debug Logging

Use the test suite to verify debugging works:

```bash
pytest tests/test_spam_detector.py -v -k "test_" --log-cli-level=DEBUG
```

Enable debug mode in tests:

```python
from usdt_monitor_bot.spam_detector import enable_spam_detector_debugging

def test_with_debug():
    enable_spam_detector_debugging()
    # ... test code ...
```

## See Also

- `spam_detector.py` - Core spam detection logic
- `SpamDebuggingLogger` class - Debug instrumentation implementation
- `checker.py` - How spam detector is used in transaction checking
- Configuration in `config.py` - Adjust detection thresholds
