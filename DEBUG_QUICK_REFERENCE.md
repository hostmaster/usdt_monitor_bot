# Spam Detector Debug Quick Reference

## Quick Enable

```bash
export SPAM_DETECTION_DEBUG=true
python -m usdt_monitor_bot.main
```

## Common Debug Queries

### Find Bypass Cases
```bash
grep "[SPAM_BYPASS_CASE]" app.log
```

### Find Near-Misses (45-50 score)
```bash
grep "[SCORE_CLOSE_TO_THRESHOLD]" app.log
```

### Analyze One Transaction
```bash
TX="0x12345678"
grep "$TX" app.log | grep -E "\[(FILTER|SIMILARITY|TIMING|WHITELIST|SPAM_VERDICT)\]"
```

### List All Bypass Reasons
```bash
grep "[SPAM_BYPASS_CASE]" app.log | grep -o "reason=[^ ]*"
```

### Find Whitelist Early Exits
```bash
grep "[WHITELIST]" app.log | grep -E "\[(FROM|TO|MONITORED)_"
```

## Log Format Reference

| Type | Level | Purpose |
|------|-------|---------|
| `[WHITELIST]` | DEBUG | Early exit reason |
| `[FILTER]` | DEBUG | Per-filter evaluation |
| `[SIMILARITY]` | DEBUG | Address similarity |
| `[TIMING]` | DEBUG | Time window analysis |
| `[SCORE_CLOSE_TO_THRESHOLD]` | INFO | Near-miss warning |
| `[SPAM_BYPASS_CASE]` | WARNING | Primary bypass alert |
| `[SPAM_VERDICT]` | DEBUG | Final decision |

## Typical Analysis Session

```bash
# 1. Capture logs with debug enabled
docker run -e SPAM_DETECTION_DEBUG=true mybot 2>&1 | tee debug.log &

# 2. Wait for issue to occur, then stop
sleep 300
pkill docker

# 3. Find bypass cases
grep "[SPAM_BYPASS_CASE]" debug.log

# 4. Extract one transaction hash
TX=$(grep "[SPAM_BYPASS_CASE]" debug.log | head -1 | grep -o "0x[a-f0-9]*" | head -1)
echo "Analyzing: $TX"

# 5. Show all logs for that transaction
grep "$TX" debug.log | less

# 6. Extract score and flags
grep "$TX" debug.log | grep BYPASS_CASE
```

## Score Breakdown Example

For transaction `0xabc12def` bypassing detection:

**Log Output:**
```
[FILTER] 0xabc12def DUST_AMOUNT       ✓ +30    (value < $1)
[FILTER] 0xabc12def TIMING_SUSPICIOUS ✓ +25    (within 20 min)
[FILTER] 0xabc12def SIMILAR_ADDRESS   ✗ +0     (not similar enough)
[SPAM_VERDICT] 0xabc12def score=45/50 suspicious=False
```

**Debugging Thought Process:**
> "I see DUST_AMOUNT (+30) and TIMING_SUSPICIOUS (+25) triggered, so I manually calculate: 30+25=55. Since the threshold is 50, this should be suspicious! But the verdict shows score=45/50 and suspicious=False. This means my manual calculation was wrong - the actual score is 45, not 55. One of those filters must not have actually contributed the full weight, or there's another factor reducing the score. Let me check the detailed logs to see what happened..."

This demonstrates how the debug logs help identify discrepancies between expected and actual behavior.

## Filter Weights (Default)

```python
"dust_risk_weight": 30         # Amount < $1
"zero_value_weight": 50        # Amount = $0
"timing_weight": 25            # Within 20 min
"similarity_weight": 40        # Similar address (prefix ≥3, suffix ≥4)
"new_address_weight": 15       # First time seeing sender
"brand_new_contract_weight": 35 # Age < 20 blocks
"rapid_cycling_weight": 30     # Multiple senders in 30 min
```

## Address Similarity Thresholds

```python
"prefix_match_threshold": 3    # First 3 chars must match
"suffix_match_threshold": 4    # Last 4 chars must match
```

Both must be ≥ threshold for flag. Example:
```
[SIMILARITY] SIMILAR   | from=0x1234ab vs ref=0x123456 | prefix: 5/3 | suffix: 4/4
✓ prefix=5 ≥ 3, suffix=4 ≥ 4 → SIMILAR
```

```
[SIMILARITY] different | from=0x1234ab vs ref=0xabcd56 | prefix: 2/3 | suffix: 2/4
✗ prefix=2 < 3, suffix=2 < 4 → NOT SIMILAR
```

## Key Bypass Patterns

### Pattern 1: Score Just Below Threshold
```
score=45/50 flags=[DUST_AMOUNT,TIMING_SUSPICIOUS]
```
Fix: Increase filter weights or lower threshold from 50 to 45

### Pattern 2: Whitelist Early Exit
```
[WHITELIST] ... [FROM_WHITELISTED]
```
Fix: Review whitelist configuration

### Pattern 3: Missing Historical Data
```
[TIMING] no_previous_tx window=1200s [NO_HISTORY] history=0
```
Fix: Ensure historical data is being stored

### Pattern 4: Address Similarity Edge Case
```
prefix: 2/3 suffix: 3/4
```
Just under threshold! Fix: Lower thresholds

## Environment Variables

```bash
# Enable debug logging
SPAM_DETECTION_DEBUG=true

# Verbose application logging (recommended with debug)
VERBOSE=true

# See debug+info level logs (info logs are near-miss warnings)
# Already shown with debug enabled
```

## Common Issues & Solutions

| Issue | Check | Fix |
|-------|-------|-----|
| Few logs appearing | `VERBOSE=true` | Enable verbose logging |
| No bypass cases | Thresholds too low | Increase weights or lower threshold |
| Many false positives | Thresholds too high | Decrease weights or raise threshold |
| Addresses not similar | Threshold too strict | Lower prefix/suffix thresholds |
| Timing window too wide | Catching legit users | Lower window from 1200s |

## Integration Examples

### Slack Alert on Bypass
```bash
grep "[SPAM_BYPASS_CASE]" app.log | \
  while read line; do
    curl -X POST -d "text=$line" $SLACK_WEBHOOK
  done
```

### Prometheus Metric
```bash
grep "[SPAM_BYPASS_CASE]" app.log | wc -l > /var/lib/prom/spam_bypass_count.txt
```

### Generate Report
```bash
echo "=== Bypass Cases ===" && grep "[SPAM_BYPASS_CASE]" app.log
echo "=== Score Summary ===" && grep "[SCORE_CLOSE_TO_THRESHOLD]" app.log
echo "=== Filter Stats ===" && grep "[FILTER]" app.log | grep "✓ TRIGGERED" | cut -d' ' -f3 | sort | uniq -c
```

## See Also

- Full guide: `docs/SPAM_DETECTOR_DEBUGGING.md`
- Implementation: `usdt_monitor_bot/spam_detector.py` → `SpamDebuggingLogger` class
- Tests: `tests/test_spam_detector_debugging.py`
