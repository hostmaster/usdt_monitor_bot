# Resource Leak Audit Report

## Summary

Comprehensive audit of file descriptor leaks and resource management issues, with all critical issues resolved.

## Issues Found and Fixed

### ✅ FIXED: EtherscanClient Session Leak

**Location:** `usdt_monitor_bot/etherscan.py`

**Problem:**
- Sessions were created on-demand in each method call without being closed
- Led to file descriptor exhaustion: "No file descriptors available"

**Solution:**
- Added `_ensure_session()` method with double-checked locking pattern to create/reuse a single session
- Added `_session_lock` to prevent race conditions during concurrent session creation
- All API methods now use `_ensure_session()` instead of creating sessions directly
- Session is properly closed in `main.py` shutdown handler via `await etherscan_client.close()`

### ✅ FIXED: Connection Pool Exhaustion

**Location:** `usdt_monitor_bot/etherscan.py`

**Solution:**
- Added `TCPConnector` with strict connection limits:
  - `limit=3` (max total connections)
  - `limit_per_host=2` (max per host)
  - `ttl_dns_cache=300` (DNS cache TTL)
- Session cleanup relies on aiohttp's automatic connector closing

### ✅ FIXED: Aiogram Bot Session Limits

**Location:** `usdt_monitor_bot/main.py`

**Solution:**
- Configured `AiohttpSession` with `limit=10` to prevent connection exhaustion during polling

### ✅ FIXED: SQLite Connection File Descriptor Leak

**Location:** `usdt_monitor_bot/database.py`

**Problem:**
- SQLite connections managed by context managers (`with sqlite3.connect(...)`) in async thread pools were not releasing file descriptors immediately
- FDs accumulated from 16 to 1000+, exhausting the 1024 limit
- Caused: "Cannot connect to host api.etherscan.io:443 ssl:default [No file descriptors available]"

**Root Cause:**
- Context manager cleanup relies on Python's garbage collection timing
- When called from `asyncio.to_thread()`, GC delays caused FD accumulation under high-frequency operations

**Solution:**
- Changed from implicit context manager to explicit connection management
- Created `try/except/finally` pattern with explicit `conn.close()` in finally block
- Ensures file descriptors are released immediately after each query, independent of GC timing

**Code Pattern:**
```python
try:
    conn = sqlite3.connect(db_path, ...)
    # Execute query
    return result
except sqlite3.Error:
    # Handle errors
finally:
    # CRITICAL: Explicitly close connection
    if conn:
        conn.close()
```

**Verification:**
- Runtime logs showed FD count stabilized at 8-9 (oscillating temporarily during operations)
- No accumulation to 1000+ like before the fix
- "No file descriptors available" errors eliminated

## Resources Verified Safe ✅

| Resource | Location | Status | Notes |
|----------|----------|--------|-------|
| Database Connections | `database.py` | ✅ Safe | Explicit `conn.close()` in finally block ensures immediate FD release |
| Bot Session | `main.py` | ✅ Safe | Closed in `finally` block: `await bot.session.close()` |
| AsyncIO Tasks | `checker.py` | ✅ Safe | Uses `asyncio.gather()` with `return_exceptions=True` |
| Scheduler | `main.py` | ✅ Safe | `scheduler.shutdown(wait=True)` waits for jobs |
| Etherscan Client | `etherscan.py` | ✅ Safe | Single session with connection limits |

## Shutdown Sequence

The application follows a proper shutdown sequence in `main.py`:

```python
finally:
    scheduler.shutdown(wait=True)  # Wait for running jobs
    await etherscan_client.close()  # Close HTTP session
    await bot.session.close()       # Close bot session
```

## Conclusion

✅ **All critical resource leaks have been identified and fixed.**

The codebase properly manages:
- HTTP sessions (single reusable session with connection limits)
- Database connections (explicit close in finally block, independent of GC timing)
- Async tasks (proper awaiting)
- Graceful shutdown (ordered resource cleanup)

### Key Learnings

1. **Context managers alone are insufficient in async contexts:**
   - When thread-pool operations use context managers, cleanup timing depends on garbage collection
   - This can cause resource accumulation under high-frequency async operations
   - Solution: Explicit resource cleanup in finally blocks

2. **File descriptor exhaustion is critical:**
   - Default FD limit is often 1024 (ulimit -n)
   - Each SQLite connection holds 1+ FD
   - Accumulation happens silently until the limit is hit
   - Prevention: Explicit, immediate cleanup patterns
