# Code Review — 2026-04-09

Reviewer: Claude (Sonnet 4.5) via pi coding agent
Scope: full repository pass (~4.5k LOC app, ~5.8k LOC tests)
Baseline commit: `2ea2cd3` (main, clean working tree)
Lint status at review time: `ruff check` passes

## Overall impression

The project is in genuinely good shape:
- Clean module boundaries
- Consistent logging style (compact `key=value` f-strings)
- Thorough test coverage with in-memory SQLite fixtures
- Fallback providers with per-provider circuit breakers (`WithFallback`)
- The tricky block-checkpoint logic is well isolated in `block_tracker.py`

The improvements below are incremental — no rewrites suggested.

---

## 🟢 Quick wins (low risk, high value)

### 1. Enable SQLite WAL mode and tune PRAGMAs
**File:** `usdt_monitor_bot/database.py` (`_init_db_sync` or `_execute_db_query`)

`_execute_db_query` opens a fresh connection per query and only sets `PRAGMA foreign_keys`. Adding WAL once at init meaningfully reduces write contention and fsync cost.

```python
# In _init_db_sync(), after connecting:
conn.execute("PRAGMA journal_mode=WAL;")
conn.execute("PRAGMA synchronous=NORMAL;")
```

WAL persists at the DB level so a one-shot migration in `_init_db_sync` is enough. `synchronous=NORMAL` is safe with WAL and much faster than the default `FULL`.

### 2. Add an index on `wallets(address)`
**File:** `usdt_monitor_bot/database.py` (`_init_db_sync`)

`_get_users_for_address_sync` runs `SELECT user_id FROM wallets WHERE address = ?` on every checker cycle × address. The table only has `UNIQUE(user_id, address)`, which SQLite cannot use for an address-only lookup → full scan.

```sql
CREATE INDEX IF NOT EXISTS idx_wallets_address ON wallets(address);
```

One-line addition to the `queries` list in `_init_db_sync`.

### 3. De-duplicate `_MAX_VALID_BLOCK_NUMBER`
**Files:** `etherscan.py`, `blockscout.py`, `moralis.py`, `transaction_parser.py`

The constant is defined three times and imported from `etherscan.py` in `transaction_parser.py`. Move it to `blockchain_provider.py` (or a new `constants.py`) and import from there — kills drift risk.

### 4. Remove the redundant `asyncio.sleep` in `_fetch_transactions_for_address`
**File:** `usdt_monitor_bot/checker.py:~118` and `:~637`

```python
await asyncio.sleep(self._config.etherscan_request_delay / 2 or 0.1)
```

`EtherscanClient` already paces every request through `AdaptiveRateLimiter.wait()`. This is double-gating: every token fetch is delayed twice. A similar redundant sleep is also present at the top of `_process_single_address`. Delete both and let the rate limiter do its job.

**Expected effect:** ~30–50% faster cycles with no change in actual API rate.

### 5. Reconsider `force_close=True` on the HTTP connectors
**Files:** `etherscan.py`, `blockscout.py`, `moralis.py`

All three provider clients do:
```python
TCPConnector(limit=3, limit_per_host=2, force_close=True, ...)
```

`force_close=True` disables keep-alive, so every call does a fresh TCP + TLS handshake. With `limit=3` the FD exposure is already bounded; dropping `force_close` will cut per-request latency by ~50–150 ms without meaningfully increasing FD pressure. Easy experiment, easy rollback.

---

## 🟡 Medium wins (small refactors, clearer code)

### 6. Extract a tiny `BaseHTTPClient` for the three providers
**Files:** `etherscan.py`, `blockscout.py`, `moralis.py`, `blockchain_provider.py`

`EtherscanClient`, `BlockscoutClient`, `MoralisClient` independently reimplement `_create_session`, `_ensure_session`, `close`, and the connector/session-lock bookkeeping (~150 duplicated lines total).

A small base class in `blockchain_provider.py` with:
- `_create_connector()` / `_create_session()`
- `_ensure_session()` with the lock + double-check pattern
- `close()` with the robust cleanup (borrowing `EtherscanClient._close_session_and_connector`, which is the most hardened version)

…lets each client be ~30% shorter and fixes bugs in one place. Currently Blockscout and Moralis have slightly weaker variants than Etherscan.

### 7. Fetch tokens per address in parallel
**File:** `checker.py:_fetch_transactions_for_address`

Currently iterates USDT then USDC serially. Since the rate limiter is per-client and already serializes requests, doing them concurrently via `asyncio.gather` is safe:

```python
results = await asyncio.gather(
    *(self._fetch_one_token(token, address_lower, query_start_block)
      for token in self._config.token_registry.get_all_tokens().values()),
    return_exceptions=True,
)
```

Extract `_fetch_one_token` with the existing per-token error handling. Halves per-address latency when both tokens are configured.

### 8. Split `_execute_db_query` into typed helpers
**File:** `database.py`

The current signature has five mutually-exclusive boolean flags (`fetch_one`, `fetch_all`, `commit`, `use_row_factory`) and a return type that's `int | bool | Row | list[Row] | None`.

Split into three small helpers:
- `_commit(query, params) -> int` (rowcount, -1 on error)
- `_fetch_one(query, params, *, row_factory=False) -> Row | tuple | None`
- `_fetch_all(query, params, *, row_factory=False) -> list[Row] | list[tuple]`

Removes every downstream `isinstance(results, list)` guard and makes intent obvious at call sites. Pure mechanical change.

### 9. Split `load_config` (~180 lines)
**File:** `config.py`

Break into:
- `_load_rate_limiter_config()`
- `_load_fallback_config()`
- `_load_spam_detector_overrides()`
- `_apply_token_overrides(config)`

The `_spam_float_keys`/`_spam_int_keys` tables are a nice pattern — keep them, just move to module-level constants.

### 10. Simplify `notifier._format_token_message`
**File:** `notifier.py`

Has several distinct `try/except` blocks for formatting, each returning `None` with a debug log. Consolidate into one try block with small pure validators (`_validate_tx_hash`, `_validate_address`, `_validate_value`) that return `bool` and log once at entry. Cuts the function in half.

---

## 🟠 Worth considering

### 11. Store token value precisely
**File:** `database.py` schema, `checker.py:_store_transaction_safely`

Schema stores `value REAL`. `checker.py` converts `Decimal(raw) / 10**decimals` → `float` at write time. For dust-amount spam detection where values like `0.01` matter, float imprecision at the edges is real (though the 0.1 USD threshold probably insulates us in practice).

Options:
- Store `value_raw TEXT` (the raw on-chain integer string) + use `token_symbol` to get decimals at read time.
- New column `value_raw TEXT` alongside existing `REAL` for backward compat.

Non-trivial migration; optional.

### 12. Remove the silent failure in `WalletAddResult.ADDED`
**File:** `database.py:_add_wallet_sync`

If inserting into `wallets` succeeds but the follow-up `tracked_addresses` insert fails, it still returns `ADDED` and logs an error. The user sees "✅ Now monitoring…" but nothing actually runs.

Fix options:
- Return `DB_ERROR` in that branch.
- Or wrap both inserts in a single transaction (they currently use two separate connections via `_execute_db_query`).

### 13. `_contract_creation_cache` eviction is FIFO, not LRU
**File:** `checker.py:_cache_contract_block`

Pops `next(iter(dict))` (insertion order) regardless of recency. For a long-running bot, hot contracts can get evicted while cold ones persist.

Fix: swap the `dict` for `collections.OrderedDict` and use `move_to_end` on hit + `popitem(last=False)` on eviction. ~5 lines for proper LRU.

### 14. Minimal ruff config
**File:** `pyproject.toml`

`pyproject.toml` has ruff installed but no `[tool.ruff]` section. Even just:
```toml
[tool.ruff]
line-length = 100
target-version = "py314"

[tool.ruff.lint]
select = ["E", "W", "F", "I", "UP", "B", "SIM", "RET"]
```

will surface small things consistently. `ruff check` currently passes because no rules are selected beyond defaults.

### 15. Turn `pyright` back on in `basic` mode
**File:** `pyproject.toml`

`[tool.pyright] typeCheckingMode = "off"`. Type hints are already everywhere — might as well get value from them. `basic` mode with `reportMissingTypeStubs=false` would catch things like the `Optional[List[int]]` return from `get_users_for_address` being iterated without a `None` guard in some call sites (it's fine today, but the type system cannot tell).

---

## 🔵 Observability / polish (nice-to-have)

### 16. Expose cycle stats via `/stats`
`_log_cycle_summary` already builds a stats dict. Keep the last N cycles in memory and add a `/stats` command so users (or operators) can sanity-check without grepping logs.

### 17. Handler flood protection
aiogram has a built-in `ThrottlingMiddleware` pattern — if the bot is ever public, add it for `/add`, `/list`, `/spam`.

### 18. Reduce `handlers.py` boilerplate
Every handler does `if not user: return` and `await db_manager.add_user(...)`. Extract a tiny middleware that injects `user` and ensures registration, then handlers become 5–10 lines shorter each.

### 19. Optional structured logging
The compact `f"key=value"` style is good. One tiny step further: a JSON formatter behind a `LOG_FORMAT=json` env var would make these trivially parseable in aggregation tools. ~20 lines, fully optional.

---

## Suggested order (if picking five for one PR-sized change)

1. **#1 WAL mode** — biggest write perf win per line of code
2. **#2 address index** — fixes a real O(n) scan on a hot path
3. **#4 remove double-sleep** — immediate cycle-time win
4. **#3 + #6 de-dupe `_MAX_VALID_BLOCK_NUMBER` + extract `BaseHTTPClient`** — kills the largest block of duplication
5. **#8 split `_execute_db_query`** — simpler DB call sites throughout

---

## Not recommended / already good

- Block checkpoint logic in `block_tracker.py` — tricky but correct; don't touch lightly.
- `WithFallback` + `ProviderCircuitBreaker` — clean design, leave alone.
- Spam detector scoring engine — 7-filter design with `_apply_filter` helper is readable; the recent refactor (`cc54c03`) already reduced complexity well.
- Signal handling / graceful shutdown in `main.py` — correct and well-commented.
- Test coverage — comprehensive; `conftest.py` is well-structured with the in-memory fixture pattern.
