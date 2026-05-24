# Performance & Scalability Review — 2026-05-24

Companion to [`../CODE_REVIEW_2026-05-24.md`](../CODE_REVIEW_2026-05-24.md). Verifies the [2026-04-09 audit memo](../CODE_REVIEW_2026-04-09.md) (45 days old at review time) against current code and adds new findings.

Baseline commit: `2ac8274`

---

## Bottom line

Audit memo is **mostly still accurate**, but every "Quick win" from items #1–#4 has shipped (WAL, address index, double-sleep removal, batch enrichment, LRU). The critical scale ceiling is unchanged: serial address processing + single SQLite writer + tiny global dedup cache cap the bot at roughly **200–500 active users** before per-cycle latency or duplicate notifications break it.

**Update 2026-05-24:** All top-5 items merged — see [CODE_REVIEW_2026-05-24.md](../CODE_REVIEW_2026-05-24.md#prs-merged-2026-05-24). #214 (TLS keep-alive) and #216 (parallel processing) are now in main; scale ceiling should improve materially.

---

## Verified findings (still present in current code)

- **Sequential address processing** — `checker.py:865-868`. Still `for address in addresses_to_check: await self._process_single_address(...)`. No semaphore/gather added. With ~0.5s/address (2 token calls + rate limiter delay of ~0.5s each plus DB roundtrips), 10k addresses = ~83 min/cycle at 60s scheduler interval; APScheduler `coalesce=True, max_instances=1` masks this by silently skipping cycles. **→ [#216](https://github.com/hostmaster/usdt_monitor_bot/pull/216) merged.**
- **Single-writer SQLite + connection-per-query** — `database.py:55-110`. Fresh `sqlite3.connect()` per call inside `asyncio.to_thread()`. WAL helps readers but writes still serialize.
- **Global notification dedup cache (10k cap)** — `checker.py:91-94`, default `NOTIFICATION_DEDUP_CACHE_SIZE=10_000` (`config.py:242`). Still an in-memory FIFO `set` + `deque`, shared across all users. At >5k users with daily activity, expect spurious duplicate notifications after restarts and partial eviction within a single cycle of a busy address. **→ [#218](https://github.com/hostmaster/usdt_monitor_bot/pull/218) merged.**
- **No per-user command rate limiting** — `handlers.py:73-197`. No middleware; every command path runs unauthenticated DB writes. **→ [#217](https://github.com/hostmaster/usdt_monitor_bot/pull/217) merged.**
- **`get_distinct_addresses()` full scan** — `database.py:307-315`. `SELECT DISTINCT address FROM wallets` runs every cycle; index helps point lookups but the DISTINCT is still a full b-tree walk over `idx_wallets_address`. Acceptable at <100k rows; problematic at multi-M.
- **Batch spam enrichment** — confirmed implemented correctly at `checker.py:456-530`, uses `get_known_senders` (`database.py:543-585`, chunk=500) + `get_contract_creation_blocks` (`etherscan.py:552-616`, chunk=5). Cache-size guard at `checker.py:504` is sound.

---

## Resolved since audit (verify ✓ against current code)

- **WAL + `synchronous=NORMAL`** shipped — `database.py:78-79` (commit `21fca3a`). Note: PRAGMAs run **per connection** which adds ~3 extra `PRAGMA` statements per query; sticky PRAGMA at `journal_mode` is a no-op but `synchronous` is set every time.
- **`idx_wallets_address` index** shipped — `database.py:220-221` (commit `a460922`).
- **Double-sleep in `_fetch_transactions_for_address`** removed — `checker.py:144-146` now has only the comment (commit `b50c933`).
- **LRU eviction for contract-creation cache** — `OrderedDict` with `move_to_end` + `popitem(last=False)` (`checker.py:89, 211-249`, commit `81faa2a`).
- **Composite `(monitored_address, from_address)` index** for `get_known_senders` — `database.py:214-215`.

---

## Drift from audit memo

- Audit cited `checker.py:715` for sequential loop; current location is **`checker.py:865-868`**.
- Audit cited `checker.py:74-78` for dedup cache; now **`checker.py:91-94`**.
- Audit cited `database.py:296` for `get_distinct_addresses`; now **`database.py:307-315`**.
- Audit cited `database.py:184` (missing index); index exists at `database.py:220-221`.
- Audit "fresh connection per query" claim at `database.py:70-104` is now `database.py:55-110` and the FK migration in `_migrate_transaction_history_fk_sync` opens **another** standalone connection at boot — fine, but not part of the pool/no-pool story.

---

## New findings

**Critical — none new beyond confirmed audit items.**

### High

1. **`force_close=True` on all three provider connectors** — `etherscan.py:173`, `blockscout.py:80`, `moralis.py:82`. Kills HTTP keep-alive: every Etherscan call pays a fresh TCP+TLS handshake (~50–150 ms on Etherscan's CDN). With ~10k–50k requests/cycle this is **8–125 min wasted per cycle** purely in TLS. The original justification (FD exhaustion) is moot because `limit=3`. Fix: drop `force_close=True`; `enable_cleanup_closed=True` if FD paranoia persists. Audit item #5 — flagged but not done. **→ [#214](https://github.com/hostmaster/usdt_monitor_bot/pull/214) merged.**
2. **`AdaptiveRateLimiter` is unsynchronised** — `etherscan.py:46-120`. `_current_delay`, `_consecutive_successes`, `_last_rate_limit_time` are mutated from concurrent `_make_request_with_rate_limiting` calls without a lock. With sequential per-address processing today the race is benign, but the moment you add `asyncio.gather` (audit fix #1) you get torn reads and lost rate-limit events. Fix: wrap `on_rate_limit`/`on_success` in `asyncio.Lock` **before** parallelising — cheap insurance. **→ [#216](https://github.com/hostmaster/usdt_monitor_bot/pull/216) merged.**
3. **PRAGMA on every connection** — `database.py:73-79`. Three `PRAGMA` statements run on **every** `_execute_db_query()` invocation. At ~5 queries/address/cycle × 10k addresses that's 150k unnecessary PRAGMA round-trips/cycle. `journal_mode` is sticky DB-wide; `foreign_keys` and `synchronous` are per-connection. Fix: keep `foreign_keys` and `synchronous` only; better, switch to a single long-lived `sqlite3.Connection` guarded by an `asyncio.Lock` (or `aiosqlite`) — eliminates the connection-open overhead the audit calls out without changing the DB.

### Medium

4. **`whitelisted_addresses` set rebuilt every transaction** — `checker.py:301-303` inside `_enrich_transaction_metadata` (called per tx). For 2 tokens it's cheap, but it iterates `token_registry.get_all_tokens().values()` and allocates a fresh `set` per tx. Trivial fix: precompute once in `__init__` (or per-cycle if tokens can hot-reload). Saves ~N×K small allocations/cycle.
5. **`get_users_for_address` runs per address per cycle** — `checker.py:645`, `database.py:317-323`. With 10k distinct addresses that's 10k single-row queries/cycle. Even with the new `idx_wallets_address`, this is still 10k thread-pool hops through `asyncio.to_thread`. Fix: bulk-load `{address: [user_ids]}` once per cycle alongside `get_distinct_addresses` (one `SELECT address, user_id FROM wallets`) — one query instead of N.
6. **`format_timestamp` uses naive `datetime.fromtimestamp`** — `notifier.py:258-263`. Returns server-local time, not UTC, in user notifications. Not a perf issue but a correctness inconsistency since stored timestamps are UTC-ISO. Fix: pass `tz=UTC`.
7. **`get_token_transactions` paginates with no max-page guard** — `etherscan.py:352-361`. Theoretical infinite loop if Etherscan ever returns a full page repeatedly. Fix: add a `max_pages` safety bound (e.g. 50 pages = 50k records).
8. **`spam_detector.analyze_transaction` rebuilds `whitelist_normalized` per tx** — `spam_detector.py:223-227`. Same allocation pattern as #4; cheap individually, multiplied by every tx. Hand the normalised set in from the caller.

---

## Recommended migration path (refined from audit)

1. **Done (merged 2026-05-24):** `force_close=True` removed (#214), parallel address processing + rate limiter lock (#216), DB-backed dedup (#218), per-user throttling (#217).
2. **Remaining short-term:** bulk `get_users_for_address` (one `SELECT address, user_id FROM wallets` per cycle instead of N queries), prune redundant PRAGMAs from `database.py:73-79`.
3. **Medium-term (L):** migrate to PostgreSQL + `asyncpg` (the audit's recommendation still stands); shard address checking across worker processes, each with its own Etherscan API key (free tier: ~5 req/s per key).

Current capacity estimate before blockers: ~200–500 users with modest address counts.
