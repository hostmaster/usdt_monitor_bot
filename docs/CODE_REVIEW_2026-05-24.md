# Code Review — 2026-05-24

Reviewer: Claude (Opus 4.7, 1M context) via Claude Code, three parallel general-purpose agents (architecture / performance / security)
Scope: full-repository pass (~5.8k LOC app, ~7.2k LOC tests)
Baseline commit: `2ac8274` (main, clean working tree)
Lint status at review time: `ruff check usdt_monitor_bot/ tests/` passes

Deep-dive companion files (full agent reports):
- [`reviews/2026-05-24-architecture.md`](reviews/2026-05-24-architecture.md)
- [`reviews/2026-05-24-performance.md`](reviews/2026-05-24-performance.md)
- [`reviews/2026-05-24-security.md`](reviews/2026-05-24-security.md)

Previous review: [`CODE_REVIEW_2026-04-09.md`](CODE_REVIEW_2026-04-09.md) (45 days ago)

---

## PRs merged (2026-05-24)

All top-5 findings were addressed and merged on 2026-05-24 in order: #214 → #215 → #217 → #218 → #216.

| PR | Title | Status |
|---|---|---|
| [#214](https://github.com/hostmaster/usdt_monitor_bot/pull/214) | Drop `force_close=True` from all three HTTP provider connectors | merged |
| [#215](https://github.com/hostmaster/usdt_monitor_bot/pull/215) | Reproducible Docker builds via `uv.lock` and pinned base images | merged |
| [#216](https://github.com/hostmaster/usdt_monitor_bot/pull/216) | Parallel address processing + thread-safe rate limiter | merged |
| [#217](https://github.com/hostmaster/usdt_monitor_bot/pull/217) | Per-user command rate limiting via aiogram middleware | merged |
| [#218](https://github.com/hostmaster/usdt_monitor_bot/pull/218) | Replace in-memory notification dedup cache with persistent DB table | merged |

---

## Bottom line

Healthy codebase with unusually careful block-checkpoint and provider-fallback design. No critical security issues. Practical scale ceiling is **~200–500 active users** — the same 2026-04-09 audit blockers are still in place, plus one quick win the previous review missed: `force_close=True` on every HTTP client is destroying TLS keep-alive across thousands of requests per cycle.

---

## Top 5 things to do first (highest ROI)

| # | Item | Where | Why it matters | Effort | PR |
|---|---|---|---|---|---|
| 1 | Drop `force_close=True` on all three providers' connectors | `etherscan.py:173`, `blockscout.py:80`, `moralis.py:82` | Each request pays full TCP+TLS handshake. At 10k–50k req/cycle this is **minutes to hours of pure handshake time per cycle**. Original FD-exhaustion concern is moot — `limit=3` already bounds the pool | XS | [#214](https://github.com/hostmaster/usdt_monitor_bot/pull/214) |
| 2 | `asyncio.gather` + bounded `Semaphore(8)` for per-address loop + `AdaptiveRateLimiter` lock | `checker.py:865-868`, `etherscan.py:46-120` | Cycle wall-time is linear today, single-threaded over a serial per-token-fetch loop. Single biggest scale blocker. Rate limiter lock is a prerequisite for safe concurrency. | M | [#216](https://github.com/hostmaster/usdt_monitor_bot/pull/216) |
| 3 | Make Docker build reproducible from `uv.lock` | `Dockerfile:17-18` doesn't reference `uv.lock`; `uv pip install --system .` re-resolves transitives at build time | Shipping `aiohttp 3.13.2` (18 CVEs) when lockfile resolves to `3.13.5`; CI security scan audits a different env than ships. Also pin base image + `astral-sh/uv:latest` by version tag | XS | [#215](https://github.com/hostmaster/usdt_monitor_bot/pull/215) |
| 4 | DB-backed notification dedup | `checker.py:91-94`, `config.py:242` | Global 10k FIFO in-memory; at >5k users one busy address can evict its own entries within a cycle → **duplicate notifications**. Also resets every restart | S | [#218](https://github.com/hostmaster/usdt_monitor_bot/pull/218) |
| 5 | Per-user aiogram throttling middleware | `handlers.py:73-197` | One user can spam `/add`/`/spam` to exhaust DB + Etherscan budget. 10 req/min/user/command is enough | S | [#217](https://github.com/hostmaster/usdt_monitor_bot/pull/217) |

---

## Architecture — summary

**Critical**
- **`TransactionChecker` is a god class** — `checker.py:65-875`. Block tracking + contract-creation LRU + notification dedup + batch enrichment + per-tx orchestration + 11 broad `except Exception`. Extract `ContractCreationCache`, `NotificationDedupCache`, `BatchEnrichmentService` — checker drops to ≲300 lines of pure orchestration.
- **`_process_single_address` holds the most non-obvious invariants** — `checker.py:723-829`. Three load-bearing rules tangled in one function (don't-advance-on-failure; triple `cap_block_to_latest` with different `log_level`s; `max_block_in_processed_batch` non-regression). Extract a pure `compute_final_block(start, raw, processed_max, latest, all_tokens_ok)` and matrix-test it.

**High**
- `SpamDetector.analyze_transaction` — 295 lines (`spam_detector.py:196-491`), filter 3 sets state that filter 4 reads, two patterns for filter helpers side-by-side. Make filters return `(flag, weight, details_patch)` tuples, run as a pipeline.
- `AdaptiveRateLimiter` lives in `etherscan.py` but is imported by Blockscout/Moralis → move to `rate_limiter.py`.
- `get_users_for_address`, `list_wallets`, `get_distinct_addresses` return `list[int] | None` — `None` silently means "DB error" and is masked by `if not user_ids`. Return `[]` and log.

**Medium**
- Three slightly-different `_ensure_session` implementations (`etherscan.py`, `blockscout.py`, `moralis.py`) — extract a `HttpSessionManager` helper.
- `_format_token_message` has 7 nested `try/except` (`notifier.py:33-151`); validate once upfront with a small dataclass.
- `BlockTracker` is mostly static methods — demote `cap_block_to_latest` etc. to module functions.
- `get_contract_creation_blocks` collapses transport errors into "not a contract" (`blockchain_provider.py:64-70`) — next cycle won't retry. Use a sentinel.
- `config.py` (384 lines) duplicates threshold defaults three times — `pydantic-settings` or per-concern dataclasses.

**What's good**
- Block-checkpoint logic with the `all_tokens_ok` guard and per-cycle `latest_block` cap (`checker.py:765-775, 802-807`) is genuinely careful — the comments explain *why*.
- `BlockchainProvider` Protocol + `WithFallback` + `ProviderCircuitBreaker` is clean composition; adding a fourth provider is trivial.
- `transaction_parser.py` — pure functions, well-tested.
- ~13k LOC tests vs 5.8k LOC source, no `time.sleep` in tests, real SQLite via `tmp_path` instead of mocks.
- CLAUDE.md is actually accurate.

Full report: [`reviews/2026-05-24-architecture.md`](reviews/2026-05-24-architecture.md).

---

## Performance & scalability — summary

**2026-04-09 audit memo verification:**
- Sequential loop, single-writer SQLite, 10k dedup cap, no rate-limit middleware, `SELECT DISTINCT address` scan — **all still present**, line numbers drifted (`checker.py:715→865`, `:74-78→:91-94`, `database.py:296→307`).
- Resolved since: WAL + `synchronous=NORMAL`, `idx_wallets_address`, double-sleep removed, LRU eviction on contract-creation cache, composite `(monitored_address, from_address)` index for `get_known_senders`. The "fix" column on items #5–#6 has shipped.

**New findings beyond the audit:**
- **`force_close=True` everywhere** — see top-5 #1. The single largest unbooked win.
- **`AdaptiveRateLimiter` is unsynchronised** — `etherscan.py:46-120`. Benign while loop is serial; torn reads the moment you `gather`. Add the lock *before* parallelising.
- **3 PRAGMA round-trips on every connection** — `database.py:73-79`. ~150k unnecessary statements/cycle at 10k addresses × 5 queries. `journal_mode` is sticky; only `foreign_keys` + `synchronous` need re-setting. Better: long-lived connection guarded by an `asyncio.Lock`, or switch to `aiosqlite`.
- **`get_users_for_address` runs N times per cycle** — `database.py:317-323`. Bulk-load `{address: [user_ids]}` once via `SELECT address, user_id FROM wallets`.
- `whitelisted_addresses` set rebuilt per transaction (`checker.py:301-303`, `spam_detector.py:223-227`); precompute once.
- `get_token_transactions` paginates with no max-page guard (`etherscan.py:352-361`); add a safety bound.
- `format_timestamp` uses naive local time (`notifier.py:258-263`) — correctness, not perf.

Full report: [`reviews/2026-05-24-performance.md`](reviews/2026-05-24-performance.md).

---

## Security — summary

**No critical issues.** Tight enough that the "verified clean" list below is the headline.

**High**
- **Docker build is non-reproducible** — `Dockerfile:17-18` runs `uv pip install --system .` without `uv.lock`. Ships `aiohttp 3.13.2` (18 CVEs) when lockfile resolves to `3.13.5`. Fix: `COPY uv.lock .` + `uv sync --frozen --system`. Same change makes the `security.yml` audit reflect what actually ships.

**Medium**
- No digest pins: `python:3.14-alpine`, `ghcr.io/astral-sh/uv:latest`, all third-party GitHub Actions on floating tags. tj-actions-style supply-chain risk; `docker.yml` runner has `packages: write` to GHCR.
- No `pre-commit` / secret-scan (no `.pre-commit-config.yaml`, no `gitleaks`/`detect-secrets`).

**Low**
- `BLOCKSCOUT_BASE_URL` not host-validated (operator-trust SSRF; could point at `169.254.169.254`).
- `tx_hash` only validated `startswith("0x")` then concatenated into `hlink` href (`notifier.py:126, 143`); aiogram doesn't escape href contents. Practical impact = Telegram rejects message, but enforce `^0x[a-fA-F0-9]{64}$`. Same for `USDT_CONTRACT_ADDRESS`/`USDC_CONTRACT_ADDRESS` operator vars.
- `.dockerignore` is permissive; current Dockerfile uses explicit `COPY` so exposure is nil, but one regression away.

**Verified clean** — all SQL parameterised; secrets only read from env, never logged; `.env` not in git history; every handler scopes by `user_id` (no cross-user leakage); `/spam` is per-user, not admin-bypass; handlers gated by `F.chat.type == "private"`; address validation `^0x[a-fA-F0-9]{40}$` at intake; aiogram `hbold`/`hcode` HTML-escape user names; no `eval`/`exec`/`shell=True`/`verify=False`/`ssl=False` anywhere; container runs as non-root with explicit `STOPSIGNAL`; CI workflows use least-privilege `permissions:`.

Full report: [`reviews/2026-05-24-security.md`](reviews/2026-05-24-security.md).

---

## Suggested sequencing

1. **Done (merged 2026-05-24):** drop `force_close=True` (#214), pin `uv.lock` into Dockerfile (#215), parallel address processing + `AdaptiveRateLimiter` lock (#216), per-user throttling (#217), DB-backed dedup (#218).
2. **Cleanup pass:** extract caches out of `TransactionChecker` (dedup cache gone via #218; contract-creation cache and enrichment service still inside), pull `AdaptiveRateLimiter` out of `etherscan.py` into `rate_limiter.py`, normalise `None`-returning DB methods to return `[]`.
3. **Hardening pass:** pin Actions + base images by SHA digest (PR #215 pins version tags; SHA pinning is the next step for Renovate to manage), add `gitleaks` pre-commit, tighten `tx_hash`/contract-address regex validation in notifier.
4. **Scale pass:** migrate to PostgreSQL + `asyncpg`, shard address checking across worker processes with separate Etherscan API keys.
