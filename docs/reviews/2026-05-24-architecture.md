# Architecture & Code-Quality Review — 2026-05-24

Companion to [`../CODE_REVIEW_2026-05-24.md`](../CODE_REVIEW_2026-05-24.md). Performance and security findings are separate files; this report is scoped to architecture, design, abstraction quality, and test discipline.

Baseline commit: `2ac8274`

---

## Top-line verdict

Solid, well-tested codebase with clear module boundaries, a thoughtful fallback/circuit-breaker layer, and unusually careful block-checkpoint semantics. The main rot is concentrated in `checker.py` — it carries too many responsibilities (orchestration + two caches + dedup + enrichment + block math) and `_process_single_address` holds the most non-obvious invariants in the project.

---

## Findings

### Critical

- **`TransactionChecker` is a god class** — `usdt_monitor_bot/checker.py:65-875`. The class owns block tracking, contract-creation LRU cache, notification dedup cache, batch enrichment pre-fetch, per-tx orchestration, error funnel, and stats. 11 broad `except Exception` blocks (lines 157, 188, 226, 333, 452, 486, 516, 561, 825). *Fix:* extract `ContractCreationCache`, `NotificationDedupCache`, and a `BatchEnrichmentService` (the prefetch + per-tx enrich pair) into their own modules; checker becomes pure orchestration <300 lines. **Partial progress:** [#218](https://github.com/hostmaster/usdt_monitor_bot/pull/218) (merged) removes the in-memory dedup cache (now DB-backed in `database.py`); contract-creation cache and enrichment service remain inside the class.
- **`_process_single_address` invariant density** — `checker.py:723-829`. Holds three load-bearing invariants: (a) don't advance block if any token fetch failed (line 771), (b) `cap_block_to_latest` applied *three* times with different `log_level`s in the same path, (c) `max_block_in_processed_batch` must never be regressed (line 804). One wrong refactor here re-notifies users or silently drops txs. *Fix:* return a single dataclass from a pure helper (`compute_final_block(start, raw, processed_max, latest, all_tokens_ok)`) and unit-test the matrix.

### High

- **`SpamDetector.analyze_transaction` is 295 lines with side-effecting debug log calls interleaved with scoring** — `spam_detector.py:196-491`. Filter 3 sets `_matched_last_sender` to gate filter 4 (lines 287-363) — a non-obvious cross-filter coupling. Filters 1/2/5/6/7 use the `_apply_filter` helper but 3/4 don't (they need `details` side effects), creating two patterns side-by-side. *Fix:* return a `(flag, weight, details_patch)` tuple from each filter, run them as a pipeline; keep `SpamDebuggingLogger` invocations in a single decorator/wrapper.
- **Sequential per-address loop blocks the cycle on slow addresses** — `checker.py:865-868`. With 500 addresses × 2 tokens × ~0.5s rate-limiter delay each, one cycle is single-threaded over a serial token-fetch loop. CLAUDE.md design says "polling every 60s" but cycle wall-time grows linearly. The abstraction (`_process_single_address` taking a shared `update_tasks` list) actively prevents parallelisation. *Fix:* `asyncio.gather` per address with a bounded `Semaphore`; the rate limiter is already centralised per provider. (See also performance report.) **→ [#216](https://github.com/hostmaster/usdt_monitor_bot/pull/216) merged: `_process_single_address` refactored to return `(stats_delta, update_tasks)`, loop replaced with `asyncio.gather` + `Semaphore(8)`.**
- **CLAUDE.md vs. code mismatch on `get_users_for_address` return type** — `database.py:317-323` returns `list[int] | None`; CLAUDE.md says checker calls it for "the per-address user fan-out" with no nullability discussion, and `_process_address_transactions:645` treats `None` as `[]` only because `if not user_ids:` happens to cover both. Same shape applies to `list_wallets`, `get_distinct_addresses`. *Fix:* return `[]` on error and log, never `None` — the union type silently leaks DB errors as "no users".
- **`AdaptiveRateLimiter` is imported from `etherscan` by both Blockscout and Moralis** — `blockscout.py:16`, `moralis.py` imports indirectly. It is not Etherscan-specific. *Fix:* move it to `rate_limiter.py` (or `blockchain_provider.py`); current placement is a leaky abstraction that pulls all of `etherscan.py` whenever a fallback wants pacing. **Note:** [#216](https://github.com/hostmaster/usdt_monitor_bot/pull/216) (merged) adds `asyncio.Lock` to `AdaptiveRateLimiter` but leaves it in `etherscan.py`; the relocation is a separate cleanup.

### Medium

- **Two parallel "ensure session" implementations** — `etherscan.py:249-275` (with double-checked lock + connector cleanup + `_close_session_and_connector`) vs. `blockscout.py:84-95` and `moralis.py:90-101` (simpler, no graceful-close delay). Same bug surface (FD leaks) reimplemented three times with subtly different semantics. *Fix:* extract a `HttpSessionManager` mixin or helper; the Etherscan version is the canonical one.
- **`_format_token_message` has 7 nested `try/except` with `except Exception`** — `notifier.py:33-151`. Many of the inner blocks catch errors that the validation immediately above already ruled out (e.g. address format error after `address.startswith("0x")`). *Fix:* validate once at the top with a small `_validate_tx_fields` dataclass and let formatting errors propagate to a single outer handler.
- **`BlockTracker` only owns 2 static methods + 1 async method** — `block_tracker.py:21-174`. `cap_block_to_latest` is called four times directly on `self._block_tracker` from `checker.py` for capping that has nothing to do with "tracking" — it's a guard. The class adds little over a module of free functions. *Fix:* keep `determine_next_block` instance-bound, demote `cap_block_to_latest` / `sync_block_with_blockchain` / `handle_latest_block_unavailable` to module functions.
- **`get_contract_creation_blocks` semantic divergence** — `blockchain_provider.py:185-225` documents that `None` entries are *not* re-queried against fallbacks; meanwhile `default_get_contract_creation_blocks:64-70` swallows per-address errors as `None`. A Blockscout transport hiccup mid-loop is therefore indistinguishable from "not a contract", and the next cycle won't retry. *Fix:* return a sentinel for transport failure, or have the per-address loop break early on the first transport error and surface it to `_call_with_fallback`.
- **`config.py` is 384 lines because every threshold has a getter and a constructor parameter** — `config.py:42-167`. Spam thresholds appear three times: in `BotConfig.__init__`, in env-var lists at lines 268-286, and as defaults inside `SpamDetector._default_config`. *Fix:* use `pydantic-settings` or a single dataclass per concern (rate-limiter config, spam config, fallback config) with `from_env()` classmethods.

### Low

- **`spam_detector.py` re-exports its split-out modules via `# noqa: F401`** — `spam_detector.py:17-26`. Reasonable backwards-compat shim but `if __name__ == "__main__":` demo block (lines 614-651) inside a production module is dead code. *Fix:* move the demo to `examples/` (the dir exists in docs).
- **Test fixtures set `os.environ` globally** — `tests/conftest.py:42-48`. With `pytest-xdist -n auto`, this is not safe in principle (workers are separate processes, so it currently works) but the fixture is order-sensitive — if any non-config test runs first, it picks up these env vars. *Fix:* use `monkeypatch.setenv` in a single fixture; never mutate `os.environ` directly in tests.
- **`SpamDebuggingLogger` is a class of static methods + class-level mutable state** — `spam_detector_logging.py:9-285`. Acts as a singleton via class attrs (`DEBUG_ENABLED`, `MIN_SCORE_FOR_DEBUG`). Threading is irrelevant here, but the global toggle is awkward to test. *Fix:* convert to a module with module-level flags or a single instance held by `SpamDetector`.
- **No `pre-commit` despite ruff + bandit in dependencies** — root dir has no `.pre-commit-config.yaml`. CI runs `ruff` and `security.yml` runs `bandit`, but local devs can push broken code. *Fix:* add a minimal `.pre-commit-config.yaml` with ruff + ruff-format + bandit.
- **`baseline.json` (3KB) and `application.log` (2MB) checked into the working tree** — likely artifacts. Should be in `.gitignore` if not already, and the 2MB log isn't a git file but pollutes greps.

---

## What the codebase does well

- **Block-checkpoint logic is genuinely careful** — the `all_tokens_ok` flag, `max_block_in_processed_batch` guard, and per-cycle `latest_block` cap together prevent both re-notification and silent skip-forward. The comments at `checker.py:765-775` and `802-807` explain *why*, which is rare.
- **Provider abstraction with `BlockchainProvider` Protocol + `WithFallback` + `ProviderCircuitBreaker`** — clean composition, easy to add a fourth provider, circuit breaker decoupled from the chain logic. `runtime_checkable` Protocol is the right tool.
- **Test discipline** — no `time.sleep` in tests (verified across `tests/`); `_opened_at` is rewound directly in `test_with_fallback.py:184,238`. Tests use real SQLite via `tmp_path`, not heavy mocking, for DB code. ~13k LOC tests vs 5.8k LOC source is a reasonable ratio.
- **`AdaptiveRateLimiter` keeps state at a small surface** (`etherscan.py:46-120`) — well-scoped, easy to reason about, properly unit-tested via `EtherscanClient` integration tests.
- **`transaction_parser.py`** — pure functions, no I/O, easy to test (`tests/test_transaction_parser.py` covers all five).
- **CLAUDE.md is accurate and up-to-date** on the load-bearing pieces (batch enrichment, dedup, block cap, fallback chain) — rare in production codebases.
