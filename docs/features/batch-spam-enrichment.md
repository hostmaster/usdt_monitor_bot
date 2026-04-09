# Feature: Batch Pre-fetch for Spam Detection Enrichment

**Status:** ✅ Implemented
**Area:** `checker.py`, `database.py`, `blockchain_provider.py`, `etherscan.py`, `blockscout.py`, `moralis.py`
**Target files:**
- `usdt_monitor_bot/checker.py` (`_send_notifications_for_batch`, `_enrich_transaction_metadata`, `_get_contract_age_blocks`)
- `usdt_monitor_bot/database.py` (new bulk query methods)
- `usdt_monitor_bot/blockchain_provider.py` + `etherscan.py` / `blockscout.py` / `moralis.py` (new bulk contract-creation method)

---

## 1. Problem

Current per-transaction enrichment in `checker.py::_enrich_transaction_metadata` (lines ~233–269) fires **two remote calls per tx**:

1. `self._db.is_new_sender_address(monitored_address, from_address)` — one SQLite roundtrip (each call dispatched via `asyncio.to_thread` → opens a fresh connection).
2. `self._get_contract_age_blocks(from_address, block_number)` — on cache miss, one Etherscan `getcontractcreation` call.

Plus, upstream, `_send_notifications_for_batch` already calls `get_recent_transactions` once per address (fine), but the inner loop is strictly sequential:

```python
for tx in batch:                                # N transactions
    await self._db.is_new_sender_address(...)   # 1 DB roundtrip
    await self._etherscan.get_contract_creation_block(...)  # 1 HTTP call on miss
    await self._db.store_transaction(...)       # 1 DB roundtrip
```

### Scaling math

At **500 k txs/cycle** (as raised in the issue):

| Call                              | Per tx | Per cycle  | Notes                                               |
|-----------------------------------|--------|------------|-----------------------------------------------------|
| `is_new_sender_address`           | 1      | 500 k      | Each = open conn + SELECT                           |
| `get_contract_creation_block`     | ≤1     | up to 500k | Cached, but cold cache / eviction → Etherscan burst |
| `store_transaction`               | 1      | 500 k      | Existing; not in scope but same pattern             |
| **Total extra per-tx roundtrips** |        | **~1.5M**  |                                                     |

Each `is_new_sender_address` call goes through `_run_sync_db_operation` → `asyncio.to_thread` → opens and closes a SQLite connection. That is cheap in absolute terms but dominates wall-clock when multiplied by 500 k, and it serialises the whole spam-detection phase behind the GIL-bounded thread pool.

The Etherscan path is worse: `getcontractcreation` is rate-limited (5 req/s on the free tier) and each miss also passes through the tenacity retry layer. A cold cache on 10 k distinct senders = ~35 minutes just for contract-age lookups.

---

## 2. Goal

Replace the inner per-tx N+1 pattern with **batch pre-fetch**, done once per address (or once per cycle where cheap), so that `_enrich_transaction_metadata` becomes a pure in-memory lookup.

Target after change, per address with `M` unique senders in the batch:

| Call                              | Before | After                          |
|-----------------------------------|--------|--------------------------------|
| `is_new_sender_address`           | `N`    | **1** (bulk SELECT IN …)       |
| `get_contract_creation_block`     | `≤N`   | **⌈M_uncached / 5⌉** (batched) |
| `get_recent_transactions`         | 1      | 1 (unchanged)                  |

For 500 k txs spread across 10 k senders, that is ~10 k → ~2 k HTTP calls on cold cache, and 500 k → number-of-addresses DB calls.

---

## 3. Non-goals

- **Not** touching `store_transaction` in this feature — it is a write path and the `INSERT OR IGNORE` pattern is already idempotent. A separate follow-up (`executemany`) can batch it later.
- **Not** changing `SpamDetector.analyze_transaction` itself — it already operates on already-enriched `TransactionMetadata`. The change is upstream.
- **Not** changing the rest of the filter pipeline (dust / similarity / timing). They already work off the in-memory historical list.
- **Not** introducing cross-cycle caching of sender-history. Dedup cache stays in-memory, per-process, as today.

---

## 4. Design

### 4.1. Bulk DB method: `get_known_senders`

Add to `DatabaseManager`:

```python
def _get_known_senders_sync(
    self, monitored_address: str, sender_addresses: list[str]
) -> set[str]:
    """Return the subset of sender_addresses already seen for monitored_address."""
    if not sender_addresses:
        return set()
    # Deduplicate + lowercase in caller; this stays a pure lookup
    placeholders = ",".join("?" * len(sender_addresses))
    query = f"""SELECT DISTINCT from_address
                FROM transaction_history
                WHERE monitored_address = ?
                  AND from_address IN ({placeholders})"""
    params = (monitored_address.lower(), *sender_addresses)
    rows = self._execute_db_query(query, params, fetch_all=True) or []
    return {row[0] for row in rows}

async def get_known_senders(
    self, monitored_address: str, sender_addresses: list[str]
) -> set[str]:
    return await self._run_sync_db_operation(
        self._get_known_senders_sync, monitored_address, sender_addresses
    )
```

Notes:
- Uses a single `IN (?, ?, …)` query. SQLite's parameter cap is 32 766 (SQLITE_MAX_VARIABLE_NUMBER on modern builds) — safely over any realistic per-address batch, but we chunk defensively at **500** per query to stay well below historic 999 cap on older builds.
- Returned as a `set[str]` of **lowercased** addresses so the caller can compute "new" with `sender not in known`.
- We already have an index on `transaction_history(monitored_address)`. Verify `(monitored_address, from_address)` composite index exists; if not, add it in the same PR (see §4.5).

### 4.2. Bulk contract-creation method

#### Per-provider batch support (verified against current clients)

| Provider | Endpoint | Batch? | Limit | Notes |
|---|---|---|---|---|
| **Etherscan** (`etherscan.py:426`) | `module=contract&action=getcontractcreation&contractaddresses=<csv>` | ✅ native | **5** per call | `contractaddresses` param is already plural; response is already a list (`result[0]` today). Rate limit unchanged (5 req/s free tier), so 1 batched call ≈ 1 single call in budget terms. |
| **Blockscout** (`blockscout.py:165`) | REST v2 `GET /api/v2/addresses/{address}` | ❌ | 1 | Address is in URL path; no filter-by-list endpoint. `/api/v2/addresses` (plural) returns the global ranked address list, not a lookup. Etherscan-compat `getcontractcreation` on Blockscout was explicitly abandoned for v2 REST in this repo (`CLAUDE.md`). Must loop. |
| **Moralis** (`moralis.py:162`) | `GET /api/v2.2/{contract_address}?chain=eth` | ❌ on current endpoint | 1 | Moralis does offer `GET /api/v2.2/erc20/metadata?chain=eth&addresses=<a>&addresses=<b>` (up to 25, returns `block_number`) but it's a different endpoint shape and schema. Moralis is fallback #2 (only hit when Etherscan + Blockscout circuits are open), so the traffic is tiny. Out of scope; filed as follow-up in §8. |

#### Protocol change

Extend `BlockchainProvider` protocol in `blockchain_provider.py`:

```python
async def get_contract_creation_blocks(
    self, contract_addresses: list[str]
) -> dict[str, int | None]:
    """
    Batch variant. Returns a mapping from lowercased address to creation block,
    or None if the address is not a contract / lookup failed for that entry.
    Missing keys in the return value are treated as None.
    """
```

- **Default implementation** on the protocol (or as a mixin) simply loops `get_contract_creation_block` for each address. This is what `BlockscoutClient` and `MoralisClient` will inherit unchanged — no client rewrite required.
- **`EtherscanClient` override** chunks into groups of 5, issues one request per chunk, parses the full `result` array, and maps each entry back by `contractAddress` (lowercased). Addresses absent from the response are mapped to `None`.
- **`WithFallback.get_contract_creation_blocks`**:
  - Call primary's batch method.
  - If the **whole call raises** a transport-level error (or the circuit is open), fall back to the next provider for the full address list — same policy as the existing single-item fallback.
  - If the primary returns normally but some addresses map to `None`, **treat those as authoritative** ("not a contract" is a valid answer) — do **not** re-query fallbacks, because Blockscout/Moralis loop per-address and would re-amplify the N+1 we are trying to kill.
  - Per-chunk Etherscan failure inside the batch method → the Etherscan override degrades that specific chunk to single-address calls, so one bad address in a chunk cannot black-hole the other four.

### 4.3. Checker changes

Rewrite `_send_notifications_for_batch` so it pre-fetches enrichment data once, before entering the loop:

```python
async def _send_notifications_for_batch(self, user_ids, batch, address_lower):
    historical_metadata = await self._get_historical_transactions_metadata(
        address_lower, limit=20
    )

    # --- Batch pre-fetch phase ---
    unique_senders = list({
        (tx.get("from") or "").lower()
        for tx in batch
        if tx.get("from")
    })

    known_senders = await self._db.get_known_senders(address_lower, unique_senders)

    # Only fetch contract ages for senders not already in the cache
    uncached_senders = [
        s for s in unique_senders if s not in self._contract_creation_cache
    ]
    if uncached_senders:
        creation_blocks = await self._etherscan.get_contract_creation_blocks(
            uncached_senders
        )
        for addr, block in creation_blocks.items():
            self._cache_contract_block(addr, block)
        # Also cache explicit misses so we don't re-query next cycle
        for addr in uncached_senders:
            if addr not in creation_blocks:
                self._cache_contract_block(addr, None)

    # --- Per-tx processing now uses pre-fetched data ---
    enrichment_ctx = EnrichmentContext(
        known_senders=known_senders,
        # contract ages read straight from self._contract_creation_cache
    )

    notifications_sent = 0
    for tx in batch:
        try:
            notifications_sent += await self._process_single_transaction(
                tx, user_ids, address_lower, historical_metadata, enrichment_ctx
            )
        except Exception as e:
            logging.error(
                f"Process tx error {tx.get('hash', 'N/A')[:16]}: {e}", exc_info=True
            )
```

New dataclass (module-level in `checker.py`):

```python
@dataclass
class EnrichmentContext:
    """Pre-fetched enrichment data shared across a batch of txs for one address."""
    known_senders: set[str]
```

Refactor `_enrich_transaction_metadata` to take the context and become non-awaiting except for the rare on-demand fallback:

```python
async def _enrich_transaction_metadata(
    self,
    tx_metadata: TransactionMetadata,
    address_lower: str,
    historical_metadata: list[TransactionMetadata],
    ctx: EnrichmentContext,
) -> RiskAnalysis:
    sender = tx_metadata.from_address.lower()
    tx_metadata.is_new_address = sender not in ctx.known_senders

    # Contract age: always read from cache (populated by batch pre-fetch).
    # On cache miss (shouldn't happen if pre-fetch ran), fall back to the old
    # single-address path so we never regress.
    cached = self._contract_creation_cache.get(sender)
    if cached is None and sender not in self._contract_creation_cache:
        contract_age = await self._get_contract_age_blocks(
            sender, tx_metadata.block_number
        )
    else:
        contract_age = (
            max(0, tx_metadata.block_number - cached) if cached is not None else 0
        )
    tx_metadata.contract_age_blocks = contract_age

    # ... whitelist + analyze_transaction unchanged
```

Key invariant: once a tx is classified as "new sender" within a batch, subsequent txs from the **same** sender in the same batch should be classified as "not new" (since the first one has now been observed). Handle this by mutating `ctx.known_senders.add(sender)` inside the loop after processing each tx. This matches the pre-change behaviour where `store_transaction` ran between loop iterations and would have made `is_new_sender_address` return `False` on the next check — **actually verify this**: today's code awaits `store_transaction` inside `_process_single_transaction` before the next iteration, so the DB state flips mid-loop. The new code must preserve that semantic.

### 4.4. Cache interaction

`_contract_creation_cache` is still the source of truth for contract ages. The batch pre-fetch simply *populates* it in bulk, then per-tx enrichment reads from it. The bounded-eviction logic in `_cache_contract_block` stays as-is.

One subtlety: if `contract_creation_cache_size` is smaller than the number of unique senders in a single batch, we could evict our own pre-fetched data mid-loop. Mitigation: during pre-fetch, detect this and either (a) log a warning and fall back to the old single-address path, or (b) use a short-lived per-batch dict overlay. Recommended: **(a)**, because hitting that limit is a config-smell worth surfacing, and the fallback behaviour is simply "same as before this feature".

### 4.5. Index check

`transaction_history` should already have an index supporting the new `IN` query. Confirm in `database.py` schema and add if missing:

```sql
CREATE INDEX IF NOT EXISTS idx_tx_history_monitored_from
    ON transaction_history(monitored_address, from_address);
```

This benefits both `is_new_sender_address` (existing, if kept for fallback) and the new `get_known_senders`.

---

## 5. Step-by-step implementation

1. **Schema/index check** (`database.py`):
   - Audit `_init_db` for `transaction_history` indexes.
   - Add `idx_tx_history_monitored_from` if not present.

2. **Add bulk DB method** (`database.py`):
   - `_get_known_senders_sync` + `get_known_senders` as in §4.1.
   - Chunking at 500 params per query.
   - Unit test: empty input → empty set; mix of known/unknown → exact subset; case-insensitive match.

3. **Extend provider protocol** (`blockchain_provider.py`):
   - Add `get_contract_creation_blocks(addresses) -> dict[str, int | None]` to the `BlockchainProvider` protocol with a default implementation that loops `get_contract_creation_block` (keeps Moralis/Blockscout working unchanged).
   - Add batch method to `WithFallback` — dispatches to primary, falls back per-provider on transport error only.

4. **Implement batch Etherscan call** (`etherscan.py`):
   - New `get_contract_creation_blocks` that chunks the input into groups of 5, issues one `getcontractcreation` request per chunk, and merges results into a `dict`.
   - Reuse `_make_request_with_rate_limiting`.
   - Same tenacity retry decorator as the single-address version.
   - On per-chunk failure, fall back to single-address calls for that chunk so we degrade gracefully (so a single bad address in a chunk does not black-hole the others).

5. **Refactor checker** (`checker.py`):
   - Add `EnrichmentContext` dataclass.
   - Rewrite `_send_notifications_for_batch` to do the batch pre-fetch as in §4.3.
   - Update `_enrich_transaction_metadata` + `_process_single_transaction` signatures to thread `ctx` through.
   - Preserve the "same-sender-appears-twice-in-batch" semantic by `ctx.known_senders.add(sender)` after each tx.
   - Leave `_get_contract_age_blocks` intact as a fallback path.

6. **Tests** (`tests/test_checker.py`, `tests/test_database.py`, `tests/test_etherscan.py`):
   - `test_get_known_senders_returns_intersection` — seed history, assert only known addresses returned.
   - `test_get_known_senders_empty_input` — no DB hit, returns `set()`.
   - `test_batch_contract_creation_chunks_by_5` — mock HTTP layer, assert 12 addresses → 3 chunked requests.
   - `test_batch_contract_creation_falls_back_on_chunk_error` — one chunk raises; verify per-address fallback.
   - `test_enrichment_uses_batch_prefetch` — spy on `is_new_sender_address` and `get_contract_creation_block` single-address methods; assert **zero calls** when batch methods return data for every sender.
   - `test_same_sender_twice_in_batch_second_is_not_new` — assert semantic parity with pre-change behaviour.
   - `test_enrichment_falls_back_when_cache_too_small` — set `contract_creation_cache_size=1`, feed batch with 5 distinct senders, assert the old single-address path is still used and results match.
   - `test_enrichment_cold_cache_1000_txs` (benchmark-style, not CI-gated): with a mocked provider, assert the number of HTTP calls is ≤ `ceil(unique_senders/5)` and DB calls ≤ `1 + ceil(unique_senders/500)`.

7. **Docs** — update `CLAUDE.md` "Key design decisions" with a bullet on batch pre-fetch, and reference this plan.

---

## 6. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Semantic drift for repeated senders in one batch | Mutate `ctx.known_senders` after each tx (see §4.3 invariant); add explicit test. |
| Batch contract-creation endpoint returns partial results (some addresses missing) | Treat missing-in-response as `None` and cache as such. Confirmed by per-chunk-fallback step 4. |
| Etherscan chunk-level failure poisons 5 addresses at once | Per-chunk fallback to single-address calls on error (§4.4 step 4). |
| `_contract_creation_cache` too small vs batch size | Detect and fall back to old path; log warning pointing at `contract_creation_cache_size`. |
| Fallback providers (Blockscout, Moralis) lack batch support | Default protocol impl loops; no change required to those clients. |
| Large `IN (?, ?, …)` blows SQLite parameter limit | Chunk at 500 per query in `get_known_senders`. |
| Index migration on existing prod DB adds load | `CREATE INDEX IF NOT EXISTS` is idempotent and fast on `transaction_history`. Run during normal startup. |

---

## 7. Success criteria

- At 10 k unique senders / 500 k txs / cycle (simulated in a benchmark test), the number of DB roundtrips for `is_new_sender_address` drops from ~500 k to ≤ 20, and the number of Etherscan `getcontractcreation` calls drops from ≤ 10 k to ≤ 2 000 on cold cache.
- No behavioural regression in existing spam-detection tests.
- `ruff check` clean, `pytest` green.
- Cycle wall-clock time for the existing prod workload measurably lower (capture before/after in PR description).

---

## 8. Out-of-scope follow-ups (noted, not done here)

- Batched `store_transaction` via `executemany`.
- Persistent (on-disk) contract-creation cache survival across restarts.
- Cross-address sharing of `known_senders` pre-fetch when many monitored addresses share the same senders (unlikely in practice).
- Moving `get_recent_transactions` into the same pre-fetch phase for multiple addresses at once.
- **Moralis bulk contract-creation**: migrate `MoralisClient.get_contract_creation_block` from the per-address `GET /api/v2.2/{address}` endpoint to the bulk `GET /api/v2.2/erc20/metadata?chain=eth&addresses=...` endpoint (up to 25 per call). Only worth doing if Moralis ever becomes the hot path (i.e. Etherscan + Blockscout circuits open for sustained periods).
