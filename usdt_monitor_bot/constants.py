"""Shared constants with no internal dependencies.

Kept dependency-free so it can be imported from any module without
risking circular imports.
"""

# Sanity cap for block numbers returned by blockchain APIs.
# Ethereum has ~22M blocks as of 2025; 1e9 gives ample headroom while
# rejecting obviously bogus values that could corrupt checkpoint state.
MAX_VALID_BLOCK_NUMBER = 1_000_000_000

# A block number far in the future, used for API queries that need an
# explicit end block (Etherscan, Blockscout). Chosen to be comfortably
# larger than any real Ethereum block for the foreseeable future while
# still fitting in the `endblock` integer parameter accepted by the APIs.
FAR_FUTURE_BLOCK = 99_999_999
