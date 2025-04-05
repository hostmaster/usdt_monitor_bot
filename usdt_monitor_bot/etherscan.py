# etherscan.py
import logging
from typing import Any, Dict, List

import aiohttp


class EtherscanError(Exception):
    """Custom exception for Etherscan API errors."""

    pass


class EtherscanRateLimitError(EtherscanError):
    """Specific exception for rate limit errors."""

    pass


class EtherscanClient:
    """Handles interactions with the Etherscan API."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        api_key: str,
        api_url: str,
        usdt_contract: str,
        timeout: int,
    ):
        self._session = session
        self._api_key = api_key
        self._api_url = api_url
        self._usdt_contract = usdt_contract
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        logging.info("EtherscanClient initialized.")

    async def get_usdt_token_transactions(
        self, address: str, start_block: int = 0, end_block: int = 99999999
    ) -> List[Dict[str, Any]]:
        """
        Fetches USDT token transactions for a given address from a specific block.

        Returns:
            List of transaction dictionaries if successful.
        Raises:
            EtherscanRateLimitError: If rate limit is hit.
            EtherscanError: For other API errors or unexpected responses.
            aiohttp.ClientError: For network-related issues.
            asyncio.TimeoutError: If the request times out.
        """
        params = {
            "module": "account",
            "action": "tokentx",
            "contractaddress": self._usdt_contract,
            "address": address,
            "startblock": start_block,
            "endblock": end_block,
            "sort": "asc",
            "apikey": self._api_key,
        }
        logging.debug(
            f"Querying Etherscan tokentx for {address} from block {start_block}"
        )

        try:
            async with self._session.get(
                self._api_url, params=params, timeout=self._timeout
            ) as response:
                response.raise_for_status()  # Raise ClientResponseError for 4xx/5xx
                data = await response.json()

                if data.get("status") == "1":
                    result = data.get("result", [])
                    if isinstance(result, list):
                        logging.debug(
                            f"Received {len(result)} tx results for {address} from Etherscan."
                        )
                        return result
                    else:
                        logging.error(
                            f"Unexpected Etherscan 'result' format for {address}: {result}"
                        )
                        raise EtherscanError(
                            f"Unexpected result format: {type(result)}"
                        )

                elif data.get("status") == "0":
                    message = data.get("message", "").lower()
                    result_info = data.get(
                        "result", ""
                    )  # Sometimes error details are in result
                    if "no transactions found" in message:
                        logging.debug(
                            f"No new USDT transactions found for {address} since block {start_block} (API Message)."
                        )
                        return []  # Return empty list, not an error
                    elif (
                        "rate limit" in message
                        or "rate limit" in str(result_info).lower()
                    ):
                        logging.warning(f"Etherscan rate limit reached for {address}.")
                        raise EtherscanRateLimitError(
                            "Etherscan API rate limit reached."
                        )
                    else:
                        logging.error(
                            f"Etherscan API error for {address}: {message} - Result: {result_info}"
                        )
                        raise EtherscanError(f"API Error: {message} - {result_info}")
                else:
                    logging.error(f"Unknown Etherscan API status for {address}: {data}")
                    raise EtherscanError(f"Unknown API status: {data.get('status')}")

        except aiohttp.ClientResponseError as e:
            logging.error(
                f"Etherscan HTTP error for {address}: Status {e.status} - {e.message}"
            )
            # Re-raise as a generic ClientError or specific EtherscanError if desired
            raise EtherscanError(f"HTTP Error {e.status}: {e.message}") from e
        # TimeoutError and other ClientErrors are implicitly raised
