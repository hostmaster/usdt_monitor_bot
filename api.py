from typing import Optional, Dict, Any
import logging
import requests
from requests.exceptions import HTTPError, RequestException
import json

from config import settings

logger = logging.getLogger(__name__)


class EtherscanClient:
    """Client for interacting with the Etherscan API."""

    def __init__(self, api_key: str, timeout: int = settings.HTTP_TIMEOUT):
        """Initialize the Etherscan client.

        Args:
            api_key: Etherscan API key
            timeout: HTTP request timeout in seconds
        """
        self.api_key = api_key
        self.timeout = timeout
        self.base_url = "https://api.etherscan.io/api"

    def _make_request(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Make a request to the Etherscan API.

        Args:
            params: Request parameters

        Returns:
            API response data or None if request fails
        """
        try:
            response = requests.get(self.base_url, params=params, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()

            if data.get("status") != "1" or data.get("message") != "OK":
                error_msg = data.get("result", "Unknown error")
                logger.error(f"Etherscan API error: {error_msg}")
                return None

            return data

        except HTTPError as http_e:
            logger.error(f"HTTP error: {http_e}")
            return None
        except RequestException as e:
            logger.error(f"Network error: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON response: {e}")
            return None

    def get_latest_transaction(
        self, contract_address: str, wallet_address: str
    ) -> Optional[Dict[str, Any]]:
        """Get the latest transaction for a given address.

        Args:
            contract_address: Token contract address
            wallet_address: Wallet address to monitor

        Returns:
            Latest transaction details or None if no transactions found
        """
        params = {
            "module": "account",
            "action": "tokentx",
            "contractaddress": contract_address,
            "address": wallet_address,
            "page": 1,
            "offset": 1,
            "startblock": 0,
            "endblock": 99999999,
            "sort": "desc",
            "apikey": self.api_key,
        }

        data = self._make_request(params)
        if not data:
            return None

        result = data.get("result", [])
        if not result:
            logger.info(f"No transactions found for address {wallet_address}")
            return None

        return result[0]
