import requests


class MalClient:
    """
    A client for interacting with the MyAnimeList (MAL) API.

    Attributes:
        access_token (str): The access token for authenticating with the MAL API.
        base_url (str): The base URL for MAL API requests.
    """

    BASE_URL = "https://api.myanimelist.net/v2/users/@me/animelist"

    def __init__(self, access_token, base_url=None):
        """
        Initializes the MAL client with the provided access token and base URL.

        Args:
            access_token (str): The user's MAL access token.
            base_url (str, optional): Overrides the default base URL. Defaults to None.
        """
        self.access_token = access_token
        self.base_url = base_url or self.BASE_URL

    def fetch_data(self, params):
        """
        Fetches data from the MAL API.

        Args:
            params (dict): Query parameters to include in the API request.

        Returns:
            dict: Parsed JSON response from the MAL API.

        Raises:
            Exception: If the API request fails.
        """
        headers = {"Authorization": f"Bearer {self.access_token}"}

        try:
            response = requests.get(self.base_url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to fetch data from MAL: {str(e)}") from e
