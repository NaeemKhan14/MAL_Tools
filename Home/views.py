from rest_framework.response import Response

from utils.BaseAnimeListView import BaseAnimeListView
from utils.MalClient import MalClient


class HighRatedAnimeView(BaseAnimeListView):
    """
    Fetches high-rated anime (scores of 9 or 10) from the user's anime list.

    This view retrieves a user's anime list from MyAnimeList (MAL), filters it for titles
    with scores of 9 or 10, and supports pagination using limit and offset query parameters.

    Inherits:
        BaseAnimeListView: Provides shared utilities for filtering anime and handling pagination.
    """

    def get(self, request):
        """
        Handles GET requests to retrieve high-rated anime from the user's anime list.

        Args:
            request (HttpRequest): The incoming HTTP request with user authentication
            and query parameters for pagination.

        Query Parameters:
            limit (int): The number of items to retrieve per page (default: 50).
            offset (int): The starting index for fetching items (default: 0).

        Returns:
            Response: A JSON response containing:
            - A list of high-rated anime (scores 9 or 10).
            - Pagination metadata including limit, offset, and navigation flags.
        """
        # Extract user and access token
        user = request.user
        access_token = user.access_token

        # Initialize the MAL client
        mal_client = MalClient(access_token)

        # Pagination parameters
        limit = int(request.query_params.get("limit", 50))
        offset = int(request.query_params.get("offset", 0))

        # API request parameters
        params = {
            "fields": "list_status",  # Include list_status for score information.
            "limit": limit,
            "offset": offset,
        }

        try:
            # Fetch data from MAL API
            animelist = mal_client.fetch_data(params)
        except Exception as e:
            # Handle errors and return an appropriate response
            return Response({"error": str(e)}, status=500)

        # Filter for high-rated anime
        high_rated_anime = self.filter_anime(
            animelist,
            lambda anime: anime.get("list_status", {}).get("score") in [9, 10]
        )

        # Prepare pagination metadata
        pagination = self.get_pagination_metadata(animelist, offset)
        pagination.update({"limit": limit, "offset": offset})

        # Return filtered data and pagination metadata
        return Response({
            "high_rated_anime": high_rated_anime,
            "pagination": pagination,
        })


class PlannedToWatchAiringView(BaseAnimeListView):
    """
    Fetches anime from the user's Planned to Watch list that are currently airing.

    This view retrieves a user's Planned to Watch anime list from MyAnimeList (MAL),
    filters it for titles that are currently airing, and supports pagination
    using limit and offset query parameters.

    Inherits:
        BaseAnimeListView: Provides shared utilities for filtering anime and handling pagination.
    """

    def get(self, request):
        """
        Handles GET requests to retrieve anime from the Planned to Watch list that are currently airing.

        Args:
            request (HttpRequest): The incoming HTTP request with user authentication
            and query parameters for pagination.

        Query Parameters:
            limit (int): The number of items to retrieve per page (default: 50).
            offset (int): The starting index for fetching items (default: 0).

        Returns:
            Response: A JSON response containing:
            - A list of currently airing anime from the Planned to Watch list.
            - Pagination metadata including limit, offset, and navigation flags.
        """
        # Extract user and access token
        user = request.user
        access_token = user.access_token

        # Initialize the MAL client
        mal_client = MalClient(access_token)

        # Pagination parameters
        limit = int(request.query_params.get("limit", 50))
        offset = int(request.query_params.get("offset", 0))

        # API request parameters
        params = {
            "fields": "status",  # Include status field to check airing status.
            "status": "plan_to_watch",  # Filter Planned to Watch list.
            "limit": limit,
            "offset": offset,
        }

        try:
            # Fetch data from MAL API
            animelist = mal_client.fetch_data(params)
        except Exception as e:
            # Handle errors and return an appropriate response
            return Response({"error": str(e)}, status=500)

        # Filter for currently airing anime
        airing_anime = self.filter_anime(
            animelist,
            lambda anime: anime.get("node", {}).get("status") == "currently_airing"
        )

        # Prepare pagination metadata
        pagination = self.get_pagination_metadata(animelist, offset)
        pagination.update({"limit": limit, "offset": offset})

        # Return filtered data and pagination metadata
        return Response({
            "airing_anime": airing_anime,
            "pagination": pagination,
        })
