import requests
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated


class HomeView(APIView):
    """
    HomeView handles requests to fetch a user's MyAnimeList (MAL) anime list,
    filtered by high ratings (scores of 9 or 10). It supports pagination
    using limit and offset parameters.

    Attributes:
        permission_classes (list): Specifies that the view is only accessible
        to authenticated users.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Handles GET requests to fetch and filter a user's MAL anime list.

        Args:
            request (HttpRequest): The incoming HTTP request containing
            authentication and query parameters.

        Query Parameters:
            limit (int): The number of items to retrieve per page (default: 50).
            offset (int): The starting index for fetching items (default: 0).

        Returns:
            Response: A JSON response containing:
            - A filtered list of high-rated anime.
            - Pagination metadata (limit, offset, total_items, and navigation flags).
        """
        user = request.user
        access_token = user.access_token  # MAL access token, stored in the user model.

        # Frontend-provided pagination parameters with defaults.
        limit = int(request.query_params.get("limit", 50))  # Default to 50 items per page.
        offset = int(request.query_params.get("offset", 0))  # Default to start from the first item.

        # Define MAL API endpoint and parameters for the request.
        mal_api_url = "https://api.myanimelist.net/v2/users/@me/animelist"
        headers = {"Authorization": f"Bearer {access_token}"}
        params = {
            "fields": "list_status",  # Include list_status for detailed scoring information.
            "limit": limit,           # Pagination limit (items per request).
            "offset": offset,         # Pagination offset (starting index).
        }

        try:
            # Send a GET request to the MAL API.
            response = requests.get(mal_api_url, headers=headers, params=params)
            response.raise_for_status()  # Raise an exception for HTTP errors.
            animelist = response.json()  # Parse the JSON response.
        except requests.exceptions.RequestException as e:
            # Handle errors during the request (e.g., network issues or API errors).
            return Response(
                {"error": "Failed to fetch user details from MAL", "details": str(e)},
                status=response.status_code if response else 500
            )

        # Filter the anime list for titles rated 9 or 10 by the user.
        high_rated_anime = [
            anime for anime in animelist.get("data", [])
            if anime.get("list_status", {}).get("score") in [9, 10]
        ]

        # Prepare pagination metadata for the response.
        total_items = animelist.get("paging", {}).get("total", len(high_rated_anime))  # Total items in the list.
        has_next_page = "next" in animelist.get("paging", {})  # Check if there's a next page.
        has_previous_page = offset > 0  # Determine if a previous page exists.

        # Return the filtered anime list and pagination metadata in the response.
        return Response({
            "high_rated_anime": high_rated_anime,
            "pagination": {
                "limit": limit,               # Number of items per page.
                "offset": offset,             # Starting index of the current page.
                "total_items": total_items,   # Total number of items in the dataset.
                "has_next_page": has_next_page,  # Flag indicating the presence of a next page.
                "has_previous_page": has_previous_page,  # Flag indicating the presence of a previous page.
            },
        })
