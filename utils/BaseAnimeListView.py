from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView


class BaseAnimeListView(APIView):
    """
    Base view for handling common functionality across anime list views.

    Attributes:
        permission_classes (list): Specifies that the view is accessible only to authenticated users.
    """
    permission_classes = [IsAuthenticated]

    def filter_anime(self, animelist, filter_function):
        """
        Filters the anime list based on a custom filter function.

        Args:
            animelist (dict): The JSON response from the MAL API.
            filter_function (callable): A function to filter anime items.

        Returns:
            list: A filtered list of anime.
        """
        return [anime for anime in animelist.get("data", []) if filter_function(anime)]

    def get_pagination_metadata(self, animelist, offset):
        """
        Extracts pagination metadata from the MAL API response.

        Args:
            animelist (dict): The JSON response from the MAL API.
            offset (int): The current offset for pagination.

        Returns:
            dict: Pagination metadata.
        """
        total_items = animelist.get("paging", {}).get("total", 0)
        has_next_page = "next" in animelist.get("paging", {})
        has_previous_page = offset > 0
        return {
            "total_items": total_items,
            "has_next_page": has_next_page,
            "has_previous_page": has_previous_page,
        }

