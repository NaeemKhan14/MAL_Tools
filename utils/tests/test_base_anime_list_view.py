
from django.test import TestCase

from utils.BaseAnimeListView import BaseAnimeListView


class TestBaseAnimeListView(TestCase):
    def setUp(self):
        # Create an instance of BaseAnimeListView
        self.view = BaseAnimeListView()

    def test_filter_anime(self):
        # Sample anime data
        animelist = {
            "data": [
                {"node": {"status": "currently_airing"}},
                {"node": {"status": "finished_airing"}},
            ]
        }

        # Filter for currently airing anime
        result = self.view.filter_anime(
            animelist,
            lambda anime: anime.get("node", {}).get("status") == "currently_airing",
        )

        # Validate the filtered output
        assert len(result) == 1
        assert result[0]["node"]["status"] == "currently_airing"

    def test_get_pagination_metadata(self):
        # Sample data with pagination
        animelist_with_next = {
            "paging": {"next": "next_page_url"},
        }
        animelist_without_next = {
            "paging": {},
        }

        metadata_with_next = self.view.get_pagination_metadata(animelist_with_next, offset=0)
        metadata_without_next = self.view.get_pagination_metadata(animelist_without_next, offset=50)

        # Validate the metadata output
        assert metadata_with_next["has_next_page"] is True
        assert metadata_with_next["has_previous_page"] is False
        assert metadata_without_next["has_next_page"] is False
        assert metadata_without_next["has_previous_page"] is True
