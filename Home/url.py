from django.urls import path

from Home.views import HighRatedAnimeView, PlannedToWatchAiringView

urlpatterns = [
    path("high-rated-anime", HighRatedAnimeView.as_view(), name="high_rated_anime"),
    path("planned-to-watch-airing", PlannedToWatchAiringView.as_view(), name="planned_to_watch_airing"),
]