from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from Users.views import MALLoginView, MALCallbackView, LogoutView, RefreshMALTokenView

urlpatterns = [
    # MAL OAuth routes
    path("login/", MALLoginView.as_view(), name="mal_login"),
    path("callback/", MALCallbackView.as_view(), name="mal_callback"),
    # MAL Token Refresh
    path("mal_token_refresh/", RefreshMALTokenView.as_view(), name="mal_token_refresh"),
    # JWT Login Routes
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    # User Logout
    path('logout/', LogoutView.as_view(), name='logout'),
]
