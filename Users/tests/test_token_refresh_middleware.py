from datetime import timedelta
from unittest.mock import patch, Mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import path, reverse
from django.utils.timezone import now
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


# Mock views for testing
class AuthRequiredView(APIView):
    """
    A view that requires authentication (permission_classes=[IsAuthenticated]).
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"detail": "You are authenticated!"})


class AuthNotRequiredView(APIView):
    """
    A view that does NOT require authentication.
    """

    def get(self, request):
        return Response({"detail": "Auth not required."})


urlpatterns = [
    path("auth-required/", AuthRequiredView.as_view(), name="auth-required"),
    path("auth-optional/", AuthNotRequiredView.as_view(), name="auth-optional"),
]


@override_settings(ROOT_URLCONF=__name__)  # Points test URL conf to our mock views
class TestTokenRefreshMiddleware(TestCase):
    def setUp(self):
        # Create a user with valid MAL token expiry in the future
        self.user = User.objects.create_user(
            mal_user_id="123456",
            username="testuser",
            access_token="valid_mal_access_token",
            refresh_token="valid_mal_refresh_token",
            token_expiry=now() + timedelta(minutes=10),  # MAL token 10 min away from expiry
        )
        refresh = RefreshToken.for_user(self.user)
        self.valid_access_token = str(refresh.access_token)
        self.valid_refresh_token = str(refresh)

        # Place them in cookies so the middleware sees them
        self.client.cookies["access_token"] = self.valid_access_token
        self.client.cookies["refresh_token"] = self.valid_refresh_token

        self.auth_header = f"Bearer {self.valid_access_token}"

    def test_no_auth_needed(self):
        """
        If the view doesn't require authentication, the middleware
        should do nothing (user can remain anonymous or no token check).
        """
        response = self.client.get(reverse("auth-optional"))
        self.assertEqual(response.status_code, 200)
        # We expect "detail": "Auth not required."
        self.assertIn("Auth not required.", response.json()["detail"])

    def test_missing_tokens(self):
        """
        If the request is missing JWT access or refresh tokens, the user should be set to AnonymousUser.
        """
        # Clear any cookies from setUp
        self.client.cookies.clear()

        response = self.client.get(reverse("auth-required"))
        # Because IsAuthenticated is required, we expect 401 or 403 from DRF
        self.assertIn(response.status_code, [401, 403])

        # Confirm user is effectively anonymous if we check in the view
        # (We can't directly see request.user here, but the 401 or 403 indicates no user)

    def test_valid_access_token(self):
        """
        With valid JWT tokens, the middleware sets request.user properly and doesn't need to refresh anything.
        """
        # The setUp cookies already contain 'valid_jwt_access_token'
        response = self.client.get(reverse("auth-required"), HTTP_AUTHORIZATION=self.auth_header)
        # Should pass IsAuthenticated => 200 OK
        self.assertEqual(response.status_code, 200)
        self.assertIn("You are authenticated!", response.json()["detail"])


    @patch("Users.middlewares.token_refresh_middleware.CustomAccessToken.verify")
    def test_expired_access_token_jwt_refresh_failure(self, mock_verify):
        """
        If JWT refresh fails (e.g., refresh token invalid), user becomes anonymous.
        """
        from rest_framework_simplejwt.exceptions import TokenError
        mock_verify.side_effect = TokenError("Access token expired.")

        response = self.client.get(
            reverse("auth-required"),
            HTTP_AUTHORIZATION=self.auth_header,
        )
        
        # Because refresh failed, user is Anonymous => 401 or 403
        self.assertIn(response.status_code, [401, 403])
