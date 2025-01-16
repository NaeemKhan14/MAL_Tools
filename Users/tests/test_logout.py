from django.test import TestCase, Client
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.timezone import now, timedelta
from django.contrib.auth import get_user_model
from Users.models import BlacklistedAccessToken


class LogoutTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.User = get_user_model()
        self.user = self.User.objects.create_user(
            mal_user_id="123456",
            username="test_logout_user",
            access_token="some_access_token",
            refresh_token="some_refresh_token",
            token_expiry=now() + timedelta(hours=1),
        )
        self.logout_url = reverse("logout")  # Update if your URL name differs

        # Generate tokens for the user
        self.refresh = RefreshToken.for_user(self.user)
        self.access_token_str = str(self.refresh.access_token)
        self.refresh_token_str = str(self.refresh)

        # Attach valid credentials so the user is considered authenticated
        self.client.cookies["refresh_token"] = self.refresh_token_str
        self.auth_header = f"Bearer {self.access_token_str}"

    def test_logout_returns_200_ok(self):
        """
        Test that the logout endpoint returns a 200 OK response when called with valid credentials.
        """
        response = self.client.post(
            self.logout_url,
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Successfully logged out", response.data["message"])

    def test_access_token_is_blacklisted_on_logout(self):
        """
        Test that the access token is blacklisted after a successful logout.
        """
        self.client.post(
            self.logout_url,
            HTTP_AUTHORIZATION=self.auth_header,
        )
        # Now the access token should be in the blacklist
        self.assertTrue(
            BlacklistedAccessToken.objects.filter(token=self.access_token_str).exists(),
            "Access token should be blacklisted after logout",
        )

    def test_refresh_token_is_blacklisted_on_logout(self):
        """
        Test that the refresh token is blacklisted after a successful logout.
        """
        self.client.post(
            self.logout_url,
            HTTP_AUTHORIZATION=self.auth_header,
        )
        # Now the refresh token should be in the blacklist
        self.assertTrue(
            OutstandingToken.objects.filter(token=self.refresh_token_str).exists(),
            "Refresh token should be blacklisted after logout",
        )

    def test_refresh_token_cookie_is_expired(self):
        """
        Test that the response sets an expired refresh_token cookie (instead of removing the key),
        ensuring the browser deletes it.
        """
        response = self.client.post(
            self.logout_url,
            HTTP_AUTHORIZATION=self.auth_header,
        )
        # The cookie name is still there but should be expired
        self.assertIn(
            "refresh_token",
            response.cookies,
            "refresh_token cookie should be present in the response headers, but expired.",
        )
        cookie = response.cookies["refresh_token"]
        # Check if the cookie is set to expire immediately
        self.assertTrue(
            cookie["expires"] or cookie["max-age"],
            "Cookie should have an expiration or max-age set.",
        )
        # For instance, if it's explicitly clearing it by setting max-age to 0:
        self.assertEqual(cookie["max-age"], 0)

    def test_access_token_cookie_is_expired(self):
        """
        Test that the logout response sets an expired access_token cookie
        so that the browser will remove it.
        """
        # 1. Ensure the user is considered authenticated by sending a valid Authorization header
        response = self.client.post(
            self.logout_url,
            HTTP_AUTHORIZATION=self.auth_header,  # 'Bearer <access_token>'
        )

        # 2. Confirm logout was successful
        self.assertEqual(response.status_code, status.HTTP_200_OK, "Logout should return 200 OK")

        # 3. Check that 'access_token' is still in the response headers but marked as expired
        self.assertIn(
            "access_token",
            response.cookies,
            "access_token cookie should be in the response (expired), not removed outright.",
        )
        cookie = response.cookies["access_token"]

        # 4. Verify the cookie's 'expires' or 'max-age' indicates immediate removal
        #    A typical sign is a past datetime or zero/negative max-age.
        has_expiry_directive = cookie["expires"] or cookie["max-age"]
        self.assertTrue(
            has_expiry_directive,
            "access_token cookie should have an 'expires' or 'max-age' attribute set."
        )

        # Optionally check if max-age is set to 0 (or negative):
        self.assertIn("max-age", cookie, "Cookie should define a max-age attribute")
        self.assertEqual(cookie["max-age"], 0, "Cookie's max-age should be 0 for immediate expiry")

    def test_session_is_cleared_on_logout(self):
        """
        Test that after logout, subsequent requests are anonymous
        (user not authenticated).
        """
        # Log the user out
        response = self.client.post(
            self.logout_url,
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Now make a new request to a protected endpoint
        protected_url = reverse("high_rated_anime")
        response_after_logout = self.client.get(protected_url)

        # We expect 401 or 403 because the user should be unauthenticated now
        self.assertIn(
            response_after_logout.status_code,
            [401, 403],
            "User should be unauthenticated after logout",
        )