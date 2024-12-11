from unittest.mock import patch

from django.test import TestCase, Client
from django.urls import reverse
from django.utils.timezone import now, timedelta
from rest_framework_simplejwt.tokens import AccessToken

from Users.models import User


class MALLoginTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="testuser",
            mal_user_id=123456,
            access_token="valid_access_token",
            refresh_token="valid_refresh_token",
            token_expiry=now() + timedelta(seconds=3600),
        )
        self.access_token = str(AccessToken.for_user(self.user))
        self.client.force_login(self.user)

    @patch("Users.views.generate_code_verifier")
    @patch("Users.views.generate_state")
    def test_login_redirects_to_mal_authorization(self, mock_state, mock_code_verifier):
        mock_state.return_value = "teststate"
        mock_code_verifier.return_value = "testcodeverifier"

        # Log out the user to test unauthenticated behavior
        self.client.logout()

        response = self.client.get(reverse("mal_login"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("https://myanimelist.net/v1/oauth2/authorize", response.url)

    def test_login_redirects_to_home_if_authenticated(self):
        response = self.client.get(
            reverse("mal_login"),
            HTTP_AUTHORIZATION=f"Bearer {self.access_token}",  # Include the token
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("home"))


class MALCallbackTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="testuser",
            mal_user_id=123456,
            refresh_token="valid_refresh_token",
            access_token="valid_access_token",  # Provide a dummy access token
            token_expiry=now() + timedelta(seconds=3600),  # Set a dummy expiry time
        )
        self.client.force_login(self.user)

    @patch("Users.views.requests.post")
    @patch("Users.views.requests.get")
    def test_callback_successful(self, mock_get, mock_post):
        # Mock the token exchange response
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600,
        }

        # Mock the user info response
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "id": 123456,
            "name": "testuser",
        }

        session = self.client.session
        session["state"] = "teststate"
        session["code_verifier"] = "testcodeverifier"
        session.save()

        response = self.client.get(
            reverse("mal_callback"), {"code": "testcode", "state": "teststate"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.json())
        self.assertIn("refresh", response.json())

    def test_callback_invalid_state(self):
        session = self.client.session
        session["state"] = "correctstate"
        session.save()

        response = self.client.get(
            reverse("mal_callback"), {"code": "testcode", "state": "wrongstate"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid state parameter", response.json()["error"])


class RefreshMALTokenTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="testuser",
            mal_user_id=123456,
            refresh_token="valid_refresh_token",
            access_token="valid_access_token",
            token_expiry=now() + timedelta(seconds=3600),
        )
        # Generate a JWT access token for the test user
        self.access_token = str(AccessToken.for_user(self.user))

    @patch("Users.views.requests.post")
    def test_refresh_token_successful(self, mock_post):
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "expires_in": 3600,
        }

        response = self.client.post(
            reverse("mal_token_refresh"),
            HTTP_AUTHORIZATION=f"Bearer {self.access_token}",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["access_token"], "new_access_token")

    def test_refresh_token_missing(self):
        self.user.refresh_token = ""  # Simulate missing refresh token
        self.user.save()

        response = self.client.post(
            reverse("mal_token_refresh"),
            HTTP_AUTHORIZATION=f"Bearer {self.access_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("No refresh token available", response.json()["error"])

    def test_refresh_token_unauthenticated(self):
        response = self.client.post(reverse("mal_token_refresh"))  # No Authorization header
        self.assertEqual(response.status_code, 401)
        self.assertIn("Authentication credentials were not provided.", response.json()["detail"])


class LogoutTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="testuser",
            mal_user_id=123456,
            refresh_token="valid_refresh_token",
            access_token="valid_access_token",  # Provide a dummy access token
            token_expiry=now() + timedelta(seconds=3600),  # Set a dummy expiry time
        )
        self.client.force_login(self.user)

    @patch("Users.views.RefreshToken")
    def test_logout_successful(self, mock_refresh_token):
        mock_refresh_token.return_value.blacklist.return_value = True
        response = self.client.post(reverse("logout"), {"refresh": "valid_refresh_token"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Successfully logged out", response.json()["message"])

    def test_logout_missing_refresh_token(self):
        response = self.client.post(reverse("logout"), {})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Refresh token is required", response.json()["error"])
