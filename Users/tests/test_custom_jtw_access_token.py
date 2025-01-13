from datetime import timedelta
from django.test import TestCase
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import AuthenticationFailed, TokenError
from Users.jwt_tokens import CustomAccessToken
from Users.models import User, BlacklistedAccessToken
from django.utils.timezone import now


class TestCustomJWTTokens(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            mal_user_id="123456",
            access_token="valid_access_token",
            refresh_token="valid_refresh_token",
            token_expiry=now() + timedelta(hours=1),
            username="test_user"
        )

    def test_create_and_verify_custom_access_token(self):
        """Test that custom access tokens are created and verified successfully."""
        # Generate tokens using RefreshToken
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)

        # Verify access token using CustomAccessToken
        token = CustomAccessToken(access_token)
        self.assertEqual(token["user_id"], self.user.id)

    def test_blacklist_custom_access_token(self):
        """Test that a custom access token can be blacklisted successfully."""
        # Generate tokens using RefreshToken
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)

        # Blacklist the access token
        BlacklistedAccessToken.objects.create(token=access_token)

        # Verify blacklisted token raises AuthenticationFailed
        with self.assertRaises(AuthenticationFailed):
            CustomAccessToken(access_token).verify()

    def test_access_token_not_added_to_blacklist_automatically(self):
        """Test that custom access tokens are not blacklisted automatically."""
        # Generate tokens using RefreshToken
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)

        # Assert token is not blacklisted
        self.assertFalse(BlacklistedAccessToken.objects.filter(token=access_token).exists())

    def test_blacklisted_token_str(self):
        """Test the string representation of BlacklistedAccessToken."""
        # Generate tokens using RefreshToken
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)

        # Blacklist the access token
        blacklisted_token = BlacklistedAccessToken.objects.create(token=access_token)

        expected_str = f"{blacklisted_token.token}"
        self.assertEqual(str(blacklisted_token), expected_str)

    def test_blacklist_refresh_token(self):
        """Test that a refresh token can be blacklisted successfully."""
        refresh = RefreshToken.for_user(self.user)
        refresh_token = str(refresh)

        # Blacklist the refresh token
        BlacklistedAccessToken.objects.create(token=refresh_token)

        # Assert the token is blacklisted
        with self.assertRaises(AuthenticationFailed):
            CustomAccessToken(refresh_token).verify()

    def test_invalid_access_token(self):
        """Test that an invalid access token raises AuthenticationFailed."""
        invalid_token = "invalid.token.string"

        with self.assertRaises(TokenError):
            CustomAccessToken(invalid_token).verify()

    def test_expired_access_token(self):
        """Test that an expired access token fails verification."""
        # Generate a RefreshToken, then extract its associated AccessToken
        refresh = RefreshToken.for_user(self.user)
        access_token_object = refresh.access_token

        # Manually expire the access token by setting a negative lifetime
        access_token_object.set_exp(lifetime=timedelta(seconds=-1))
        expired_token = str(access_token_object)

        # Attempt to verify the expired token; expect a TokenError
        with self.assertRaises(TokenError):
            CustomAccessToken(expired_token).verify()

    def test_expired_refresh_token(self):
        """Test that an expired refresh token fails verification."""
        # Generate a valid RefreshToken for the user
        refresh = RefreshToken.for_user(self.user)

        # Force the token to expire
        refresh.set_exp(lifetime=timedelta(seconds=-1))
        expired_refresh_token = str(refresh)

        # Attempt to verify the expired refresh token; expect a TokenError
        with self.assertRaises(TokenError):
            CustomAccessToken(expired_refresh_token).verify()


    def test_blacklisted_access_token_failure(self):
        """Test that accessing a blacklisted token fails."""
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)

        # Blacklist the access token
        BlacklistedAccessToken.objects.create(token=access_token)

        with self.assertRaises(AuthenticationFailed):
            CustomAccessToken(access_token).verify()
