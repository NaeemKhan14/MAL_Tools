from django.contrib.auth import get_user_model
from django.test import TestCase, Client
from django.utils.timezone import now, timedelta


class CustomUserModelTest(TestCase):
    def setUp(self):
        # Custom user model
        self.client = Client()

        self.User = get_user_model()
        self.mal_user_id = "123456"
        self.username = "testuser"
        self.access_token = "test_access_token"
        self.refresh_token = "test_refresh_token"
        self.token_expiry = now() + timedelta(hours=1)

    def test_create_user(self):
        """Test creating a user with the custom user model."""
        user = self.User.objects.create_user(
            mal_user_id=self.mal_user_id,
            username=self.username,
            access_token=self.access_token,
            refresh_token=self.refresh_token,
            token_expiry=self.token_expiry
        )
        self.assertIsNotNone(user.id)
        self.assertEqual(user.mal_user_id, self.mal_user_id)
        self.assertEqual(user.username, self.username)
        self.assertEqual(user.access_token, self.access_token)
        self.assertEqual(user.refresh_token, self.refresh_token)
        self.assertEqual(user.token_expiry, self.token_expiry)

    def test_retrieve_user(self):
        """Test retrieving a user by MAL user ID."""
        self.User.objects.create_user(
            mal_user_id=self.mal_user_id,
            username=self.username,
            access_token=self.access_token,
            refresh_token=self.refresh_token,
            token_expiry=self.token_expiry
        )
        user = self.User.objects.get(mal_user_id=self.mal_user_id)
        self.assertIsNotNone(user)
        self.assertEqual(user.mal_user_id, self.mal_user_id)
        self.assertEqual(user.username, self.username)

    def test_missing_required_fields(self):
        """Test that creating a user without required fields raises an error."""
        with self.assertRaises(ValueError):
            self.User.objects.create_user(
                mal_user_id=self.mal_user_id,
                username=self.username,
                access_token=None,  # Missing required field
                refresh_token=self.refresh_token,
                token_expiry=self.token_expiry
            )

        with self.assertRaises(ValueError):
            self.User.objects.create_user(
                mal_user_id=self.mal_user_id,
                username=self.username,
                access_token=self.access_token,
                refresh_token=None,  # Missing required field
                token_expiry=self.token_expiry
            )
