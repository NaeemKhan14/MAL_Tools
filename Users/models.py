from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models


class UserManager(BaseUserManager):
    def create_user(self, access_token, refresh_token, token_expiry, **extra_fields):
        if not access_token or not refresh_token or not token_expiry:
            raise ValueError("Access token, refresh token, and token expiry must be provided")
        user = self.model(
            access_token=access_token,
            refresh_token=refresh_token,
            token_expiry=token_expiry,
            **extra_fields,
        )
        # No local password, as MAL handles authentication
        user.set_unusable_password()
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    # MAL-specific information
    mal_user_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    username = models.CharField(max_length=255, null=True, blank=True)

    # Token information
    access_token = models.TextField()
    refresh_token = models.TextField()
    token_expiry = models.DateTimeField()

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Permissions
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = "mal_user_id"  # Unique field for authentication
    REQUIRED_FIELDS = ['access_token', 'refresh_token']

    def __str__(self):
        return self.username


class BlacklistedAccessToken(models.Model):
    token = models.TextField(unique=True)
    blacklisted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.token
