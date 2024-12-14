import os
from datetime import timedelta

import requests
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.utils.deprecation import MiddlewareMixin
from django.utils.timezone import now
from django.views import View
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from Users.jwt_tokens import CustomAccessToken

User = get_user_model()


class TokenRefreshMiddleware(MiddlewareMixin):
    """
    Middleware to handle automatic token refresh for authenticated views.
    """

    def process_request(self, request):
        """
        Process the incoming request and handle token validation/refresh logic.

        Args:
            request: The incoming HTTP request.
        """
        # Check if the view requires authentication
        if not isinstance(getattr(request, 'resolver_match', None), type(None)):
            view = request.resolver_match.func
            if not hasattr(view, 'view_class') or not issubclass(view.view_class, View):
                return

            permission_classes = getattr(view.view_class, 'permission_classes', [])
            if not any(perm.__name__ == 'IsAuthenticated' for perm in permission_classes):
                return  # Skip views that don't require authentication

        # Get tokens from cookies
        access_token = request.COOKIES.get('access_token')
        refresh_token = request.COOKIES.get('refresh_token')

        if not access_token or not refresh_token:
            # If tokens are missing, mark the user as unauthenticated
            request.user = AnonymousUser()
            return

        # Validate or refresh the JWT access token
        try:
            # Attempt to validate the access token
            token = CustomAccessToken(access_token)
            token.verify()

            # Associate the user with the request
            request.user = self.get_user_from_token(token)
        except TokenError:
            # If the token is invalid or expired, attempt to refresh it
            self.refresh_jwt_token(request, refresh_token)

        # Refresh MAL token if needed
        if hasattr(request, 'user') and request.user.is_authenticated:
            if now() + timedelta(minutes=5) >= request.user.token_expiry:
                self.refresh_mal_token(request.user)

    def get_user_from_token(self, token):
        """
        Extract the user from the token payload.

        Args:
            token: The validated token.

        Returns:
            User: The user associated with the token.
        """

        user_id = token.get("user_id")
        return User.objects.get(id=user_id)

    def refresh_jwt_token(self, request, refresh_token):
        """
        Refresh the JWT access token using the refresh token.

        Args:
            request: The incoming HTTP request.
            refresh_token: The refresh token from cookies.
        """
        try:
            refresh = RefreshToken(refresh_token)
            new_access_token = str(refresh.access_token)

            # Set the new access token in cookies
            response = Response()
            response.set_cookie(
                key='access_token',
                value=new_access_token,
                httponly=True,
                secure=True,
                samesite='Strict',
                max_age=60 * 15  # Access token lifetime (15 minutes)
            )

            # Update the user in the request
            token = CustomAccessToken(new_access_token)

            request.user = self.get_user_from_token(token)
        except TokenError:
            request.user = AnonymousUser()

    def refresh_mal_token(self, user):
        """
        Refresh the MyAnimeList (MAL) token if it is expired or about to expire.

        Args:
            user: The user whose token needs refreshing.
        """
        if not user.refresh_token:
            return

        client_id = os.environ.get("Client_ID")
        client_secret = os.environ.get("Client_Secret")

        if not client_id or not client_secret:
            raise Exception("Client_ID or Client_Secret is missing in environment variables.")

        token_url = "https://myanimelist.net/v1/oauth2/token"
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": user.refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }

        response = requests.post(token_url, data=payload)

        if response.status_code == 200:
            token_data = response.json()
            user.access_token = token_data.get("access_token")
            user.refresh_token = token_data.get("refresh_token", user.refresh_token)
            user.token_expiry = now() + timedelta(seconds=token_data.get("expires_in"))
            user.save()