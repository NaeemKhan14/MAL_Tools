import logging
import os

import requests
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.timezone import now, timedelta
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User, BlacklistedAccessToken
from .utils import generate_code_verifier, generate_state


class MALLoginView(APIView):
    """
    Handles the login flow by redirecting the user to the MyAnimeList (MAL) OAuth2 authorization page.

    If the user is already authenticated, they are redirected to the home page.
    Otherwise, this view generates an OAuth2 authorization URL and redirects the user to MAL.
    """

    def get(self, request):
        # Redirect to home if the user is already authenticated
        if request.user.is_authenticated:
            return redirect(reverse("high_rated_anime"))

        # Get client_id from environment variables
        client_id = os.environ.get("Client_ID")
        if not client_id:
            return Response({"error": "Client_ID is not configured"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Generate code_verifier and state for OAuth2
        code_verifier = generate_code_verifier()
        state = generate_state()

        # Store generated values in session for later validation
        request.session["code_verifier"] = code_verifier
        request.session["state"] = state

        code_challenge = code_verifier  # Using the 'plain' method for simplicity
        redirect_uri = request.build_absolute_uri('/user/callback/')  # Construct redirect_uri dynamically

        # Build the authorization URL
        auth_url = (
            f"https://myanimelist.net/v1/oauth2/authorize"
            f"?response_type=code&client_id={client_id}&code_challenge_method=plain"
            f"&code_challenge={code_challenge}&state={state}&redirect_uri={redirect_uri}"
        )

        # Redirect the user to the MAL authorization page
        return redirect(auth_url)


class MALCallbackView(APIView):
    """
    Handles the OAuth2 callback from MyAnimeList after user authorization.

    This view exchanges the authorization code for tokens, retrieves user details from MAL,
    and creates or updates the user in the database.
    """
    logger = logging.getLogger(__name__)

    def get(self, request):
        # Retrieve code and state parameters from the callback URL
        code = request.GET.get("code")
        state = request.GET.get("state")

        if not code:
            return Response({"error": "Authorization code is missing"}, status=status.HTTP_400_BAD_REQUEST)

        if not state:
            return Response({"error": "State parameter is missing"}, status=status.HTTP_400_BAD_REQUEST)

        # Validate the state parameter against the one stored in the session
        stored_state = request.session.pop("state", None)
        if not stored_state or stored_state != state:
            return Response({"error": "Invalid state parameter"}, status=status.HTTP_400_BAD_REQUEST)

        # Retrieve required credentials from environment and session
        client_id = os.environ.get("Client_ID")
        client_secret = os.environ.get("Client_Secret")
        code_verifier = request.session.pop("code_verifier", None)

        if not client_id or not client_secret or not code_verifier:
            return Response({"error": "Invalid configuration or session state"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Token exchange URL and payload
        token_url = "https://myanimelist.net/v1/oauth2/token"
        redirect_uri = request.build_absolute_uri('/user/callback/')
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
        }

        # Exchange authorization code for access and refresh tokens
        response = requests.post(token_url, data=payload)
        if response.status_code != 200:
            return Response({"error": "Failed to exchange authorization code for tokens"},
                            status=status.HTTP_400_BAD_REQUEST)

        token_data = response.json()
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in")

        if not access_token or not refresh_token or not expires_in:
            return Response({"error": "Invalid token response from MyAnimeList"}, status=status.HTTP_400_BAD_REQUEST)

        # Calculate token expiry time
        token_expiry = now() + timedelta(seconds=expires_in)

        # Fetch user information from MyAnimeList
        user_info_url = "https://api.myanimelist.net/v2/users/@me"
        headers = {"Authorization": f"Bearer {access_token}"}
        user_info_response = requests.get(user_info_url, headers=headers)

        if user_info_response.status_code != 200:
            return Response({"error": "Failed to fetch user information from MyAnimeList"},
                            status=status.HTTP_400_BAD_REQUEST)

        user_info = user_info_response.json()
        mal_user_id = user_info.get("id")
        username = user_info.get("name")

        # Create or update user in the database
        user, created = User.objects.update_or_create(
            mal_user_id=mal_user_id,
            defaults={
                "username": username,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_expiry": token_expiry,
            },
        )

        # Generate JWT tokens for the user
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        # Prepare response
        response = Response({"message": "Login successful."})

        # Set the tokens in HTTP-only secure cookies
        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=True,
            secure=True,
            samesite='Strict',
            max_age=60 * 15  # Access token lifetime (15 minutes)
        )
        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite='Strict',
            max_age=60 * 60 * 24 * 7  # Refresh token lifetime (7 days)
        )

        return response


class LogoutView(APIView):
    """
    Handles user logout by blacklisting JWT tokens and clearing the session.

    This view ensures that both the access token and refresh token are blacklisted,
    and the user's session is cleared to prevent further access.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handle POST request for logging out the user.

        Blacklists the refresh token and access token, and clears the session.

        Args:
            request: The incoming HTTP request containing the tokens.

        Returns:
            Response: A success message on successful logout.

        Raises:
            400 Bad Request: If the refresh token is not provided or invalid.
        """
        # Blacklist the refresh token
        refresh_token = request.COOKIES.get('refresh_token')

        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()  # Blacklist the refresh token
            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Blacklist the access token
        auth_header = request.headers.get("Authorization")

        if auth_header and auth_header.startswith("Bearer "):
            access_token = auth_header.split(" ")[1]
            BlacklistedAccessToken.objects.create(token=access_token)

        # Log out the user and clear session
        logout(request)
        request.session.flush()

        # Prepare response and clear the refresh token cookie
        response = Response({"message": "Successfully logged out"}, status=status.HTTP_200_OK)
        response.delete_cookie('refresh_token')
        response.delete_cookie('access_token')

        return response