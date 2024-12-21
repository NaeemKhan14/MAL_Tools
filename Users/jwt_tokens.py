from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import AuthenticationFailed, TokenError
from .models import BlacklistedAccessToken

class CustomAccessToken(AccessToken):
    """
    Custom access token class to handle token validation and blacklisting.

    This class extends SimpleJWT's `AccessToken` to add logic for checking
    if a token is blacklisted. Blacklisted tokens are invalid and cannot
    be used for authentication.
    """
    def verify(self):
        """
        Verifies the token's validity and checks if it is blacklisted.

        Raises:
            AuthenticationFailed: If the token is invalid, malformed, or blacklisted.
        """
        try:
            # Perform standard validation using the parent class
            super().verify()
        except TokenError:
            # Handle malformed or invalid tokens
            raise AuthenticationFailed()

        # Check if the token exists in the blacklist
        if BlacklistedAccessToken.objects.filter(token=str(self)).exists():
            raise AuthenticationFailed()
