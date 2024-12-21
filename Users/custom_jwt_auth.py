from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed, TokenError

from Users.jwt_tokens import CustomAccessToken


class CustomJWTAuthentication(JWTAuthentication):
    """
    Custom JWT Authentication class to handle access token validation.

    This class extends SimpleJWT's `JWTAuthentication` to use a custom
    access token class (`CustomAccessToken`). It verifies the validity
    of access tokens and ensures blacklisted tokens are rejected.
    """

    def get_validated_token(self, raw_token):
        """
        Validates the provided raw token.

        Args:
            raw_token (str): The raw access token to validate.

        Returns:
            CustomAccessToken: A validated and verified access token.

        Raises:
            AuthenticationFailed: If the token is invalid, malformed, or blacklisted.
        """
        try:
            # Use the custom access token class for validation
            token = CustomAccessToken(raw_token)
            token.verify()  # Verifies the token's validity and checks blacklisting
            return token
        except TokenError:
            # Raised for malformed or invalid tokens
            raise AuthenticationFailed()
