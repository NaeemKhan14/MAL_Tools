import requests
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated


class HomeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        access_token = user.access_token  # Assuming access_token is stored in the user model

        # Query MAL API for user details
        mal_api_url = "https://api.myanimelist.net/v2/users/@me/animelist"
        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            response = requests.get(mal_api_url, headers=headers)
            response.raise_for_status()  # Raise an exception for HTTP errors
            user_details = response.json()
        except requests.exceptions.RequestException as e:
            return Response(
                {"error": "Failed to fetch user details from MAL", "details": str(e)},
                status=response.status_code if response else 500
            )

        # Return user details in the response
        return Response(user_details)
