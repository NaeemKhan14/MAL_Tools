import os
import secrets

import requests
from django.shortcuts import redirect
from rest_framework.response import Response
from rest_framework.views import APIView


def get_new_code_verifier() -> str:
    token = secrets.token_urlsafe(100)
    return token[:128]


code_challenge = get_new_code_verifier()


class UserInformationView(APIView):
    url = f"https://myanimelist.net/v1/oauth2/authorize?response_type=code&client_id={os.environ['Client_ID']}&code_challenge={code_challenge}"

    def get(self, request, format=None):
        return redirect(self.url)


class GetToken(APIView):

    def get(self, request):
        data = {'code': request.GET['code'],
                'client_id': os.environ['Client_ID'],
                'client_secret': os.environ['Client_Secret'],
                'code_verifier': code_challenge,
                'grant_type': 'authorization_code',
                }

        res = requests.post('https://myanimelist.net/v1/oauth2/token', data)

        return Response(res.json())
