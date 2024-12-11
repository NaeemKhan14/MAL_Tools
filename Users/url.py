from django.urls import path

from Users.views import UserInformationView, GetToken

urlpatterns = [
    path('login/', UserInformationView.as_view(), name='login'),
    path('get_token/', GetToken.as_view(), name='get_token'),
]
