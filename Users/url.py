from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from Users.views import MALLoginView, MALCallbackView, LogoutView

urlpatterns = [
    # MAL OAuth routes
    path("login/", MALLoginView.as_view(), name="mal_login"),
    path("callback/", MALCallbackView.as_view(), name="mal_callback"),
    # User Logout
    path('logout/', LogoutView.as_view(), name='logout'),
]
