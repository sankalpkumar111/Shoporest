from django.urls import path
from .views import SendOTPView, VerifyRegisterView, LoginView

urlpatterns = [
    path("api/send-otp/", SendOTPView.as_view(), name="send-otp"),
    path("api/register/", VerifyRegisterView.as_view(), name="register"),
    path("api/login/", LoginView.as_view(), name="login"),
]
