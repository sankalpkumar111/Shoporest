from django.urls import path
from .views import SendOTPView, VerifyRegisterView, LoginView
from .views import *

urlpatterns = [
    path("api/send-otp/", SendOTPView.as_view(), name="send-otp"),
    path("api/register/", VerifyRegisterView.as_view(), name="register"),
    path("api/login/", LoginView.as_view(), name="login"),
    path("", index_view, name="index"),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    path("register/", register_view, name="register"),
    path("forgot_password/", forgot_password_view, name="forgot_password"),
    # path("send_otp/", send_otp_view, name="send_otp"),
]
