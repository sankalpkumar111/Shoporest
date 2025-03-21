import random
import datetime
import jwt
from django.shortcuts import render, redirect
from django.utils.timezone import now, timedelta
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings
from .models import UserProfile
from .serializers import SendOTPSerializer, VerifyRegisterSerializer, UserSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import HttpResponseRedirect
from rest_framework.permissions import AllowAny

# ----------------------------- MVT (TEMPLATE) VIEWS -----------------------------

def index_view(request):
    """Home page view (Accessible without login)"""
    return render(request, "index.html")

def login_view(request):
    """Login page"""
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        user = authenticate(username=email, password=password)
        if user:
            login(request, user)
            return redirect("index")  # Redirect to home after login
        else:
            return render(request, "login.html", {"error": "Invalid credentials"})

    return render(request, "login.html")

def logout_view(request):
    """Logout user and redirect to login page"""
    logout(request)
    return redirect("login")


def register_view(request):
    """Register user and verify OTP"""
    if request.method == "POST":
        print("📩 POST request received")  # Debugging

        email = request.POST.get("email")
        otp = request.POST.get("otp")
        password = request.POST.get("password")

        print(f"📧 Email: {email}, 🔢 OTP: {otp}, 🔑 Password: {password}")  # Debugging



        # Check if OTP is provided (verifying step)
        if otp:
            try:
                print("🔎 Fetching user profile...")
                profile = UserProfile.objects.get(user__email=email)  # Fetch user by email

                if not profile.is_otp_valid():
                    print("⏳ OTP expired")  # Debugging
                    return render(request, "signup.html", {"error": "OTP expired. Request a new one."})

                if str(profile.otp) != otp:
                    print("❌ Invalid OTP")  # Debugging
                    return render(request, "signup.html", {"error": "Invalid OTP"})

                # Ensure user exists
                user = profile.user
                if not user:
                    print("👤 Creating new user...")
                    user = User.objects.create(username=email, email=email, password=make_password(password))
                    profile.user = user
                    profile.save()

                # Update user password (ensure hashing)
                print("🔑 Setting user password...")
                user.password = make_password(password)
                user.save()

                # Clear OTP after registration
                print("🧹 Clearing OTP...")
                profile.otp = None
                profile.save()

                print("✅ Redirecting to login page...")  # Debugging
                return redirect("login")  # Redirect to login after successful registration

            except UserProfile.DoesNotExist:
                print("❌ UserProfile does not exist")  # Debugging
                return render(request, "signup.html", {"error": "Invalid Email"})

    print("📄 Rendering signup.html...")  # Debugging
    return render(request, "signup.html")


# Forgot password implementation


def forgot_password_view(request):
    """Forgot Password - Handles OTP Sending & Verification"""
    if request.method == "POST":
        email = request.POST.get("email")
        otp = request.POST.get("otp")
        new_password = request.POST.get("new_password")
        action = request.POST.get("action")  # To differentiate between 'send_otp' & 'reset_password'

        try:
            user = User.objects.get(email=email)
            profile, created = UserProfile.objects.get_or_create(user=user, email=email)

            if action == "send_otp":
                # Generate and send OTP
                otp_code = random.randint(100000, 999999)
                profile.otp = otp_code
                profile.otp_created_at = now()
                profile.save()

                send_mail(
                    "Reset Your Password - OTP Verification",
                    f"Your OTP for password reset is: {otp_code}. It expires in 5 minutes.",
                    "your-email@gmail.com",
                    [email],
                    fail_silently=False,
                )

                return render(request, "forgot_password.html", {"email": email, "otp_sent": True})

            elif action == "reset_password":
                # Validate OTP & Reset Password
                if not profile.is_otp_valid():
                    return render(request, "forgot_password.html", {"error": "OTP expired", "email": email})

                if str(profile.otp) != otp:
                    return render(request, "forgot_password.html", {"error": "Invalid OTP", "email": email})

                user.password = make_password(new_password)
                user.save()

                return redirect("login")  # Redirect to login after successful reset

        except User.DoesNotExist:
            return render(request, "forgot_password.html", {"error": "Email not found!"})

    return render(request, "forgot_password.html")




# ----------------------------- API VIEWS -----------------------------

class SendOTPView(APIView):
    """Send OTP via API"""
    def post(self, request):
        serializer = SendOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]

            if User.objects.filter(email=email).exists():
                return Response({"error": "Email already exists!"}, status=status.HTTP_400_BAD_REQUEST)

            user, created= User.objects.get_or_create(username=email, email=email)
            profile, _ = UserProfile.objects.get_or_create(user=user, email=email)

            otp = random.randint(100000, 999999)
            profile.otp = otp
            profile.otp_created_at = now()
            profile.save()

            subject = "Your OTP Code for ShopOrest"
            message = f"Your OTP code is: {otp}. It expires in 5 minutes."
            from_email = "your-email@gmail.com"  
            recipient_list = [email]

            try:
                send_mail(subject, message, from_email, recipient_list, fail_silently=False)
                return Response({"message": "OTP sent successfully!"}, status=status.HTTP_200_OK)
            except Exception:
                return Response({"error": "Failed to send OTP"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyRegisterView(APIView):
    """Verify OTP & Register via API"""
    def post(self, request):
        serializer = VerifyRegisterSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            otp = serializer.validated_data["otp"]
            password = serializer.validated_data["password"]

            try:
                profile = UserProfile.objects.get(email=email)

                if not profile.is_otp_valid():
                    return Response({"error": "OTP expired"}, status=status.HTTP_400_BAD_REQUEST)

                if str(profile.otp) != otp:
                    return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

                profile.user.password = make_password(password)
                profile.user.save()

                profile.otp = None
                profile.save()

                return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)

            except UserProfile.DoesNotExist:
                return Response({"error": "Invalid Email"}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    """Login via API"""
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User does not exist. Please register."}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(username=email, password=password)
        if user:
            login(request, user)

            token = jwt.encode(
                {"id": user.id, "email": user.email, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)},
                settings.SECRET_KEY,
                algorithm="HS256",
            )

            return Response({"message": "Login successful", "token": token}, status=status.HTTP_200_OK)

        return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)

from .serializers import SendOTPSerializer, ResetPasswordSerializer


class SendResetOTPView(APIView):
    """Send OTP for password reset"""
    def post(self, request):
        serializer = SendOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]

            try:
                user = User.objects.get(email=email)
                profile, created = UserProfile.objects.get_or_create(user=user, email=email)

                # Generate OTP
                otp_code = random.randint(100000, 999999)
                profile.otp = otp_code
                profile.otp_created_at = now()
                profile.save()

                # Send OTP email
                send_mail(
                    "Reset Your Password - OTP Verification",
                    f"Your OTP for password reset is: {otp_code}. It expires in 5 minutes.",
                    "your-email@gmail.com",
                    [email],
                    fail_silently=False,
                )

                return Response({"message": "OTP sent successfully!"}, status=status.HTTP_200_OK)

            except User.DoesNotExist:
                return Response({"error": "Email not found!"}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(APIView):
    """Verify OTP and reset password"""
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            otp = serializer.validated_data["otp"]
            new_password = serializer.validated_data["new_password"]

            try:
                profile = UserProfile.objects.get(email=email)

                # Validate OTP
                if not profile.is_otp_valid():
                    return Response({"error": "OTP expired"}, status=status.HTTP_400_BAD_REQUEST)

                if str(profile.otp) != otp:
                    return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

                # Update Password
                user = profile.user
                user.password = make_password(new_password)
                user.save()

                # Clear OTP after successful password reset
                profile.otp = None
                profile.save()

                return Response({"message": "Password reset successfully"}, status=status.HTTP_200_OK)

            except UserProfile.DoesNotExist:
                return Response({"error": "Invalid Email"}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
