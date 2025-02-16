import random
from django.utils.timezone import now, timedelta
from django.core.mail import send_mail
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, login
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import UserProfile
from .serializers import SendOTPSerializer, VerifyRegisterSerializer, UserSerializer
import jwt
import datetime
from django.conf import settings
from rest_framework.permissions import AllowAny

#  Send OTP and Store in Database
class SendOTPView(APIView):
    def post(self, request):
        serializer = SendOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]

            # Check if email already exists
            if User.objects.filter(email=email).exists():
                return Response({"error": "Email already exists!"}, status=status.HTTP_400_BAD_REQUEST)

            user, created = User.objects.get_or_create(username=email, email=email)
            profile, _ = UserProfile.objects.get_or_create(user=user, email=email)

            # Generate and store OTP in the database
            otp = random.randint(100000, 999999)
            profile.otp = otp
            profile.otp_created_at = now()
            profile.save()

            # Send OTP via Email
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

# Verify OTP & Register User
class VerifyRegisterView(APIView):
    def post(self, request):
        serializer = VerifyRegisterSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            entered_otp = serializer.validated_data["otp"]
            password = serializer.validated_data["password"]

            try:
                profile = UserProfile.objects.get(email=email)
            except UserProfile.DoesNotExist:
                return Response({"error": "Invalid Email"}, status=status.HTTP_400_BAD_REQUEST)

            #  Check if OTP is valid and not expired
            if profile.otp is None or profile.otp != entered_otp:
                return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
            if now() > profile.otp_created_at + timedelta(minutes=5):  # 5 min expiry
                return Response({"error": "OTP expired. Request a new one."}, status=status.HTTP_400_BAD_REQUEST)

            #  Check if user is already registered
            if profile.user and profile.user.password:
                return Response({"error": "Email already registered"}, status=status.HTTP_400_BAD_REQUEST)

            #  Register the user
            profile.user.password = make_password(password)
            profile.user.save()

            #  Clear OTP after successful registration
            profile.otp = None
            profile.save()

            return Response({"message": "User registered successfully", "user": UserSerializer(profile.user).data}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Login User


class LoginView(APIView):
    permission_classes = [AllowAny]  # Allow login without authentication

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        # Check if the user exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User does not exist. Please register."}, status=status.HTTP_400_BAD_REQUEST)

        #  Authenticate user
        user = authenticate(username=email, password=password)
        if user:
            login(request, user)

            #  Generate JWT Token
            payload = {
                "id": user.id,
                "email": user.email,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),  # Token expires in 1 day
                "iat": datetime.datetime.utcnow(),
            }
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

            return Response({
                "message": "Login successful",
                "token": token,
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "username": user.username
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
