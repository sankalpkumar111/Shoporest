from rest_framework import serializers
from django.contrib.auth.models import User

class SendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

class VerifyRegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.IntegerField()
    password = serializers.CharField(write_only=True)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email"]

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
