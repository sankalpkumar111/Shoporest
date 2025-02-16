from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email = models.EmailField(unique=True, null=True, blank=True) 
    otp = models.IntegerField(null=True, blank=True)
    otp_created_at = models.DateTimeField(auto_now=True)  

    def __str__(self):
        return self.user.email
