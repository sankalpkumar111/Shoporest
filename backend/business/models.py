from django.db import models
from django.contrib.auth.models import User
from datetime import timedelta
from django.utils.timezone import now  

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email = models.EmailField(unique=True, null=True, blank=True) 
    otp = models.IntegerField(null=True, blank=True)
    otp_created_at = models.DateTimeField(auto_now=True)  
    
    def is_otp_valid(self):
        """Check if OTP is valid (not expired)."""
        if self.otp:
            otp_expiry_time = self.otp_created_at + timedelta(minutes=5)  # OTP valid for 5 minutes
            return now() <= otp_expiry_time
        return False

    def __str__(self):
        return self.user.email  # No need for a separate email field
