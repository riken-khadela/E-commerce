from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm

from .models import CustomUser

class CustomUserCreationForm(UserCreationForm):

    """ This Form will ceate a form from Django defualt Forms to register a new user which will be use to get New user's Details """
    class Meta:
        model = CustomUser
        fields = ("first_name","last_name","username", "email","Mobile_number","city","gender")

class CustomUserChangeForm(UserChangeForm):
    """ This will create a form for already Registed user to Login """
    class Meta:
        model = CustomUser
        fields = ("username", "email")