from django.contrib.auth.models import AbstractUser, BaseUserManager
from django import forms
from django.db import models
from djongo import models as models_D
# from django.contrib.postgres.fields import ArrayField

class TimeStampModel(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        
class UserManager(BaseUserManager):
    """ 
    Create a usernamager to create new user's data.
    """
    
    def create_user(self, email,username,  password=None, password2=None,Mobile_number=None,gender=None,city=None,first_name=None,last_name=None):
        """ 
        Create a normal user instead of super user with his/ her personal details.
        """
        if not email:
            raise ValueError('User must have an email address')

        user = self.model(
            email=self.normalize_email(email),
        )
        
        user.username = username
        user.gender  = gender 
        user.Mobile_number = Mobile_number
        user.city = city
        user.first_name = first_name
        user.last_name = last_name
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None):
        """
        Creates and saves a superuser with the given email, name and password.
        """
        user = self.create_user(
            email,
            password=password,
            name=name,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class CustomUser(AbstractUser,TimeStampModel):
    """ 
    This models is create to store and edit the New registered User's Data and edit Django defualt User authentication 
    """
    GENDER = (
        ('MALE','MALE'),
        ('FEMALE','FEMALE'),
        ('CUSTOME','CUSTOME'),
    )
    email = models.EmailField(unique=True)
    Mobile_number = models.CharField(max_length=10)
    first_name = models.CharField(max_length=25)
    last_name = models.CharField(max_length=25)
    city = models.CharField(max_length=25)
    gender = models.CharField(max_length=25,choices=GENDER)
    is_user_verified = models.BooleanField(default=False)
    
    objects = UserManager()
    REQUIRED_FIELDS = ["email","Mobile_number"]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True
    
    

class Product(models_D.Model):
    """ 
    A model to store and use Products data
    """
    id = models_D.AutoField(primary_key=True)
    Name = models_D.TextField(max_length=1000,null=False,blank=False)
    ImgLink = models_D.CharField(max_length=255,null=False,blank=False)
    Price = models_D.IntegerField(null=False,blank=False)
    
    class Meta:
        db_table = 'Product'


        
class Cart(models_D.Model):
    """ 
    A model to store and use Cart details of particular user and this will be connected to the User and Products as well which will add in the cart
    """
    id = models_D.AutoField(primary_key=True)
    user = models_D.ForeignKey(CustomUser,on_delete=models.CASCADE)
    Products =  models_D.ArrayReferenceField(to=Product,on_delete=models_D.CASCADE,null=True,blank=True)
    
    