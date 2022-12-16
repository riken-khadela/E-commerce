from rest_framework import serializers
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.password_validation import UserAttributeSimilarityValidator, validate_password
from .models import Product,Cart, CustomUser
import re

class ProductSerializer(serializers.ModelSerializer):
    """ 
    Create serialize data to use for Product as Products module
    """
    def create(self, validated_data):
        return Product.objects.create(
          Name=validated_data.get('Name'),
          ImgLink = validated_data.get('ImgLink'),
          Price = validated_data.get('Price')
        )

    class Meta:
        model = Product
        fields = (
                '__all__'
            )


class CartSerializer(serializers.ModelSerializer):
    """ 
    A serializer for Cart to serialize cart data
    """
    
    class Meta:
      model = Cart
      fields = (
              '__all__'
          )
        
        

class UserRegistrationSerializer(serializers.ModelSerializer):
      """ 
      This serializer will help to create new user's registration data and validate the password.
      """
      password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
      class Meta:
          model = CustomUser
          fields = (
                  '__all__'
              )

    # Validating Password and Confirm Password while Registration
      def validate(self, attrs):
        password_validator = "^(?=.[a-z])(?=.[A-Z])(?=.\d)(?=.[@$!%#?&])[A-Za-z\d@$!#%?&]{8,20}$"

        password = attrs.get('password')
        password2 = attrs.get('password2')
        if len(password) <= 7: raise serializers.ValidationError("Password's Length should be minimum 8 ")
        if password != password2:
          raise serializers.ValidationError("Password and Confirm Password doesn't match")
        check_p = re.search(re.compile(password_validator),password)
        if check_p:
          return attrs
        else: raise serializers.ValidationError("Password must be with at least one uppercase, special Char and A number.")


      def create(self, validated_data):
        created_user =CustomUser.objects.create_user(
            username= validated_data.get('username'),
            Mobile_number = validated_data.get('Mobile_number'),
            email = validated_data.get('email'),
            gender = validated_data.get('gender'),
            city = validated_data.get('city'),
            first_name = validated_data.get('first_name'),
            last_name = validated_data.get('last_name'),
            password= validated_data.get('password')
          )
        return created_user

class UserLoginSerializer(serializers.ModelSerializer):
  """ 
  A serializer for login user
  """
  
  email = serializers.EmailField(max_length=255)
  class Meta:
      model = CustomUser
      fields = ['email', 'password']

class UserProfileSerializer(serializers.ModelSerializer):
    """ 
    Get a login user's data and send data
    """
    class Meta:
        model = CustomUser
        fields =('__all__')

class UserChangePasswordSerializer(serializers.Serializer):
    """ 
    To change a password for user if they forget password
    """
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        user.set_password(password)
        user.save()
        return attrs
