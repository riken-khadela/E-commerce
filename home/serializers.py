from rest_framework import serializers
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.password_validation import UserAttributeSimilarityValidator, validate_password
from .models import Product,Cart, CustomUser


class ProductSerializer(serializers.ModelSerializer):
    
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
    
    
    
    class Meta:
      model = Cart
      fields = (
              '__all__'
          )
        
        

class UserRegistrationSerializer(serializers.ModelSerializer):
    # We are writing this becoz we need confirm password field in our Registratin Request
      password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
      class Meta:
          model = CustomUser
          fields = (
                  '__all__'
              )

    # Validating Password and Confirm Password while Registration
      def validate(self, attrs):
        print(UserAttributeSimilarityValidator(attrs.get('password')``````````````````),'------------------')
        # user = User(**attrs)
        # print(attrs.data) 
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
          raise serializers.ValidationError("Password and Confirm Password doesn't match")
        return attrs


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
  email = serializers.EmailField(max_length=255)
  class Meta:
    model = CustomUser
    fields = ['email', 'password']

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
      model = CustomUser
      fields =('__all__')

class UserChangePasswordSerializer(serializers.Serializer):
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

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
      fields = ['email']

    def validate(self, attrs):
      email = attrs.get('email')
      if CustomUser.objects.filter(email=email).exists():
        user = CustomUser.objects.get(email = email)
        uid = urlsafe_base64_encode(force_bytes(user.id))
        print('Encoded UID', uid)
        token = PasswordResetTokenGenerator().make_token(user)
        print('Password Reset Token', token)
        link = 'http://localhost:3000/api/user/reset/'+uid+'/'+token
        print('Password Reset Link', link)
        # Send EMail
        body = 'Click Following Link to Reset Your Password '+link
        data = {
          'subject':'Reset Your Password',
          'body':body,
          'to_email':user.email
        }
        # Util.send_email(data)
        return attrs
      else:
        raise serializers.ValidationError('You are not a Registered User')

class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    class Meta:
      fields = ['password', 'password2']

    def validate(self, attrs):
      try:
        password = attrs.get('password')
        password2 = attrs.get('password2')
        uid = self.context.get('uid')
        token = self.context.get('token')
        if password != password2:
          raise serializers.ValidationError("Password and Confirm Password doesn't match")
        id = smart_str(urlsafe_base64_decode(uid))
        user = CustomUser.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user, token):
          raise serializers.ValidationError('Token is not Valid or Expired')
        user.set_password(password)
        user.save()
        return attrs
      except DjangoUnicodeDecodeError as identifier:
        PasswordResetTokenGenerator().check_token(user, token)
        raise serializers.ValidationError('Token is not Valid or Expired')
    