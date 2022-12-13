from django.urls import reverse_lazy
from django.views.generic.edit import CreateView
from django.shortcuts import render, redirect
from .forms import CustomUserCreationForm
from django.views.generic.base import TemplateView
from home.utils import Mobile_verification
import random, requests, json
from rest_framework import status
from .renderers import UserRenderer
from django.contrib.auth import authenticate
from home.models import CustomUser,Product, Cart
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.mixins import UpdateModelMixin, DestroyModelMixin
from .serializers import ProductSerializer, CartSerializer,Cart,SendPasswordResetEmailSerializer, UserChangePasswordSerializer, UserLoginSerializer, UserPasswordResetSerializer, UserProfileSerializer, UserRegistrationSerializer
import random
from django.contrib.postgres.search import SearchVector

class SignUpView(CreateView):
    form_class = CustomUserCreationForm
    success_url = reverse_lazy("login")
    template_name = "registration/signup.html"
    
def get_or_createToken(request):
    if request.user.is_authenticated and 'access_token' not in request.session  :
        user = CustomUser.objects.get(email = request.user.email)
        token = get_tokens_for_user(user)
        request.session['access_token'] = token['access']
    

class HomeView(TemplateView):

    def get(self,request,name=''):
        
        get_or_createToken(request)
        all_product_shown = False
        if name == "all" :
            all_product_shown = True
            all_products = requests.get('http://127.0.0.1:8000/api/product/').json()
            
        elif name == "Ascending": 
            all_product_shown = True
            all_products = requests.get('http://127.0.0.1:8000/api/product/',data={'order_by' : "Name"}).json()
            
        elif name == "Descending" : 
            all_product_shown = True
            all_products = requests.get('http://127.0.0.1:8000/api/product/',data={'order_by' : "-Name"}).json()
            
        elif name== "PriceDescending" :
            all_product_shown = True
            all_products = requests.get('http://127.0.0.1:8000/api/product/',data={'order_by' : "Price"}).json()
             
        elif name== "PriceAscending" : 
            all_product_shown = True
            all_products = requests.get('http://127.0.0.1:8000/api/product/',data={'order_by' : "-Price"}).json()
            
        elif name:
            
            data = {"product_name" : name}
            all_products = requests.get('http://127.0.0.1:8000/api/product_search',data=data).json()
            
            if request.user.is_authenticated :
                if not request.user.is_user_verified:
                    return redirect("verify")
        else:
            all_products = random.sample(list(Product.objects.all()),8)
            
        return render(request,'home.html',{ "all_products" : all_products, "all_product_shown" : all_product_shown })
    
    
class cartView(TemplateView) :
    def get(self,request):
        get_or_createToken(request)
        if not request.user.is_authenticated :
            return redirect('login')
        
        if not request.user.is_user_verified:
            return redirect("verify")
        url = "http://127.0.0.1:8000/api/cart/"

        payload = json.dumps({
        "user_id": request.user.id
        })
        headers = {
        'Authorization': f'Bearer {request.session["access_token"]}',
        'Content-Type': 'application/json'
        }

        response = requests.request("GET", url, headers=headers, data=payload)
        return render(request,'cart.html',{"cart" : response, "products" :response.json()[0]['Products']})
    
class RemoveCartProduct(APIView):
    def get(self,request,product_id=0,user_id=0):
        payload = json.dumps({
            "user_id": user_id,
            "product_ids":[product_id],
            "product_remove": True
            })
        headers = {
        'Authorization': f'Bearer {request.session["access_token"]}',
        'Content-Type': 'application/json'
        }
        response = requests.request("POST", 'http://127.0.0.1:8000/api/cart/', headers=headers, data=payload)
        return Response(response.json())    
    
class AddCartProduct(APIView):
    def get(self,request,product_id=0,user_id=0):
        payload = json.dumps({
            "user_id": user_id,
            "product_ids":[product_id]
            })
        headers = {
        'Authorization': f'Bearer {request.session["access_token"]}',
        'Content-Type': 'application/json'
        }
        response = requests.request("POST", 'http://127.0.0.1:8000/api/cart/', headers=headers, data=payload)
        return Response(response.json())    

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
  
class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
            serializer = UserRegistrationSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            if not request.data['email'] :
                return Response({'msg':'email field is required'}, status=status.HTTP_400_BAD_REQUEST)
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({'token':token, 'msg':'Registration Successful'}, status=status.HTTP_201_CREATED)

class UserLoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        user = CustomUser.objects.get(email = email)
        if user.check_password(password)  :
            token = get_tokens_for_user(user)
            return Response({'token':token, 'msg':'Login Success'}, status=status.HTTP_200_OK)
        else:
            return Response({'errors':{'non_field_errors':['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)

class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)

class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)




class VerifyView(TemplateView):
    def __init__(self):
        self.mobile = Mobile_verification()
        self.created_email_otp = ''

    def get(self,request):
        if not request.user.is_authenticated:
            return redirect('login')
        from django.core.mail import send_mail
        if not request.user.is_user_verified:
            self.created_email_otp = random.randint(100000,999999)
            aaa = send_mail(
                'Verification of email',
                f'Verification code : {self.created_email_otp}',
                'rikenkhadelamain@gmail.com',
                [str(request.user.email)],
                fail_silently=False,
            )
            request.session['created_email_otp'] = self.created_email_otp
            self.mobile.get_otp(request.user.Mobile_number)
            return render(request,'registration/verify.html')
        else:
            return redirect('home')

    def post(self,request):
        mobile_otp_bool = False
        email_otp_bool = False
        mobile_otp = request.POST.get('mobile_otp')
        email_otp = request.POST.get('email_otp')
        self.created_email_otp = request.session.get('created_email_otp')
        otp_output = self.mobile.send_otp(mobile_otp,request.user.Mobile_number)
        if otp_output == "approved" :
            mobile_otp_bool = True
        if str(email_otp).strip() == str(self.created_email_otp).strip() :
            email_otp_bool = True

        if mobile_otp_bool and email_otp_bool :
            request.user.is_user_verified = True
            request.user.save()

        return redirect('home')
    
class ProductView(APIView, DestroyModelMixin,):
    
    def get(self, request, product_id=None):
        if product_id:
            try:
                queryset = Product.objects.get(id=product_id)
            except Product.DoesNotExist:
                return Response({'errors': 'This Product item does not exist.'}, status=400)

            read_serializer = ProductSerializer(queryset)
        elif 'order_by' in request.data :
            queryset = Product.objects.order_by(request.data['order_by'])
            read_serializer = ProductSerializer(queryset, many=True)
            
        else:
            queryset = Product.objects.order_by('Price')
            read_serializer = ProductSerializer(queryset, many=True)

        
        
        return Response(read_serializer.data)
        
    def post(self,request):
        create_serializer = ProductSerializer(data=request.data)
        if create_serializer.is_valid():

            Product_item_object = create_serializer.save()

            read_serializer = ProductSerializer(Product_item_object)

            return Response(read_serializer.data, status=201)

        return Response(create_serializer.errors, status=400)
    
    def delete(self, request, id=None):
        try:
            product_item = Product.objects.get(id=id)
        except Product.DoesNotExist:
            return Response({'errors': 'This Product item does not exist.'}, status=400)
        product_item.delete()
        return Response(status=204)
    
class CartView(APIView,DestroyModelMixin):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    
    def get(self,request):
        data = request.data
        cart, _ = Cart.objects.get_or_create(user = CustomUser.objects.filter(id=data['user_id']).first())
        data = {
            "id" : cart.id,
            "user" : cart.user_id,
            "Products" : [ ProductSerializer(Product.objects.get(id=i)).data for i in cart.Products_id]
        }
        return Response([data])
    
    def post(self,request,cart_id=None):
        data = request.data
        cart, _ = Cart.objects.get_or_create(user = CustomUser.objects.filter(id=data['user_id']).first())
        if data['product_ids'] :
            if 'product_remove' in data and data['product_remove'] == True :
                for product in data['product_ids']:
                    cart.Products.remove(Product.objects.filter(id=product).first())
            else:
                for product in data['product_ids'] :cart.Products.add(Product.objects.filter(id=product).first())
            cart.save()
        data = {
            "id" : cart.id,
            "user" : cart.user_id,
            "Products" :[ ProductSerializer(Product.objects.get(id=i)).data for i in cart.Products_id]
        }
        return Response([data])
            
    def delete(self, request, cart_id=None):
        try:
            cart_item = Cart.objects.get(id=cart_id)
        except Cart.DoesNotExist:
            return Response({'errors': 'This cart item does not exist.'}, status=400)
        cart_item.delete()
        return Response(status=204)
    
    
class Product_search(APIView,DestroyModelMixin):
    def get(self, request):
        if request.data['product_name']:
            queryset = Product.objects.filter(Name__icontains=request.data['product_name'])
            read_serializer = ProductSerializer(queryset, many=True)
            return Response(read_serializer.data)
        else:
            queryset = Product.objects.all()
            read_serializer = ProductSerializer(queryset, many=True)
        return Response(read_serializer.data)
    
