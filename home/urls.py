from django.urls import path, include

from .views import *

urlpatterns = [
    path(r'',HomeView.as_view(),name="home"),
    path(r'ShopingCart/',cartView.as_view(),name="cart"),
    path(r'<str:name>/',HomeView.as_view(),name="home"),
    path("account/signup/", SignUpView.as_view(), name="signup"),
    path('verify', VerifyView.as_view(),name="verify"),
    path("accounts/", include("django.contrib.auth.urls")),
    path('api/product/',ProductView.as_view(),name='product'),
    path('api/product_search',Product_search.as_view(),name='product_search'),
    path('api/product/<int:product_id>',ProductView.as_view(),name='product'),
    path('api/cart/',CartView.as_view(),name='api-cart'),
    path('api/removecartproduct/<int:product_id>/<int:user_id>',RemoveCartProduct.as_view(),name='api-removecartproduct'),
    path('api/addcartproduct/<int:product_id>/<int:user_id>',AddCartProduct.as_view(),name='api-addcartproduct'),
    path('api/cart/<int:cart_id>',CartView.as_view(),name='api-cart'),
    path('api/register/', UserRegistrationView.as_view(), name='api-register'),
    path('api/login/', UserLoginView.as_view(), name='api-login'),
    path('api/profile/', UserProfileView.as_view(), name='api-profile'),
    path('api/changepassword/', UserChangePasswordView.as_view(), name='api-changepassword'),
]
