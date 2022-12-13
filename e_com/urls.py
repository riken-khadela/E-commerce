from django.contrib import admin
from django.urls import path, include
from django.views.generic.base import TemplateView
from home.views import HomeView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("home.urls")),
    # path('api/user/', include('account.urls')),
    # path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),

]