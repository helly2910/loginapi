"""loginapi URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from .views import RegisterView,VerifyEmail,LoginAPIView, PasswordTokenCheckAPI, RequestPasswordResetEmail,SetNewPassword

urlpatterns = [
    # path('', views.home, name="index"),
    path('register/', RegisterView.as_view(), name="register"),
    path('verify', VerifyEmail.as_view(), name="verify"),
    path('login/', LoginAPIView.as_view(), name="login"),
    path('request-reset-email/', RequestPasswordResetEmail.as_view(), name='request-reset-email'),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPI.as_view(), name='password-reset'),
    path('password_reset-complete', SetNewPassword.as_view(), name='password_reset-complete'),
]
