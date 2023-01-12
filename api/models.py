from datetime import datetime, timedelta

import jwt
from django.db import models
from django.contrib.auth.models import (BaseUserManager, AbstractBaseUser, PermissionsMixin)
from rest_framework_simplejwt.tokens import RefreshToken
from loginapi import settings


# Create your models here.

class UserManager(BaseUserManager):

    def create_user(self, username, email, password=None):

        if username is None:
            raise TypeError('user should have username')
        if email is None:
            raise TypeError('user should have email')

        user = self.model(username=username, email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password=None):

        if password is None:
            raise TypeError('password should not be none')
        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


class User(AbstractBaseUser,PermissionsMixin):
    username = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_At = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.email

    # @property
    # def token(self):
    #     return self._generate_jwt_token()
    #
    # def _generate_jwt_token(self):
    #     dt = datetime.now() + timedelta(days=60)
    #
    #     token = jwt.encode({
    #         'id': self.pk,
    #         'exp': int(dt.strftime('%s'))
    #     }, settings.SECRET_KEY, algorithm='HS256')
    #
    #     return token
    def tokens(self):
        tokens = RefreshToken.for_user(self)
        return {
            'refresh': str(tokens),
            'access': str(tokens.access_token)
        }