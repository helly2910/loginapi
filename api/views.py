import jwt
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from jwt.utils import force_bytes
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from .utils import send_reset_mail
from .models import User
from .serializers import RegisterSerializer, LoginSerializer, ResetPasswordEmailRequestSerializer, SetNewPasswordSerailizer
from .utils import send_email


# def home(request):
#     return render(request, "authentication/signup.html")


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        # uid = urlsafe_base64_encode(force_bytes(user.pk))
        # token = User.token
        token = RefreshToken.for_user(user).access_token
        send_email(user, token)
        return Response({"msg": "your Account has been successfully created we have sent you a confirmation email, please confirm your email in order to activate your account "})


class VerifyEmail(generics.GenericAPIView):
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
                return Response({'email': 'successfully activated'}, status=status.HTTP_201_CREATED)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid Token'}, status=status.HTTP_400_BAD_REQUEST)

class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'msg': "Login Successfully"}, status=status.HTTP_200_OK)

class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request).domain
            relativelink = reverse('password-reset', kwargs={'uidb64': uidb64, 'token': token})
            absurl = 'http://' + current_site + relativelink
            email_body = 'Hello, \n Use link below to reset your password \n' + absurl
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Reset Your password'}
            send_reset_mail(data)
            return Response({'success': 'we have sent you a link to reset your password'}, status=status.HTTP_200_OK)
        return Response({'error': 'Email id Doesnt Exists'})
class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self,request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new one'},
                                status=status.HTTP_401_UNAUTHORIZED)
            return Response({'success': True, 'message': 'Credentials Valid', 'uidb64': uidb64, 'token': token},
                            status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator():
                return Response({'error': 'Token is not valid'})

class SetNewPassword(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerailizer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'password reset success'}, status=status.HTTP_200_OK)