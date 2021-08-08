from django.contrib.auth import get_user_model
from django.db.models.functions import datetime
from rest_framework import generics, status, views, permissions
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from rest_framework.settings import api_settings

from .models import CustomUser
from .serializer import RegisterSerializer, LoginSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token

model = get_user_model()


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    authentication_classes = (TokenAuthentication,)

    def post(self, request, ):
        # user = request.data.get('user', {})
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        return Response( serializer.data, status=status.HTTP_201_CREATED)


        # return Response({"data": serializer.data}, status=status.HTTP_201_CREATED)


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
































































# from rest_framework.response import Response
# from rest_framework_simplejwt.tokens import RefreshToken
# from .models import CustomUser
# from .serializer import MyTokenObtainPairSerializer
# from rest_framework.permissions import AllowAny
# from rest_framework_simplejwt.views import TokenObtainPairView
# from .serializer import RegisterSerializer
# from rest_framework import generics, status
# from rest_framework_simplejwt.tokens import RefreshToken


# class MyObtainTokenPairView(TokenObtainPairView):
#     permission_classes = (AllowAny,)
#     serializer_class = MyTokenObtainPairSerializer
#
#
# class RegisterView(generics.CreateAPIView):
#     # # queryset = CustomUser.objects.all()
#     # permission_classes = (AllowAny,)
#     # serializer_class = RegisterSerializer
#     serializer_class = RegisterSerializer
#     permission_classes = (AllowAny,)
#
#     def post(self, request, ):
#         user = request.data.get('user', {})
#         # user = request.data['user']
#         serializer = self.serializer_class(data=user)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         # user_data = serializer.data
#         # current_site = get_current_site(request).domain
#         # return Response({"data": serializer.data}, status=status.HTTP_201_CREATED)
#         return Response({"data": serializer.data}, status=status.HTTP_201_CREATED)
