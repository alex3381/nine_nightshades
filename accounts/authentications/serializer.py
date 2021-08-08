from django.contrib.auth import get_user_model
from django.core import exceptions
from rest_framework import serializers
from rest_framework.settings import api_settings
import django.contrib.auth.password_validation as validators
from .models import CustomUser
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework_jwt.settings import api_settings

UserModel = get_user_model()


class RegisterSerializer(serializers.HyperlinkedModelSerializer):
    password = serializers.CharField(write_only=True)
    token = serializers.SerializerMethodField()

    def get_token(self, obj):
        jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

        payload = jwt_payload_handler(obj)
        token = jwt_encode_handler(payload)
        return token

    def validate(self, data):
        password = data.get('password')
        errors = dict()
        try:
            validators.validate_password(password=password)

        # the exception raised here is different than serializers.ValidationError
        except exceptions.ValidationError as e:
            errors [ 'password' ] = list(e.messages)

        if errors:
            raise serializers.ValidationError(errors)

        return super(RegisterSerializer, self).validate(data)

    class Meta:
        model = CustomUser
        fields = ('email', 'password', 'token')
                  # 'firstname', 'lastname', 'phone_number', 'token')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        return user


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(
        max_length=255, min_length=3, read_only=True)

    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = CustomUser.objects.get(email=obj [ 'email' ])

        return {
            'refresh': user.tokens() [ 'refresh' ],
            'access': user.tokens() [ 'access' ]
        }

    class Meta:
        model = CustomUser
        fields = [ 'email', 'password', 'username', 'tokens' ]

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        filtered_user_by_email = CustomUser.objects.filter(email=email)
        user = auth.authenticate(email=email, password=password)

        if filtered_user_by_email.exists() and filtered_user_by_email [ 0 ].auth_provider != 'email':
            raise AuthenticationFailed(
                detail='Please continue your login using ' + filtered_user_by_email [ 0 ].auth_provider)

        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')

        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens
        }

        return super().validate(attrs)

# from django.contrib.auth import get_user_model
# from django.contrib.auth.hashers import make_password
# from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
# from rest_framework import serializers
# from django.contrib.auth.models import User
# from rest_framework.validators import UniqueValidator
# from django.contrib.auth.password_validation import validate_password
# from rest_framework_simplejwt.tokens import RefreshToken
# from sqlparse.compat import text_type
#
# from .models import CustomUser
#
# CustomUserModel = get_user_model()
#
#
# class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
#
#     @classmethod
#     def get_token(cls, user):
#         token = super(MyTokenObtainPairSerializer, cls).get_token(user)
#
#         # Add custom claims
#         token [ 'email' ] = user.email
#         return token
#
#
# class RegisterSerializer(serializers.ModelSerializer):
#     email = serializers.EmailField(
#         required=True,
#         validators=[ UniqueValidator(queryset=CustomUser.objects.all()) ]
#     )
#
#     password = serializers.CharField(write_only=True, required=True, validators=[ validate_password ])
#     password_confirmation = serializers.CharField(write_only=True, required=True)
#
#     class Meta:
#         model = CustomUser
#         fields = ('last_name', 'first_name','phone_number','email', 'password', 'password_confirmation', 'id','tokens', )
#         # extra_kwargs = {
#         #     'last_name': {'required': True},
#         #     'first_name': {'required': True},
#         #     'phone_number': {'required': True}
#         #     # 'id': {'required': True}
#         # }
#
#     # def get_tokens(self, user):
#     #     tokens = RefreshToken.for_user(user)
#     #     refresh = text_type(tokens)
#     #     access = text_type(tokens.access_token)
#     #     data = {
#     #         "refresh": refresh,
#     #         "access": access
#     #         }
#     #     return data
#
#     def create(self, validated_data):
#         if validated_data.get('password') != validated_data.get('password_confirmation'):
#             raise serializers.ValidationError("Those password don't match")
#
#         elif validated_data.get('password') == validated_data.get('password_confirmation'):
#             validated_data [ 'password' ] = make_password(
#                 validated_data.get('password')
#             )
#
#         validated_data.pop('password_confirmation')  # add this
#         return super(RegisterSerializer, self).create(validated_data)
#
#     # def validate(self, attrs):
#     #     if attrs [ 'password' ] != attrs [ 'password_confirmation' ]:
#     #         raise serializers.ValidationError({"password": "Password fields didn't match."})
#     #
#     #     return attrs
#     #
#     # def create(self, validated_data):
#     #     user = CustomUser.objects.create(
#     #         # id=validated_data [ 'id' ],
#     #         email=validated_data [ 'email' ],
#     #         type=validated_data [ 'type' ],
#     #         password_confirmation=validated_data [ 'password_confirmation' ]
#     #     )
#     #
#     #     user.set_password(validated_data [ 'password' ])
#     #     user.save()
#     #
#     #     return user
