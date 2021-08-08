from django.urls import path
from .views import RegisterView, LoginAPIView

from rest_framework_simplejwt.views import (
    TokenObtainPairView,

)

urlpatterns = [

    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('login/', LoginAPIView.as_view(), name="login"),
    path('register/', RegisterView.as_view(), name="register"),
]
