from django.contrib import admin
from django.urls import path

from .views import (PasswordResetConfirmView, PasswordResetView, UserLoginView,
                    UserRegistrationView, UserUpdateView)

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='user-registration'),
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('update/', UserUpdateView, name='user-update'),
    path('password-reset/', PasswordResetView.as_view(), name='password-reset'),
    path('password-reset-confirm/', PasswordResetConfirmView.as_view(),name='password-reset-confirm'),

]
