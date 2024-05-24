from django.urls import path

from .views import CustomAdminDashboardView, CustomAdminLoginView

urlpatterns = [
    path('login/', CustomAdminLoginView, name="customadmin-login"),
    path('dashboard/', CustomAdminDashboardView, name="dashboard"),
]
