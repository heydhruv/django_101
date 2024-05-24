from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import redirect, render
from rest_framework.decorators import api_view


@api_view(['GET', 'POST'])
def CustomAdminLoginView(request, *args, **kwargs):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user is not None and user.is_staff:
            login(request, user)
            return redirect('dashboard')
        else:
            error = "Invalid username or password"
            return render(request, 'customadmin/login.html', {'error': error})
    return render(request, 'customadmin/login.html')


@login_required
def CustomAdminDashboardView(request, *args, **kwargs):
    users = User.objects.all()
    return render(request, 'customadmin/dashboard.html', {"users": users})
