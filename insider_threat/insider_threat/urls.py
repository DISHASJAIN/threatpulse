"""
URL configuration for insider_threat project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
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
from django.urls import path, include

from threat_detection.views import (
    dashboard,
    login_view,
    logout_view,
    alerts_page,
    users_page,
    reports_page,
    logs_page,
    risk_page,
    export_pdf,
    export_csv,
    trigger_demo_alert,
    alert_count_api,
    blockchain_page,
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', login_view, name='home'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('dashboard/', dashboard, name='dashboard'),
    path('alerts/', alerts_page, name='alerts'),
    path('users/', users_page, name='users'),
    path('reports/', reports_page, name='reports'),
    path('logs/', logs_page, name='logs'),         
    path('risk/', risk_page, name='risk'),  
    path('export/pdf/', export_pdf, name='export_pdf'),        
    path('export/csv/', export_csv, name='export_csv'), 
    path('trigger-demo-alert/', trigger_demo_alert, name='trigger_demo_alert'),
    path('blockchain/', blockchain_page, name='blockchain'),
    path('api/alert-count/', alert_count_api, name='alert_count_api'),
    path('api/', include('threat_detection.urls')),
    path('api-auth/', include('rest_framework.urls')),
]
