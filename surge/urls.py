from django.urls import path
from . import views

app_name = 'surge'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),  # Redirects to about
    path('about/', views.dashboard_about, name='dashboard_about'),
    path('controls/', views.dashboard_controls, name='dashboard_controls'),
    path('api/status/', views.api_status, name='api_status'),
    path('api/scanner/start/', views.api_start_scanner, name='api_start_scanner'),
    path('api/scanner/stop/', views.api_stop_scanner, name='api_stop_scanner'),
    path('api/scanner/status/', views.api_scanner_status, name='api_scanner_status'),
    path('api/findings/', views.api_findings, name='api_findings'),
    path('api/findings/<uuid:finding_id>/', views.api_finding_detail, name='api_finding_detail'),
    path('upload-templates/', views.upload_templates, name='upload_templates'),
    path('koga/about/', views.koga_about, name='koga_about'),
    path('koga/controls/', views.koga_controls, name='koga_controls'),
    path('bugsy/about/', views.bugsy_about, name='bugsy_about'),
    path('bugsy/controls/', views.bugsy_controls, name='bugsy_controls'),
]
