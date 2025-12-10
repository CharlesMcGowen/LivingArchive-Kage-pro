"""
URL configuration for ryu_project.
"""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('ryu_app.urls')),
    path('reconnaissance/', include(('ryu_app.urls', 'ryu_app'), namespace='reconnaissance')),
]

