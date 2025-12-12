"""
URL configuration for ryu_app.
"""
from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views
from .daemon_api import (
    daemon_get_eggrecords,
    daemon_submit_scan,
    daemon_submit_spider,
    daemon_submit_assessment,
    daemon_submit_enumeration,
    daemon_health_check
)

app_name = 'ryu_app'

urlpatterns = [
    path('', views.general_dashboard, name='index'),
    path('general/', views.general_dashboard, name='general_dashboard'),
    path('kage/', views.kage_dashboard, name='kage_dashboard'),
    path('kaze/', views.kaze_dashboard, name='kaze_dashboard'),
    path('kumo/', views.kumo_dashboard, name='kumo_dashboard'),
    path('suzu/', views.suzu_dashboard, name='suzu_dashboard'),
    path('ryu/', views.ryu_dashboard, name='ryu_dashboard'),
    path('learning/', views.learning_dashboard, name='learning_dashboard'),
    path('monitoring/', views.monitoring_dashboard, name='monitoring_dashboard'),
    path('network/', views.network_visualizer_dashboard, name='network_visualizer_dashboard'),
    path('eggrecords/', views.eggrecord_list, name='eggrecord_list'),
    path('eggrecords/<uuid:eggrecord_id>/', views.eggrecord_detail, name='eggrecord_detail'),
    path('api/check-empty/', views.check_empty, name='check_empty'),
    path('api/seed-entries/', views.seed_initial_entries, name='seed_entries'),
    path('api/eggrecords/create/', views.create_eggrecord_api, name='create_eggrecord_api'),
    path('api/projectegg/generate/', views.generate_projectegg_api, name='generate_projectegg_api'),
    # Learning API endpoints
    path('api/learning/heuristics/', views.learning_heuristics_api, name='learning_heuristics_api'),
    path('api/learning/techniques/', views.learning_techniques_api, name='learning_techniques_api'),
    path('api/learning/ip-effectiveness/', views.learning_ip_effectiveness_api, name='learning_ip_effectiveness_api'),
    # Network visualization API endpoints (must come before generic personality routes)
    path('api/network/graph/', views.network_graph_api, name='network_graph_api'),
    path('api/network/options/', views.network_options_api, name='network_options_api'),
    path('api/network/visual-settings/', views.network_visual_settings_api, name='network_visual_settings_api'),
    # Eggs search API endpoint
    path('api/eggs/search/', views.eggs_search_api, name='eggs_search_api'),
    # Daemon API endpoints (must come before generic personality routes)
    # All daemon API endpoints are CSRF-exempt (no browser-based requests)
    path('api/daemon/<str:personality>/eggrecords/', csrf_exempt(daemon_get_eggrecords), name='daemon_get_eggrecords'),
    path('api/daemon/<str:personality>/scan/', csrf_exempt(daemon_submit_scan), name='daemon_submit_scan'),
    path('api/daemon/kumo/spider/', csrf_exempt(daemon_submit_spider), name='daemon_submit_spider'),
    path('api/daemon/ryu/assessment/', csrf_exempt(daemon_submit_assessment), name='daemon_submit_assessment'),
    path('api/daemon/enumeration/', csrf_exempt(daemon_submit_enumeration), name='daemon_submit_enumeration'),
    path('api/daemon/<str:personality>/health/', csrf_exempt(daemon_health_check), name='daemon_health_check'),
    # Oak Nuclei template API endpoints (for Surge)
    path('api/oak/nuclei-templates/<uuid:egg_record_id>/', views.oak_nuclei_templates_api, name='oak_nuclei_templates_api'),
    path('api/oak/refresh-templates/', views.oak_refresh_templates_api, name='oak_refresh_templates_api'),
    path('api/oak/curate-sample/', views.oak_curate_sample_api, name='oak_curate_sample_api'),
    # Personality control API endpoints
    path('api/<str:personality>/status/', views.personality_status_api, name='personality_status_api'),
    path('api/<str:personality>/logs/', views.personality_logs_api, name='personality_logs_api'),  # Must come before generic action route
    path('api/<str:personality>/<str:action>/', views.personality_control_api, name='personality_control_api'),
    path('api/eggs/<int:egg_id>/queue-status/', views.check_egg_queue_status_api, name='check_egg_queue_status_api'),
]

