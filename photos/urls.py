from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('auth/', views.google_auth, name='google_auth'),  # Redirects to Google OAuth
    path('auth/callback/', views.google_auth_callback, name='google_auth_callback'),  # Handles Google callback
    path('migrate/', views.migrate_photos, name='migrate_photos'),  # Migrates photos
]
