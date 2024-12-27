from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('auth/', views.google_auth, name='google_auth'),  # Redirects to Google OAuth
    path('auth/callback/', views.google_auth_callback, name='google_auth_callback'),  # Handles Google callback
    path('migrate/', views.migrate_photos, name='migrate_photos'),  # Migrate photos
    path('destination/auth/<str:email>/', views.destination_google_auth, name='destination_google_auth'),  # Auth for destination account
    path('destination/auth/callback/', views.destination_google_auth_callback, name='destination_google_auth_callback'),  # Callback for destination account
    path('logout/', views.logout_view, name='logout'),
]
