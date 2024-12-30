from django.urls import path
from photos import views

urlpatterns = [
    path('', views.home, name='home'),  # Home page
    path('auth/', views.oauth, name='oauth'),  # Authentication template ### UPDATED ###
    path('auth/redirect/', views.google_auth, name='google_auth'),  # Redirect to Google OAuth ### NEW ###
    path('auth/callback/', views.google_auth_callback, name='google_auth_callback'),  # Google OAuth callback
    path('migrate/', views.migrate_photos, name='migrate_photos'),  # Migrate photos
    path('destination/auth/', views.destination_google_auth, name='destination_google_auth'),  # Destination auth
    path('destination/auth/callback/', views.destination_google_auth_callback, name='destination_google_auth_callback'),  # Destination callback
    path('logout/', views.logout_view, name='logout'),  # Logout
]
