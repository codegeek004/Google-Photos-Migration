from django.urls import path
from photos import views

urlpatterns = [
    path('', views.home, name='home'),
    path('auth/', views.google_auth, name='google_auth'),
    path('auth/callback/', views.google_auth_callback, name='google_auth_callback'),
    path('migrate/', views.migrate_photos, name='migrate_photos'),
    path('destination/auth/', views.destination_google_auth, name='destination_google_auth'),
    path('destination/auth/callback/', views.destination_google_auth_callback, name='destination_google_auth_callback'),
    path('logout/', views.logout_view, name='logout'),
]
