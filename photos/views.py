import os
import io
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from django.contrib.auth.models import User
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaFileUpload
from google.oauth2.credentials import Credentials
from google_auth_httplib2 import AuthorizedHttp
import httplib2
import requests

# Define constants
CLIENT_SECRETS_FILE = "credentials.json"
API_NAME = 'photoslibrary'
API_VERSION = 'v1'

# Set up the OAuth flow
def get_google_auth_flow():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,  # Path to your credentials.json file
        scopes=[
            'https://www.googleapis.com/auth/photoslibrary.readonly',
            'https://www.googleapis.com/auth/photoslibrary.appendonly'
        ],
        redirect_uri='https://127.0.0.1:8000/photos/auth/callback/'  # This should match the callback URL registered in Google Console
    )
    return flow

def home(request):
    return render(request, 'home.html')

def google_auth(request):
    flow = get_google_auth_flow()
    authorization_url, state = flow.authorization_url()
    return redirect(authorization_url)

def google_auth_callback(request):
    print("Callback URL:", request.build_absolute_uri())  # Debug the full callback URL
    print("Request GET Data:", request.GET)  # Debug the query parameters
    
    if 'code' not in request.GET:
        return redirect('home')  # Redirect or show an error if the code is missing

    flow = get_google_auth_flow()
    flow.fetch_token(authorization_response=request.build_absolute_uri())
    credentials = flow.credentials

    # Save credentials in the session
    request.session['credentials'] = credentials_to_dict(credentials)

    # Authenticate and log the user in (dummy user for simplicity)
    user, created = User.objects.get_or_create(username="google_user")
    login(request, user)  # Log the user into the Django session system

    return redirect('migrate_photos')  # Redirect to migrate_photos

# Convert Credentials object to a dictionary
def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

# Get Google Photos API client
def get_photos_service(credentials_dict):
    credentials = Credentials(
        token=credentials_dict['token'],
        refresh_token=credentials_dict.get('refresh_token'),
        token_uri=credentials_dict['token_uri'],
        client_id=credentials_dict['client_id'],
        client_secret=credentials_dict['client_secret'],
        scopes=credentials_dict['scopes']
    )
    http = httplib2.Http()
    authorized_http = AuthorizedHttp(credentials, http=http)
    return build(API_NAME, API_VERSION, http=authorized_http, static_discovery=False)

@login_required
def migrate_photos(request):
    if 'source_credentials' not in request.session or 'destination_credentials' not in request.session:
        return redirect('source_google_auth')  # Redirect to authenticate both accounts

    source_credentials = request.session['source_credentials']
    destination_credentials = request.session['destination_credentials']

    source_service = get_photos_service(source_credentials)
    destination_service = get_photos_service(destination_credentials)

    photos = get_photos(source_credentials)

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'migrate_all':
            for photo in photos:
                file_url = photo['baseUrl'] + "=d"
                file_name = photo['filename']
                photo_data = download_photo(file_url)
                if photo_data:
                    upload_photo(destination_service, photo_data, file_name)
            return render(request, 'migrate_photos.html', {'photos': photos, 'success_all': True})

        elif action == 'migrate_selected':
            selected_photo_ids = request.POST.getlist('selected_photos')
            for photo in photos:
                if photo['id'] in selected_photo_ids:
                    file_url = photo['baseUrl'] + "=d"
                    file_name = photo['filename']
                    photo_data = download_photo(file_url)
                    if photo_data:
                        upload_photo(destination_service, photo_data, file_name)
            return render(request, 'migrate_photos.html', {'photos': photos, 'success_selected': True})

    return render(request, 'migrate_photos.html', {'photos': photos})
@login_required
def migrate_photos(request):
    if 'source_credentials' not in request.session or 'destination_credentials' not in request.session:
        return redirect('source_google_auth')  # Redirect to authenticate both accounts

    source_credentials = request.session['source_credentials']
    destination_credentials = request.session['destination_credentials']

    source_service = get_photos_service(source_credentials)
    destination_service = get_photos_service(destination_credentials)

    photos = get_photos(source_credentials)

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'migrate_all':
            for photo in photos:
                file_url = photo['baseUrl'] + "=d"
                file_name = photo['filename']
                photo_data = download_photo(file_url)
                if photo_data:
                    upload_photo(destination_service, photo_data, file_name)
            return render(request, 'migrate_photos.html', {'photos': photos, 'success_all': True})

        elif action == 'migrate_selected':
            selected_photo_ids = request.POST.getlist('selected_photos')
            for photo in photos:
                if photo['id'] in selected_photo_ids:
                    file_url = photo['baseUrl'] + "=d"
                    file_name = photo['filename']
                    photo_data = download_photo(file_url)
                    if photo_data:
                        upload_photo(destination_service, photo_data, file_name)
            return render(request, 'migrate_photos.html', {'photos': photos, 'success_selected': True})

    return render(request, 'migrate_photos.html', {'photos': photos})

# Fetch photos from Google Photos
def get_photos(credentials_dict):
    service = get_photos_service(credentials_dict)
    results = service.mediaItems().list(pageSize=100).execute()
    print('results', results)
    items = results.get('mediaItems', [])
    return items

# Download a photo
def download_photo(url):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        return io.BytesIO(response.content)  # Return file-like object
    except requests.exceptions.RequestException as e:
        print(f"Error downloading photo: {e}")
        return None

# Upload a photo to Google Photos
def upload_photo(service, photo_data, file_name):
    try:
        media_item = {
            'newMediaItems': [
                {
                    'simpleMediaItem': {
                        'fileName': file_name
                    }
                }
            ]
        }
        media = MediaFileUpload(file_name, resumable=True)
        request = service.mediaItems().batchCreate(body=media_item)
        response = request.execute()
        return response
    except Exception as e:
        print(f"Error uploading photo: {e}")
        return None



def destination_google_auth(request):
    flow = get_google_auth_flow()
    authorization_url, state = flow.authorization_url()
    return redirect(authorization_url)

def destination_google_auth_callback(request):
    if 'code' not in request.GET:
        return redirect('home')  # Redirect if the code is missing

    flow = get_google_auth_flow()
    flow.fetch_token(authorization_response=request.build_absolute_uri())
    credentials = flow.credentials

    # Save credentials in session
    request.session['destination_credentials'] = credentials_to_dict(credentials)
    return redirect('migrate_photos')
