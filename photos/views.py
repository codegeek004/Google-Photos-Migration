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
    if 'code' not in request.GET:
        return redirect('home')  # Redirect or show an error if the code is missing

    flow = get_google_auth_flow()
    flow.fetch_token(authorization_response=request.build_absolute_uri())
    credentials = flow.credentials

    # Save credentials in the session
    request.session['source_credentials'] = credentials_to_dict(credentials)

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
    if 'source_credentials' not in request.session:
        return redirect('source_google_auth')  # Redirect to authenticate the source account

    # Fetch photos from the source account with pagination
    source_credentials = request.session['source_credentials']
    page_token = request.GET.get('page_token')  # Retrieve page token from query parameters
    photos, next_page_token = get_photos(source_credentials, page_token)

    if request.method == 'POST' and 'action' in request.POST:
        action = request.POST['action']

        # Handle "Migrate All" action
        if action == 'migrate_all':
            destination_credentials = request.session.get('destination_credentials')
            if destination_credentials:
                destination_service = get_photos_service(destination_credentials)
                for photo in photos:
                    file_url = photo['baseUrl'] + "=d"
                    file_name = photo['filename']
                    photo_data = download_photo(file_url)
                    print('Downloaded photo data', photo_data)
                    if photo_data:
                        upload_photo(destination_service, photo_data, file_name)
                return render(request, 'migrate_photos.html', {'photos': photos, 'success_all': True, 'next_page_token': next_page_token})

        # Handle "Migrate Selected" action
        elif action == 'migrate_selected':
            selected_photo_ids = request.POST.getlist('selected_photos')
            destination_credentials = request.session.get('destination_credentials')
            if destination_credentials and selected_photo_ids:
                destination_service = get_photos_service(destination_credentials)
                selected_photos = [photo for photo in photos if photo['id'] in selected_photo_ids]
                for photo in selected_photos:
                    file_url = photo['baseUrl'] + "=d"
                    file_name = photo['filename']
                    photo_data = download_photo(file_url)
                    if photo_data:
                        upload_photo(destination_service, photo_data, file_name)
                return render(request, 'migrate_photos.html', {'photos': photos, 'success_selected': True, 'next_page_token': next_page_token})

    return render(request, 'migrate_photos.html', {'photos': photos, 'next_page_token': next_page_token})


def destination_google_auth(request, email):
    flow = get_google_auth_flow()
    authorization_url, state = flow.authorization_url(access_type='offline')
    
    # Store the destination email in session for later use
    request.session['destination_email'] = email
    
    return redirect(authorization_url)

def destination_google_auth_callback(request):
    if 'code' not in request.GET:
        return redirect('home')  # Redirect if the code is missing

    flow = get_google_auth_flow()
    flow.fetch_token(authorization_response=request.build_absolute_uri())
    credentials = flow.credentials

    # Store destination credentials in session
    request.session['destination_credentials'] = credentials_to_dict(credentials)
    return redirect('migrate_photos')

def get_photos(credentials_dict, page_token=None):
    print('Fetching photos with pagination...')
    service = get_photos_service(credentials_dict)
    results = service.mediaItems().list(pageSize=20, pageToken=page_token).execute()
    
    items = results.get('mediaItems', [])
    next_page_token = results.get('nextPageToken')  # Token for the next page, if available
    
    return items, next_page_token


# Download a photo
def download_photo(url):
    print('download photo mai gaya')
    try:
        response = requests.get(url, stream=True)
        print('response', response)
        response.raise_for_status()
        return io.BytesIO(response.content)  # Return file-like object
    except requests.exceptions.RequestException as e:
        print(f"Error downloading photo: {e}")
        return None

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
        # Debugging information
        print("Uploading Photo:", file_name)
        print("Photo Data:", photo_data.getbuffer().nbytes)  # File size
        
        media = MediaFileUpload(file_name, resumable=True)
        request = service.mediaItems().batchCreate(body=media_item)
        response = request.execute()
        print("Upload Response:", response)
        return response
    except Exception as e:
        print(f"Error uploading photo: {e}")
        return None





import requests
from django.contrib.auth import logout
def logout_view(request):
    # Revoke tokens if they exist
    source_credentials = request.session.get('source_credentials')
    destination_credentials = request.session.get('destination_credentials')

    if source_credentials:
        requests.post(
            'https://oauth2.googleapis.com/revoke',
            params={'token': source_credentials['token']},
            headers={'content-type': 'application/x-www-form-urlencoded'}
        )

    if destination_credentials:
        requests.post(
            'https://oauth2.googleapis.com/revoke',
            params={'token': destination_credentials['token']},
            headers={'content-type': 'application/x-www-form-urlencoded'}
        )

    # Clear session data and logout
    request.session.flush()
    logout(request)

    # Redirect to home or login page
    return redirect('home')


