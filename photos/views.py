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
import json

# Define constants
CLIENT_SECRETS_FILE = "credentials.json"
API_NAME = 'photoslibrary'
API_VERSION = 'v1'

def get_google_auth_flow():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=[
            'https://www.googleapis.com/auth/photoslibrary.readonly',
            'https://www.googleapis.com/auth/photoslibrary.appendonly',
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email',
            'openid'
        ],
        redirect_uri='https://127.0.0.1:8000/photos/auth/callback/'
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
        return redirect('home')

    flow = get_google_auth_flow()
    flow.fetch_token(authorization_response=request.build_absolute_uri())
    credentials = flow.credentials
    print('creds in auth callback', credentials)

    # Fetch user info using the token
    userinfo_endpoint = 'https://www.googleapis.com/oauth2/v3/userinfo'
    userinfo_response = requests.get(userinfo_endpoint, headers={
        'Authorization': f'Bearer {credentials.token}'
    })
    
    if userinfo_response.status_code == 200:
        userinfo = userinfo_response.json()
        print('userinfo', userinfo)
        username = userinfo.get('name', 'Unknown User')
        email = userinfo.get('email', 'Unknown Email')
        print('username: ', username)
        print('email: ', email)

        # Save user info or use it
        user, created = User.objects.get_or_create(username=email)
        user.first_name = username
        user.save()

        login(request, user)
    else:
        print("Failed to fetch user info:", userinfo_response.text)

    # Save credentials in session
    request.session['source_credentials'] = credentials_to_dict(credentials)
    return redirect('migrate_photos')

def credentials_to_dict(credentials):
    print('creds to dict function mai gaya')
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

def get_photos_service(credentials_dict):
    print('get photos service function mai gaya')
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
    print('migrate photos mai gaya')
    if 'source_credentials' not in request.session:
        return redirect('google_auth')

    source_credentials = request.session['source_credentials']
    print('src creds', source_credentials)
    page_token = request.GET.get('page_token')
    photos, next_page_token = get_photos(source_credentials, page_token)

    if request.method == 'POST' and 'action' in request.POST:
        print('post method mai gaya')
        action = request.POST['action']
        print('action', action)
        destination_credentials = request.session.get('destination_credentials')
        print('dest creds', destination_credentials)
        
        if isinstance(destination_credentials, str) and destination_credentials.strip():
            print('inside if isinstance')
            destination_credentials = json.loads(destination_credentials)
        else:
            print('inside else of isinstance')
            print("Error: destination_credentials is missing or invalid.")
            return render(request, 'migrate_photos.html', {
                'photos': photos,
                'error': 'Destination credentials are missing.'
            })

        if action == 'migrate_all':
            print('in migrate all ')
            if destination_credentials:
                print('dest creds mil gaye')
                destination_service = get_photos_service(destination_credentials)
                for photo in photos:
                    file_url = photo['baseUrl'] + "=d"
                    file_name = photo['filename']
                    photo_data = download_photo(file_url)
                    if photo_data:
                        upload_photo(destination_service, photo_data, file_name)
                return render(request, 'migrate_photos.html', {
                    'photos': photos,
                    'success_all': True,
                    'next_page_token': next_page_token
                })

        elif action == 'migrate_selected':
            selected_photo_ids = request.POST.getlist('selected_photos')
            if destination_credentials and selected_photo_ids:
                destination_service = get_photos_service(destination_credentials)
                selected_photos = [photo for photo in photos if photo['id'] in selected_photo_ids]
                for photo in selected_photos:
                    file_url = photo['baseUrl'] + "=d"
                    file_name = photo['filename']
                    photo_data = download_photo(file_url)
                    if photo_data:
                        upload_photo(destination_service, photo_data, file_name)
                return render(request, 'migrate_photos.html', {
                    'photos': photos,
                    'success_selected': True,
                    'next_page_token': next_page_token
                })

    return render(request, 'migrate_photos.html', {
        'photos': photos,
        'next_page_token': next_page_token
    })

def destination_google_auth(request):
    print('destination google auth mai gaya')
    if request.method == 'POST':
        email = request.POST.get('destination_email')
        flow = get_google_auth_flow()
        authorization_url, state = flow.authorization_url(access_type='offline')
        request.session['destination_email'] = email
        return redirect(authorization_url)
    return redirect('home')

def destination_google_auth_callback(request):
    print('inside destination google auth callback')
    if 'code' not in request.GET:
        return redirect('home')

    flow = get_google_auth_flow()
    flow.fetch_token(authorization_response=request.build_absolute_uri())
    credentials = flow.credentials
    print('creds in destination auth callback', credentials)
    request.session['destination_credentials'] = credentials_to_dict(credentials)
    return redirect('migrate_photos')

def get_photos(credentials_dict, page_token=None):
    service = get_photos_service(credentials_dict)
    results = service.mediaItems().list(pageSize=20, pageToken=page_token).execute()
    items = results.get('mediaItems', [])
    next_page_token = results.get('nextPageToken')
    return items, next_page_token

def download_photo(url):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        return io.BytesIO(response.content)
    except requests.exceptions.RequestException as e:
        print(f"Error downloading photo: {e}")
        return None

def upload_photo(service, photo_data, file_name):
    try:
        media_item = {'newMediaItems': [{'simpleMediaItem': {'fileName': file_name}}]}
        service.mediaItems().batchCreate(body=media_item).execute()
    except Exception as e:
        print(f"Error uploading photo: {e}")

from django.contrib.auth import logout
def logout_view(request):
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

    request.session.flush()
    logout(request)
    return redirect('home')

def fetch_user_info(credentials):
    try:
        response = requests.get(
            'https://www.googleapis.com/oauth2/v1/userinfo',
            headers={'Authorization': f'Bearer {credentials.token}'}
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching user info: {e}")
        return None
